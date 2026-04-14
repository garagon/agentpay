package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// HookInput is the JSON payload received from Claude Code on stdin
// when a PreToolUse hook fires.
type HookInput struct {
	SessionID      string         `json:"session_id"`
	TranscriptPath string         `json:"transcript_path"`
	Cwd            string         `json:"cwd"`
	PermissionMode string         `json:"permission_mode"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
}

// HookOutput is the JSON payload returned to Claude Code on stdout.
type HookOutput struct {
	HookSpecificOutput *HookDecision `json:"hookSpecificOutput,omitempty"`
}

// HookDecision describes the permission decision for a tool call.
type HookDecision struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string `json:"additionalContext,omitempty"`
}

// StageResult records the outcome of one pipeline stage.
type StageResult struct {
	Name   string // e.g. "classify", "credentials", "policy", "integrity"
	Status string // e.g. "financial", "clean", "allow", "ok"
}

// GuardResult is the full pipeline output for a single tool call.
type GuardResult struct {
	ToolName       string
	Classification ToolClassification
	Amount         float64
	Recipient      string
	Currency       string
	Decision       string // "allow", "deny", "ask"
	Reason         string
	Stages         []StageResult
}

func (r GuardResult) StageStrings() []string {
	out := make([]string, len(r.Stages))
	for i, s := range r.Stages {
		out[i] = s.Name + ":" + s.Status
	}
	return out
}

// Pipeline orchestrates the five-stage security check for a tool call.
type Pipeline struct {
	policy   Policy
	state    *State
	auditLog *AuditLog

	configDir string
	statePath string
	lock      *FileLock
}

// NewPipeline loads policy and state, acquires the state file lock, and
// opens the audit log. Call Close() after Run() to persist state and
// release the lock.
func NewPipeline(configDir string) (*Pipeline, error) {
	policyPath := filepath.Join(configDir, "policy.yaml")
	policy, err := LoadPolicy(policyPath)
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}

	statePath := filepath.Join(configDir, "state.json")
	lockPath := filepath.Join(configDir, "state.lock")

	lock, err := AcquireLock(lockPath)
	if err != nil {
		// Fail-open: if we can't lock, proceed without state tracking.
		lock = nil
	}

	state, err := LoadState(statePath)
	if err != nil {
		state = NewState()
	}

	auditPath := filepath.Join(configDir, "audit.jsonl")
	auditLog, err := NewAuditLog(auditPath)
	if err != nil {
		auditLog = &AuditLog{path: auditPath, prevHash: genesisHash}
	}

	return &Pipeline{
		policy:    policy,
		state:     state,
		auditLog:  auditLog,
		configDir: configDir,
		statePath: statePath,
		lock:      lock,
	}, nil
}

// Run executes the five-stage security pipeline and returns both the
// guard result (for logging/demo) and the hook output (for Claude Code).
func (p *Pipeline) Run(input HookInput) (GuardResult, HookOutput) {
	result := GuardResult{
		ToolName: input.ToolName,
	}

	// Stage 1: Classify tool.
	cls := ClassifyTool(input.ToolName, "")

	// Check policy overrides for always/never financial.
	cls.Financial = p.applyFinancialOverrides(input.ToolName, cls.Financial)

	result.Classification = cls

	if !cls.Financial {
		result.Decision = "allow"
		result.Stages = []StageResult{{Name: "classify", Status: "not_financial"}}
		return result, makeAllow("")
	}
	result.Stages = append(result.Stages, StageResult{
		Name:   "classify",
		Status: fmt.Sprintf("financial:%s", cls.RiskTier),
	})

	// Stage 2: Credential scan.
	if cred := ScanCredentials(input.ToolInput); cred != nil {
		result.Decision = "deny"
		result.Reason = fmt.Sprintf("%s detected in field %q (%s)", cred.Type, cred.Field, cred.Redacted)
		result.Stages = append(result.Stages, StageResult{Name: "credentials", Status: "DETECTED"})
		p.logAudit(input, result)
		return result, makeDeny(fmt.Sprintf("[AgentPay] BLOCKED: %s", result.Reason))
	}
	result.Stages = append(result.Stages, StageResult{Name: "credentials", Status: "clean"})

	// Extract payment parameters.
	amount := ExtractAmount(input.ToolInput)
	recipient := ExtractRecipient(input.ToolInput)
	currency := strings.ToLower(ExtractCurrency(input.ToolInput))
	result.Amount = amount
	result.Recipient = recipient
	result.Currency = currency

	// Stage 3: Policy enforcement.
	calls := p.state.Calls[input.ToolName]
	spends := p.state.Spends[input.ToolName]
	policyResult := CheckPolicy(p.policy, input.ToolName, amount, calls, spends)

	switch policyResult.Decision {
	case DecisionAmountExceeded, DecisionRateLimited, DecisionDailyLimitExceeded:
		result.Decision = "deny"
		result.Reason = policyResult.Reason
		result.Stages = append(result.Stages, StageResult{
			Name:   "policy",
			Status: string(policyResult.Decision),
		})
		p.logAudit(input, result)
		return result, makeDeny(fmt.Sprintf("[AgentPay] BLOCKED: %s", policyResult.Reason))

	case DecisionApprovalRequired:
		result.Decision = "ask"
		result.Reason = policyResult.Reason
		result.Stages = append(result.Stages, StageResult{
			Name:   "policy",
			Status: "approval_required",
		})
		p.logAudit(input, result)
		return result, makeAsk(fmt.Sprintf("[AgentPay] %s", policyResult.Reason))

	default:
		result.Stages = append(result.Stages, StageResult{Name: "policy", Status: "allow"})
	}

	// Stage 4: Payment integrity (drift detection).
	// We scan ALL intents for this session, not just the current recipient's
	// key, because a poisoned MCP may have changed the recipient field.
	if recipient != "" {
		sessionIntents := p.state.GetSessionIntents(input.SessionID)
		if len(sessionIntents) == 0 {
			// First payment in session: register as baseline.
			key := IntentKey(input.SessionID, recipient)
			p.state.RegisterIntent(key, recipient, amount, currency)
			result.Stages = append(result.Stages, StageResult{Name: "integrity", Status: "registered"})
		} else {
			// Check if this recipient is in any registered intent.
			var matchingIntent *PaymentIntent
			for i := range sessionIntents {
				if sessionIntents[i].Recipient == recipient {
					matchingIntent = &sessionIntents[i]
					break
				}
			}
			if matchingIntent == nil {
				// Recipient not authorized in this session — MCP likely
				// swapped the destination.
				result.Decision = "deny"
				result.Reason = fmt.Sprintf("recipient drift: expected %s, got %s",
					sessionIntents[0].Recipient, recipient)
				result.Stages = append(result.Stages, StageResult{
					Name:   "integrity",
					Status: "RECIPIENT_DRIFT",
				})
				p.logAudit(input, result)
				return result, makeDeny(fmt.Sprintf("[AgentPay] BLOCKED: payment %s", result.Reason))
			}
			// Recipient matches — check amount and currency drift.
			drift := CheckIntentDrift(*matchingIntent, recipient, amount, currency, p.policy.AmountDriftTolerance)
			if drift.HasDrift {
				result.Decision = "deny"
				result.Reason = fmt.Sprintf("%s drift: expected %s, got %s", drift.Type, drift.Expected, drift.Got)
				result.Stages = append(result.Stages, StageResult{
					Name:   "integrity",
					Status: fmt.Sprintf("%s_DRIFT", strings.ToUpper(string(drift.Type))),
				})
				p.logAudit(input, result)
				return result, makeDeny(fmt.Sprintf("[AgentPay] BLOCKED: payment %s", result.Reason))
			}
			result.Stages = append(result.Stages, StageResult{Name: "integrity", Status: "verified"})
		}
	} else {
		result.Stages = append(result.Stages, StageResult{Name: "integrity", Status: "no_recipient"})
	}

	// All stages passed. Record the call for rate/spend tracking.
	p.state.RecordCall(input.ToolName)
	p.state.RecordSpend(input.ToolName, amount)

	result.Decision = "allow"
	p.logAudit(input, result)

	context := fmt.Sprintf("[AgentPay] Payment verified: $%.2f to %s (risk: %s)",
		amount, recipient, cls.RiskTier)
	return result, makeAllow(context)
}

// Close persists state to disk and releases the file lock.
func (p *Pipeline) Close() {
	if p.state != nil && p.statePath != "" {
		_ = p.state.Save(p.statePath)
	}
	if p.lock != nil {
		p.lock.Release()
	}
}

func (p *Pipeline) applyFinancialOverrides(toolName string, detected bool) bool {
	lower := strings.ToLower(toolName)
	for _, pattern := range p.policy.NeverFinancial {
		if matchGlob(lower, strings.ToLower(pattern)) {
			return false
		}
	}
	for _, pattern := range p.policy.AlwaysFinancial {
		if matchGlob(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return detected
}

func (p *Pipeline) logAudit(input HookInput, result GuardResult) {
	entry := AuditEntry{
		SessionID:      input.SessionID,
		ToolName:       input.ToolName,
		Classification: fmt.Sprintf("%s:%s", result.Classification.ImpactTier, result.Classification.RiskTier),
		Amount:         result.Amount,
		Recipient:      result.Recipient,
		Currency:       result.Currency,
		Decision:       result.Decision,
		Reason:         result.Reason,
		Stages:         result.StageStrings(),
	}
	_ = p.auditLog.Log(entry)
}

func makeAllow(context string) HookOutput {
	return HookOutput{
		HookSpecificOutput: &HookDecision{
			HookEventName:      "PreToolUse",
			PermissionDecision: "allow",
			AdditionalContext:  context,
		},
	}
}

func makeDeny(reason string) HookOutput {
	return HookOutput{
		HookSpecificOutput: &HookDecision{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		},
	}
}

func makeAsk(reason string) HookOutput {
	return HookOutput{
		HookSpecificOutput: &HookDecision{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "ask",
			PermissionDecisionReason: reason,
		},
	}
}

// matchGlob performs simple wildcard matching supporting * at the start
// and/or end of the pattern (e.g. "*stripe*", "mcp__stripe__*").
func matchGlob(s, pattern string) bool {
	if pattern == "*" || pattern == s {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		return strings.Contains(s, pattern[1:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(s, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return false
}
