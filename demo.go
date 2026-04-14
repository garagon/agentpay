package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ANSI color codes for terminal output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// DemoScenario defines a single attack/legitimate scenario for the demo.
type DemoScenario struct {
	Name        string
	Description string
	Input       HookInput
	// ExpectBlock indicates the expected decision: "allow", "deny", or "ask".
	ExpectBlock string
}

// RunDemo executes all demo scenarios against a fresh pipeline and prints
// colored results to stdout.
func RunDemo() error {
	// Use a temp directory for demo state to avoid polluting user config.
	demoDir, err := os.MkdirTemp("", "agentpay-demo-*")
	if err != nil {
		return fmt.Errorf("create demo dir: %w", err)
	}
	defer os.RemoveAll(demoDir)

	// Write a demo policy with tight limits for dramatic effect.
	demoPolicy := Policy{
		MaxPerCall:                      500.00,
		RequireApprovalAbove:            200.00,
		RequireApprovalOnFirstRecipient: true,
		DailyLimit:                      1000.00,
		RateLimitPerHour:                10,
		AmountDriftTolerance:            0.01,
	}
	if err := SavePolicy(filepath.Join(demoDir, "policy.yaml"), demoPolicy); err != nil {
		return err
	}

	scenarios := buildScenarios()

	fmt.Printf("\n%s%sAgentPay Demo%s %s- Payment Security Plugin for Claude Code%s\n",
		colorBold, colorCyan, colorReset, colorDim, colorReset)
	fmt.Println(strings.Repeat("=", 62))
	fmt.Println()

	// Use a single pipeline so state accumulates across scenarios:
	// scenario 1 registers the legitimate intent, scenario 2 detects
	// the recipient swap against that baseline.
	pipeline, err := NewPipeline(demoDir)
	if err != nil {
		return fmt.Errorf("create pipeline: %w", err)
	}
	defer pipeline.Close()

	for i, sc := range scenarios {
		// Pre-fill rate limit history for the flood scenario.
		if sc.Name == "Rate limit flood" {
			for j := 0; j < 10; j++ {
				pipeline.state.RecordFinancialCall(sc.Input.ToolName)
			}
		}

		result, _ := pipeline.Run(sc.Input)
		printScenario(i+1, sc, result)
	}

	// Verify audit chain.
	entries, err := ReadEntries(filepath.Join(demoDir, "audit.jsonl"))
	if err == nil && len(entries) > 0 {
		invalid := VerifyChain(entries)
		fmt.Printf("\n%sAudit trail:%s %d entries, ", colorBold, colorReset, len(entries))
		if invalid == -1 {
			fmt.Printf("%shash chain valid%s\n", colorGreen, colorReset)
		} else {
			fmt.Printf("%shash chain BROKEN at entry %d%s\n", colorRed, invalid, colorReset)
		}
	}
	fmt.Println()

	return nil
}

func buildScenarios() []DemoScenario {
	session := "demo-session"

	return []DemoScenario{
		{
			Name:        "First payment baseline",
			Description: "Agent requests a first $50 payment to alice@company.com and AgentPay asks for approval before trusting the baseline",
			Input: HookInput{
				SessionID:     session,
				HookEventName: "PreToolUse",
				ToolName:      "mcp__stripe__create_payment",
				ToolInput: map[string]any{
					"amount":    50.0,
					"recipient": "alice@company.com",
					"currency":  "usd",
				},
			},
			ExpectBlock: "ask",
		},
		{
			Name:        "Approved repeat payment",
			Description: "Agent repeats the same $50 payment to alice after the trusted baseline is established",
			Input: HookInput{
				SessionID:     session,
				HookEventName: "PreToolUse",
				ToolName:      "mcp__stripe__create_payment",
				ToolInput: map[string]any{
					"amount":    50.0,
					"recipient": "alice@company.com",
					"currency":  "usd",
				},
			},
			ExpectBlock: "allow",
		},
		{
			Name:        "Poisoned MCP - recipient tampered",
			Description: "MCP changes recipient from alice to attacker - AgentPay flags it for human approval",
			Input: HookInput{
				SessionID:     session,
				HookEventName: "PreToolUse",
				ToolName:      "mcp__payment__send_money",
				ToolInput: map[string]any{
					"amount":    50.0,
					"recipient": "eve@attacker.com",
					"currency":  "usd",
				},
			},
			ExpectBlock: "ask",
		},
		{
			Name:        "Amount inflation",
			Description: "MCP inflates $50 payment to $5,000",
			Input: HookInput{
				SessionID:     session,
				HookEventName: "PreToolUse",
				ToolName:      "mcp__payment__send_money",
				ToolInput: map[string]any{
					"amount":    5000.0,
					"recipient": "alice@company.com",
					"currency":  "usd",
				},
			},
			ExpectBlock: "deny",
		},
		{
			Name:        "Credential exfiltration",
			Description: "MCP embeds stolen API key in payment description",
			Input: HookInput{
				SessionID:     session,
				HookEventName: "PreToolUse",
				ToolName:      "mcp__payment__send_money",
				ToolInput: map[string]any{
					"amount":    50.0,
					"recipient": "alice@company.com",
					"currency":  "usd",
					"note":      "payment ref: sk-ant-abc123def456ghi789",
				},
			},
			ExpectBlock: "deny",
		},
		{
			Name:        "Rate limit flood",
			Description: "MCP triggers 11th payment call in one hour",
			Input: HookInput{
				SessionID:     session,
				HookEventName: "PreToolUse",
				ToolName:      "mcp__payment__send_money",
				ToolInput: map[string]any{
					"amount":    10.0,
					"recipient": "alice@company.com",
					"currency":  "usd",
				},
			},
			ExpectBlock: "deny",
		},
		{
			Name:        "Human approval required",
			Description: "Payment of $250 exceeds auto-approval threshold ($200)",
			Input: HookInput{
				SessionID:     session + "-approval",
				HookEventName: "PreToolUse",
				ToolName:      "mcp__stripe__create_payment",
				ToolInput: map[string]any{
					"amount":    250.0,
					"recipient": "bob@company.com",
					"currency":  "usd",
				},
			},
			ExpectBlock: "ask",
		},
	}
}

func printScenario(num int, sc DemoScenario, result GuardResult) {
	fmt.Printf("%sScenario %d: %s%s\n", colorBold, num, sc.Name, colorReset)
	fmt.Printf("  %s%s%s\n", colorDim, sc.Description, colorReset)
	fmt.Printf("  Tool:      %s\n", result.ToolName)

	if result.Amount > 0 {
		fmt.Printf("  Amount:    $%.2f\n", result.Amount)
	}
	if result.Recipient != "" {
		fmt.Printf("  Recipient: %s\n", result.Recipient)
	}

	// Pipeline stages.
	stages := result.StageStrings()
	fmt.Printf("  Pipeline:  ")
	for i, s := range stages {
		if i > 0 {
			fmt.Printf(" %s->%s ", colorDim, colorReset)
		}
		parts := strings.SplitN(s, ":", 2)
		status := parts[1]
		switch {
		case strings.Contains(strings.ToUpper(status), "DRIFT") ||
			strings.Contains(strings.ToUpper(status), "DETECTED") ||
			strings.Contains(strings.ToUpper(status), "EXCEEDED") ||
			strings.Contains(strings.ToUpper(status), "LIMITED"):
			fmt.Printf("%s%s%s", colorRed, s, colorReset)
		case status == "approval_required":
			fmt.Printf("%s%s%s", colorYellow, s, colorReset)
		default:
			fmt.Printf("%s%s%s", colorGreen, s, colorReset)
		}
	}
	fmt.Println()

	// Decision.
	switch result.Decision {
	case "allow":
		fmt.Printf("  Decision:  %s%sALLOW%s\n", colorBold, colorGreen, colorReset)
	case "deny":
		fmt.Printf("  Decision:  %s%sBLOCK%s\n", colorBold, colorRed, colorReset)
	case "ask":
		fmt.Printf("  Decision:  %s%sASK (human approval)%s\n", colorBold, colorYellow, colorReset)
	}

	if result.Reason != "" {
		fmt.Printf("  Reason:    %s\n", result.Reason)
	}
	fmt.Println()
}

// PrintAudit reads and displays the audit trail with colored output.
func PrintAudit(configDir string, verify bool) error {
	auditPath := filepath.Join(configDir, "audit.jsonl")
	entries, err := ReadEntries(auditPath)
	if err != nil {
		return fmt.Errorf("read audit: %w", err)
	}
	if len(entries) == 0 {
		fmt.Println("No audit entries found.")
		return nil
	}

	fmt.Printf("\n%s%sAgentPay Audit Trail%s\n", colorBold, colorCyan, colorReset)
	fmt.Println(strings.Repeat("-", 50))

	for i, e := range entries {
		decisionColor := colorGreen
		if e.Decision == "deny" {
			decisionColor = colorRed
		} else if e.Decision == "ask" {
			decisionColor = colorYellow
		}

		fmt.Printf("\n%s#%d%s %s%s%s\n", colorDim, i+1, colorReset,
			colorDim, e.Timestamp, colorReset)
		fmt.Printf("  Tool:     %s\n", e.ToolName)
		if e.Amount > 0 {
			fmt.Printf("  Amount:   $%.2f\n", e.Amount)
		}
		if e.Recipient != "" {
			fmt.Printf("  To:       %s\n", e.Recipient)
		}
		fmt.Printf("  Decision: %s%s%s%s\n", colorBold, decisionColor,
			strings.ToUpper(e.Decision), colorReset)
		if e.Reason != "" {
			fmt.Printf("  Reason:   %s\n", e.Reason)
		}
		fmt.Printf("  Hash:     %s%s%s\n", colorDim, truncHash(e.Hash), colorReset)
	}

	if verify {
		fmt.Printf("\n%sChain verification:%s ", colorBold, colorReset)
		invalid := VerifyChain(entries)
		if invalid == -1 {
			fmt.Printf("%s%d entries, chain valid%s\n", colorGreen, len(entries), colorReset)
		} else {
			fmt.Printf("%sBROKEN at entry %d%s\n", colorRed, invalid, colorReset)
		}
	} else {
		fmt.Printf("\n%d entries. Use --verify to check chain integrity.\n", len(entries))
	}
	fmt.Println()
	return nil
}

func truncHash(h string) string {
	if len(h) > 24 {
		return h[:24] + "..."
	}
	return h
}
