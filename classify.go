package main

import "strings"

// ImpactTier represents a tool's impact level from the UK AISI taxonomy.
type ImpactTier string

const (
	ImpactPerception ImpactTier = "perception"
	ImpactReasoning  ImpactTier = "reasoning"
	ImpactAction     ImpactTier = "action"
)

// Generality represents how broadly a tool can operate.
type Generality string

const (
	GeneralityNarrow  Generality = "narrow"
	GeneralityGeneral Generality = "general"
)

// RiskTier is the derived risk level for a tool.
type RiskTier string

const (
	RiskLow      RiskTier = "low"
	RiskMedium   RiskTier = "medium"
	RiskHigh     RiskTier = "high"
	RiskCritical RiskTier = "critical"
)

// ToolClassification holds the classification result for a tool call.
type ToolClassification struct {
	ImpactTier      ImpactTier `json:"impact_tier"`
	Generality      Generality `json:"generality"`
	RiskTier        RiskTier   `json:"risk_tier"`
	Financial       bool       `json:"financial"`
	MatchedKeywords []string   `json:"matched_keywords,omitempty"`
}

var (
	actionKeywords = []string{
		"write", "create", "delete", "send", "execute", "deploy",
		"transfer", "pay", "update", "modify", "post", "put",
		"patch", "remove", "install", "run", "invoke",
	}

	perceptionKeywords = []string{
		"read", "get", "list", "search", "query", "fetch",
		"describe", "show", "view", "check", "status", "find",
	}

	reasoningKeywords = []string{
		"analyze", "plan", "summarize", "calculate", "classify",
		"evaluate", "compare", "predict",
	}

	generalKeywords = []string{
		"bash", "shell", "execute", "eval", "browser",
		"computer", "click", "navigate", "terminal",
	}

	financeKeywords = []string{
		"pay", "payment", "transfer", "wallet", "crypto", "trade",
		"withdraw", "deposit", "invoice", "checkout",
		"stripe", "coinbase", "paypal", "send_money",
		"create_payment", "create_charge", "purchase",
		"refund", "payout", "billing", "charge",
	}
)

// ClassifyTool classifies a tool by name and description into impact,
// generality, risk, and financial tiers using keyword matching.
func ClassifyTool(name, description string) ToolClassification {
	text := strings.ToLower(name + " " + description)
	words := tokenize(text)

	var matched []string

	// Determine generality.
	gen := GeneralityNarrow
	if hits := matchWords(words, generalKeywords); len(hits) > 0 {
		gen = GeneralityGeneral
		matched = append(matched, hits...)
	}

	// Determine impact tier (action > perception > reasoning).
	impact := ImpactReasoning
	actionHits := matchWords(words, actionKeywords)
	perceptionHits := matchWords(words, perceptionKeywords)

	switch {
	case len(actionHits) > 0 && len(actionHits) >= len(perceptionHits):
		impact = ImpactAction
		matched = append(matched, actionHits...)
	case len(perceptionHits) > 0:
		impact = ImpactPerception
		matched = append(matched, perceptionHits...)
	default:
		if hits := matchWords(words, reasoningKeywords); len(hits) > 0 {
			matched = append(matched, hits...)
		}
	}

	// General tools are inherently action-capable.
	if gen == GeneralityGeneral && impact != ImpactAction {
		impact = ImpactAction
	}

	// Check finance keywords.
	financeHits := matchWords(words, financeKeywords)
	financial := len(financeHits) > 0
	if financial {
		matched = append(matched, financeHits...)
	}

	return ToolClassification{
		ImpactTier:      impact,
		Generality:      gen,
		RiskTier:        deriveRiskTier(impact, gen, financial),
		Financial:       financial,
		MatchedKeywords: matched,
	}
}

// IsFinancial returns true if the tool name alone matches financial patterns.
// This is the fast-path check used by the guard to decide whether to run the
// full security pipeline.
func IsFinancial(toolName string) bool {
	return ClassifyTool(toolName, "").Financial
}

// ParseMCPToolName extracts server and tool from an MCP tool name
// formatted as "mcp__<server>__<tool>".
func ParseMCPToolName(name string) (server, tool string) {
	if !strings.HasPrefix(name, "mcp__") {
		return "", name
	}
	rest := name[5:]
	idx := strings.Index(rest, "__")
	if idx < 0 {
		return "", name
	}
	return rest[:idx], rest[idx+2:]
}

func deriveRiskTier(impact ImpactTier, gen Generality, financial bool) RiskTier {
	if financial {
		if impact == ImpactAction {
			return RiskCritical
		}
		return RiskHigh
	}
	if impact == ImpactAction && gen == GeneralityGeneral {
		return RiskHigh
	}
	if impact == ImpactAction || gen == GeneralityGeneral {
		return RiskMedium
	}
	return RiskLow
}

func tokenize(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '_' || r == '-' || r == '/' || r == '.' || r == ','
	})
}

func matchWords(words, keywords []string) []string {
	kwSet := make(map[string]struct{}, len(keywords))
	for _, kw := range keywords {
		kwSet[kw] = struct{}{}
	}
	var hits []string
	seen := make(map[string]bool)
	for _, w := range words {
		if _, ok := kwSet[w]; ok && !seen[w] {
			hits = append(hits, w)
			seen[w] = true
		}
	}
	return hits
}
