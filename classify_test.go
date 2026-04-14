package main

import "testing"

func TestClassifyTool(t *testing.T) {
	tests := []struct {
		name        string
		toolName    string
		description string
		wantFinance bool
		wantImpact  ImpactTier
		wantRisk    RiskTier
	}{
		{
			name:        "stripe payment tool",
			toolName:    "mcp__stripe__create_payment",
			wantFinance: true,
			wantImpact:  ImpactAction,
			wantRisk:    RiskCritical,
		},
		{
			name:        "generic send_money",
			toolName:    "send_money",
			wantFinance: true,
			wantImpact:  ImpactAction,
			wantRisk:    RiskCritical,
		},
		{
			name:        "payment in description",
			toolName:    "process_order",
			description: "Create a payment via Stripe",
			wantFinance: true,
			wantImpact:  ImpactAction,
			wantRisk:    RiskCritical,
		},
		{
			name:        "read-only financial",
			toolName:    "mcp__stripe__list_payments",
			wantFinance: true,
			wantImpact:  ImpactPerception,
			wantRisk:    RiskHigh,
		},
		{
			name:        "bash is general+action",
			toolName:    "Bash",
			description: "Execute a shell command",
			wantFinance: false,
			wantImpact:  ImpactAction,
			wantRisk:    RiskHigh,
		},
		{
			name:        "read file is perception",
			toolName:    "Read",
			description: "Read a file from disk",
			wantFinance: false,
			wantImpact:  ImpactPerception,
			wantRisk:    RiskLow,
		},
		{
			name:        "analyze is reasoning",
			toolName:    "analyze_data",
			wantFinance: false,
			wantImpact:  ImpactReasoning,
			wantRisk:    RiskLow,
		},
		{
			name:        "crypto wallet",
			toolName:    "mcp__coinbase__transfer_crypto",
			wantFinance: true,
			wantImpact:  ImpactAction,
			wantRisk:    RiskCritical,
		},
		{
			name:        "invoice tool",
			toolName:    "create_invoice",
			wantFinance: true,
			wantImpact:  ImpactAction,
			wantRisk:    RiskCritical,
		},
		{
			name:        "checkout is financial read",
			toolName:    "mcp__shop__checkout",
			wantFinance: true,
			wantImpact:  ImpactReasoning,
			wantRisk:    RiskHigh,
		},
		{
			name:        "checkout with create is critical",
			toolName:    "mcp__shop__create_checkout",
			wantFinance: true,
			wantImpact:  ImpactAction,
			wantRisk:    RiskCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cls := ClassifyTool(tt.toolName, tt.description)
			if cls.Financial != tt.wantFinance {
				t.Errorf("Financial = %v, want %v", cls.Financial, tt.wantFinance)
			}
			if cls.ImpactTier != tt.wantImpact {
				t.Errorf("ImpactTier = %v, want %v", cls.ImpactTier, tt.wantImpact)
			}
			if tt.wantRisk != "" && cls.RiskTier != tt.wantRisk {
				t.Errorf("RiskTier = %v, want %v", cls.RiskTier, tt.wantRisk)
			}
		})
	}
}

func TestClassifyTool_NoFalsePositiveOnSubstring(t *testing.T) {
	// P1 regression: "pay" must not match "payload", "display", "repay" etc.
	falsePositives := []string{
		"mcp__api__send_payload",
		"mcp__ui__display_results",
		"mcp__data__replay_events",
		"mcp__net__tcp_relay",
	}
	for _, name := range falsePositives {
		t.Run(name, func(t *testing.T) {
			cls := ClassifyTool(name, "")
			if cls.Financial {
				t.Errorf("ClassifyTool(%q) = financial (matched: %v), want non-financial",
					name, cls.MatchedKeywords)
			}
		})
	}
}

func TestIsFinancial(t *testing.T) {
	tests := []struct {
		toolName string
		want     bool
	}{
		{"mcp__stripe__create_payment", true},
		{"mcp__coinbase__transfer_crypto", true},
		{"Bash", false},
		{"Read", false},
		{"Edit", false},
		{"mcp__github__search_repositories", false},
		{"mcp__api__send_payload", false},     // P1: "pay" substring
		{"mcp__ui__display_results", false},   // P1: "pay" substring
	}
	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			if got := IsFinancial(tt.toolName); got != tt.want {
				t.Errorf("IsFinancial(%q) = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestParseMCPToolName(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantServer string
		wantTool   string
	}{
		{"standard mcp", "mcp__stripe__create_payment", "stripe", "create_payment"},
		{"nested", "mcp__my_server__do_thing", "my_server", "do_thing"},
		{"non-mcp", "Bash", "", "Bash"},
		{"partial prefix", "mcp__incomplete", "", "mcp__incomplete"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, tool := ParseMCPToolName(tt.input)
			if server != tt.wantServer {
				t.Errorf("server = %q, want %q", server, tt.wantServer)
			}
			if tool != tt.wantTool {
				t.Errorf("tool = %q, want %q", tool, tt.wantTool)
			}
		})
	}
}
