package main

import (
	"testing"
)

func newTestPipeline(t *testing.T) *Pipeline {
	t.Helper()
	dir := t.TempDir()
	p, err := NewPipeline(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestGuard_NonFinancialPassThrough(t *testing.T) {
	p := newTestPipeline(t)
	input := HookInput{
		SessionID: "test",
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "ls -la"},
	}
	result, output := p.Run(input)
	if result.Decision != "allow" {
		t.Errorf("Decision = %q, want allow", result.Decision)
	}
	if len(result.Stages) != 1 || result.Stages[0].Status != "not_financial" {
		t.Errorf("Stages = %v, want classify:not_financial", result.Stages)
	}
	// Non-financial: no hook output needed.
	if output.HookSpecificOutput != nil && output.HookSpecificOutput.AdditionalContext != "" {
		t.Errorf("expected empty context for non-financial, got %q",
			output.HookSpecificOutput.AdditionalContext)
	}
}

func TestGuard_FirstPaymentRequiresApproval(t *testing.T) {
	p := newTestPipeline(t)
	input := HookInput{
		SessionID: "test",
		ToolName:  "mcp__stripe__create_payment",
		ToolInput: map[string]any{
			"amount":    50.0,
			"recipient": "alice@co.com",
			"currency":  "usd",
		},
	}
	result, output := p.Run(input)
	if result.Decision != "ask" {
		t.Errorf("Decision = %q, want ask: %s", result.Decision, result.Reason)
	}
	if !result.Classification.Financial {
		t.Error("expected financial classification")
	}
	if output.HookSpecificOutput == nil {
		t.Fatal("expected hook output")
	}
	if output.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("PermissionDecision = %q, want ask", output.HookSpecificOutput.PermissionDecision)
	}
}

func TestGuard_RepeatPaymentToApprovedRecipientAllowed(t *testing.T) {
	p := newTestPipeline(t)

	first, _ := p.Run(HookInput{
		SessionID: "test",
		ToolName:  "mcp__stripe__create_payment",
		ToolInput: map[string]any{
			"amount":    50.0,
			"recipient": "alice@co.com",
			"currency":  "usd",
		},
	})
	if first.Decision != "ask" {
		t.Fatalf("first decision = %q, want ask", first.Decision)
	}

	second, output := p.Run(HookInput{
		SessionID: "test",
		ToolName:  "mcp__stripe__create_payment",
		ToolInput: map[string]any{
			"amount":    50.0,
			"recipient": "alice@co.com",
			"currency":  "usd",
		},
	})
	if second.Decision != "allow" {
		t.Fatalf("second decision = %q, want allow", second.Decision)
	}
	if output.HookSpecificOutput == nil || output.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("second output = %+v, want allow", output.HookSpecificOutput)
	}
}

func TestGuard_CredentialBlocked(t *testing.T) {
	p := newTestPipeline(t)
	input := HookInput{
		SessionID: "test",
		ToolName:  "mcp__stripe__create_payment",
		ToolInput: map[string]any{
			"amount": 50.0,
			"note":   "ref: sk-ant-abc123def456ghi789jkl",
		},
	}
	result, output := p.Run(input)
	if result.Decision != "deny" {
		t.Errorf("Decision = %q, want deny", result.Decision)
	}
	if output.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("PermissionDecision = %q, want deny", output.HookSpecificOutput.PermissionDecision)
	}
}

func TestGuard_AmountExceeded(t *testing.T) {
	p := newTestPipeline(t)
	input := HookInput{
		SessionID: "test",
		ToolName:  "mcp__stripe__create_payment",
		ToolInput: map[string]any{
			"amount":    5000.0,
			"recipient": "alice@co.com",
		},
	}
	result, _ := p.Run(input)
	if result.Decision != "deny" {
		t.Errorf("Decision = %q, want deny", result.Decision)
	}
}

func TestGuard_ApprovalRequired(t *testing.T) {
	p := newTestPipeline(t)
	input := HookInput{
		SessionID: "test",
		ToolName:  "mcp__stripe__create_payment",
		ToolInput: map[string]any{
			"amount":    250.0,
			"recipient": "alice@co.com",
		},
	}
	result, output := p.Run(input)
	if result.Decision != "ask" {
		t.Errorf("Decision = %q, want ask", result.Decision)
	}
	if output.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("PermissionDecision = %q, want ask", output.HookSpecificOutput.PermissionDecision)
	}
}

func TestGuard_RecipientDrift(t *testing.T) {
	p := newTestPipeline(t)

	// First call: register intent.
	input1 := HookInput{
		SessionID: "session-1",
		ToolName:  "mcp__stripe__create_payment",
		ToolInput: map[string]any{
			"amount":    50.0,
			"recipient": "alice@co.com",
			"currency":  "usd",
		},
	}
	result1, _ := p.Run(input1)
	if result1.Decision != "ask" {
		t.Fatalf("first call: Decision = %q, want ask", result1.Decision)
	}

	// Second call: different recipient. New recipients get ASK (approval)
	// rather than BLOCK, so the human decides if it's legit or a MCP swap.
	input2 := HookInput{
		SessionID: "session-1",
		ToolName:  "mcp__payment__send_money",
		ToolInput: map[string]any{
			"amount":    50.0,
			"recipient": "eve@attacker.com",
			"currency":  "usd",
		},
	}
	result2, output2 := p.Run(input2)
	if result2.Decision != "ask" {
		t.Errorf("new recipient: Decision = %q, want ask", result2.Decision)
	}
	if output2.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("PermissionDecision = %q, want ask", output2.HookSpecificOutput.PermissionDecision)
	}
}

func TestGuard_AmountDriftOnKnownRecipient(t *testing.T) {
	p := newTestPipeline(t)
	p.policy.RequireApprovalAbove = 0 // disable so we isolate drift

	// First call: register intent for alice at $50.
	r1, _ := p.Run(HookInput{
		SessionID: "drift-test",
		ToolName:  "mcp__stripe__create_payment",
		ToolInput: map[string]any{
			"amount": 50.0, "recipient": "alice@co.com", "currency": "usd",
		},
	})
	if r1.Decision != "ask" {
		t.Fatalf("first: %q, want ask", r1.Decision)
	}

	// Second call: same recipient, inflated amount = real drift = BLOCK.
	r2, _ := p.Run(HookInput{
		SessionID: "drift-test",
		ToolName:  "mcp__stripe__create_payment",
		ToolInput: map[string]any{
			"amount": 5000.0, "recipient": "alice@co.com", "currency": "usd",
		},
	})
	if r2.Decision != "deny" {
		t.Fatalf("amount drift: %q, want deny", r2.Decision)
	}
}

func TestGuard_RateLimit(t *testing.T) {
	p := newTestPipeline(t)
	p.policy.RateLimitPerHour = 3
	p.policy.RequireApprovalAbove = 0 // disable for this test

	input := HookInput{
		SessionID: "test",
		ToolName:  "mcp__stripe__create_payment",
		ToolInput: map[string]any{
			"amount":    10.0,
			"recipient": "alice@co.com",
		},
	}

	// First call asks to establish a baseline; next two are allowed.
	for i := 0; i < 3; i++ {
		result, _ := p.Run(input)
		want := "allow"
		if i == 0 {
			want = "ask"
		}
		if result.Decision != want {
			t.Fatalf("call %d: Decision = %q, want %s", i+1, result.Decision, want)
		}
	}

	// 4th call should be rate limited.
	result, _ := p.Run(input)
	if result.Decision != "deny" {
		t.Errorf("call 4: Decision = %q, want deny (rate limited)", result.Decision)
	}
}

func TestGuard_GlobalRateLimitAcrossFinancialTools(t *testing.T) {
	p := newTestPipeline(t)
	p.policy.RateLimitPerHour = 2
	p.policy.RequireApprovalAbove = 0

	first, _ := p.Run(HookInput{
		SessionID: "multi-tool",
		ToolName:  "mcp__stripe__create_payment",
		ToolInput: map[string]any{"amount": 10.0, "recipient": "alice@co.com", "currency": "usd"},
	})
	if first.Decision != "ask" {
		t.Fatalf("first decision = %q, want ask", first.Decision)
	}

	second, _ := p.Run(HookInput{
		SessionID: "multi-tool",
		ToolName:  "mcp__paypal__send_money",
		ToolInput: map[string]any{"amount": 10.0, "recipient": "alice@co.com", "currency": "usd"},
	})
	if second.Decision != "allow" {
		t.Fatalf("second decision = %q, want allow", second.Decision)
	}

	third, _ := p.Run(HookInput{
		SessionID: "multi-tool",
		ToolName:  "mcp__coinbase__transfer_crypto",
		ToolInput: map[string]any{"amount": 10.0, "recipient": "alice@co.com", "currency": "usd"},
	})
	if third.Decision != "deny" {
		t.Fatalf("third decision = %q, want deny due to global rate limit", third.Decision)
	}
}

func TestGuard_ClassifiesFinancialFromArguments(t *testing.T) {
	p := newTestPipeline(t)
	result, _ := p.Run(HookInput{
		SessionID: "args-financial",
		ToolName:  "mcp__custom__submit_order",
		ToolInput: map[string]any{
			"amount":    25.0,
			"recipient": "alice@co.com",
			"currency":  "usd",
		},
	})
	if !result.Classification.Financial {
		t.Fatal("expected arguments to trigger financial classification")
	}
	if result.Decision != "ask" {
		t.Fatalf("decision = %q, want ask for first financial payment", result.Decision)
	}
}

func TestGuard_FinancialOverrides(t *testing.T) {
	p := newTestPipeline(t)
	p.policy.AlwaysFinancial = []string{"*custom_pay*"}
	p.policy.NeverFinancial = []string{"mcp__stripe__list_payments"}

	// Tool matching always_financial.
	result, _ := p.Run(HookInput{
		SessionID: "test",
		ToolName:  "my_custom_pay_tool",
		ToolInput: map[string]any{"amount": 10.0, "recipient": "a@b.com"},
	})
	if !result.Classification.Financial {
		t.Error("expected financial from always_financial override")
	}

	// Tool matching never_financial.
	result, _ = p.Run(HookInput{
		SessionID: "test",
		ToolName:  "mcp__stripe__list_payments",
		ToolInput: map[string]any{},
	})
	if result.Classification.Financial {
		t.Error("expected non-financial from never_financial override")
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		s, pattern string
		want       bool
	}{
		{"mcp__stripe__create", "mcp__stripe__*", true},
		{"mcp__stripe__create", "*stripe*", true},
		{"mcp__github__search", "*stripe*", false},
		{"anything", "*", true},
		{"exact", "exact", true},
		{"exact", "wrong", false},
		{"send_money", "*money", true},
		{"send_money", "*cash", false},
	}
	for _, tt := range tests {
		t.Run(tt.s+"~"+tt.pattern, func(t *testing.T) {
			got := matchGlob(tt.s, tt.pattern)
			if got != tt.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.s, tt.pattern, got, tt.want)
			}
		})
	}
}
