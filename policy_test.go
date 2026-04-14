package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckPolicy_MaxPerCall(t *testing.T) {
	p := Policy{MaxPerCall: 500}
	result := CheckPolicy(p, "send_money", 600, nil, nil)
	if result.Allowed {
		t.Error("expected deny for amount exceeding max per call")
	}
	if result.Decision != DecisionAmountExceeded {
		t.Errorf("Decision = %v, want %v", result.Decision, DecisionAmountExceeded)
	}

	result = CheckPolicy(p, "send_money", 400, nil, nil)
	if !result.Allowed {
		t.Error("expected allow for amount within limit")
	}
}

func TestCheckPolicy_ApprovalThreshold(t *testing.T) {
	p := Policy{MaxPerCall: 1000, RequireApprovalAbove: 200}
	result := CheckPolicy(p, "send_money", 250, nil, nil)
	if result.Allowed {
		t.Error("expected deny for amount above approval threshold")
	}
	if result.Decision != DecisionApprovalRequired {
		t.Errorf("Decision = %v, want %v", result.Decision, DecisionApprovalRequired)
	}
}

func TestCheckPolicy_RateLimit(t *testing.T) {
	p := Policy{RateLimitPerHour: 3}
	now := time.Now().Unix()
	calls := []int64{now - 100, now - 50, now - 10}

	result := CheckPolicy(p, "send_money", 10, calls, nil)
	if result.Allowed {
		t.Error("expected deny for rate limit exceeded")
	}
	if result.Decision != DecisionRateLimited {
		t.Errorf("Decision = %v, want %v", result.Decision, DecisionRateLimited)
	}

	// Old calls should not count.
	oldCalls := []int64{now - 7200, now - 7100}
	result = CheckPolicy(p, "send_money", 10, oldCalls, nil)
	if !result.Allowed {
		t.Error("expected allow with only expired calls")
	}
}

func TestCheckPolicy_DailyLimit(t *testing.T) {
	p := Policy{DailyLimit: 100}
	now := time.Now().Unix()
	spends := []SpendRecord{
		{Amount: 40, At: now - 3600},
		{Amount: 40, At: now - 1800},
	}

	result := CheckPolicy(p, "send_money", 25, nil, spends)
	if result.Allowed {
		t.Error("expected deny for daily limit exceeded")
	}
	if result.Decision != DecisionDailyLimitExceeded {
		t.Errorf("Decision = %v, want %v", result.Decision, DecisionDailyLimitExceeded)
	}

	result = CheckPolicy(p, "send_money", 15, nil, spends)
	if !result.Allowed {
		t.Errorf("expected allow for amount within daily limit, got %v: %s", result.Decision, result.Reason)
	}
}

func TestCheckPolicy_AllPass(t *testing.T) {
	p := DefaultPolicy()
	result := CheckPolicy(p, "send_money", 50, nil, nil)
	if !result.Allowed {
		t.Errorf("expected allow, got %v: %s", result.Decision, result.Reason)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Decision = %v, want %v", result.Decision, DecisionAllow)
	}
}

func TestExtractAmount(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
		want float64
	}{
		{"float amount", map[string]any{"amount": 50.0}, 50.0},
		{"int amount", map[string]any{"amount": 100}, 100.0},
		{"string amount", map[string]any{"amount": "75.50"}, 75.50},
		{"value field", map[string]any{"value": 30.0}, 30.0},
		{"cost field", map[string]any{"cost": 20.0}, 20.0},
		{"no amount", map[string]any{"name": "test"}, 0},
		{"amount precedence", map[string]any{"amount": 10.0, "value": 20.0}, 10.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractAmount(tt.args)
			if got != tt.want {
				t.Errorf("ExtractAmount() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractRecipient(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
		want string
	}{
		{"recipient field", map[string]any{"recipient": "alice@co.com"}, "alice@co.com"},
		{"to field", map[string]any{"to": "bob@co.com"}, "bob@co.com"},
		{"destination field", map[string]any{"destination": "carol@co.com"}, "carol@co.com"},
		{"no recipient", map[string]any{"amount": 50}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractRecipient(tt.args)
			if got != tt.want {
				t.Errorf("ExtractRecipient() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadSavePolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	// Load non-existent returns defaults.
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxPerCall != 500 {
		t.Errorf("MaxPerCall = %v, want 500", p.MaxPerCall)
	}

	// Save and reload.
	p.MaxPerCall = 1000
	if err := SavePolicy(path, p); err != nil {
		t.Fatal(err)
	}
	p2, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if p2.MaxPerCall != 1000 {
		t.Errorf("MaxPerCall after reload = %v, want 1000", p2.MaxPerCall)
	}

	// Verify file permissions.
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %o, want 0600", info.Mode().Perm())
	}
}
