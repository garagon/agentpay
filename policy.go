package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy defines spending and rate limits for financial tool calls.
type Policy struct {
	MaxPerCall                      float64  `yaml:"max_per_call"`
	RequireApprovalAbove            float64  `yaml:"require_approval_above"`
	RequireApprovalOnFirstRecipient bool     `yaml:"require_approval_on_first_recipient"`
	DailyLimit                      float64  `yaml:"daily_limit"`
	RateLimitPerHour                int      `yaml:"rate_limit_per_hour"`
	AmountDriftTolerance            float64  `yaml:"amount_drift_tolerance"`
	AlwaysFinancial                 []string `yaml:"always_financial,omitempty"`
	NeverFinancial                  []string `yaml:"never_financial,omitempty"`
}

// PolicyDecision is the outcome of a policy check.
type PolicyDecision string

const (
	DecisionAllow              PolicyDecision = "allow"
	DecisionAmountExceeded     PolicyDecision = "amount_exceeded"
	DecisionApprovalRequired   PolicyDecision = "approval_required"
	DecisionRateLimited        PolicyDecision = "rate_limited"
	DecisionDailyLimitExceeded PolicyDecision = "daily_limit_exceeded"
)

// PolicyResult holds the outcome of a policy enforcement check.
type PolicyResult struct {
	Allowed  bool
	Decision PolicyDecision
	Reason   string
}

// DefaultPolicy returns conservative default spending limits.
func DefaultPolicy() Policy {
	return Policy{
		MaxPerCall:                      500.00,
		RequireApprovalAbove:            200.00,
		RequireApprovalOnFirstRecipient: true,
		DailyLimit:                      2000.00,
		RateLimitPerHour:                10,
		AmountDriftTolerance:            0.01,
	}
}

// LoadPolicy reads a policy from a YAML file. Returns DefaultPolicy if the
// file does not exist.
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultPolicy(), nil
		}
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	p := DefaultPolicy()
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	return p, nil
}

// SavePolicy writes a policy to a YAML file with 0600 permissions.
func SavePolicy(path string, p Policy) error {
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	header := []byte("# AgentPay payment security policy\n# See: github.com/garagon/agentpay\n\n")
	return os.WriteFile(path, append(header, data...), 0600)
}

// SpendRecord tracks a single financial tool call for daily limit enforcement.
type SpendRecord struct {
	Amount float64 `json:"amount"`
	At     int64   `json:"at"` // unix timestamp
}

// CheckPolicy validates a financial tool call against the policy.
// calls contains unix timestamps of recent calls for rate limiting.
// spends contains recent spend records for daily limit tracking.
func CheckPolicy(p Policy, tool string, amount float64, calls []int64, spends []SpendRecord) PolicyResult {
	now := time.Now()

	// 1. Per-call maximum amount.
	if p.MaxPerCall > 0 && amount > p.MaxPerCall {
		return PolicyResult{
			Decision: DecisionAmountExceeded,
			Reason:   fmt.Sprintf("amount $%.2f exceeds per-call limit $%.2f for %s", amount, p.MaxPerCall, tool),
		}
	}

	// 2. Human approval threshold.
	if p.RequireApprovalAbove > 0 && amount > p.RequireApprovalAbove {
		return PolicyResult{
			Decision: DecisionApprovalRequired,
			Reason:   fmt.Sprintf("amount $%.2f exceeds auto-approval threshold $%.2f for %s", amount, p.RequireApprovalAbove, tool),
		}
	}

	// 3. Rate limit (calls per hour).
	if p.RateLimitPerHour > 0 {
		cutoff := now.Add(-1 * time.Hour).Unix()
		recent := 0
		for _, ts := range calls {
			if ts > cutoff {
				recent++
			}
		}
		if recent >= p.RateLimitPerHour {
			return PolicyResult{
				Decision: DecisionRateLimited,
				Reason:   fmt.Sprintf("rate limit %d calls/hr exceeded for %s", p.RateLimitPerHour, tool),
			}
		}
	}

	// 4. Rolling 24-hour spending limit.
	if p.DailyLimit > 0 && amount > 0 {
		cutoff := now.Add(-24 * time.Hour).Unix()
		var total float64
		for _, s := range spends {
			if s.At > cutoff {
				total += s.Amount
			}
		}
		if total+amount > p.DailyLimit {
			return PolicyResult{
				Decision: DecisionDailyLimitExceeded,
				Reason:   fmt.Sprintf("daily spend $%.2f + $%.2f exceeds limit $%.2f for %s", total, amount, p.DailyLimit, tool),
			}
		}
	}

	return PolicyResult{Allowed: true, Decision: DecisionAllow}
}

// ExtractAmount looks for a monetary value in tool call arguments by checking
// common field names: amount, value, price, cost, total.
func ExtractAmount(args map[string]any) float64 {
	for _, key := range []string{"amount", "value", "price", "cost", "total"} {
		v, ok := args[key]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			return n
		case int:
			return float64(n)
		case string:
			if f, err := strconv.ParseFloat(n, 64); err == nil {
				return f
			}
		}
	}
	return 0
}

// ExtractRecipient looks for a recipient identifier in tool call arguments.
func ExtractRecipient(args map[string]any) string {
	for _, key := range []string{"recipient", "to", "destination", "payee", "receiver", "target"} {
		v, ok := args[key]
		if !ok {
			continue
		}
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// ExtractCurrency looks for a currency code in tool call arguments.
func ExtractCurrency(args map[string]any) string {
	for _, key := range []string{"currency", "cur", "denomination"} {
		v, ok := args[key]
		if !ok {
			continue
		}
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
