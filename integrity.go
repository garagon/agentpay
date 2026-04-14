package main

import (
	"crypto/sha256"
	"fmt"
	"math"
)

// PaymentIntent records the first-seen parameters for a payment to a
// specific recipient within a session. Subsequent calls are compared
// against this baseline to detect MCP tampering.
type PaymentIntent struct {
	Recipient    string  `json:"recipient"`
	Amount       float64 `json:"amount"`
	Currency     string  `json:"currency"`
	RegisteredAt int64   `json:"registered_at"`
	Hash         string  `json:"hash"`
}

// DriftType identifies which payment parameter was tampered with.
type DriftType string

const (
	DriftNone      DriftType = ""
	DriftRecipient DriftType = "recipient"
	DriftAmount    DriftType = "amount"
	DriftCurrency  DriftType = "currency"
)

// DriftResult holds the outcome of an integrity check comparing a tool
// call's parameters against the registered payment intent.
type DriftResult struct {
	HasDrift bool
	Type     DriftType
	Expected string
	Got      string
}

// IntentKey builds a state map key from session and recipient.
func IntentKey(sessionID, recipient string) string {
	return sessionID + ":" + recipient
}

// HashIntent computes a SHA-256 fingerprint of the payment parameters.
func HashIntent(recipient string, amount float64, currency string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%.2f\n%s", recipient, amount, currency)
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

// CheckIntentDrift compares current tool call parameters against a
// registered intent. Returns a DriftResult describing the first
// discrepancy found, or a clean result if parameters match.
//
// tolerance is the fractional amount drift allowed (e.g. 0.01 = 1%).
func CheckIntentDrift(intent PaymentIntent, recipient string, amount float64, currency string, tolerance float64) DriftResult {
	// Recipient must match exactly.
	if intent.Recipient != recipient {
		return DriftResult{
			HasDrift: true,
			Type:     DriftRecipient,
			Expected: intent.Recipient,
			Got:      recipient,
		}
	}

	// Amount drift check with configurable tolerance.
	if intent.Amount > 0 {
		diff := math.Abs(amount-intent.Amount) / intent.Amount
		if diff > tolerance {
			return DriftResult{
				HasDrift: true,
				Type:     DriftAmount,
				Expected: fmt.Sprintf("$%.2f", intent.Amount),
				Got:      fmt.Sprintf("$%.2f", amount),
			}
		}
	}

	// Currency must match exactly (case-insensitive is handled by caller).
	if intent.Currency != "" && currency != "" && intent.Currency != currency {
		return DriftResult{
			HasDrift: true,
			Type:     DriftCurrency,
			Expected: intent.Currency,
			Got:      currency,
		}
	}

	return DriftResult{}
}
