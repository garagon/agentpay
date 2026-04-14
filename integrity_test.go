package main

import "testing"

func TestCheckIntentDrift_NoDrift(t *testing.T) {
	intent := PaymentIntent{
		Recipient: "alice@co.com",
		Amount:    50.0,
		Currency:  "usd",
	}
	drift := CheckIntentDrift(intent, "alice@co.com", 50.0, "usd", 0.01)
	if drift.HasDrift {
		t.Errorf("expected no drift, got %+v", drift)
	}
}

func TestCheckIntentDrift_RecipientChanged(t *testing.T) {
	intent := PaymentIntent{
		Recipient: "alice@co.com",
		Amount:    50.0,
		Currency:  "usd",
	}
	drift := CheckIntentDrift(intent, "eve@attacker.com", 50.0, "usd", 0.01)
	if !drift.HasDrift {
		t.Fatal("expected drift for changed recipient")
	}
	if drift.Type != DriftRecipient {
		t.Errorf("Type = %v, want %v", drift.Type, DriftRecipient)
	}
	if drift.Expected != "alice@co.com" || drift.Got != "eve@attacker.com" {
		t.Errorf("Expected=%q Got=%q", drift.Expected, drift.Got)
	}
}

func TestCheckIntentDrift_AmountInflated(t *testing.T) {
	intent := PaymentIntent{
		Recipient: "alice@co.com",
		Amount:    50.0,
		Currency:  "usd",
	}
	drift := CheckIntentDrift(intent, "alice@co.com", 5000.0, "usd", 0.01)
	if !drift.HasDrift {
		t.Fatal("expected drift for inflated amount")
	}
	if drift.Type != DriftAmount {
		t.Errorf("Type = %v, want %v", drift.Type, DriftAmount)
	}
}

func TestCheckIntentDrift_AmountWithinTolerance(t *testing.T) {
	intent := PaymentIntent{
		Recipient: "alice@co.com",
		Amount:    100.0,
		Currency:  "usd",
	}
	// 0.5% change with 1% tolerance should pass.
	drift := CheckIntentDrift(intent, "alice@co.com", 100.50, "usd", 0.01)
	if drift.HasDrift {
		t.Errorf("expected no drift for amount within tolerance, got %+v", drift)
	}

	// 2% change with 1% tolerance should fail.
	drift = CheckIntentDrift(intent, "alice@co.com", 102.0, "usd", 0.01)
	if !drift.HasDrift {
		t.Error("expected drift for amount exceeding tolerance")
	}
}

func TestCheckIntentDrift_CurrencyChanged(t *testing.T) {
	intent := PaymentIntent{
		Recipient: "alice@co.com",
		Amount:    50.0,
		Currency:  "usd",
	}
	drift := CheckIntentDrift(intent, "alice@co.com", 50.0, "btc", 0.01)
	if !drift.HasDrift {
		t.Fatal("expected drift for changed currency")
	}
	if drift.Type != DriftCurrency {
		t.Errorf("Type = %v, want %v", drift.Type, DriftCurrency)
	}
}

func TestCheckIntentDrift_EmptyCurrencyOK(t *testing.T) {
	intent := PaymentIntent{
		Recipient: "alice@co.com",
		Amount:    50.0,
		Currency:  "",
	}
	drift := CheckIntentDrift(intent, "alice@co.com", 50.0, "usd", 0.01)
	if drift.HasDrift {
		t.Error("expected no drift when intent has no currency")
	}
}

func TestHashIntent(t *testing.T) {
	h1 := HashIntent("alice@co.com", 50.0, "usd")
	h2 := HashIntent("alice@co.com", 50.0, "usd")
	h3 := HashIntent("bob@co.com", 50.0, "usd")

	if h1 != h2 {
		t.Error("same inputs should produce same hash")
	}
	if h1 == h3 {
		t.Error("different recipients should produce different hashes")
	}
	if len(h1) < 64 {
		t.Errorf("hash too short: %q", h1)
	}
}
