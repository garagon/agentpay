package main

import (
	"path/filepath"
	"testing"
)

func TestAuditLog_WriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	al, err := NewAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}

	entries := []AuditEntry{
		{ToolName: "send_money", Amount: 50, Recipient: "alice", Decision: "allow"},
		{ToolName: "send_money", Amount: 5000, Recipient: "eve", Decision: "deny"},
		{ToolName: "create_payment", Amount: 250, Recipient: "bob", Decision: "ask"},
	}

	for _, e := range entries {
		if err := al.Log(e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	read, err := ReadEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(read) != 3 {
		t.Fatalf("got %d entries, want 3", len(read))
	}

	// Verify fields.
	if read[0].ToolName != "send_money" || read[0].Decision != "allow" {
		t.Errorf("entry 0: %+v", read[0])
	}
	if read[1].Decision != "deny" {
		t.Errorf("entry 1 decision = %q, want deny", read[1].Decision)
	}

	// All entries should have hashes.
	for i, e := range read {
		if e.Hash == "" {
			t.Errorf("entry %d has empty hash", i)
		}
		if e.Timestamp == "" {
			t.Errorf("entry %d has empty timestamp", i)
		}
	}
}

func TestAuditLog_HashChainValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	al, err := NewAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		_ = al.Log(AuditEntry{
			ToolName: "send_money",
			Amount:   float64(i * 10),
			Decision: "allow",
		})
	}

	entries, _ := ReadEntries(path)
	invalid := VerifyChain(entries)
	if invalid != -1 {
		t.Errorf("expected valid chain, got invalid at entry %d", invalid)
	}

	// First entry should reference genesis hash.
	if entries[0].PrevHash != genesisHash {
		t.Errorf("first entry prev_hash = %q, want genesis", entries[0].PrevHash)
	}

	// Each entry's prev_hash should be the previous entry's hash.
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevHash != entries[i-1].Hash {
			t.Errorf("entry %d prev_hash doesn't match entry %d hash", i, i-1)
		}
	}
}

func TestAuditLog_TamperDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	al, err := NewAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = al.Log(AuditEntry{ToolName: "a", Decision: "allow", Amount: 10})
	_ = al.Log(AuditEntry{ToolName: "b", Decision: "deny", Amount: 20})
	_ = al.Log(AuditEntry{ToolName: "c", Decision: "allow", Amount: 30})

	entries, _ := ReadEntries(path)

	// Tamper with entry 1.
	entries[1].Amount = 99999
	invalid := VerifyChain(entries)
	if invalid != 1 {
		t.Errorf("expected tampering detected at entry 1, got %d", invalid)
	}
}

func TestAuditLog_TamperDetectionCoversReasonAndStages(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	al, err := NewAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = al.Log(AuditEntry{
		ToolName:       "send_money",
		Classification: "action:critical",
		Decision:       "deny",
		Reason:         "recipient drift",
		Stages:         []string{"classify:financial:critical", "integrity:RECIPIENT_DRIFT"},
	})

	entries, _ := ReadEntries(path)
	entries[0].Reason = "different reason"
	if invalid := VerifyChain(entries); invalid != 0 {
		t.Fatalf("expected reason tampering detected at entry 0, got %d", invalid)
	}

	entries, _ = ReadEntries(path)
	entries[0].Stages = []string{"classify:not_financial"}
	if invalid := VerifyChain(entries); invalid != 0 {
		t.Fatalf("expected stage tampering detected at entry 0, got %d", invalid)
	}
}

func TestAuditLog_VerifyChainSupportsLegacyEntries(t *testing.T) {
	entry := AuditEntry{
		Timestamp: "2026-04-14T00:00:00Z",
		SessionID: "legacy",
		ToolName:  "send_money",
		Amount:    50,
		Recipient: "alice",
		Decision:  "allow",
		Stages:    []string{"policy:allow"},
		PrevHash:  genesisHash,
	}
	entry.Hash = computeEntryHashLegacy(entry)

	if invalid := VerifyChain([]AuditEntry{entry}); invalid != -1 {
		t.Fatalf("expected legacy entry to verify, got invalid at %d", invalid)
	}
}

func TestAuditLog_ChainContinuity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Write two entries, close, reopen, write more.
	al1, _ := NewAuditLog(path)
	_ = al1.Log(AuditEntry{ToolName: "a", Decision: "allow"})
	_ = al1.Log(AuditEntry{ToolName: "b", Decision: "deny"})

	al2, _ := NewAuditLog(path)
	_ = al2.Log(AuditEntry{ToolName: "c", Decision: "allow"})

	entries, _ := ReadEntries(path)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	invalid := VerifyChain(entries)
	if invalid != -1 {
		t.Errorf("chain broken at %d after reopen", invalid)
	}
}

func TestReadEntries_NonExistent(t *testing.T) {
	entries, err := ReadEntries("/nonexistent/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if entries != nil {
		t.Errorf("expected nil entries, got %d", len(entries))
	}
}
