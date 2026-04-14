package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// AuditEntry records a single payment security decision.
type AuditEntry struct {
	Timestamp      string   `json:"timestamp"`
	SessionID      string   `json:"session_id"`
	ToolName       string   `json:"tool_name"`
	Classification string   `json:"classification"`
	Amount         float64  `json:"amount,omitempty"`
	Recipient      string   `json:"recipient,omitempty"`
	Currency       string   `json:"currency,omitempty"`
	Decision       string   `json:"decision"`
	Reason         string   `json:"reason,omitempty"`
	Stages         []string `json:"pipeline_stages"`
	PrevHash       string   `json:"prev_hash"`
	Hash           string   `json:"hash"`
}

// AuditLog appends entries to a JSONL file with a hash chain.
type AuditLog struct {
	path     string
	prevHash string
}

const genesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// NewAuditLog opens or creates an audit log. It reads the last entry's
// hash to continue the chain.
func NewAuditLog(path string) (*AuditLog, error) {
	al := &AuditLog{path: path, prevHash: genesisHash}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return al, nil
		}
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	// Read the last line to get prevHash for chain continuity.
	var lastLine string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lastLine = scanner.Text()
	}
	if lastLine != "" {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(lastLine), &entry); err == nil && entry.Hash != "" {
			al.prevHash = entry.Hash
		}
	}
	return al, nil
}

// Log appends an entry to the audit trail. The entry's PrevHash and Hash
// fields are set automatically to maintain chain integrity.
func (al *AuditLog) Log(entry AuditEntry) error {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	entry.PrevHash = al.prevHash
	entry.Hash = computeEntryHash(entry)
	al.prevHash = entry.Hash

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	f, err := os.OpenFile(al.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open audit log for write: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	return nil
}

// ReadEntries reads all entries from the audit log.
func ReadEntries(path string) ([]AuditEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	var entries []AuditEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var e AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}

// VerifyChain checks the hash chain integrity of audit entries.
// Returns the index of the first invalid entry, or -1 if the chain is valid.
func VerifyChain(entries []AuditEntry) int {
	prev := genesisHash
	for i, e := range entries {
		if e.PrevHash != prev {
			return i
		}
		if !entryHashMatches(e) {
			return i
		}
		prev = e.Hash
	}
	return -1
}

func computeEntryHash(e AuditEntry) string {
	payload := struct {
		Timestamp      string   `json:"timestamp"`
		SessionID      string   `json:"session_id"`
		ToolName       string   `json:"tool_name"`
		Classification string   `json:"classification"`
		Amount         float64  `json:"amount,omitempty"`
		Recipient      string   `json:"recipient,omitempty"`
		Currency       string   `json:"currency,omitempty"`
		Decision       string   `json:"decision"`
		Reason         string   `json:"reason,omitempty"`
		Stages         []string `json:"pipeline_stages"`
		PrevHash       string   `json:"prev_hash"`
	}{
		Timestamp:      e.Timestamp,
		SessionID:      e.SessionID,
		ToolName:       e.ToolName,
		Classification: e.Classification,
		Amount:         e.Amount,
		Recipient:      e.Recipient,
		Currency:       e.Currency,
		Decision:       e.Decision,
		Reason:         e.Reason,
		Stages:         e.Stages,
		PrevHash:       e.PrevHash,
	}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum[:])
}

func computeEntryHashLegacy(e AuditEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%.2f\n%s",
		e.PrevHash, e.Timestamp, e.ToolName, e.Decision, e.Amount, e.Recipient)
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

func entryHashMatches(e AuditEntry) bool {
	return e.Hash == computeEntryHash(e) || e.Hash == computeEntryHashLegacy(e)
}
