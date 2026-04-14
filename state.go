package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// State persists rate limit counters, spend records, and payment intents
// between hook invocations. Each agentpay guard call is a separate OS
// process, so state is serialized to disk with file locking.
type State struct {
	Calls   map[string][]int64       `json:"calls"`   // tool → unix timestamps
	Spends  map[string][]SpendRecord `json:"spends"`  // tool → spend records
	Intents map[string]PaymentIntent `json:"intents"` // session:recipient → intent
}

const financialStateKey = "__agentpay_financial__"

// NewState creates an empty state.
func NewState() *State {
	return &State{
		Calls:   make(map[string][]int64),
		Spends:  make(map[string][]SpendRecord),
		Intents: make(map[string]PaymentIntent),
	}
}

// LoadState reads state from disk. Returns empty state if the file does
// not exist. Prunes stale entries (older than 24h) on load.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewState(), nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	s := NewState()
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	s.prune()
	return s, nil
}

// Save writes state to disk atomically with 0600 permissions.
func (s *State) Save(path string) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write state tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}

// RecordCall records a tool call timestamp for rate limiting.
func (s *State) RecordCall(tool string) {
	s.Calls[tool] = append(s.Calls[tool], time.Now().Unix())
}

// RecordFinancialCall records a financial tool call both globally and per tool.
func (s *State) RecordFinancialCall(tool string) {
	s.RecordCall(financialStateKey)
	if tool != "" {
		s.RecordCall(tool)
	}
}

// RecordSpend records a spend amount for daily limit tracking.
func (s *State) RecordSpend(tool string, amount float64) {
	if amount <= 0 {
		return
	}
	s.Spends[tool] = append(s.Spends[tool], SpendRecord{
		Amount: amount,
		At:     time.Now().Unix(),
	})
}

// RecordFinancialSpend records a financial spend both globally and per tool.
func (s *State) RecordFinancialSpend(tool string, amount float64) {
	s.RecordSpend(financialStateKey, amount)
	if tool != "" {
		s.RecordSpend(tool, amount)
	}
}

// RegisterIntent stores a payment intent baseline if one does not already
// exist for the given key. Returns true if a new intent was registered.
func (s *State) RegisterIntent(key, recipient string, amount float64, currency string) bool {
	if _, exists := s.Intents[key]; exists {
		return false
	}
	s.Intents[key] = PaymentIntent{
		Recipient:    recipient,
		Amount:       amount,
		Currency:     currency,
		RegisteredAt: time.Now().Unix(),
		Hash:         HashIntent(recipient, amount, currency),
	}
	return true
}

// GetIntent retrieves a registered payment intent, or nil if none exists.
func (s *State) GetIntent(key string) *PaymentIntent {
	intent, ok := s.Intents[key]
	if !ok {
		return nil
	}
	return &intent
}

// GetSessionIntents returns all registered payment intents for a session.
// This is used to detect recipient tampering: when a MCP changes the
// recipient, the lookup key changes, so we must scan all session intents.
func (s *State) GetSessionIntents(sessionID string) []PaymentIntent {
	prefix := sessionID + ":"
	var intents []PaymentIntent
	for key, intent := range s.Intents {
		if strings.HasPrefix(key, prefix) {
			intents = append(intents, intent)
		}
	}
	return intents
}

// prune removes entries older than 25 hours for calls and spends,
// and intents older than 24 hours.
func (s *State) prune() {
	callCutoff := time.Now().Add(-25 * time.Hour).Unix()
	for tool, timestamps := range s.Calls {
		pruned := timestamps[:0]
		for _, ts := range timestamps {
			if ts > callCutoff {
				pruned = append(pruned, ts)
			}
		}
		if len(pruned) == 0 {
			delete(s.Calls, tool)
		} else {
			s.Calls[tool] = pruned
		}
	}

	spendCutoff := time.Now().Add(-25 * time.Hour).Unix()
	for tool, records := range s.Spends {
		pruned := records[:0]
		for _, r := range records {
			if r.At > spendCutoff {
				pruned = append(pruned, r)
			}
		}
		if len(pruned) == 0 {
			delete(s.Spends, tool)
		} else {
			s.Spends[tool] = pruned
		}
	}

	intentCutoff := time.Now().Add(-24 * time.Hour).Unix()
	for key, intent := range s.Intents {
		if intent.RegisteredAt < intentCutoff {
			delete(s.Intents, key)
		}
	}
}

// FileLock holds an OS-level advisory lock on a file descriptor.
// Used to serialize concurrent agentpay guard invocations.
type FileLock struct {
	f *os.File
}

// AcquireLock obtains an exclusive lock on the given path. Returns a
// FileLock that must be released with Release(). If the lock cannot be
// obtained (another guard is running), returns an error.
func AcquireLock(path string) (*FileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("acquire lock: %w", err)
	}
	return &FileLock{f: f}, nil
}

// Release releases the file lock and cleans up.
func (fl *FileLock) Release() {
	if fl.f == nil {
		return
	}
	name := fl.f.Name()
	_ = syscall.Flock(int(fl.f.Fd()), syscall.LOCK_UN)
	fl.f.Close()
	fl.f = nil
	os.Remove(name)
}
