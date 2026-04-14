package main

import (
	"strings"
	"testing"
)

func TestHandleGuard_InvalidJSONFailsClosed(t *testing.T) {
	out, err := HandleGuard([]byte("{not-json"), t.TempDir())
	if err != nil {
		t.Fatalf("HandleGuard returned error: %v", err)
	}
	if !strings.Contains(string(out), "\"permissionDecision\":\"deny\"") {
		t.Fatalf("expected deny output, got %s", out)
	}
}

func TestHandleGuard_InitFailureFailsClosed(t *testing.T) {
	configPath := t.TempDir()
	out, err := HandleGuard([]byte(`{"session_id":"bad","hook_event_name":"PreToolUse","tool_name":"mcp__stripe__create_payment","tool_input":{"amount":50,"recipient":"alice"}}`), configPath+"/missing/child")
	if err != nil {
		t.Fatalf("HandleGuard returned error: %v", err)
	}
	if !strings.Contains(string(out), "\"permissionDecision\":\"deny\"") {
		t.Fatalf("expected deny output, got %s", out)
	}
}
