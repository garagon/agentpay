package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanFindingsAvoidsDestinationCollision(t *testing.T) {
	root := t.TempDir()

	lockfile := filepath.Join(root, "package-lock.json")
	if err := os.WriteFile(lockfile, []byte(`{}`), 0600); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	pkgDir := filepath.Join(root, "node_modules", "axios")
	if err := os.MkdirAll(pkgDir, 0700); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}

	findings := []ScanFinding{
		{Package: "axios", Version: "1.7.9", Path: lockfile},
		{Package: "axios", Version: "1.7.9", Path: pkgDir},
	}

	actions := CleanFindings(findings, false)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}

	if actions[0].Action != "quarantined" {
		t.Fatalf("expected first action quarantined, got %q (err=%s)", actions[0].Action, actions[0].Error)
	}
	if actions[1].Action != "quarantined" {
		t.Fatalf("expected second action quarantined, got %q (err=%s)", actions[1].Action, actions[1].Error)
	}
	if actions[0].Destination == actions[1].Destination {
		t.Fatalf("expected unique destinations, both were %q", actions[0].Destination)
	}
	for _, action := range actions {
		if _, err := os.Stat(action.Destination); err != nil {
			t.Fatalf("expected destination %q to exist: %v", action.Destination, err)
		}
	}
}
