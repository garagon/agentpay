package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScanNodeModules_DetectsCompromised(t *testing.T) {
	dir := t.TempDir()
	mkPkg(t, dir, "node_modules/axios", "axios", "1.7.9")
	mkPkg(t, dir, "node_modules/express", "express", "4.21.0")

	result, err := ScanNodeModules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.Findings))
	}
	if result.Findings[0].Package != "axios" {
		t.Errorf("Package = %q, want axios", result.Findings[0].Package)
	}
}

func TestScanNodeModules_SafeVersionPasses(t *testing.T) {
	dir := t.TempDir()
	mkPkg(t, dir, "node_modules/axios", "axios", "1.7.7")

	result, err := ScanNodeModules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("got %d findings, want 0", len(result.Findings))
	}
}

func TestScanLockfile_DetectsCompromised(t *testing.T) {
	dir := t.TempDir()
	lock := map[string]any{
		"packages": map[string]any{
			"node_modules/axios": map[string]any{"version": "1.7.8"},
			"node_modules/lodash": map[string]any{"version": "4.17.21"},
		},
	}
	data, _ := json.Marshal(lock)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), data, 0644)

	result, err := ScanNodeModules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.Findings))
	}
	if result.Findings[0].Version != "1.7.8" {
		t.Errorf("Version = %q, want 1.7.8", result.Findings[0].Version)
	}
}

func TestCleanFindings_QuarantinesPackage(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "node_modules", "axios")
	mkPkg(t, dir, "node_modules/axios", "axios", "1.7.9")

	findings := []ScanFinding{{
		Package: "axios",
		Version: "1.7.9",
		Path:    pkgDir,
	}}

	actions := CleanFindings(findings, false)
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want 1", len(actions))
	}
	if actions[0].Action != "quarantined" {
		t.Errorf("Action = %q, want quarantined: %s", actions[0].Action, actions[0].Error)
	}
	// Verify original is gone.
	if _, err := os.Stat(pkgDir); !os.IsNotExist(err) {
		t.Error("original package dir still exists after quarantine")
	}
}

func TestCleanFindings_DryRunDoesNotRemove(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "node_modules", "axios")
	mkPkg(t, dir, "node_modules/axios", "axios", "1.7.9")

	findings := []ScanFinding{{
		Package: "axios",
		Version: "1.7.9",
		Path:    pkgDir,
	}}

	actions := CleanFindings(findings, true)
	if actions[0].Action != "would remove" {
		t.Errorf("Action = %q, want 'would remove'", actions[0].Action)
	}
	// Verify original still exists.
	if _, err := os.Stat(pkgDir); err != nil {
		t.Error("package dir was removed during dry run")
	}
}

// Regression: same package in lockfile + node_modules must both quarantine
// without destination collision.
func TestCleanFindings_DuplicateSourcesNoColl(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "node_modules", "axios")
	lockFile := filepath.Join(dir, "package-lock.json")

	mkPkg(t, dir, "node_modules/axios", "axios", "1.7.9")

	lock := map[string]any{
		"packages": map[string]any{
			"node_modules/axios": map[string]any{"version": "1.7.9"},
		},
	}
	data, _ := json.Marshal(lock)
	os.WriteFile(lockFile, data, 0644)

	findings := []ScanFinding{
		{Package: "axios", Version: "1.7.9", Path: pkgDir},
		{Package: "axios", Version: "1.7.9", Path: lockFile},
	}

	actions := CleanFindings(findings, false)
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want 2", len(actions))
	}

	for i, a := range actions {
		if a.Action != "quarantined" {
			t.Errorf("action[%d] = %q, want quarantined: %s", i, a.Action, a.Error)
		}
	}

	// Destinations must differ.
	if actions[0].Destination == actions[1].Destination {
		t.Errorf("both findings quarantined to same path: %s", actions[0].Destination)
	}
}

func TestIsCompromisedPkg(t *testing.T) {
	if cp := IsCompromisedPkg("axios", "1.7.9"); cp == nil {
		t.Error("expected axios 1.7.9 to be compromised")
	}
	if cp := IsCompromisedPkg("axios", "1.7.7"); cp != nil {
		t.Error("axios 1.7.7 should not be compromised")
	}
	if cp := IsCompromisedPkg("express", "4.21.0"); cp != nil {
		t.Error("express should not be compromised")
	}
}

func mkPkg(t *testing.T, root, rel, name, ver string) {
	t.Helper()
	dir := filepath.Join(root, rel)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	pkg := map[string]string{"name": name, "version": ver}
	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
}
