package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadState_InvalidJSONReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadState(path); err == nil {
		t.Fatal("expected invalid state JSON to return error")
	}
}

func TestAcquireLockWaitsForRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.lock")
	first, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("first AcquireLock: %v", err)
	}
	defer first.Release()

	acquired := make(chan struct{})
	go func() {
		second, err := AcquireLock(path)
		if err == nil {
			second.Release()
		}
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("second lock acquired before first was released")
	case <-time.After(100 * time.Millisecond):
	}

	first.Release()

	select {
	case <-acquired:
	case <-time.After(1 * time.Second):
		t.Fatal("second lock did not acquire after release")
	}
}
