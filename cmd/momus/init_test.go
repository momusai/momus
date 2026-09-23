package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/momus-ai/momus/internal/mal"
)

// TestInitScaffoldIsValid: a freshly scaffolded pack must load and pass strict
// validation, and re-running against a non-empty dir must refuse to clobber.
func TestInitScaffoldIsValid(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "momus-pack")
	if err := scaffoldPack(dir); err != nil {
		t.Fatalf("scaffoldPack: %v", err)
	}

	results, err := mal.ValidatePack(dir)
	if err != nil {
		t.Fatalf("ValidatePack: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("scaffolded pack has no attacks")
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("scaffolded attack invalid: %s: %v", r.Path, r.Err)
		}
	}

	// README present at the pack root.
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err != nil {
		t.Errorf("README.md missing: %v", err)
	}

	// Refuses to clobber a non-empty directory.
	if err := scaffoldPack(dir); err == nil {
		t.Error("expected scaffoldPack to refuse a non-empty directory")
	}
}
