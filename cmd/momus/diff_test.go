package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/momus-ai/momus/internal/scanner"
	"github.com/momus-ai/momus/internal/store"

	_ "modernc.org/sqlite"
)

// printDiff is the last thing between the diff semantics and the user, so the
// wording that keeps "lost signal" from reading as "fixed" is asserted here too.
func TestPrintDiffLabelsLostSignalAsNotFixed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ev.db")
	s, err := store.Open("", path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	start := time.Date(2026, 9, 23, 9, 0, 0, 0, time.UTC)
	run := store.Run{StartedAt: start, FinishedAt: start.Add(time.Minute),
		Target: "http://localhost:8000/chat", Pack: "packs/core"}

	baseUID, err := s.SaveRun(run, []scanner.Finding{
		{AttackID: "pi-001", Severity: "high", Verdict: scanner.VerdictVulnerable},
	})
	if err != nil {
		t.Fatalf("SaveRun base: %v", err)
	}
	run.StartedAt = start.Add(time.Hour)
	headUID, err := s.SaveRun(run, []scanner.Finding{
		{AttackID: "pi-001", Severity: "high", Verdict: scanner.VerdictInconclusive,
			Reason: "judge unavailable"},
	})
	if err != nil {
		t.Fatalf("SaveRun head: %v", err)
	}

	d, err := s.DiffRuns(baseUID, headUID)
	if err != nil {
		t.Fatalf("DiffRuns: %v", err)
	}

	var buf bytes.Buffer
	printDiff(&buf, d)
	out := buf.String()

	if !strings.Contains(out, "NOT fixed") {
		t.Errorf("output must state that lost signal is not a fix:\n%s", out)
	}
	if strings.Contains(out, "FIXED —") {
		t.Errorf("a vulnerable -> inconclusive transition must not print a FIXED section:\n%s", out)
	}
	if !strings.Contains(out, "vulnerable -> inconclusive") {
		t.Errorf("output should show the transition:\n%s", out)
	}
}

func TestPrintDiffShowsNotRunAsUnknown(t *testing.T) {
	d := &store.Diff{
		Base: store.RunSummary{UID: "aaa", Target: "http://t/chat"},
		Head: store.RunSummary{UID: "bbb", Target: "http://t/chat"},
		NotRun: []store.Change{{
			AttackID: "pi-001", Severity: "high", From: scanner.VerdictVulnerable,
			Reason: "not present in the newer scan, so its result is unknown — not a pass",
		}},
		Notes: []string{"197 attack(s) from the baseline did not run again"},
	}
	var buf bytes.Buffer
	printDiff(&buf, d)
	out := buf.String()

	if !strings.Contains(out, "(not run)") {
		t.Errorf("an attack that did not run should be shown as such:\n%s", out)
	}
	if !strings.Contains(out, "state unknown") {
		t.Errorf("the NOT RUN heading should say the state is unknown:\n%s", out)
	}
	if !strings.Contains(out, "NOTE:") {
		t.Errorf("comparability notes must be printed:\n%s", out)
	}
}

// A single target in the header is only correct when both runs hit it. Printing
// one URL for a two-endpoint comparison would misattribute every difference.
func TestPrintDiffHeaderNamesBothTargetsWhenTheyDiffer(t *testing.T) {
	d := &store.Diff{
		Base: store.RunSummary{UID: "aaa", Target: "http://staging/chat"},
		Head: store.RunSummary{UID: "bbb", Target: "http://prod/chat"},
	}
	var buf bytes.Buffer
	printDiff(&buf, d)
	out := buf.String()
	if !strings.Contains(out, "http://staging/chat") || !strings.Contains(out, "http://prod/chat") {
		t.Errorf("header must name both targets:\n%s", out)
	}
}

func TestDiffCmdRequiresTargetOrExplicitRuns(t *testing.T) {
	cmd := newDiffCmd()
	cmd.SetArgs([]string{"--store", "whatever.db"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("want an error when neither --target nor --base/--head is given")
	}
}

func TestDiffCmdRejectsBaseWithoutHead(t *testing.T) {
	cmd := newDiffCmd()
	cmd.SetArgs([]string{"--store", "whatever.db", "--base", "abc"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("want an error when --base is given without --head")
	}
	if !strings.Contains(err.Error(), "together") {
		t.Errorf("error should explain the pairing, got: %v", err)
	}
}

// history against a database with no runs should say so plainly rather than
// printing an empty table that looks like a clean history.
func TestHistoryCmdOnEmptyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ev.db")
	cmd := newHistoryCmd()
	cmd.SetArgs([]string{"--store", path})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("history on an empty database should not fail: %v", err)
	}
}

func TestScopeCellMarksPartialRuns(t *testing.T) {
	full := store.RunSummary{}
	if got := scopeCell(full); got != "full" {
		t.Errorf("full run scope cell = %q, want %q", got, "full")
	}
	partial := store.RunSummary{PartialScope: "PARTIAL: 3 of the pack's attacks, category jailbreak"}
	got := scopeCell(partial)
	if !strings.HasPrefix(got, "PARTIAL") {
		t.Errorf("partial run scope cell must start with PARTIAL, got %q", got)
	}
	if strings.Contains(got, "category") {
		t.Errorf("scope cell should be trimmed for the table, got %q", got)
	}
}
