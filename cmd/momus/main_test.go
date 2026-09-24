package main

import (
	"strings"
	"testing"

	"github.com/momusai/momus/internal/mal"
	"github.com/momusai/momus/internal/scanner"
)

func TestFailCount(t *testing.T) {
	findings := []scanner.Finding{
		{Verdict: scanner.VerdictVulnerable, Severity: "high"},
		{Verdict: scanner.VerdictVulnerable, Severity: "low"},
		{Verdict: scanner.VerdictInconclusive, Severity: "critical"}, // not vulnerable -> ignored
		{Verdict: scanner.VerdictSafe, Severity: "critical"},         // not vulnerable -> ignored
	}
	cases := []struct {
		failOn string
		want   int
	}{
		{"", 0},         // gating disabled
		{"any", 2},      // both vulnerable findings
		{"low", 2},      // high + low
		{"medium", 1},   // only high
		{"high", 1},     // only high
		{"critical", 0}, // none this severe among vulnerable
		{"bogus", 0},    // unknown threshold does not gate
	}
	for _, c := range cases {
		if got := failCount(findings, c.failOn); got != c.want {
			t.Errorf("failCount(fail-on=%q) = %d, want %d", c.failOn, got, c.want)
		}
	}
}

// TestFailCountUnknownSeverity: a finding with an unrecognized severity must
// trip the gate (fail-safe), never silently rank as info and pass.
func TestFailCountUnknownSeverity(t *testing.T) {
	findings := []scanner.Finding{{Verdict: scanner.VerdictVulnerable, Severity: "sev-critical"}}
	if got := failCount(findings, "critical"); got != 1 {
		t.Errorf("unknown severity should trip the gate at floor critical, got %d", got)
	}
	if got := failCount(findings, ""); got != 0 {
		t.Errorf("empty fail-on must never gate, got %d", got)
	}
}

func TestSelectAttacks(t *testing.T) {
	attacks := []mal.Attack{
		{ID: "a1", Category: "prompt-injection"},
		{ID: "a2", Category: "jailbreak"},
		{ID: "a3", Category: "jailbreak"},
		{ID: "a4", Category: "data-exfil"},
	}
	// Category filter.
	got, err := selectAttacks(attacks, "jailbreak", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("category filter: want 2, got %d", len(got))
	}
	// Limit.
	got, err = selectAttacks(attacks, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("limit: want 3, got %d", len(got))
	}
	// Combined.
	got, _ = selectAttacks(attacks, "jailbreak", 1)
	if len(got) != 1 || got[0].ID != "a2" {
		t.Errorf("combined filter wrong: %+v", got)
	}
	// A limit larger than the pack is not an error.
	if got, _ = selectAttacks(attacks, "", 99); len(got) != 4 {
		t.Errorf("oversized limit: want 4, got %d", len(got))
	}
	// An unknown category must fail loudly and name the real ones.
	_, err = selectAttacks(attacks, "nope", 0)
	if err == nil {
		t.Fatal("unknown category must error")
	}
	if !strings.Contains(err.Error(), "jailbreak") {
		t.Errorf("error should list available categories, got %q", err)
	}
}

// An interrupted scan must say so in the artifacts, not just in the exit code.
// A SARIF uploaded to code scanning outlives the process that wrote it, and a
// 56-of-200 run that doesn't declare itself partial reads as a clean full pass.
func TestScanScope(t *testing.T) {
	cases := []struct {
		name        string
		interrupted bool
		ran, plan   int
		limit       int
		category    string
		want        string
	}{
		{name: "complete run has no caveat", ran: 200, plan: 200},
		{
			name: "interrupted", interrupted: true, ran: 56, plan: 200,
			want: "INTERRUPTED: only 56 of 200 attacks ran; the rest were never tested",
		},
		{
			name: "limit", ran: 5, plan: 5, limit: 5,
			want: "PARTIAL: 5 of the pack's attacks",
		},
		{
			name: "category", ran: 20, plan: 20, category: "jailbreak",
			want: "PARTIAL: 20 of the pack's attacks, category jailbreak",
		},
		{
			// Both at once: the interruption is the more serious caveat, and a
			// partial-by-flag run that was ALSO cut short must not report the
			// gentler message.
			name: "interrupted during a limited run", interrupted: true, ran: 3, plan: 10, limit: 10,
			want: "INTERRUPTED: only 3 of 10 attacks ran; the rest were never tested",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanScope(tc.interrupted, tc.ran, tc.plan, tc.limit, tc.category)
			if got != tc.want {
				t.Errorf("scanScope = %q, want %q", got, tc.want)
			}
		})
	}
}
