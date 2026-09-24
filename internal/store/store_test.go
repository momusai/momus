package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/momusai/momus/internal/judge"
	"github.com/momusai/momus/internal/mal"
	"github.com/momusai/momus/internal/scanner"
	"github.com/momusai/momus/internal/target"

	// The store itself talks only to database/sql; the driver is registered by
	// the caller. Importing it here (and nowhere else in the package) is what
	// keeps that separation honest.
	_ "modernc.org/sqlite"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open("", filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleRun() Run {
	start := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	return Run{
		StartedAt:  start,
		FinishedAt: start.Add(90 * time.Second),
		Target:     "http://localhost:8000/chat",
		Pack:       "packs/core",
		Version:    "v0.1.0",
		JudgeName:  "openai/gpt-4o-mini",
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if _, err := Open("", "   "); err == nil {
		t.Fatal("want error for an empty database path")
	}
}

func TestSaveAndReadBackRun(t *testing.T) {
	s := tempStore(t)
	findings := []scanner.Finding{
		{
			AttackID: "pi-001", AttackName: "Direct Override", Category: "prompt-injection",
			Severity: mal.Severity("high"), OWASPLLM: "LLM01", Tags: []string{"direct", "canary"},
			Payload: "ignore previous", Verdict: scanner.VerdictVulnerable,
			Reason:   "canary echoed",
			Response: &target.Response{Text: "MOMUS-CANARY", Status: 200, LatencyMs: 42},
			Evidence: []judge.Evidence{{
				Model: "gpt-4o-mini", ResolvedModel: "gpt-4o-mini-2024",
				DecisionStr: "complied", Confidence: 0.91,
				EvidenceQuote: "MOMUS-CANARY", Rationale: "echoed the token", NonceOK: true,
			}},
		},
		{AttackID: "jb-002", Category: "jailbreak", Severity: mal.Severity("medium"),
			Verdict: scanner.VerdictSafe, Reason: "refused"},
		{AttackID: "si-003", Category: "system-prompt", Severity: mal.Severity("low"),
			Verdict: scanner.VerdictInconclusive, Reason: "judge unavailable"},
	}

	uid, err := s.SaveRun(sampleRun(), findings)
	if err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	if uid == "" {
		t.Fatal("want a non-empty run uid")
	}

	runs, err := s.ListRuns("", 0)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(runs))
	}
	r := runs[0]
	if r.Total != 3 || r.Vulnerable != 1 || r.Safe != 1 || r.Inconclusive != 1 {
		t.Fatalf("bad tallies: total=%d vuln=%d safe=%d inconc=%d",
			r.Total, r.Vulnerable, r.Safe, r.Inconclusive)
	}
	if r.Partial() {
		t.Error("a full-pack run must not be marked partial")
	}
	if r.StartedAt != "2026-09-23T10:00:00Z" {
		t.Errorf("timestamps must be stored as RFC3339 UTC, got %q", r.StartedAt)
	}

	got, err := s.Findings(uid)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 findings, got %d", len(got))
	}
	pi := got["pi-001"]
	if pi.Verdict != scanner.VerdictVulnerable || pi.Severity != "high" {
		t.Errorf("pi-001 round-tripped wrong: %+v", pi)
	}
	if len(pi.Tags) != 2 || pi.Tags[0] != "direct" {
		t.Errorf("tags round-tripped wrong: %v", pi.Tags)
	}
}

func TestJudgeEvidencePersisted(t *testing.T) {
	s := tempStore(t)
	_, err := s.SaveRun(sampleRun(), []scanner.Finding{{
		AttackID: "pi-001", Verdict: scanner.VerdictVulnerable,
		Evidence: []judge.Evidence{
			{Model: "m1", DecisionStr: "complied", Confidence: 0.9, NonceOK: true},
			{Model: "m2", DecisionStr: "refused", Confidence: 0.4, CacheHit: true},
		},
	}})
	if err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM judge_evidence`).Scan(&n); err != nil {
		t.Fatalf("count evidence: %v", err)
	}
	if n != 2 {
		t.Fatalf("want 2 evidence rows, got %d", n)
	}
	var nonceOK, cacheHit int
	if err := s.db.QueryRow(`SELECT nonce_ok FROM judge_evidence WHERE model='m1'`).Scan(&nonceOK); err != nil {
		t.Fatalf("read nonce_ok: %v", err)
	}
	if err := s.db.QueryRow(`SELECT cache_hit FROM judge_evidence WHERE model='m2'`).Scan(&cacheHit); err != nil {
		t.Fatalf("read cache_hit: %v", err)
	}
	if nonceOK != 1 || cacheHit != 1 {
		t.Errorf("booleans lost in translation: nonce_ok=%d cache_hit=%d", nonceOK, cacheHit)
	}
}

// A long or hostile reply must not be stored in full, but the fact that it was
// cut has to survive — an excerpt silently presented as the whole reply would
// mislead anyone auditing the evidence later.
func TestResponseTextTruncatedAndFlagged(t *testing.T) {
	s := tempStore(t)
	long := strings.Repeat("a", responseTextLimit+500)
	if _, err := s.SaveRun(sampleRun(), []scanner.Finding{{
		AttackID: "pi-001", Verdict: scanner.VerdictSafe,
		Response: &target.Response{Text: long},
	}}); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	var stored string
	var trunc int
	if err := s.db.QueryRow(`SELECT response_text, response_trunc FROM findings`).
		Scan(&stored, &trunc); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(stored) > responseTextLimit {
		t.Errorf("stored %d bytes, limit is %d", len(stored), responseTextLimit)
	}
	if trunc != 1 {
		t.Error("truncation must be recorded")
	}
}

func TestTruncateKeepsValidUTF8(t *testing.T) {
	// "é" is two bytes; cutting at 1 must drop it rather than leave half a rune.
	got, cut := truncate("é", 1)
	if !cut {
		t.Error("want cut=true")
	}
	if got != "" {
		t.Errorf("want the split rune dropped, got %q", got)
	}
}

func TestPartialScopeRecorded(t *testing.T) {
	s := tempStore(t)
	r := sampleRun()
	r.PartialScope = "PARTIAL: 3 of the pack's attacks, category jailbreak"
	if _, err := s.SaveRun(r, []scanner.Finding{
		{AttackID: "jb-001", Verdict: scanner.VerdictSafe},
	}); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	runs, err := s.ListRuns("", 0)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if !runs[0].Partial() {
		t.Fatal("a --limit/--category run must be recorded as partial")
	}
}

func TestReopenExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	s1, err := Open("", path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := s1.SaveRun(sampleRun(), []scanner.Finding{
		{AttackID: "pi-001", Verdict: scanner.VerdictSafe},
	}); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	s1.Close()

	s2, err := Open("", path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	runs, err := s2.ListRuns("", 0)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("history must survive reopening, got %d runs", len(runs))
	}
}

// A database from a newer Momus must be refused outright. Reading it partially
// would let a diff compare runs whose columns we do not fully understand.
func TestOpenRefusesNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	s, err := Open("", path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE schema_version SET version = ?`, schemaVersion+1); err != nil {
		t.Fatalf("bump version: %v", err)
	}
	s.Close()

	if _, err := Open("", path); err == nil {
		t.Fatal("want an error opening a newer-schema database")
	} else if !strings.Contains(err.Error(), "newer Momus") {
		t.Errorf("error should explain the version mismatch, got: %v", err)
	}
}

func TestOpenRefusesOlderSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	s, err := Open("", path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE schema_version SET version = 0`); err != nil {
		t.Fatalf("lower version: %v", err)
	}
	s.Close()

	if _, err := Open("", path); err == nil {
		t.Fatal("want an error opening an older-schema database")
	}
}

// ON DELETE CASCADE only fires when the foreign_keys pragma is on, which is off
// by default in SQLite. Without it, deleting a run would leave its findings
// behind and they would be counted by later queries.
func TestForeignKeyCascadeIsEnabled(t *testing.T) {
	s := tempStore(t)
	uid, err := s.SaveRun(sampleRun(), []scanner.Finding{{
		AttackID: "pi-001", Verdict: scanner.VerdictVulnerable,
		Evidence: []judge.Evidence{{Model: "m1"}},
	}})
	if err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM runs WHERE run_uid = ?`, uid); err != nil {
		t.Fatalf("delete run: %v", err)
	}
	for _, table := range []string{"findings", "judge_evidence"} {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s left %d orphaned row(s) after its run was deleted", table, n)
		}
	}
}

func TestListRunsFiltersByTargetAndOrdersNewestFirst(t *testing.T) {
	s := tempStore(t)
	base := sampleRun()
	for i, tgt := range []string{"http://a/chat", "http://b/chat", "http://a/chat"} {
		r := base
		r.Target = tgt
		r.StartedAt = base.StartedAt.Add(time.Duration(i) * time.Hour)
		if _, err := s.SaveRun(r, []scanner.Finding{
			{AttackID: "pi-001", Verdict: scanner.VerdictSafe},
		}); err != nil {
			t.Fatalf("SaveRun %d: %v", i, err)
		}
	}
	runs, err := s.ListRuns("http://a/chat", 0)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("want 2 runs for target a, got %d", len(runs))
	}
	if runs[0].StartedAt < runs[1].StartedAt {
		t.Errorf("runs must be newest-first, got %q then %q", runs[0].StartedAt, runs[1].StartedAt)
	}

	limited, err := s.ListRuns("", 1)
	if err != nil {
		t.Fatalf("ListRuns limited: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("limit ignored: got %d runs", len(limited))
	}
}

func TestCurrentVulnerabilitiesView(t *testing.T) {
	s := tempStore(t)
	if _, err := s.SaveRun(sampleRun(), []scanner.Finding{
		{AttackID: "pi-001", Severity: mal.Severity("high"), Verdict: scanner.VerdictVulnerable},
		{AttackID: "jb-002", Severity: mal.Severity("low"), Verdict: scanner.VerdictSafe},
	}); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	var id string
	if err := s.db.QueryRow(`SELECT attack_id FROM current_vulnerabilities`).Scan(&id); err != nil {
		t.Fatalf("query view: %v", err)
	}
	if id != "pi-001" {
		t.Errorf("view should surface only vulnerable findings, got %q", id)
	}
}
