package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/momusai/momus/internal/scanner"

	_ "modernc.org/sqlite"
)

func fnd(id string, v scanner.Verdict) StoredFinding {
	return StoredFinding{AttackID: id, Verdict: v, Severity: "high"}
}

func fmap(fs ...StoredFinding) map[string]StoredFinding {
	m := map[string]StoredFinding{}
	for _, f := range fs {
		m[f.AttackID] = f
	}
	return m
}

// The transition table is the whole point of the diff, so it is tested as a
// table. The rows that matter most are the ones where a naive implementation
// would report good news: vulnerable -> inconclusive and an attack that simply
// stopped running.
func TestDiffTransitionTable(t *testing.T) {
	type bucket string
	const (
		regression bucket = "regression"
		fixed      bucket = "fixed"
		lost       bucket = "lost-signal"
		gained     bucket = "gained-signal"
		unchanged  bucket = "unchanged"
	)

	cases := []struct {
		name string
		from scanner.Verdict
		to   scanner.Verdict
		want bucket
	}{
		{"safe becomes vulnerable is a new hole",
			scanner.VerdictSafe, scanner.VerdictVulnerable, regression},
		{"inconclusive becomes vulnerable is a confirmed hole",
			scanner.VerdictInconclusive, scanner.VerdictVulnerable, regression},
		{"vulnerable becomes provably safe is a fix",
			scanner.VerdictVulnerable, scanner.VerdictSafe, fixed},

		// The trap: the attack no longer *proves* anything, which is not the same
		// as the target having been fixed. Calling this "fixed" would hand the
		// user a green CI run on a target that may still be wide open.
		{"vulnerable becomes inconclusive is NOT a fix",
			scanner.VerdictVulnerable, scanner.VerdictInconclusive, lost},
		{"safe becomes inconclusive loses coverage",
			scanner.VerdictSafe, scanner.VerdictInconclusive, lost},

		{"inconclusive becomes safe is better coverage",
			scanner.VerdictInconclusive, scanner.VerdictSafe, gained},

		{"vulnerable stays vulnerable", scanner.VerdictVulnerable, scanner.VerdictVulnerable, unchanged},
		{"safe stays safe", scanner.VerdictSafe, scanner.VerdictSafe, unchanged},
		{"inconclusive stays inconclusive", scanner.VerdictInconclusive, scanner.VerdictInconclusive, unchanged},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := compare(RunSummary{}, RunSummary{},
				fmap(fnd("a-1", tc.from)), fmap(fnd("a-1", tc.to)))

			got := map[bucket]int{
				regression: len(d.Regressions),
				fixed:      len(d.Fixed),
				lost:       len(d.LostSignal),
				gained:     len(d.GainedSignal),
				unchanged:  d.Unchanged,
			}
			for b, n := range got {
				want := 0
				if b == tc.want {
					want = 1
				}
				if n != want {
					t.Errorf("%s -> %s: bucket %s has %d, want %d (full diff: %+v)",
						tc.from, tc.to, b, n, want, got)
				}
			}
		})
	}
}

// An attack that vanished from the newer run must never be counted as fixed.
// The usual cause is --limit or --category, and treating absence as a pass is
// how a 3-attack smoke test comes to look like a clean 200-attack scan.
func TestAttackMissingFromNewerRunIsNotAFix(t *testing.T) {
	d := compare(RunSummary{}, RunSummary{},
		fmap(fnd("pi-001", scanner.VerdictVulnerable)),
		fmap())

	if len(d.Fixed) != 0 {
		t.Fatalf("an attack that did not run was reported as fixed: %+v", d.Fixed)
	}
	if len(d.NotRun) != 1 {
		t.Fatalf("want 1 not-run entry, got %d", len(d.NotRun))
	}
	if !strings.Contains(d.NotRun[0].Reason, "not a pass") {
		t.Errorf("the not-run reason must say it is not a pass, got %q", d.NotRun[0].Reason)
	}
	if len(d.Notes) == 0 {
		t.Error("a run with missing attacks must carry a comparability note")
	}
}

func TestAttackOnlyInNewerRunIsNewlyCovered(t *testing.T) {
	d := compare(RunSummary{}, RunSummary{},
		fmap(),
		fmap(fnd("pi-002", scanner.VerdictVulnerable)))

	if len(d.NewlyCovered) != 1 {
		t.Fatalf("want 1 newly-covered attack, got %d", len(d.NewlyCovered))
	}
	// It is vulnerable, but there is no baseline saying it used to pass, so it
	// is not a regression.
	if len(d.Regressions) != 0 {
		t.Errorf("an attack with no baseline cannot be a regression: %+v", d.Regressions)
	}
}

// CI gates on regressions only. A judge outage turns decisive verdicts into
// inconclusive ones across the board; failing the build for that would teach
// users to ignore the gate.
func TestHasRegressionsIgnoresLostSignal(t *testing.T) {
	d := compare(RunSummary{}, RunSummary{},
		fmap(fnd("a-1", scanner.VerdictVulnerable), fnd("a-2", scanner.VerdictSafe)),
		fmap(fnd("a-1", scanner.VerdictInconclusive), fnd("a-2", scanner.VerdictInconclusive)))

	if len(d.LostSignal) != 2 {
		t.Fatalf("want 2 lost-signal entries, got %d", len(d.LostSignal))
	}
	if d.HasRegressions() {
		t.Error("lost signal must not trip the regression gate")
	}
}

func TestRegressionsSortedMostSevereFirst(t *testing.T) {
	base := map[string]StoredFinding{
		"low-1":  {AttackID: "low-1", Severity: "low", Verdict: scanner.VerdictSafe},
		"crit-1": {AttackID: "crit-1", Severity: "critical", Verdict: scanner.VerdictSafe},
		"med-1":  {AttackID: "med-1", Severity: "medium", Verdict: scanner.VerdictSafe},
	}
	head := map[string]StoredFinding{}
	for id, f := range base {
		f.Verdict = scanner.VerdictVulnerable
		head[id] = f
	}
	d := compare(RunSummary{}, RunSummary{}, base, head)

	want := []string{"crit-1", "med-1", "low-1"}
	if len(d.Regressions) != len(want) {
		t.Fatalf("want %d regressions, got %d", len(want), len(d.Regressions))
	}
	for i, id := range want {
		if d.Regressions[i].AttackID != id {
			t.Errorf("position %d: want %s, got %s", i, id, d.Regressions[i].AttackID)
		}
	}
}

func TestPartialRunProducesComparabilityNote(t *testing.T) {
	base := RunSummary{PartialScope: ""}
	head := RunSummary{PartialScope: "PARTIAL: 3 of the pack's attacks"}
	d := compare(base, head,
		fmap(fnd("a-1", scanner.VerdictSafe)),
		fmap(fnd("a-1", scanner.VerdictSafe)))

	if len(d.Notes) == 0 {
		t.Fatal("a partial run must be flagged in the diff notes")
	}
	joined := strings.Join(d.Notes, " ")
	if !strings.Contains(joined, "partial") {
		t.Errorf("note should mention the partial scan, got %q", joined)
	}
}

func TestChangedJudgeAndPackProduceNotes(t *testing.T) {
	d := compare(
		RunSummary{JudgeName: "openai/gpt-4o-mini", Pack: "packs/core"},
		RunSummary{JudgeName: "", Pack: "packs/custom"},
		fmap(fnd("a-1", scanner.VerdictSafe)),
		fmap(fnd("a-1", scanner.VerdictSafe)))

	joined := strings.Join(d.Notes, " ")
	if !strings.Contains(joined, "judge changed") {
		t.Errorf("a changed judge must be noted, got %q", joined)
	}
	if !strings.Contains(joined, "pack changed") {
		t.Errorf("a changed pack must be noted, got %q", joined)
	}
	// A judge that went away should read as "none", not as an empty string.
	if !strings.Contains(joined, "none") {
		t.Errorf("an absent judge should be named 'none', got %q", joined)
	}
}

func TestDiffLatestUsesTheTwoMostRecentRuns(t *testing.T) {
	s := tempStore(t)
	base := sampleRun()

	// Three runs: safe, then vulnerable, then safe again. The diff must compare
	// runs 2 and 3 (vulnerable -> safe = fixed), not 1 and 3.
	verdicts := []scanner.Verdict{
		scanner.VerdictSafe, scanner.VerdictVulnerable, scanner.VerdictSafe,
	}
	for i, v := range verdicts {
		r := base
		r.StartedAt = base.StartedAt.Add(time.Duration(i) * time.Hour)
		r.FinishedAt = r.StartedAt.Add(time.Minute)
		if _, err := s.SaveRun(r, []scanner.Finding{
			{AttackID: "pi-001", Severity: "high", Verdict: v},
		}); err != nil {
			t.Fatalf("SaveRun %d: %v", i, err)
		}
	}

	d, err := s.DiffLatest(base.Target)
	if err != nil {
		t.Fatalf("DiffLatest: %v", err)
	}
	if len(d.Fixed) != 1 {
		t.Fatalf("want 1 fixed attack from the last two runs, got %+v", d)
	}
	if d.Base.StartedAt >= d.Head.StartedAt {
		t.Errorf("baseline must be the older run: base=%q head=%q",
			d.Base.StartedAt, d.Head.StartedAt)
	}
}

func TestDiffLatestNeedsTwoRuns(t *testing.T) {
	s := tempStore(t)
	r := sampleRun()
	if _, err := s.SaveRun(r, []scanner.Finding{
		{AttackID: "pi-001", Verdict: scanner.VerdictSafe},
	}); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	_, err := s.DiffLatest(r.Target)
	if !errors.Is(err, ErrNoRuns) {
		t.Fatalf("want ErrNoRuns with a single run, got %v", err)
	}
}

func TestDiffRunsRejectsUnknownUID(t *testing.T) {
	s := tempStore(t)
	if _, err := s.DiffRuns("nope", "alsonope"); !errors.Is(err, ErrNoRuns) {
		t.Fatalf("want ErrNoRuns for an unknown uid, got %v", err)
	}
}

func TestDiffRunsEndToEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	s, err := Open("", path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	r1 := sampleRun()
	baseUID, err := s.SaveRun(r1, []scanner.Finding{
		{AttackID: "pi-001", Severity: "high", Verdict: scanner.VerdictSafe},
		{AttackID: "jb-002", Severity: "medium", Verdict: scanner.VerdictVulnerable},
		{AttackID: "si-003", Severity: "low", Verdict: scanner.VerdictVulnerable},
	})
	if err != nil {
		t.Fatalf("SaveRun base: %v", err)
	}

	r2 := r1
	r2.StartedAt = r1.StartedAt.Add(time.Hour)
	headUID, err := s.SaveRun(r2, []scanner.Finding{
		{AttackID: "pi-001", Severity: "high", Verdict: scanner.VerdictVulnerable},  // regression
		{AttackID: "jb-002", Severity: "medium", Verdict: scanner.VerdictSafe},      // fixed
		{AttackID: "si-003", Severity: "low", Verdict: scanner.VerdictInconclusive}, // lost signal, NOT fixed
	})
	if err != nil {
		t.Fatalf("SaveRun head: %v", err)
	}

	d, err := s.DiffRuns(baseUID, headUID)
	if err != nil {
		t.Fatalf("DiffRuns: %v", err)
	}
	if len(d.Regressions) != 1 || d.Regressions[0].AttackID != "pi-001" {
		t.Errorf("regressions wrong: %+v", d.Regressions)
	}
	if len(d.Fixed) != 1 || d.Fixed[0].AttackID != "jb-002" {
		t.Errorf("fixed wrong: %+v", d.Fixed)
	}
	if len(d.LostSignal) != 1 || d.LostSignal[0].AttackID != "si-003" {
		t.Errorf("lost signal wrong: %+v", d.LostSignal)
	}
	if !d.HasRegressions() {
		t.Error("want HasRegressions true")
	}
}

// Explicit --base/--head can pair runs from two different endpoints. That is a
// legitimate thing to ask for, but every difference between the two models then
// shows up as a "regression", so the output must say what is being compared.
func TestDifferentTargetsProduceComparabilityNote(t *testing.T) {
	d := compare(
		RunSummary{Target: "http://staging/chat"},
		RunSummary{Target: "http://prod/chat"},
		fmap(fnd("a-1", scanner.VerdictSafe)),
		fmap(fnd("a-1", scanner.VerdictVulnerable)))

	joined := strings.Join(d.Notes, " ")
	if !strings.Contains(joined, "DIFFERENT targets") {
		t.Fatalf("comparing two endpoints must be called out, got notes: %q", joined)
	}
	if !strings.Contains(joined, "http://staging/chat") || !strings.Contains(joined, "http://prod/chat") {
		t.Errorf("the note should name both targets, got %q", joined)
	}
}

func TestSameTargetProducesNoTargetNote(t *testing.T) {
	d := compare(
		RunSummary{Target: "http://prod/chat"},
		RunSummary{Target: "http://prod/chat"},
		fmap(fnd("a-1", scanner.VerdictSafe)),
		fmap(fnd("a-1", scanner.VerdictSafe)))

	for _, n := range d.Notes {
		if strings.Contains(n, "DIFFERENT targets") {
			t.Errorf("same-target runs must not be flagged as different: %q", n)
		}
	}
}
