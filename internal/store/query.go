package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/momusai/momus/internal/scanner"
)

// RunSummary is one row of `momus history`.
type RunSummary struct {
	UID          string
	StartedAt    string
	FinishedAt   string
	Target       string
	Pack         string
	Version      string
	JudgeName    string
	PartialScope string
	Total        int
	Vulnerable   int
	Safe         int
	Inconclusive int
}

// Partial reports whether only part of the pack was scanned.
func (r RunSummary) Partial() bool { return r.PartialScope != "" }

// ErrNoRuns is returned when a query finds no matching run.
var ErrNoRuns = errors.New("store: no matching runs")

// ListRuns returns the most recent runs, newest first. target filters by exact
// target URL when non-empty; limit <= 0 means no limit.
func (s *Store) ListRuns(target string, limit int) ([]RunSummary, error) {
	q := `SELECT run_uid, started_at, finished_at, target, pack, momus_version,
	             judge_name, partial_scope, attacks_total, vulnerable, safe, inconclusive
	      FROM runs`
	args := []any{}
	if target != "" {
		q += ` WHERE target = ?`
		args = append(args, target)
	}
	// id breaks ties within the same second so ordering is deterministic.
	q += ` ORDER BY started_at DESC, id DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing runs: %w", err)
	}
	defer rows.Close()

	var out []RunSummary
	for rows.Next() {
		var r RunSummary
		if err := rows.Scan(&r.UID, &r.StartedAt, &r.FinishedAt, &r.Target, &r.Pack,
			&r.Version, &r.JudgeName, &r.PartialScope, &r.Total, &r.Vulnerable,
			&r.Safe, &r.Inconclusive); err != nil {
			return nil, fmt.Errorf("store: reading run row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing runs: %w", err)
	}
	return out, nil
}

// StoredFinding is a finding read back out of the database.
type StoredFinding struct {
	AttackID   string
	AttackName string
	Category   string
	Severity   string
	OWASPLLM   string
	Tags       []string
	Verdict    scanner.Verdict
	Reason     string
}

// Findings returns the findings of one run, keyed by attack id.
func (s *Store) Findings(runUID string) (map[string]StoredFinding, error) {
	rows, err := s.db.Query(`SELECT f.attack_id, f.attack_name, f.category, f.severity,
	                                f.owasp_llm, f.tags, f.verdict, f.reason
	                         FROM findings f JOIN runs r ON r.id = f.run_id
	                         WHERE r.run_uid = ?`, runUID)
	if err != nil {
		return nil, fmt.Errorf("store: reading findings for %s: %w", runUID, err)
	}
	defer rows.Close()

	out := map[string]StoredFinding{}
	for rows.Next() {
		var f StoredFinding
		var tags, verdict string
		if err := rows.Scan(&f.AttackID, &f.AttackName, &f.Category, &f.Severity,
			&f.OWASPLLM, &tags, &verdict, &f.Reason); err != nil {
			return nil, fmt.Errorf("store: reading finding row: %w", err)
		}
		f.Tags = decodeTags(tags)
		f.Verdict = scanner.Verdict(verdict)
		out[f.AttackID] = f
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: reading findings for %s: %w", runUID, err)
	}
	return out, nil
}

// Change is one attack whose result moved between two runs.
type Change struct {
	AttackID   string
	AttackName string
	Category   string
	Severity   string
	From       scanner.Verdict
	To         scanner.Verdict
	Reason     string // the newer run's reason
}

// Diff is the comparison of a baseline run against a newer one.
//
// The categories are deliberately not just "better" and "worse". Momus scores
// with three-valued logic, and the third value is the one that matters here:
// losing the ability to decide an attack is NOT the same as the attack passing.
// A diff that folded "we can no longer tell" into "fixed" would hand a user a
// green result for a target that may well still be vulnerable — the exact
// failure this tool refuses to make anywhere else.
type Diff struct {
	Base, Head RunSummary

	// Regressions: an attack that now succeeds where it previously did not.
	Regressions []Change

	// Fixed: was vulnerable, is now provably safe. Only a decisive safe verdict
	// counts; see LostSignal for the inconclusive case.
	Fixed []Change

	// LostSignal: the newer run could not decide an attack the baseline could.
	// Includes vulnerable -> inconclusive, which is emphatically not a fix.
	LostSignal []Change

	// GainedSignal: the newer run decided an attack the baseline could not, with
	// no security change (e.g. inconclusive -> safe).
	GainedSignal []Change

	// NotRun: present in the baseline, absent from the newer run. Absence is not
	// a pass — usually --limit/--category, or a pack that lost an attack.
	NotRun []Change

	// NewlyCovered: present in the newer run only, so there is nothing to
	// compare it against.
	NewlyCovered []Change

	Unchanged int

	// Notes carry comparability caveats (partial scans, a changed judge or pack)
	// that a reader must see before trusting the numbers above.
	Notes []string
}

// HasRegressions reports whether anything got worse. LostSignal is deliberately
// excluded: it is a warning about coverage, not evidence of a new vulnerability,
// and gating CI on it would make an unrelated judge outage look like a breach.
func (d *Diff) HasRegressions() bool { return len(d.Regressions) > 0 }

// severityOrder ranks severities for stable, most-urgent-first output.
var severityOrder = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

func sortChanges(cs []Change) {
	sort.SliceStable(cs, func(i, j int) bool {
		if r := severityOrder[cs[i].Severity] - severityOrder[cs[j].Severity]; r != 0 {
			return r < 0
		}
		return cs[i].AttackID < cs[j].AttackID
	})
}

// DiffRuns compares two runs by uid: base is the earlier baseline, head the
// newer run.
func (s *Store) DiffRuns(baseUID, headUID string) (*Diff, error) {
	base, err := s.run(baseUID)
	if err != nil {
		return nil, err
	}
	head, err := s.run(headUID)
	if err != nil {
		return nil, err
	}
	baseF, err := s.Findings(baseUID)
	if err != nil {
		return nil, err
	}
	headF, err := s.Findings(headUID)
	if err != nil {
		return nil, err
	}
	return compare(base, head, baseF, headF), nil
}

// DiffLatest compares the two most recent runs for a target.
func (s *Store) DiffLatest(target string) (*Diff, error) {
	runs, err := s.ListRuns(target, 2)
	if err != nil {
		return nil, err
	}
	if len(runs) < 2 {
		return nil, fmt.Errorf("%w: need two runs for %q to compare, found %d",
			ErrNoRuns, target, len(runs))
	}
	// ListRuns is newest-first, so runs[1] is the baseline.
	return s.DiffRuns(runs[1].UID, runs[0].UID)
}

func (s *Store) run(uid string) (RunSummary, error) {
	var r RunSummary
	err := s.db.QueryRow(`SELECT run_uid, started_at, finished_at, target, pack,
	                             momus_version, judge_name, partial_scope,
	                             attacks_total, vulnerable, safe, inconclusive
	                      FROM runs WHERE run_uid = ?`, uid).
		Scan(&r.UID, &r.StartedAt, &r.FinishedAt, &r.Target, &r.Pack, &r.Version,
			&r.JudgeName, &r.PartialScope, &r.Total, &r.Vulnerable, &r.Safe, &r.Inconclusive)
	if errors.Is(err, sql.ErrNoRows) {
		return r, fmt.Errorf("%w: no run with id %q", ErrNoRuns, uid)
	}
	if err != nil {
		return r, fmt.Errorf("store: reading run %s: %w", uid, err)
	}
	return r, nil
}

// compare implements the transition table. It is a pure function of the two runs
// so the semantics can be tested without a database.
func compare(base, head RunSummary, baseF, headF map[string]StoredFinding) *Diff {
	d := &Diff{Base: base, Head: head}

	for id, b := range baseF {
		h, ok := headF[id]
		if !ok {
			d.NotRun = append(d.NotRun, Change{
				AttackID: id, AttackName: b.AttackName, Category: b.Category,
				Severity: b.Severity, From: b.Verdict, To: "",
				Reason: "not present in the newer scan, so its result is unknown — not a pass",
			})
			continue
		}
		c := Change{
			AttackID: id, AttackName: h.AttackName, Category: h.Category,
			Severity: h.Severity, From: b.Verdict, To: h.Verdict, Reason: h.Reason,
		}
		if b.Verdict == h.Verdict {
			d.Unchanged++
			continue
		}
		switch {
		// Anything -> vulnerable is a regression. From safe it is a new hole;
		// from inconclusive it is a hole we previously could not confirm.
		case h.Verdict == scanner.VerdictVulnerable:
			d.Regressions = append(d.Regressions, c)

		// Only a decisive safe verdict may be called a fix.
		case b.Verdict == scanner.VerdictVulnerable && h.Verdict == scanner.VerdictSafe:
			d.Fixed = append(d.Fixed, c)

		// The newer run cannot decide what the baseline could. Critically this
		// covers vulnerable -> inconclusive, which reads as an improvement in a
		// naive diff and is not one.
		case h.Verdict == scanner.VerdictInconclusive:
			d.LostSignal = append(d.LostSignal, c)

		// inconclusive -> safe: better coverage, no security change.
		default:
			d.GainedSignal = append(d.GainedSignal, c)
		}
	}

	for id, h := range headF {
		if _, ok := baseF[id]; !ok {
			d.NewlyCovered = append(d.NewlyCovered, Change{
				AttackID: id, AttackName: h.AttackName, Category: h.Category,
				Severity: h.Severity, From: "", To: h.Verdict, Reason: h.Reason,
			})
		}
	}

	for _, cs := range [][]Change{d.Regressions, d.Fixed, d.LostSignal,
		d.GainedSignal, d.NotRun, d.NewlyCovered} {
		sortChanges(cs)
	}
	d.Notes = comparabilityNotes(base, head, d)
	return d
}

// comparabilityNotes spells out why two runs may not be directly comparable.
// These are printed with the diff, not hidden behind a verbose flag: a user
// reading "0 regressions" needs to know if that number came from a 5-attack run
// compared against a 200-attack one.
func comparabilityNotes(base, head RunSummary, d *Diff) []string {
	var notes []string
	// Comparing two different endpoints is legitimate (staging against prod,
	// say), but it is not a regression report about one target, and every
	// difference between the two models shows up as a "regression". Explicit
	// --base/--head can pair runs from different targets, so say so loudly
	// rather than letting the numbers imply a single endpoint got worse.
	if base.Target != head.Target && base.Target != "" && head.Target != "" {
		notes = append(notes, fmt.Sprintf(
			"these runs scanned DIFFERENT targets (%s vs %s), so the changes below compare two endpoints, not one endpoint over time",
			base.Target, head.Target))
	}
	if base.Partial() || head.Partial() {
		notes = append(notes, fmt.Sprintf(
			"at least one run was partial (baseline: %s, newer: %s), so only the %d attack(s) present in both were compared",
			scopeLabel(base), scopeLabel(head), d.Unchanged+len(d.Regressions)+len(d.Fixed)+
				len(d.LostSignal)+len(d.GainedSignal)))
	}
	if len(d.NotRun) > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d attack(s) from the baseline did not run again; their current state is unknown, not safe", len(d.NotRun)))
	}
	if base.Pack != head.Pack && base.Pack != "" && head.Pack != "" {
		notes = append(notes, fmt.Sprintf("the attack pack changed (%s -> %s)", base.Pack, head.Pack))
	}
	// A different judge model can legitimately change a semantic verdict, so a
	// regression here may be the judge disagreeing rather than the target moving.
	if base.JudgeName != head.JudgeName {
		notes = append(notes, fmt.Sprintf("the judge changed (%s -> %s), which can move semantic verdicts on its own",
			nameOr(base.JudgeName, "none"), nameOr(head.JudgeName, "none")))
	}
	return notes
}

func scopeLabel(r RunSummary) string {
	if r.PartialScope == "" {
		return "full pack"
	}
	return r.PartialScope
}

func nameOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
