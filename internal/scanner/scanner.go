// Package scanner drives an attack pack against a Target and produces
// findings.
package scanner

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/momusai/momus/internal/judge"
	"github.com/momusai/momus/internal/mal"
	"github.com/momusai/momus/internal/target"
)

// Verdict is a scanner's judgment on one attack.
type Verdict string

const (
	VerdictVulnerable   Verdict = "vulnerable"
	VerdictSafe         Verdict = "safe"
	VerdictInconclusive Verdict = "inconclusive"
)

// Finding is one attack's result: the request, response, and the scorer's
// verdict, plus any judge audit records.
type Finding struct {
	AttackID   string           `json:"attack_id"`
	AttackName string           `json:"attack_name"`
	Category   string           `json:"category"`
	Severity   mal.Severity     `json:"severity"`
	OWASPLLM   string           `json:"owasp_llm,omitempty"`
	Tags       []string         `json:"tags,omitempty"`
	References []string         `json:"references,omitempty"`
	Payload    string           `json:"payload"`
	Response   *target.Response `json:"response,omitempty"`
	Verdict    Verdict          `json:"verdict"`
	Reason     string           `json:"reason"`
	Evidence   []judge.Evidence `json:"evidence,omitempty"`
}

// defaultConcurrency bounds how many attacks are dispatched at once when the
// caller doesn't set one. Modest by default so we don't hammer a target.
const defaultConcurrency = 8

// Scanner runs attacks against a single Target, optionally using a Judge for
// llm_judge detector nodes.
type Scanner struct {
	Target      target.Target
	Judge       judge.Judge // may be nil -> llm_judge nodes resolve inconclusive
	Concurrency int         // in-flight attacks; <=0 uses defaultConcurrency

	// Progress, if set, is called as each attack finishes. A scan against a real
	// endpoint takes minutes; without any output it is indistinguishable from a
	// hang. Called from worker goroutines, so implementations must be safe for
	// concurrent use.
	Progress func(done, total int)
}

// Option configures a Scanner.
type Option func(*Scanner)

// WithJudge injects a judge for llm_judge detector nodes.
func WithJudge(j judge.Judge) Option { return func(s *Scanner) { s.Judge = j } }

// WithConcurrency sets how many attacks run in flight at once.
func WithConcurrency(n int) Option { return func(s *Scanner) { s.Concurrency = n } }

// WithProgress reports completion as the scan runs.
func WithProgress(fn func(done, total int)) Option {
	return func(s *Scanner) { s.Progress = fn }
}

// New constructs a Scanner. The variadic options keep existing New(t) call sites
// compiling; with no judge injected, llm_judge nodes resolve inconclusive and a
// refusing target can never be flagged vulnerable.
func New(t target.Target, opts ...Option) *Scanner {
	s := &Scanner{Target: t}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Run dispatches attacks across a bounded worker pool and returns findings in
// the SAME order as the input attacks (deterministic, so evidence bundles
// reproduce) regardless of completion order. A cancelled context stops dispatch;
// only completed findings are returned. Safe for concurrent target/judge use:
// http.Client is concurrency-safe and the judge cache is mutex-guarded.
func (s *Scanner) Run(ctx context.Context, attacks []mal.Attack) []Finding {
	workers := s.Concurrency
	if workers <= 0 {
		workers = defaultConcurrency
	}
	if workers > len(attacks) {
		workers = len(attacks)
	}
	if workers < 1 {
		return nil
	}

	results := make([]Finding, len(attacks))
	done := make([]bool, len(attacks)) // each index written by exactly one worker
	jobs := make(chan int)

	var completed atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					continue // drain remaining jobs without work once cancelled
				}
				f := s.runOne(ctx, &attacks[i])
				// If the context was cancelled while this attack was in flight, its
				// result is an artefact of the shutdown, not a real evaluation.
				// Recording it would inflate the "completed" count and contradict the
				// interruption message.
				if ctx.Err() != nil {
					continue
				}
				results[i] = f
				done[i] = true
				if s.Progress != nil {
					s.Progress(int(completed.Add(1)), len(attacks))
				}
			}
		}()
	}

dispatch:
	for i := range attacks {
		select {
		case <-ctx.Done():
			break dispatch
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()

	findings := make([]Finding, 0, len(attacks))
	for i := range results {
		if done[i] {
			findings = append(findings, results[i])
		}
	}
	if len(findings) < len(attacks) {
		slog.Warn("scan incomplete (cancelled)", "completed", len(findings), "total", len(attacks))
	}
	return findings
}

func (s *Scanner) runOne(ctx context.Context, a *mal.Attack) Finding {
	// Build the attack's metadata ONCE. The transport-error path used to
	// construct its own Finding literal and quietly omitted OWASPLLM, Tags and
	// References, so every attack that failed on a 429, a 5xx or a timeout lost
	// its classification in the HTML and SARIF reports — and those are exactly
	// the findings a reader needs to triage.
	f := Finding{
		AttackID: a.ID, AttackName: a.Name, Category: a.Category,
		Severity: a.Severity, OWASPLLM: a.OWASPLLM, Tags: a.Tags, References: a.References,
		Payload: a.Payload,
	}

	resp, err := s.Target.Send(ctx, target.Request{Payload: a.Payload})
	if err != nil {
		// No slog here: the error is already reported in Finding.Reason and
		// rendered per attack. Logging it too printed every failure twice.
		f.Verdict, f.Reason = VerdictInconclusive, err.Error()
		return f
	}

	var evidence []judge.Evidence
	ec := &mal.EvalContext{Judge: s.Judge, AttackID: a.ID, Evidence: &evidence}
	outcome, err := a.Detect.Evaluate(ctx, resp.Text, ec)
	f.Response, f.Evidence = resp, evidence

	switch {
	case err != nil: // malformed rule only
		f.Verdict, f.Reason = VerdictInconclusive, err.Error()
	case outcome == mal.Matched:
		f.Verdict, f.Reason = VerdictVulnerable, "detect rule matched"
	case outcome == mal.NotMatched:
		f.Verdict, f.Reason = VerdictSafe, "detect rule did not match"
	default: // mal.Inconclusive
		f.Verdict, f.Reason = VerdictInconclusive, "detector undecided (judge unavailable or uncertain)"
	}
	return f
}
