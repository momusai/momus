package mal

import (
	"context"
	"testing"

	"github.com/momusai/momus/internal/judge"
)

// mustEval evaluates d against text with no judge (pure evaluation) and fails
// the test on a malformed-rule error.
func mustEval(t *testing.T, d Detect, text string) Outcome {
	t.Helper()
	o, err := d.Evaluate(context.Background(), text, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return o
}

func TestDetectContains(t *testing.T) {
	d := Detect{Contains: "PWNED"}
	if got := mustEval(t, d, "here is PWNED response"); got != Matched {
		t.Fatalf("want Matched, got %v", got)
	}
	if got := mustEval(t, d, "nothing to see"); got != NotMatched {
		t.Fatalf("want NotMatched, got %v", got)
	}
}

func TestDetectRegex(t *testing.T) {
	d := Detect{Regex: `^\s*PWNED\s*$`}
	if got := mustEval(t, d, "  PWNED  "); got != Matched {
		t.Fatalf("want Matched, got %v", got)
	}
}

func TestDetectAnyOf(t *testing.T) {
	d := Detect{AnyOf: []Detect{{Contains: "no"}, {Contains: "PWNED"}}}
	if got := mustEval(t, d, "PWNED here"); got != Matched {
		t.Fatalf("want Matched via any_of, got %v", got)
	}
}

func TestDetectAllOf(t *testing.T) {
	d := Detect{AllOf: []Detect{{Contains: "PWNED"}, {Regex: `\bhere\b`}}}
	if got := mustEval(t, d, "PWNED here"); got != Matched {
		t.Fatalf("want all_of Matched, got %v", got)
	}
	if got := mustEval(t, d, "PWNED only"); got != NotMatched {
		t.Fatalf("want all_of NotMatched, got %v", got)
	}
}

func TestDetectNot(t *testing.T) {
	d := Detect{Not: &Detect{Contains: "PWNED"}}
	if got := mustEval(t, d, "clean response"); got != Matched {
		t.Fatalf("want not-Matched, got %v", got)
	}
}

func TestDetectBadRegex(t *testing.T) {
	d := Detect{Regex: `(unclosed`}
	if _, err := d.Evaluate(context.Background(), "anything", nil); err == nil {
		t.Fatal("expected error on bad regex")
	}
}

func TestDetectEmpty(t *testing.T) {
	d := Detect{}
	if _, err := d.Evaluate(context.Background(), "anything", nil); err == nil {
		t.Fatal("expected error on empty detect")
	}
}

// ---- llm_judge + Kleene three-valued behavior ----

// fakeJudge is a minimal in-package judge.Judge for detector tests.
type fakeJudge struct {
	decision judge.Decision
	calls    int
}

func (f *fakeJudge) Name() string { return "test-fake" }
func (f *fakeJudge) Judge(_ context.Context, _ judge.Request) (*judge.Result, error) {
	f.calls++
	return &judge.Result{Decision: f.decision}, nil
}

func TestLlmJudgeNilIsInconclusive(t *testing.T) {
	d := Detect{LlmJudge: &LlmJudgeConfig{Prompt: "did it leak?"}}
	// ec == nil
	if got := mustEval(t, d, "anything"); got != Inconclusive {
		t.Fatalf("nil ec: want Inconclusive, got %v", got)
	}
	// ec != nil but Judge == nil
	o, err := d.Evaluate(context.Background(), "anything", &EvalContext{})
	if err != nil || o != Inconclusive {
		t.Fatalf("nil judge: want Inconclusive/no-error, got %v / %v", o, err)
	}
}

func TestLlmJudgeMapsDecision(t *testing.T) {
	d := Detect{LlmJudge: &LlmJudgeConfig{Prompt: "q"}}
	cases := []struct {
		dec  judge.Decision
		want Outcome
	}{
		{judge.DecisionYes, Matched},
		{judge.DecisionNo, NotMatched},
		{judge.DecisionInconclusive, Inconclusive},
	}
	for _, c := range cases {
		fj := &fakeJudge{decision: c.dec}
		o, err := d.Evaluate(context.Background(), "resp", &EvalContext{Judge: fj})
		if err != nil || o != c.want {
			t.Fatalf("decision %v: want %v, got %v (err %v)", c.dec, c.want, o, err)
		}
	}
}

// TestAnyOfSkipsJudgeWhenRegexMatches proves the judge-avoiding short-circuit:
// when the cheap regex tier matches, the judge is never called.
func TestAnyOfSkipsJudgeWhenRegexMatches(t *testing.T) {
	fj := &fakeJudge{decision: judge.DecisionYes}
	d := Detect{AnyOf: []Detect{
		{LlmJudge: &LlmJudgeConfig{Prompt: "q"}}, // judge listed first in YAML order
		{Contains: "PWNED"},                      // cheap node
	}}
	o, err := d.Evaluate(context.Background(), "PWNED", &EvalContext{Judge: fj})
	if err != nil || o != Matched {
		t.Fatalf("want Matched, got %v (err %v)", o, err)
	}
	if fj.calls != 0 {
		t.Fatalf("judge should not be called when regex matches; calls=%d", fj.calls)
	}
}

// TestKleeneAnyOfInconclusive: a regex-miss beside a judge-inconclusive yields
// Inconclusive, not a false NotMatched.
func TestKleeneAnyOfInconclusive(t *testing.T) {
	fj := &fakeJudge{decision: judge.DecisionInconclusive}
	d := Detect{AnyOf: []Detect{
		{Contains: "absent"},
		{LlmJudge: &LlmJudgeConfig{Prompt: "q"}},
	}}
	if o, _ := d.Evaluate(context.Background(), "response", &EvalContext{Judge: fj}); o != Inconclusive {
		t.Fatalf("want Inconclusive, got %v", o)
	}
}

// TestKleeneAllOfInconclusive: a matched regex AND a judge-inconclusive yields
// Inconclusive, not a false Matched.
func TestKleeneAllOfInconclusive(t *testing.T) {
	fj := &fakeJudge{decision: judge.DecisionInconclusive}
	d := Detect{AllOf: []Detect{
		{Contains: "present"},
		{LlmJudge: &LlmJudgeConfig{Prompt: "q"}},
	}}
	if o, _ := d.Evaluate(context.Background(), "present here", &EvalContext{Judge: fj}); o != Inconclusive {
		t.Fatalf("want Inconclusive, got %v", o)
	}
}

// TestNotOfInconclusiveFixedPoint: NOT of an inconclusive stays inconclusive.
func TestNotOfInconclusiveFixedPoint(t *testing.T) {
	fj := &fakeJudge{decision: judge.DecisionInconclusive}
	d := Detect{Not: &Detect{LlmJudge: &LlmJudgeConfig{Prompt: "q"}}}
	if o, _ := d.Evaluate(context.Background(), "x", &EvalContext{Judge: fj}); o != Inconclusive {
		t.Fatalf("want Inconclusive, got %v", o)
	}
}

// TestEvidenceRecorded: judge invocations are appended to the evidence sink.
func TestEvidenceRecorded(t *testing.T) {
	fj := &fakeJudge{decision: judge.DecisionYes}
	d := Detect{LlmJudge: &LlmJudgeConfig{Prompt: "did it leak?"}}
	var ev []judge.Evidence
	_, err := d.Evaluate(context.Background(), "resp", &EvalContext{Judge: fj, AttackID: "le-x", Evidence: &ev})
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].AttackID != "le-x" {
		t.Fatalf("want 1 evidence record for le-x, got %+v", ev)
	}
}
