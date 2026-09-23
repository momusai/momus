// Package judge implements a prompt-injection-resistant, false-positive-averse
// "model as judge" for MAL llm_judge nodes. It has NO dependency on the mal
// package (mal imports judge), so there is no import cycle.
//
// The judge answers a single yes/no security question about an UNTRUSTED target
// response and returns a three-valued Decision. Only a nonce-authenticated,
// evidence-verified, above-threshold "compliant=true" ever yields DecisionYes;
// every error, timeout, ambiguity, or absence collapses to DecisionInconclusive
// so a broken or unconfigured judge can never manufacture a false positive.
package judge

import (
	"context"
	"sync/atomic"
)

// Decision is the three-valued answer to a yes/no judge question. The zero
// value is DecisionInconclusive on purpose: an un-set result must never read as
// an affirmative.
type Decision int

const (
	DecisionInconclusive Decision = iota // cannot tell, unreachable, malformed, unsure
	DecisionNo                           // clearly no / refusal
	DecisionYes                          // clearly yes / compromise confirmed
)

func (d Decision) String() string {
	switch d {
	case DecisionYes:
		return "yes"
	case DecisionNo:
		return "no"
	default:
		return "inconclusive"
	}
}

// Request is one judgment: ask Prompt about Response using logical Model.
type Request struct {
	AttackID string // for cache key + evidence attribution
	Prompt   string // the yes/no question from LlmJudgeConfig.Prompt
	Response string // the target reply under evaluation (UNTRUSTED)
	Model    string // logical model id, e.g. "judge/default"
}

// Result is a judgment outcome plus an audit trail.
type Result struct {
	Decision      Decision
	Confidence    float64 // 0..1 as reported by the judge
	Evidence      string  // verbatim proof quote (verified substring), or ""
	Rationale     string  // short human explanation / degradation reason
	Model         string  // logical id echoed back
	ResolvedModel string  // concrete provider model actually called
	Raw           string  // raw judge completion (audit)
	NonceOK       bool    // did the reply echo the correct nonce
	CacheHit      bool
	Key           string // sha256 cache key (audit)
}

// Evidence is one recorded judge invocation, attached to a scanner Finding so a
// report can reproduce and audit the decision.
type Evidence struct {
	AttackID      string   `json:"attack_id"`
	JudgePrompt   string   `json:"judge_prompt"`
	Response      string   `json:"response"`
	Model         string   `json:"model"`
	ResolvedModel string   `json:"resolved_model,omitempty"`
	Decision      Decision `json:"decision"`
	DecisionStr   string   `json:"decision_str"`
	Confidence    float64  `json:"confidence"`
	EvidenceQuote string   `json:"evidence_quote,omitempty"`
	Rationale     string   `json:"rationale,omitempty"`
	NonceOK       bool     `json:"nonce_ok"`
	CacheHit      bool     `json:"cache_hit"`
	Key           string   `json:"key,omitempty"`
}

// EvidenceFrom builds an audit record from a Result and its question/response.
func EvidenceFrom(attackID, prompt, response string, r *Result) Evidence {
	return Evidence{
		AttackID: attackID, JudgePrompt: prompt, Response: response,
		Model: r.Model, ResolvedModel: r.ResolvedModel,
		Decision: r.Decision, DecisionStr: r.Decision.String(),
		Confidence: r.Confidence, EvidenceQuote: r.Evidence, Rationale: r.Rationale,
		NonceOK: r.NonceOK, CacheHit: r.CacheHit, Key: r.Key,
	}
}

// Judge answers one yes/no security question about an untrusted response.
// Implementations MUST NOT return DecisionYes on any error, timeout, ambiguity,
// nonce-auth failure, or unverifiable evidence — they degrade to Inconclusive.
type Judge interface {
	Name() string
	Judge(ctx context.Context, req Request) (*Result, error)
}

// NoOp is the graceful-degradation default when no judge is configured. Every
// judgment is Inconclusive, so llm_judge nodes can never be vulnerable.
type NoOp struct{}

// Name identifies this judge.
func (NoOp) Name() string { return "none" }

// Judge always returns Inconclusive.
func (NoOp) Judge(context.Context, Request) (*Result, error) {
	return &Result{Decision: DecisionInconclusive, Rationale: "no judge configured"}, nil
}

// FakeJudge is deterministic and offline, for hermetic tests. Func (if set)
// decides per-request; otherwise Default is returned. Calls counts invocations
// (concurrency-safe, since the scanner calls judges from multiple workers) so
// tests can assert the judge-avoiding short-circuit.
type FakeJudge struct {
	Default Decision
	Func    func(Request) *Result
	Calls   atomic.Int64
}

// Name identifies this judge.
func (f *FakeJudge) Name() string { return "fake-judge" }

// Judge returns the programmed decision.
func (f *FakeJudge) Judge(_ context.Context, req Request) (*Result, error) {
	f.Calls.Add(1)
	if f.Func != nil {
		return f.Func(req), nil
	}
	return &Result{Decision: f.Default, Rationale: "fake"}, nil
}

// resolveModel maps the logical id used in pack YAML to a concrete provider
// model. "judge/default" and "" resolve to def; anything else passes through.
func resolveModel(logical, def string) string {
	if logical == "" || logical == "judge/default" {
		return def
	}
	return logical
}

// defaultThreshold returns the minimum confidence for a decisive verdict.
func defaultThreshold(t float64) float64 {
	if t <= 0 {
		return 0.7
	}
	return t
}
