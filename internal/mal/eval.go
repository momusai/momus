package mal

import "github.com/momus-ai/momus/internal/judge"

// Outcome is a three-valued (Kleene) matcher result. The zero value is
// Inconclusive on purpose: an un-set result must never read as Matched.
type Outcome int

const (
	Inconclusive Outcome = iota // undecided: no judge, judge error, or low confidence
	NotMatched                  // definitively did not match (Kleene False)
	Matched                     // definitively matched (Kleene True)
)

func (o Outcome) String() string {
	switch o {
	case Matched:
		return "matched"
	case NotMatched:
		return "not_matched"
	default:
		return "inconclusive"
	}
}

// EvalContext threads the optional judge, attack identity, and an append-only
// evidence sink through Evaluate. A nil *EvalContext means pure evaluation with
// no judge; a nil Judge field means llm_judge leaves resolve Inconclusive.
type EvalContext struct {
	Judge    judge.Judge       // may be nil -> llm_judge leaves are Inconclusive
	AttackID string            // identifies the attack for cache key + evidence
	Evidence *[]judge.Evidence // append-only audit sink; nil to discard
}

// outcomeOf maps a judge Decision to a matcher Outcome.
func outcomeOf(d judge.Decision) Outcome {
	switch d {
	case judge.DecisionYes:
		return Matched
	case judge.DecisionNo:
		return NotMatched
	default:
		return Inconclusive
	}
}
