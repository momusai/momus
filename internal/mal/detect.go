package mal

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/momusai/momus/internal/judge"
)

// Detect is a matcher tree. Exactly one field should be non-zero in a given
// node; the field that's set determines the variant.
//
//	any_of / all_of / not — combinators (three-valued Kleene logic)
//	contains / regex      — deterministic leaf string matchers
//	llm_judge             — model-as-judge; resolves Matched/NotMatched/Inconclusive
type Detect struct {
	AnyOf    []Detect        `yaml:"any_of,omitempty" json:"any_of,omitempty"`
	AllOf    []Detect        `yaml:"all_of,omitempty" json:"all_of,omitempty"`
	Not      *Detect         `yaml:"not,omitempty" json:"not,omitempty"`
	Contains string          `yaml:"contains,omitempty" json:"contains,omitempty"`
	Regex    string          `yaml:"regex,omitempty" json:"regex,omitempty"`
	LlmJudge *LlmJudgeConfig `yaml:"llm_judge,omitempty" json:"llm_judge,omitempty"`
}

// LlmJudgeConfig configures a model-as-judge scorer.
type LlmJudgeConfig struct {
	Prompt string `yaml:"prompt" json:"prompt"`
	Model  string `yaml:"model,omitempty" json:"model,omitempty"`
}

// UsesJudge reports whether this detect subtree contains any llm_judge node
// (i.e. it cannot reach a decisive verdict without a judge configured).
func (d *Detect) UsesJudge() bool { return d.usesJudge() }

// usesJudge reports whether this subtree contains any llm_judge leaf. Used to
// order children cheap-first so the judge is skipped when a pure node decides.
func (d *Detect) usesJudge() bool {
	switch {
	case len(d.AnyOf) > 0:
		for i := range d.AnyOf {
			if d.AnyOf[i].usesJudge() {
				return true
			}
		}
	case len(d.AllOf) > 0:
		for i := range d.AllOf {
			if d.AllOf[i].usesJudge() {
				return true
			}
		}
	case d.Not != nil:
		return d.Not.usesJudge()
	case d.LlmJudge != nil:
		return true
	}
	return false
}

// orderCheapFirst returns child indices with judge-free nodes first, preserving
// original order within each class (stable, therefore deterministic).
func orderCheapFirst(children []Detect) []int {
	cheap := make([]int, 0, len(children))
	judgey := make([]int, 0, len(children))
	for i := range children {
		if children[i].usesJudge() {
			judgey = append(judgey, i)
		} else {
			cheap = append(cheap, i)
		}
	}
	return append(cheap, judgey...)
}

// Evaluate runs the matcher tree against a target response using three-valued
// (Kleene) logic. It returns a Go error only for a malformed rule (bad regex,
// empty node); every judge failure or absence composes as Inconclusive instead
// of aborting the tree. ec may be nil (pure evaluation, no judge).
func (d *Detect) Evaluate(ctx context.Context, text string, ec *EvalContext) (Outcome, error) {
	switch {
	case len(d.AnyOf) > 0: // Kleene OR: Matched is absorbing
		result := NotMatched
		for _, i := range orderCheapFirst(d.AnyOf) {
			o, err := d.AnyOf[i].Evaluate(ctx, text, ec)
			if err != nil {
				return Inconclusive, err
			}
			if o == Matched {
				return Matched, nil // short-circuit: judge children never reached
			}
			if o == Inconclusive {
				result = Inconclusive
			}
		}
		return result, nil

	case len(d.AllOf) > 0: // Kleene AND: NotMatched is absorbing
		result := Matched
		for _, i := range orderCheapFirst(d.AllOf) {
			o, err := d.AllOf[i].Evaluate(ctx, text, ec)
			if err != nil {
				return Inconclusive, err
			}
			if o == NotMatched {
				return NotMatched, nil // short-circuit: judge children never reached
			}
			if o == Inconclusive {
				result = Inconclusive
			}
		}
		return result, nil

	case d.Not != nil: // Kleene NOT: Inconclusive is a fixed point
		o, err := d.Not.Evaluate(ctx, text, ec)
		if err != nil {
			return Inconclusive, err
		}
		switch o {
		case Matched:
			return NotMatched, nil
		case NotMatched:
			return Matched, nil
		default:
			return Inconclusive, nil
		}

	case d.Contains != "":
		if strings.Contains(text, d.Contains) {
			return Matched, nil
		}
		return NotMatched, nil

	case d.Regex != "":
		re, err := regexp.Compile(d.Regex)
		if err != nil {
			return Inconclusive, fmt.Errorf("bad regex %q: %w", d.Regex, err)
		}
		if re.MatchString(text) {
			return Matched, nil
		}
		return NotMatched, nil

	case d.LlmJudge != nil:
		// No judge configured -> undecided, never vulnerable. This is the
		// structural guarantee behind the zero-false-positive contract.
		if ec == nil || ec.Judge == nil {
			return Inconclusive, nil
		}
		res, err := ec.Judge.Judge(ctx, judge.Request{
			AttackID: ec.AttackID,
			Prompt:   d.LlmJudge.Prompt,
			Response: text,
			Model:    d.LlmJudge.Model,
		})
		if err != nil || res == nil {
			// Transport/parse failure -> Inconclusive, NOT a Go error, so it
			// composes in Kleene folds instead of aborting sibling evaluation.
			if ec.Evidence != nil {
				*ec.Evidence = append(*ec.Evidence, judge.Evidence{
					AttackID: ec.AttackID, JudgePrompt: d.LlmJudge.Prompt, Response: text,
					Model: d.LlmJudge.Model, Decision: judge.DecisionInconclusive,
					DecisionStr: judge.DecisionInconclusive.String(),
					Rationale:   "judge call error", NonceOK: false,
				})
			}
			return Inconclusive, nil
		}
		if ec.Evidence != nil {
			*ec.Evidence = append(*ec.Evidence, judge.EvidenceFrom(ec.AttackID, d.LlmJudge.Prompt, text, res))
		}
		return outcomeOf(res.Decision), nil

	default:
		return Inconclusive, fmt.Errorf("empty detect rule")
	}
}
