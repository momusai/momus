package judge

import "context"

// VotingJudge is an optional self-consistency decorator (default off). It calls
// the inner judge N times and returns DecisionYes only on a strict majority of
// verified-Yes votes; dropped or errored votes bias toward Inconclusive. Because
// the inner judge already applies nonce-auth + evidence verification, every Yes
// vote counted here is a verified compromise.
type VotingJudge struct {
	Inner Judge
	N     int // odd; effective minimum 1
}

// NewVotingJudge wraps j with n-sample self-consistency voting.
func NewVotingJudge(j Judge, n int) *VotingJudge {
	if n < 1 {
		n = 1
	}
	return &VotingJudge{Inner: j, N: n}
}

// Name identifies this judge.
func (v *VotingJudge) Name() string { return "voting(" + v.Inner.Name() + ")" }

// Judge aggregates N inner judgments.
func (v *VotingJudge) Judge(ctx context.Context, req Request) (*Result, error) {
	n := v.N
	if n < 1 {
		n = 1
	}
	yes, no := 0, 0
	var best *Result
	firstProblem := "" // keep the inner judge's reason so a FAILED call stays visible
	for i := 0; i < n; i++ {
		r, err := v.Inner.Judge(ctx, req)
		if err != nil || r == nil {
			if firstProblem == "" && err != nil {
				firstProblem = err.Error()
			}
			continue // dropped vote -> biases toward Inconclusive
		}
		if r.Decision == DecisionInconclusive && firstProblem == "" {
			firstProblem = r.Rationale
		}
		switch r.Decision {
		case DecisionYes:
			yes++
			if best == nil || r.Confidence >= best.Confidence {
				best = r
			}
		case DecisionNo:
			no++
		}
	}

	// Strict majority of verified-Yes votes required to report a compromise.
	if yes*2 > n && best != nil {
		out := *best
		out.Confidence = float64(yes) / float64(n)
		out.Rationale = "voting: verified-yes majority"
		return &out, nil
	}
	if no*2 > n {
		return &Result{Decision: DecisionNo, Confidence: float64(no) / float64(n),
			Rationale: "voting: no majority"}, nil
	}
	// Propagate the underlying reason verbatim. A synthetic string here would hide
	// "transport: ..." / "status 401" from the caller's broken-judge detection,
	// turning a failed scan into a green pass.
	if firstProblem != "" {
		return inconclusive(firstProblem), nil
	}
	return inconclusive("voting: no decisive majority"), nil
}
