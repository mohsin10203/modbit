package review

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Review context, risk triage, dispositions and feedback (REV-1, REV-2, REV-6, REV-7).
//
// Requirements: PRD §8.5 REV-1 (review runs in a context isolated from the implementation agent's
// hidden state), REV-2 (change risk is classified before deep analysis), REV-6 (users mark findings
// valid, invalid, accepted risk, or fixed), REV-7 (feedback improves rules, heuristics, or
// evaluation data without silently changing user policy).
//
// # Isolation is about the implementer's reasoning, not its output
//
// REV-1 asks for a context isolated from the implementation agent's *hidden state*. The diff is not
// hidden state — a reviewer that cannot see the change cannot review it. What must not cross is the
// implementer's reasoning: its plan, its scratch notes, its explanation of why the approach is
// sound. A reviewer given those does not review the change, it evaluates an argument, and it
// agrees, because the argument was written to be agreed with.
//
// This is a different failure from a reviewer that is simply wrong. A reviewer that has read the
// implementer's rationale is confidently, specifically wrong in the implementer's own terms, and
// its finding-free report reads as corroboration.
//
// # Feedback is evidence, not policy
//
// REV-7's "without silently changing user policy" is the requirement. Marking a finding invalid is
// a small, frequent, low-ceremony action — a click. Changing what a deployment enforces is a large,
// rare, high-ceremony one. Wiring the first to the second means a reviewer dismissing three noisy
// findings has quietly turned a rule off for their organization, and nobody decided that.
//
// So ApplyFeedback returns learning signal and states that policy is unchanged, and changing policy
// is a separate call that requires an actor and a reason.

// RiskClass is REV-2's pre-analysis triage.
type RiskClass string

const (
	// RiskUnclassified is the zero value and is never admissible for deep analysis. "Low" as a zero
	// value means a change nobody triaged is reviewed as though somebody had decided it was safe.
	RiskUnclassified RiskClass = ""
	RiskLow          RiskClass = "low"
	RiskMedium       RiskClass = "medium"
	RiskHigh         RiskClass = "high"
)

// Valid reports whether r is a declared class.
func (r RiskClass) Valid() bool {
	switch r {
	case RiskLow, RiskMedium, RiskHigh:
		return true
	}
	return false
}

// Context is what a review is allowed to see (REV-1).
type Context struct {
	// Diff is the change under review. Not hidden state: a reviewer that cannot see the change
	// cannot review it.
	Diff string `json:"diff"`
	// Revision is the revision the change applies to.
	Revision string `json:"revision"`
	// RepositoryRefs are references into the repository the reviewer may retrieve.
	RepositoryRefs []string `json:"repository_refs,omitempty"`
	// ImplementerPlan, ImplementerNotes and ImplementerRationale are the implementation agent's
	// hidden state. They are fields on this type rather than simply absent so that a caller
	// assembling a context cannot pass them through some other channel without this noticing — the
	// check has to be able to see what it is refusing.
	ImplementerPlan      string `json:"-"`
	ImplementerNotes     string `json:"-"`
	ImplementerRationale string `json:"-"`
}

// Isolated reports whether the context is free of the implementation agent's hidden state, and
// names what leaked if not.
func (c Context) Isolated() (bool, []string) {
	var leaked []string
	if strings.TrimSpace(c.ImplementerPlan) != "" {
		leaked = append(leaked, "plan")
	}
	if strings.TrimSpace(c.ImplementerNotes) != "" {
		leaked = append(leaked, "notes")
	}
	if strings.TrimSpace(c.ImplementerRationale) != "" {
		leaked = append(leaked, "rationale")
	}
	sort.Strings(leaked)
	return len(leaked) == 0, leaked
}

// Admit decides whether a review may begin (REV-1, REV-2).
//
// Risk is classified before deep analysis, so the classification is an input here rather than
// something the analysis produces. A triage derived from the deep pass has already spent the cost
// it existed to avoid.
func Admit(c Context, risk RiskClass) error {
	if strings.TrimSpace(c.Diff) == "" {
		return field("a review has no change to review", "diff")
	}
	if strings.TrimSpace(c.Revision) == "" {
		return field("a review names no revision", "revision")
	}
	if ok, leaked := c.Isolated(); !ok {
		// A reviewer given the implementer's reasoning does not review the change, it evaluates an
		// argument written to be agreed with — and its finding-free report reads as corroboration.
		return modberr.Newf(modberr.CodePolicyDenied,
			"the review context carries the implementation agent's %s; REV-1 requires isolation from "+
				"its hidden state", strings.Join(leaked, " and ")).
			WithDetail("constraint", "review_isolation")
	}
	if !risk.Valid() {
		return field(
			"the change has not been risk-classified; REV-2 requires triage before deep analysis",
			"risk")
	}
	return nil
}

// Feedback is a user's judgement on one finding (REV-6).
type Feedback struct {
	FindingID   string      `json:"finding_id"`
	Disposition Disposition `json:"disposition"`
	ActorID     string      `json:"actor_id"`
	// Note explains an invalid or accepted-risk judgement. Required for both, because those are the
	// two that stop a real finding being acted on and a bare dismissal leaves nothing for the next
	// person to evaluate.
	Note string `json:"note,omitempty"`
}

// Validate enforces REV-6.
func (f Feedback) Validate() error {
	switch {
	case strings.TrimSpace(f.FindingID) == "":
		return field("feedback names no finding", "finding_id")
	case !f.Disposition.Valid():
		return field(fmt.Sprintf("feedback on %s carries no disposition", f.FindingID), "disposition")
	case strings.TrimSpace(f.ActorID) == "":
		// An unattributed dismissal is one nobody can be asked about.
		return field(fmt.Sprintf("feedback on %s names no actor", f.FindingID), "actor_id")
	}
	switch f.Disposition {
	case DispositionInvalid, DispositionAcceptedRisk:
		if strings.TrimSpace(f.Note) == "" {
			return field(fmt.Sprintf(
				"a %s judgement on %s carries no note; these are the two dispositions that stop a real "+
					"finding being acted on", f.Disposition, f.FindingID), "note")
		}
	}
	return nil
}

// LearningUpdate is what feedback contributes (REV-7).
type LearningUpdate struct {
	// EvaluationExamples are added to the evaluation set.
	EvaluationExamples []string `json:"evaluation_examples,omitempty"`
	// HeuristicSignals are inputs to ranking and heuristics.
	HeuristicSignals []string `json:"heuristic_signals,omitempty"`
	// PolicyChanged is always false. It is a field rather than an absence so that a caller reading
	// the result sees the answer stated, and so that a change to this behaviour has to change a
	// value a test is watching.
	PolicyChanged bool `json:"policy_changed"`
	// SuppressFuture names findings that will be suppressed on recurrence (REV-5 interaction).
	SuppressFuture []string `json:"suppress_future,omitempty"`
}

// ApplyFeedback turns judgements into learning signal (REV-7).
//
// It never changes policy. Marking a finding invalid is a small, frequent, low-ceremony action;
// changing what a deployment enforces is large, rare and high-ceremony. Wire the first to the
// second and a reviewer dismissing three noisy findings has turned a rule off for their
// organization, and nobody decided that.
func ApplyFeedback(fs []Feedback) (LearningUpdate, error) {
	out := LearningUpdate{PolicyChanged: false}
	for _, f := range fs {
		if err := f.Validate(); err != nil {
			return LearningUpdate{}, err
		}
		switch f.Disposition {
		case DispositionInvalid:
			// A false positive is the most useful evaluation example there is.
			out.EvaluationExamples = append(out.EvaluationExamples, f.FindingID)
			out.HeuristicSignals = append(out.HeuristicSignals, f.FindingID)
			out.SuppressFuture = append(out.SuppressFuture, f.FindingID)
		case DispositionAcceptedRisk:
			// Accepted risk suppresses the recurrence but is not evidence the finding was wrong —
			// treating it as a false positive teaches the reviewer to stop reporting real problems.
			out.SuppressFuture = append(out.SuppressFuture, f.FindingID)
		case DispositionValid, DispositionFixed:
			// A confirmed finding is a positive example. It is never suppressed: REV-5 suppresses
			// dismissed findings, and a fixed finding that comes back is a regression.
			out.EvaluationExamples = append(out.EvaluationExamples, f.FindingID)
		}
	}
	sort.Strings(out.EvaluationExamples)
	sort.Strings(out.HeuristicSignals)
	sort.Strings(out.SuppressFuture)
	return out, nil
}

// PolicyChange is an explicit, attributed change to what a deployment enforces (REV-7).
//
// Separate from feedback and deliberately more ceremonious: an actor, a rule, and a reason. This is
// the only way policy moves, so a rule that stops firing can always be traced to somebody who
// decided it should.
type PolicyChange struct {
	RuleID  string `json:"rule_id"`
	Enabled bool   `json:"enabled"`
	ActorID string `json:"actor_id"`
	Reason  string `json:"reason"`
	// DerivedFromFindings may cite the findings that prompted the change. Citing them is allowed;
	// being *caused* by them is not, which is the distinction REV-7 draws.
	DerivedFromFindings []string `json:"derived_from_findings,omitempty"`
}

// Validate enforces REV-7's ceremony.
func (p PolicyChange) Validate() error {
	switch {
	case strings.TrimSpace(p.RuleID) == "":
		return field("a policy change names no rule", "rule_id")
	case strings.TrimSpace(p.ActorID) == "":
		return field(fmt.Sprintf("the change to %s names no actor", p.RuleID), "actor_id")
	case strings.TrimSpace(p.Reason) == "":
		// A rule that stops firing has to be traceable to somebody who decided it should, and a
		// blank reason is how a change becomes archaeology six months later.
		return field(fmt.Sprintf("the change to %s gives no reason", p.RuleID), "reason")
	}
	return nil
}
