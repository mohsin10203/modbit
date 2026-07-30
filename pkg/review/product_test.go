package review_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/review"
)

// Review product invariants (R9–R14). One test each; a test without an R-number, or an R-number
// without a test, is a gap. R1–R8 cover findings, suppression and verifier diversity.
//
//	R9  REV-1: the implementation agent's hidden state never reaches the review context.
//	R10 REV-2: risk is classified before deep analysis, and the zero class is not low.
//	R11 REV-6: four dispositions, and the zero means nobody looked rather than nobody objected.
//	R12 REV-7: feedback never changes policy.
//	R13 REV-7: a policy change is possible and requires an actor and a reason.
//	R14 REV-6: an invalid judgement is a false-positive example; an accepted risk is not.

func reviewContext() review.Context {
	return review.Context{Diff: "@@ -1 +1 @@", Revision: "abc123"}
}

// R9. REV-1: isolation is from the implementer's reasoning, not from its output.
//
// A reviewer given the implementer's rationale does not review the change, it evaluates an argument
// written to be agreed with — and then it is confidently, specifically wrong in the implementer's
// own terms, and its finding-free report reads as corroboration.
func TestSecurityTheImplementersHiddenStateNeverReachesTheReviewer(t *testing.T) {
	ok, leaked := reviewContext().Isolated()
	if !ok {
		t.Fatalf("a clean context reported leaks: %v", leaked)
	}
	if err := review.Admit(reviewContext(), review.RiskLow); err != nil {
		t.Fatalf("a clean review was refused: %v", err)
	}

	// Each channel independently, because one check standing in for three would pass a single
	// witness.
	for name, mutate := range map[string]func(*review.Context){
		"plan":      func(c *review.Context) { c.ImplementerPlan = "step 1: refactor auth" },
		"notes":     func(c *review.Context) { c.ImplementerNotes = "tried X, it did not work" },
		"rationale": func(c *review.Context) { c.ImplementerRationale = "this is safe because..." },
	} {
		c := reviewContext()
		mutate(&c)

		isolated, got := c.Isolated()
		if isolated {
			t.Errorf("%s: a context carrying the implementer's %s reported itself isolated", name, name)
		}
		if len(got) != 1 || got[0] != name {
			t.Errorf("%s: leaked = %v, want [%s]", name, got, name)
		}

		err := review.Admit(c, review.RiskLow)
		if err == nil {
			t.Errorf("%s: a review was admitted with the implementer's %s", name, name)
			continue
		}
		if !modberr.Is(err, modberr.CodePolicyDenied) {
			t.Errorf("%s: error = %v, want POLICY_DENIED", name, err)
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("%s: error %v does not name what leaked", name, err)
		}
	}

	// All three at once are all reported, so a caller fixing one does not discover the next on the
	// following attempt.
	all := reviewContext()
	all.ImplementerPlan, all.ImplementerNotes, all.ImplementerRationale = "p", "n", "r"
	if _, got := all.Isolated(); len(got) != 3 {
		t.Fatalf("leaked = %v, want all three named at once", got)
	}

	// The diff and repository references are not hidden state: a reviewer that cannot see the
	// change cannot review it.
	withRefs := reviewContext()
	withRefs.RepositoryRefs = []string{"src/auth.go"}
	if err := review.Admit(withRefs, review.RiskHigh); err != nil {
		t.Fatalf("a reviewer was denied the repository: %v", err)
	}
}

// R10. REV-2: triage before deep analysis.
//
// "Low" as a zero value means a change nobody triaged is reviewed as though somebody had decided it
// was safe. And a triage derived from the deep pass has already spent the cost it existed to avoid,
// which is why the classification is an input here.
func TestSecurityDeepAnalysisRequiresATriageThatAlreadyHappened(t *testing.T) {
	var zero review.RiskClass
	if zero != review.RiskUnclassified {
		t.Fatalf("the zero RiskClass is %q", zero)
	}
	if zero.Valid() {
		t.Fatal("the zero RiskClass reports itself valid")
	}
	if review.RiskClass("trivial").Valid() {
		t.Fatal("an invented risk class reports itself valid")
	}

	if err := review.Admit(reviewContext(), review.RiskUnclassified); err == nil {
		t.Fatal("an untriaged change was admitted to deep analysis")
	}
	for _, r := range []review.RiskClass{review.RiskLow, review.RiskMedium, review.RiskHigh} {
		if !r.Valid() {
			t.Errorf("%s is not a valid risk class", r)
		}
		if err := review.Admit(reviewContext(), r); err != nil {
			t.Errorf("a %s-risk change was refused: %v", r, err)
		}
	}

	// A review with nothing to review is refused too, so the diff is not optional.
	empty := reviewContext()
	empty.Diff = " "
	if err := review.Admit(empty, review.RiskHigh); err == nil {
		t.Fatal("a review with no diff was admitted")
	}
	noRev := reviewContext()
	noRev.Revision = ""
	if err := review.Admit(noRev, review.RiskHigh); err == nil {
		t.Fatal("a review against no revision was admitted")
	}
}

// R11. REV-6: four dispositions, and the zero is not one of them.
//
// An unreviewed finding and a dismissed one are opposite states, and collapsing them clears a queue
// by forgetting it.
func TestSecurityTheZeroDispositionMeansNobodyLooked(t *testing.T) {
	var zero review.Disposition
	if zero != review.DispositionNone {
		t.Fatalf("the zero Disposition is %q", zero)
	}
	if zero.Valid() || zero.Judged() {
		t.Fatal("the zero Disposition reports itself judged")
	}
	if zero.Dismissed() {
		t.Fatal("an unreviewed finding reports itself dismissed")
	}

	for _, d := range []review.Disposition{
		review.DispositionValid, review.DispositionInvalid,
		review.DispositionAcceptedRisk, review.DispositionFixed,
	} {
		if !d.Valid() || !d.Judged() {
			t.Errorf("%s is not accepted as a judgement", d)
		}
	}

	// Feedback carrying no disposition, no actor, or a bare dismissal is refused.
	for name, f := range map[string]review.Feedback{
		"no finding":     {Disposition: review.DispositionValid, ActorID: "u1"},
		"no disposition": {FindingID: "f-1", ActorID: "u1"},
		"no actor":       {FindingID: "f-1", Disposition: review.DispositionValid},
		"bare invalid": {
			FindingID: "f-1", Disposition: review.DispositionInvalid, ActorID: "u1",
		},
		"bare accepted risk": {
			FindingID: "f-1", Disposition: review.DispositionAcceptedRisk, ActorID: "u1",
		},
	} {
		if err := f.Validate(); err == nil {
			t.Errorf("%s: unusable feedback validated", name)
		}
	}

	// Valid and fixed need no note: the finding itself is the record.
	for _, d := range []review.Disposition{review.DispositionValid, review.DispositionFixed} {
		f := review.Feedback{FindingID: "f-1", Disposition: d, ActorID: "u1"}
		if err := f.Validate(); err != nil {
			t.Errorf("a %s judgement was required to carry prose: %v", d, err)
		}
	}
}

// R12. REV-7: feedback never changes policy.
//
// Marking a finding invalid is a click. Changing what a deployment enforces is not. Wire the first
// to the second and a reviewer dismissing three noisy findings has turned a rule off for their
// organization, and nobody decided that.
func TestSecurityFeedbackNeverChangesPolicy(t *testing.T) {
	fs := []review.Feedback{
		{FindingID: "f-1", Disposition: review.DispositionInvalid, ActorID: "u1", Note: "false positive"},
		{FindingID: "f-2", Disposition: review.DispositionInvalid, ActorID: "u1", Note: "also wrong"},
		{FindingID: "f-3", Disposition: review.DispositionInvalid, ActorID: "u1", Note: "noise"},
	}

	got, err := review.ApplyFeedback(fs)
	if err != nil {
		t.Fatalf("ApplyFeedback: %v", err)
	}
	if got.PolicyChanged {
		t.Fatal("three dismissals changed policy")
	}

	// It does produce learning signal, so the requirement is not satisfied by doing nothing.
	if len(got.EvaluationExamples) != 3 {
		t.Fatalf("evaluation examples = %v, want all three false positives", got.EvaluationExamples)
	}
	if len(got.HeuristicSignals) != 3 {
		t.Fatalf("heuristic signals = %v, want all three", got.HeuristicSignals)
	}

	// No amount of feedback moves it.
	var many []review.Feedback
	for i := 0; i < 100; i++ {
		many = append(many, review.Feedback{
			FindingID: "f", Disposition: review.DispositionInvalid, ActorID: "u1", Note: "no",
		})
	}
	bulk, err := review.ApplyFeedback(many)
	if err != nil {
		t.Fatalf("ApplyFeedback: %v", err)
	}
	if bulk.PolicyChanged {
		t.Fatal("a hundred dismissals changed policy")
	}

	// Invalid feedback stops the whole application rather than partially applying.
	if _, err := review.ApplyFeedback([]review.Feedback{
		{FindingID: "f-1", Disposition: review.DispositionValid, ActorID: "u1"},
		{FindingID: "f-2", Disposition: review.DispositionInvalid, ActorID: "u1"}, // no note
	}); err == nil {
		t.Fatal("a batch containing unusable feedback was applied")
	}
}

// R13. REV-7: policy can change, and it takes an actor and a reason.
//
// A rule that stops firing has to be traceable to somebody who decided it should.
func TestAPolicyChangeRequiresAnActorAndAReason(t *testing.T) {
	good := review.PolicyChange{
		RuleID: "sql-injection", Enabled: false, ActorID: "admin-1",
		Reason:              "superseded by the static analyser",
		DerivedFromFindings: []string{"f-1", "f-2"},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("a complete policy change was refused: %v", err)
	}

	for name, mutate := range map[string]func(*review.PolicyChange){
		"no rule":   func(p *review.PolicyChange) { p.RuleID = "" },
		"no actor":  func(p *review.PolicyChange) { p.ActorID = " " },
		"no reason": func(p *review.PolicyChange) { p.Reason = "" },
	} {
		p := good
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: an untraceable policy change validated", name)
		}
	}

	// Citing the findings that prompted it is allowed — being caused by them is what REV-7 forbids,
	// and the difference is that this required a person.
	cited := good
	cited.DerivedFromFindings = nil
	if err := cited.Validate(); err != nil {
		t.Fatalf("a policy change citing no findings was refused: %v", err)
	}
}

// R14. REV-6: accepted risk is not a false positive.
//
// Treating it as one teaches the reviewer to stop reporting real problems, which is the opposite of
// what the user meant by accepting the risk.
func TestSecurityAnAcceptedRiskIsNotAFalsePositive(t *testing.T) {
	got, err := review.ApplyFeedback([]review.Feedback{
		{FindingID: "wrong", Disposition: review.DispositionInvalid, ActorID: "u1", Note: "not real"},
		{FindingID: "known", Disposition: review.DispositionAcceptedRisk, ActorID: "u1", Note: "legacy"},
		{FindingID: "real", Disposition: review.DispositionValid, ActorID: "u1"},
		{FindingID: "done", Disposition: review.DispositionFixed, ActorID: "u1"},
	})
	if err != nil {
		t.Fatalf("ApplyFeedback: %v", err)
	}

	// The false positive teaches the heuristics; the accepted risk does not.
	if !containsStr(got.HeuristicSignals, "wrong") {
		t.Error("a false positive contributed no heuristic signal")
	}
	if containsStr(got.HeuristicSignals, "known") {
		t.Error("an accepted risk was fed back as a false positive; that teaches the reviewer to " +
			"stop reporting real problems")
	}
	if containsStr(got.EvaluationExamples, "known") {
		t.Error("an accepted risk became an evaluation example")
	}

	// Both suppress recurrence — the user does not want to see either again.
	for _, id := range []string{"wrong", "known"} {
		if !containsStr(got.SuppressFuture, id) {
			t.Errorf("%s was not suppressed on recurrence", id)
		}
	}
	// A fixed finding is never suppressed: its return is a regression, which is R5's rule and must
	// survive contact with the feedback path.
	if containsStr(got.SuppressFuture, "done") {
		t.Error("a fixed finding was suppressed; its recurrence is a regression")
	}
	if containsStr(got.SuppressFuture, "real") {
		t.Error("a confirmed finding was suppressed")
	}
	// And confirmed findings are positive evaluation examples.
	for _, id := range []string{"real", "done"} {
		if !containsStr(got.EvaluationExamples, id) {
			t.Errorf("%s was not recorded as a confirmed example", id)
		}
	}
}

func containsStr(in []string, v string) bool {
	for _, s := range in {
		if s == v {
			return true
		}
	}
	return false
}
