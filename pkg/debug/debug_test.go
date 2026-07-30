package debug_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/debug"
)

// DBG invariants (J1–J8). One test each; a test without a J-number, or a J-number without a test,
// is a gap.
//
//	J1 DBG-1: a run with neither a reproduction command nor an environment is refused.
//	J2 DBG-2: hypotheses are explicitly ranked, and two at the same rank are not ranked.
//	J3 DBG-2: an untested hypothesis is distinct from a refuted one.
//	J4 DBG-4: a diagnosis without runtime evidence is refused.
//	J5 DBG-5: the *original* reproduction must pass; verifying a narrowed case does not count.
//	J6 DBG-6: an unchecked regression pass blocks completion, distinctly from finding none.
//	J7 DBG-3: instrumentation must be removed or identified; forgotten is neither.
//	J8 The zero Completion closes nothing, and every blocker is reported at once.

func repro() debug.Reproduction {
	return debug.Reproduction{
		Command: "go test ./auth -run TestLogin", Environment: "sha256:beef",
		ExpectedFailure: "TestLogin panics on a nil session",
	}
}

func run() debug.Run {
	return debug.Run{
		ID: "dbg-1", Reproduction: repro(),
		Hypotheses: []debug.Hypothesis{
			{Statement: "the session is never initialised", Rank: 1,
				State: debug.HypothesisSupported, Evidence: "nil at auth.go:40"},
			{Statement: "the cache returns a zero value", Rank: 2, State: debug.HypothesisRefuted},
		},
		Diagnosis: debug.Diagnosis{
			Statement:       "Login dereferences a session the middleware never sets",
			RuntimeEvidence: []string{"panic trace at auth.go:40"},
		},
	}
}

func passed() debug.Verification {
	return debug.Verification{
		Reproduction: repro(), ReproductionStillFails: false, RegressionsChecked: true,
	}
}

// J1. DBG-1: a run that cannot say how the bug is provoked cannot tell whether it has finished.
func TestSecurityADebugRunMustRecordItsReproduction(t *testing.T) {
	for name, mutate := range map[string]func(*debug.Reproduction){
		"neither command nor environment": func(r *debug.Reproduction) {
			r.Command, r.Environment = "", " "
		},
		"no expected failure": func(r *debug.Reproduction) { r.ExpectedFailure = "" },
	} {
		rp := repro()
		mutate(&rp)
		if err := rp.Validate(); err == nil {
			t.Errorf("%s: an unreproducible run validated", name)
		}
		r := run()
		r.Reproduction = rp
		if err := r.Validate(); err == nil {
			t.Errorf("%s: a run with an unusable reproduction validated", name)
		}
	}

	// Either one alone is enough — a bug reproducible only by environment is still reproducible.
	for name, rp := range map[string]debug.Reproduction{
		"command only":     {Command: "make test", ExpectedFailure: "it hangs"},
		"environment only": {Environment: "staging", ExpectedFailure: "500 on login"},
	} {
		if err := rp.Validate(); err != nil {
			t.Errorf("%s: a usable reproduction was refused: %v", name, err)
		}
	}
}

// J2. DBG-2: ranked explicitly, because list order is invisible in a report and gets shuffled by
// anything that re-serialises it.
func TestSecurityHypothesesAreExplicitlyRankedAndTheRanksAreDistinct(t *testing.T) {
	if err := run().Validate(); err != nil {
		t.Fatalf("a well-formed run was refused: %v", err)
	}

	none := run()
	none.Hypotheses = nil
	if err := none.Validate(); err == nil {
		t.Fatal("a debug run with no hypotheses validated")
	}

	unranked := run()
	unranked.Hypotheses[1].Rank = 0
	if err := unranked.Validate(); err == nil {
		t.Fatal("an unranked hypothesis validated")
	}

	// Two at the same rank are not ranked: which the reader takes as more likely would be decided
	// by serialisation order, which is the thing the rank exists to stop mattering.
	tied := run()
	tied.Hypotheses[1].Rank = 1
	if err := tied.Validate(); err == nil {
		t.Fatal("two hypotheses at the same rank validated")
	}

	blank := run()
	blank.Hypotheses[0].Statement = " "
	if err := blank.Validate(); err == nil {
		t.Fatal("an empty hypothesis validated")
	}

	// Ranked() orders by rank rather than by position, so a shuffled slice still reads correctly.
	shuffled := run()
	shuffled.Hypotheses[0], shuffled.Hypotheses[1] = shuffled.Hypotheses[1], shuffled.Hypotheses[0]
	got := shuffled.Ranked()
	if got[0].Rank != 1 || got[1].Rank != 2 {
		t.Fatalf("Ranked returned ranks %d, %d; want 1, 2", got[0].Rank, got[1].Rank)
	}
}

// J3. DBG-2: an untested hypothesis is not a refuted one.
//
// "We thought of this and ruled it out" and "we thought of this and never got to it" are different
// things to whoever reads the diagnosis, and the second is where the real cause hides.
func TestSecurityAnUntestedHypothesisIsNotARefutedOne(t *testing.T) {
	var zero debug.HypothesisState
	if zero != debug.HypothesisUntested {
		t.Fatalf("the zero HypothesisState is %q, want untested", zero)
	}
	if zero == debug.HypothesisRefuted {
		t.Fatal("an untested hypothesis is indistinguishable from a refuted one")
	}
	if debug.HypothesisSupported == debug.HypothesisRefuted {
		t.Fatal("supported and refuted are the same value")
	}

	// A run may carry untested hypotheses — they are honest, and refusing them would push somebody
	// to mark them refuted.
	open := run()
	open.Hypotheses = append(open.Hypotheses, debug.Hypothesis{
		Statement: "the middleware ordering changed", Rank: 3,
	})
	if err := open.Validate(); err != nil {
		t.Fatalf("a run carrying an untested hypothesis was refused: %v", err)
	}
	if open.Ranked()[2].State != debug.HypothesisUntested {
		t.Fatal("an untested hypothesis did not survive as untested")
	}
}

// J4. DBG-4: a diagnosis without runtime evidence is a hypothesis wearing a hat, and it reads
// identically in a report.
func TestSecurityADiagnosisWithoutRuntimeEvidenceIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*debug.Diagnosis){
		"no statement":   func(d *debug.Diagnosis) { d.Statement = " " },
		"no evidence":    func(d *debug.Diagnosis) { d.RuntimeEvidence = nil },
		"empty evidence": func(d *debug.Diagnosis) { d.RuntimeEvidence = []string{" "} },
	} {
		d := run().Diagnosis
		mutate(&d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: an unevidenced diagnosis validated", name)
		}
		r := run()
		r.Diagnosis = d
		if err := r.Validate(); err == nil {
			t.Errorf("%s: a run with an unevidenced diagnosis validated", name)
		}
	}
}

// J5. DBG-5: the *original* reproduction.
//
// The natural end of a debugging session is a narrowed-down case: a small command that demonstrates
// the bug, fixed until that command passes. That is a different claim from the one the user made,
// and the gap between them is where a fix that addresses the symptom lives.
func TestSecurityVerifyingANarrowedReproductionDoesNotCompleteTheRepair(t *testing.T) {
	done, err := debug.Complete(run(), passed())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !done.Complete {
		t.Fatalf("a fully verified repair was not complete: %v", done.Outstanding)
	}

	// A narrowed command — green, and not the claim that was made.
	narrowed := passed()
	narrowed.Reproduction.Command = "go test ./auth -run TestLogin/nil_session"
	got, err := debug.Complete(run(), narrowed)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got.Complete {
		t.Fatal("a repair verified against a narrowed reproduction was called complete")
	}
	if !strings.Contains(strings.Join(got.Outstanding, " "), "different reproduction") {
		t.Fatalf("outstanding = %v; it must say the verifier ran something else", got.Outstanding)
	}

	// A different environment is the same problem: same command, different place.
	elsewhere := passed()
	elsewhere.Reproduction.Environment = "sha256:other"
	if got, _ := debug.Complete(run(), elsewhere); got.Complete {
		t.Fatal("a repair verified in a different environment was called complete")
	}

	// And the original still failing blocks, distinctly from running the wrong thing.
	failing := passed()
	failing.ReproductionStillFails = true
	got, err = debug.Complete(run(), failing)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got.Complete {
		t.Fatal("a repair whose reproduction still fails was called complete")
	}
	if !strings.Contains(strings.Join(got.Outstanding, " "), "still fails") {
		t.Fatalf("outstanding = %v, want the still-failing reproduction named", got.Outstanding)
	}
}

// J6. DBG-6: "we looked and found nothing" and "we did not look" produce the same empty list.
func TestSecurityAnUncheckedRegressionPassBlocksCompletion(t *testing.T) {
	unchecked := passed()
	unchecked.RegressionsChecked = false
	unchecked.NewFailures = nil

	got, err := debug.Complete(run(), unchecked)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got.Complete {
		t.Fatal("a repair whose regressions were never checked was called complete")
	}
	if !strings.Contains(strings.Join(got.Outstanding, " "), "did not check") {
		t.Fatalf("outstanding = %v, want the unchecked pass named", got.Outstanding)
	}

	// Checked and clean does complete, so the flag means something.
	if done, _ := debug.Complete(run(), passed()); !done.Complete {
		t.Fatal("a checked, clean repair was not complete")
	}

	// A repair that fixes the bug and breaks something else is not a repair, and each new failure
	// is named so a reader knows what to look at.
	broke := passed()
	broke.NewFailures = []string{"TestLogout", "TestRefresh"}
	got, err = debug.Complete(run(), broke)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got.Complete {
		t.Fatal("a repair that broke two tests was called complete")
	}
	joined := strings.Join(got.Outstanding, " ")
	for _, want := range []string{"TestLogout", "TestRefresh"} {
		if !strings.Contains(joined, want) {
			t.Errorf("outstanding = %v, missing %s", got.Outstanding, want)
		}
	}
}

// J7. DBG-3: removed or identified. Forgotten is neither.
//
// Identifying rather than removing is the right allowance — a log line that turned out to be worth
// keeping should be kept. What it does not permit is instrumentation nobody decided about, which is
// what a run leaves behind when it ends by getting the tests to pass.
func TestSecurityInstrumentationMustBeRemovedOrIdentified(t *testing.T) {
	forgotten := run()
	forgotten.Instruments = []debug.Instrumentation{{Location: "auth.go:40"}}

	got, err := debug.Complete(forgotten, passed())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got.Complete {
		t.Fatal("a repair leaving untracked instrumentation was called complete")
	}
	if !strings.Contains(strings.Join(got.Outstanding, " "), "auth.go:40") {
		t.Fatalf("outstanding = %v, want the location named", got.Outstanding)
	}

	// Both resolutions are accepted, and they are genuinely different decisions.
	for name, inst := range map[string]debug.Instrumentation{
		"removed":    {Location: "auth.go:40", Removed: true},
		"identified": {Location: "auth.go:40", KeptReason: "useful production log line"},
	} {
		if !inst.Resolved() {
			t.Errorf("%s instrumentation reported itself unresolved", name)
		}
		r := run()
		r.Instruments = []debug.Instrumentation{inst}
		done, err := debug.Complete(r, passed())
		if err != nil {
			t.Fatalf("%s: Complete: %v", name, err)
		}
		if !done.Complete {
			t.Errorf("%s: a resolved instrument blocked completion: %v", name, done.Outstanding)
		}
	}

	// A blank reason is not an identification.
	blank := debug.Instrumentation{Location: "auth.go:40", KeptReason: "   "}
	if blank.Resolved() {
		t.Fatal("whitespace was accepted as a reason to keep instrumentation")
	}
	// Instrumentation with no location cannot be found to be removed.
	nowhere := run()
	nowhere.Instruments = []debug.Instrumentation{{Removed: true}}
	if err := nowhere.Validate(); err == nil {
		t.Fatal("instrumentation with no location validated")
	}
}

// J8. The zero Completion closes nothing, and every blocker is reported at once.
//
// A debugging session that reports one blocker at a time takes as many rounds as it has problems.
func TestSecurityTheZeroCompletionClosesNothingAndBlockersComeTogether(t *testing.T) {
	var zero debug.Completion
	if zero.Complete {
		t.Fatal("the zero Completion closed a bug")
	}

	bad := run()
	bad.Instruments = []debug.Instrumentation{{Location: "auth.go:40"}}
	v := debug.Verification{
		Reproduction:           debug.Reproduction{Command: "something else"},
		ReproductionStillFails: true,
		RegressionsChecked:     false,
		NewFailures:            []string{"TestLogout"},
	}

	got, err := debug.Complete(bad, v)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got.Complete {
		t.Fatal("a run with four problems was complete")
	}
	// Four distinct blockers: wrong reproduction, unchecked regressions, a new failure, and
	// forgotten instrumentation. The still-fails one is subsumed by the wrong-reproduction one,
	// because a verifier that ran the wrong thing has said nothing about the right one.
	if len(got.Outstanding) != 4 {
		t.Fatalf("outstanding = %v, want all four at once", got.Outstanding)
	}
	joined := strings.Join(got.Outstanding, " ")
	for _, want := range []string{"different reproduction", "did not check", "TestLogout", "auth.go:40"} {
		if !strings.Contains(joined, want) {
			t.Errorf("outstanding = %v, missing %q", got.Outstanding, want)
		}
	}
	// "Still fails" is not reported alongside "ran the wrong thing", because it would be a claim
	// about a run that did not happen.
	if strings.Contains(joined, "still fails") {
		t.Error("a verifier that ran the wrong reproduction also reported on the right one")
	}

	// An invalid run is an error rather than an incomplete one: a malformed run is a caller defect,
	// not a bug that is not fixed yet.
	if _, err := debug.Complete(debug.Run{}, passed()); err == nil {
		t.Fatal("an empty run produced a completion rather than an error")
	}
}
