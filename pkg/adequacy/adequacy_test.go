package adequacy_test

import (
	"math"
	"testing"

	"github.com/modbit/modbit/pkg/adequacy"
	"github.com/modbit/modbit/pkg/modberr"
)

// VAD invariants (A1–A9). One test each; a test without an A-number, or an A-number without a test,
// is a gap.
//
//	A1 With no policy threshold, signals are recorded and the claim is not gated.
//	A2 A signal below the threshold is inadequate and does not pass.
//	A3 A missing signal is inconclusive, not inadequate, and does not pass.
//	A4 A signal over too small a population is inconclusive, however high its ratio.
//	A5 The strongest available method decides, not the most favourable.
//	A6 Inconsistent results at one revision are flaky and inconclusive, never passed.
//	A7 Consistent failure is not flaky; the test is telling the truth.
//	A8 Too few runs cannot establish stability.
//	A9 Disagreement across different revisions is not flakiness.

func ptr(f float64) *float64 { return &f }

func mutation(value float64, population int) adequacy.Measurement {
	return adequacy.Measurement{
		Method: adequacy.MethodMutationScore, Value: value, Population: population,
	}
}

// A1. VAD-2 makes the threshold optional; a repository that set none has not asked for a gate.
func TestWithNoThresholdTheClaimIsNotGated(t *testing.T) {
	a, err := adequacy.Assess([]adequacy.Measurement{mutation(0.1, 100)}, nil)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !a.Verdict.Passes() {
		t.Fatalf("verdict = %s with no threshold set; VAD-2 gates only where policy sets one", a.Verdict)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// The signal is still recorded, because VAD-1 requires it in the evidence bundle regardless.
	if len(a.Measurements) != 1 {
		t.Fatalf("the assessment discarded the measurement")
	}
}

// A2. VAD-2: a mandatory claim must not pass on evidence below the threshold.
func TestSecurityASignalBelowTheThresholdDoesNotPass(t *testing.T) {
	a, err := adequacy.Assess([]adequacy.Measurement{mutation(0.60, 50)}, ptr(0.80))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if a.Verdict.Passes() {
		t.Fatal("a mutation score of 0.60 passed a threshold of 0.80")
	}
	if a.Verdict != adequacy.VerdictInadequate {
		t.Fatalf("verdict = %s, want inadequate", a.Verdict)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// A3. A signal nobody computed must not read as a measurement.
//
// This is the dangerous direction: inadequate blocks a run, which is safe and annoying, while
// treating an absent signal as a pass lets a suite nobody assessed clear a threshold nobody applied.
func TestSecurityAMissingSignalIsInconclusiveAndDoesNotPass(t *testing.T) {
	a, err := adequacy.Assess(nil, ptr(0.80))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if a.Verdict.Passes() {
		t.Fatal("an assessment with no signal at all passed")
	}
	if a.Verdict != adequacy.VerdictInconclusive {
		t.Fatalf("verdict = %s, want inconclusive: no signal is not the same as a bad one", a.Verdict)
	}
	if a.Reason == "" {
		t.Fatal("an inconclusive assessment carries no reason")
	}
}

// A4. A perfect ratio over a tiny population is the most confident-looking way to be wrong.
func TestSecurityAPerfectScoreOverATinyPopulationIsInconclusive(t *testing.T) {
	a, err := adequacy.Assess([]adequacy.Measurement{mutation(1.0, 2)}, ptr(0.80))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if a.Verdict.Passes() {
		t.Fatal("a mutation score of 1.00 over two mutants passed a 0.80 threshold")
	}
	if a.Verdict != adequacy.VerdictInconclusive {
		t.Fatalf("verdict = %s, want inconclusive", a.Verdict)
	}
}

// A5. The strongest method decides, so a heuristic cannot overrule a real measurement.
//
// Assertion density is a guess about whether tests assert anything. A mutation score is a
// measurement of whether they can fail. Taking the best number across methods would let the guess
// override the measurement whenever the guess was more flattering.
func TestTheStrongestSignalDecidesNotTheMostFavourable(t *testing.T) {
	a, err := adequacy.Assess([]adequacy.Measurement{
		{Method: adequacy.MethodAssertionDensity, Value: 1.0, Population: 40},
		mutation(0.30, 40),
	}, ptr(0.80))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if a.Verdict.Passes() {
		t.Fatal("a perfect assertion-density heuristic overrode a mutation score of 0.30")
	}
}

// A malformed measurement is refused rather than scored.
//
// NaN is the case worth naming: it compares false against every threshold, so an unchecked NaN
// would fail closed in a way nobody could diagnose from the number.
func TestAMalformedMeasurementIsRefused(t *testing.T) {
	for _, bad := range []adequacy.Measurement{
		{Method: "guesswork", Value: 0.9, Population: 10},
		{Method: adequacy.MethodMutationScore, Value: math.NaN(), Population: 10},
		{Method: adequacy.MethodMutationScore, Value: 1.5, Population: 10},
		{Method: adequacy.MethodMutationScore, Value: 0.9, Population: -1},
	} {
		if _, err := adequacy.Assess([]adequacy.Measurement{bad}, ptr(0.5)); err == nil {
			t.Errorf("a malformed measurement was accepted: %+v", bad)
		}
	}
	if _, err := adequacy.Assess([]adequacy.Measurement{mutation(0.9, 10)}, ptr(1.5)); err == nil {
		t.Error("a threshold outside 0..1 was accepted")
	}
}

// An assessment short of adequate must explain itself.
func TestAnAssessmentShortOfAdequateExplainsItself(t *testing.T) {
	silent := adequacy.Assessment{Verdict: adequacy.VerdictInadequate}
	if err := silent.Validate(); err == nil {
		t.Fatal("an inadequate assessment with no reason validated")
	}
	if err := silent.Validate(); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("err = %v, want CodeInvalidArgument", err)
	}
	stale := adequacy.Assessment{Verdict: adequacy.VerdictAdequate, Reason: "left over"}
	if err := stale.Validate(); err == nil {
		t.Fatal("an adequate assessment carrying a failure reason validated")
	}
}

// A6. VAD-5: repeated inconsistent results are inconclusive, never passed.
//
// This is the case the session that wrote this package hit. `make check` failed once under CPU
// contention and passed eighteen times afterwards, and the truthful answer was neither "passing"
// nor "broken" — which is exactly the distinction VAD-5 exists to preserve.
func TestSecurityInconsistentResultsAreInconclusiveNeverPassed(t *testing.T) {
	h := adequacy.History{Test: "TestCancellation", Observations: []adequacy.Observation{
		{Passed: true, Revision: "abc"},
		{Passed: false, Revision: "abc"},
		{Passed: true, Revision: "abc"},
		{Passed: true, Revision: "abc"},
	}}
	stability, verdict, reason, err := h.Verdict()
	if err != nil {
		t.Fatalf("Verdict: %v", err)
	}
	if stability != adequacy.StabilityFlaky {
		t.Fatalf("stability = %s, want flaky", stability)
	}
	if verdict.Passes() {
		t.Fatal("a test that failed 1 run in 4 at one revision was reported as passed")
	}
	if verdict != adequacy.VerdictInconclusive {
		t.Fatalf("verdict = %s, want inconclusive: flaky evidence is not a failure either", verdict)
	}
	if reason == "" {
		t.Fatal("a flaky verdict carries no reason")
	}
}

// A7. Consistent failure is not flakiness. The test is telling the truth and must not be quarantined.
func TestConsistentFailureIsNotFlaky(t *testing.T) {
	h := adequacy.History{Test: "TestBroken", Observations: []adequacy.Observation{
		{Passed: false, Revision: "abc"},
		{Passed: false, Revision: "abc"},
		{Passed: false, Revision: "abc"},
	}}
	stability, verdict, _, err := h.Verdict()
	if err != nil {
		t.Fatalf("Verdict: %v", err)
	}
	if stability != adequacy.StabilityStable {
		t.Fatalf("stability = %s, want stable: consistent failure is consistent", stability)
	}
	if verdict != adequacy.VerdictInadequate {
		t.Fatalf("verdict = %s, want inadequate", verdict)
	}
	if verdict.Passes() {
		t.Fatal("a consistently failing test passed")
	}
}

// A8. One green run establishes nothing about consistency.
func TestTooFewRunsCannotEstablishStability(t *testing.T) {
	h := adequacy.History{Test: "TestOnce", Observations: []adequacy.Observation{
		{Passed: true, Revision: "abc"},
	}}
	stability, verdict, reason, err := h.Verdict()
	if err != nil {
		t.Fatalf("Verdict: %v", err)
	}
	if stability != adequacy.StabilityUnknown {
		t.Fatalf("stability = %s after one run, want unknown", stability)
	}
	if verdict.Passes() {
		t.Fatal("a single green run was reported as adequate evidence of stability")
	}
	if reason == "" {
		t.Fatal("an unknown stability carries no reason")
	}
}

// A9. Disagreement across revisions is a code change, not flakiness.
//
// Mixing revisions is how a real regression gets filed as flaky and ignored, which is strictly worse
// than not quarantining at all.
func TestSecurityDisagreementAcrossRevisionsIsNotFlakiness(t *testing.T) {
	h := adequacy.History{Test: "TestRegressed", Observations: []adequacy.Observation{
		{Passed: true, Revision: "before"},
		{Passed: true, Revision: "before"},
		{Passed: true, Revision: "before"},
		{Passed: false, Revision: "after"},
		{Passed: false, Revision: "after"},
		{Passed: false, Revision: "after"},
	}}
	stability, verdict, _, err := h.Verdict()
	if err != nil {
		t.Fatalf("Verdict: %v", err)
	}
	if stability == adequacy.StabilityFlaky {
		t.Fatal("a clean regression across two revisions was filed as flaky")
	}
	if verdict.Passes() {
		t.Fatal("a test failing consistently at the current revision passed")
	}
}

// Quarantine separates unusable evidence and names it rather than dropping it.
func TestQuarantineNamesWhatItWithholds(t *testing.T) {
	flaky := adequacy.History{Test: "TestFlaky", Observations: []adequacy.Observation{
		{Passed: true, Revision: "r1"}, {Passed: false, Revision: "r1"}, {Passed: true, Revision: "r1"},
	}}
	stable := adequacy.History{Test: "TestStable", Observations: []adequacy.Observation{
		{Passed: true, Revision: "r1"}, {Passed: true, Revision: "r1"}, {Passed: true, Revision: "r1"},
	}}

	usable, quarantined, err := adequacy.Quarantine([]adequacy.History{flaky, stable})
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if len(quarantined) != 1 || quarantined[0].Test != "TestFlaky" {
		t.Fatalf("quarantined = %v, want exactly TestFlaky", quarantined)
	}
	if len(usable) != 1 || usable[0].Test != "TestStable" {
		t.Fatalf("usable = %v, want exactly TestStable", usable)
	}
}

// An observation with no revision is refused.
//
// Without one, same-revision disagreement cannot be distinguished from a regression, and the whole
// quarantine rule collapses into "sometimes red".
func TestAnObservationWithoutARevisionIsRefused(t *testing.T) {
	h := adequacy.History{Test: "TestNoRev", Observations: []adequacy.Observation{{Passed: true}}}
	if _, _, _, err := h.Verdict(); err == nil {
		t.Fatal("an observation with no revision was accepted")
	}
}
