package benchmark_test

import (
	"math"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/benchmark"
)

// §37.2 invariants (E1–E8). One test each; a test without an E-number, or an E-number without a
// test, is a gap.
//
//	E1 A trial with no hidden tests is refused; a visible-only score is not a score.
//	E2 A pass requires both test sets.
//	E3 Unattended means zero corrective messages, not few.
//	E4 A failed trial must carry a failure class; the zero class is not admissible.
//	E5 A converted cost needs source, rate and timestamp.
//	E6 A stochastic task needs multiple trials before a rate is published.
//	E7 The interval is never zero-width at 0 or 1, where a normal approximation would be.
//	E8 A trial with no fixed revision is refused.

func cost() benchmark.Cost {
	return benchmark.Cost{
		OriginalMicros: 1000, OriginalCurrency: "USD",
		ReportedMicros: 800, ReportedCurrency: "GBP",
		FXSource: "ecb", FXRate: 0.8, FXAt: time.Now(),
	}
}

func trial(task string, seed int, pass bool) benchmark.Trial {
	t := benchmark.Trial{
		TaskID: task, Seed: seed, Revision: "abc123",
		VisibleTestsPassed: pass, HiddenTestsRun: true, HiddenTestsPassed: pass,
		Cost: cost(), RouteProviderID: "vendor", RouteModelID: "model-1",
	}
	if !pass {
		t.Failure = benchmark.FailureVerification
	}
	return t
}

// E1. A score computed on tests the agent can read is measuring its own reading.
//
// Refused rather than caveated: a caveat is a footnote and the figure is what gets quoted.
func TestSecurityAVisibleOnlyResultIsNotAScore(t *testing.T) {
	tr := trial("task-1", 1, true)
	tr.HiddenTestsRun = false

	if err := tr.Validate(); err == nil {
		t.Fatal("a trial that ran no hidden tests validated")
	}
	if _, err := benchmark.Summarize("task-1", []benchmark.Trial{tr}, false); err == nil {
		t.Fatal("a visible-only trial was summarized into a result")
	}
}

// E2. A pass requires both test sets.
func TestAPassRequiresBothTestSets(t *testing.T) {
	tr := trial("task-1", 1, true)
	tr.HiddenTestsPassed = false
	tr.Failure = benchmark.FailureVerification
	if tr.Succeeded() {
		t.Fatal("a trial passing only the visible tests reported success")
	}

	tr = trial("task-1", 1, true)
	tr.VisibleTestsPassed = false
	tr.Failure = benchmark.FailureVerification
	if tr.Succeeded() {
		t.Fatal("a trial passing only the hidden tests reported success")
	}
}

// E3. §37.2's unattended subset is zero corrective messages.
//
// A subset admitting one nudge per task measures a different thing and reports it under the same
// name, and the difference is invisible in the headline.
func TestSecurityUnattendedMeansZeroCorrectiveMessages(t *testing.T) {
	clean := trial("task-1", 1, true)
	if !clean.Unattended() {
		t.Fatal("a trial with no corrective messages was not unattended")
	}
	nudged := trial("task-1", 2, true)
	nudged.CorrectiveMessages = 1
	if nudged.Unattended() {
		t.Fatal("a trial with one corrective message was counted as unattended")
	}

	trials := []benchmark.Trial{clean, nudged, trial("task-1", 3, true)}
	full, err := benchmark.Summarize("task-1", trials, true)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if full.UnattendedTrials != 2 {
		t.Fatalf("unattended = %d of 3, want 2", full.UnattendedTrials)
	}

	// The unattended result is computed from the subset, not the whole.
	sub, err := benchmark.UnattendedResult("task-1", trials, false)
	if err != nil {
		t.Fatalf("UnattendedResult: %v", err)
	}
	if sub.Trials != 2 {
		t.Fatalf("the unattended result covered %d trials, want the 2 clean ones", sub.Trials)
	}

	// A task with no clean trials has no unattended result, rather than a zero one.
	only := []benchmark.Trial{nudged}
	if _, err := benchmark.UnattendedResult("task-1", only, false); err == nil {
		t.Fatal("a task with no unattended trials produced an unattended result")
	}
}

// E4. A failed trial must be classified; the zero class is where an "other" bucket forms.
func TestSecurityAFailedTrialMustBeClassified(t *testing.T) {
	tr := trial("task-1", 1, false)
	tr.Failure = benchmark.FailureUnclassified
	if err := tr.Validate(); err == nil {
		t.Fatal("a failed trial with no failure class validated")
	}

	// And a success carrying a stale class is refused, or the taxonomy counts things that did not
	// happen.
	ok := trial("task-1", 1, true)
	ok.Failure = benchmark.FailureTimeout
	if err := ok.Validate(); err == nil {
		t.Fatal("a successful trial carrying a failure class validated")
	}
	if benchmark.FailureUnclassified.Valid() {
		t.Fatal("the zero FailureClass reports itself valid")
	}
}

// E5. A converted cost with no FX evidence is a number somebody computed once.
func TestSecurityAConvertedCostNeedsItsFXEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*benchmark.Cost){
		"no source":    func(c *benchmark.Cost) { c.FXSource = " " },
		"no rate":      func(c *benchmark.Cost) { c.FXRate = 0 },
		"nan rate":     func(c *benchmark.Cost) { c.FXRate = math.NaN() },
		"no timestamp": func(c *benchmark.Cost) { c.FXAt = time.Time{} },
		"no currency":  func(c *benchmark.Cost) { c.ReportedCurrency = "" },
	} {
		c := cost()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: an unauditable cost validated", name)
		}
	}
	if err := cost().Validate(); err != nil {
		t.Fatalf("a complete cost was refused: %v", err)
	}

	// An unconverted figure needs no FX evidence, but must not have silently changed.
	same := benchmark.Cost{
		OriginalMicros: 100, OriginalCurrency: "GBP",
		ReportedMicros: 100, ReportedCurrency: "GBP",
	}
	if err := same.Validate(); err != nil {
		t.Fatalf("an unconverted cost was refused: %v", err)
	}
	same.ReportedMicros = 90
	if err := same.Validate(); err == nil {
		t.Fatal("a cost that changed without converting validated")
	}
}

// E6. A stochastic task needs multiple trials before a rate means anything.
func TestSecurityAStochasticTaskNeedsMultipleTrials(t *testing.T) {
	one := []benchmark.Trial{trial("task-1", 1, true)}
	if _, err := benchmark.Summarize("task-1", one, true); err == nil {
		t.Fatal("a stochastic task published a rate from one trial")
	}
	// Deterministic tasks may be reported from one: repeating adds no information.
	if _, err := benchmark.Summarize("task-1", one, false); err != nil {
		t.Fatalf("a deterministic task was refused from one trial: %v", err)
	}

	three := []benchmark.Trial{
		trial("task-1", 1, true), trial("task-1", 2, false), trial("task-1", 3, true),
	}
	got, err := benchmark.Summarize("task-1", three, true)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if got.Trials != 3 {
		t.Fatalf("trials = %d, want 3", got.Trials)
	}
	if got.SuccessRate < 0.66 || got.SuccessRate > 0.67 {
		t.Fatalf("success rate = %v, want 2/3", got.SuccessRate)
	}
	if got.Failures[benchmark.FailureVerification] != 1 {
		t.Fatalf("failures = %v, want one verification failure", got.Failures)
	}
}

// E7. The interval is never zero-width at the extremes.
//
// A normal approximation gives a zero-width interval at 0 and 1, which reports perfect certainty
// from three trials — the most confident-looking way to be wrong, and exactly where a benchmark
// gets quoted.
func TestSecurityTheIntervalIsNotZeroWidthAtTheExtremes(t *testing.T) {
	allPass := []benchmark.Trial{
		trial("t", 1, true), trial("t", 2, true), trial("t", 3, true),
	}
	got, err := benchmark.Summarize("t", allPass, true)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if got.SuccessRate != 1 {
		t.Fatalf("rate = %v, want 1", got.SuccessRate)
	}
	// The property is non-zero *width*, not a bound below 1. A mutation substituting the normal
	// approximation produced low == high == 0.719 — zero width, and it slipped past an assertion
	// that only checked the lower bound. Width is what "the interval says something" means.
	if got.IntervalHigh-got.IntervalLow <= 0 {
		t.Fatalf("interval [%v,%v] at 3/3 has zero width; that claims certainty from three trials",
			got.IntervalLow, got.IntervalHigh)
	}
	if got.IntervalLow >= 1 {
		t.Fatalf("interval low = %v at 3/3, want room below the point estimate", got.IntervalLow)
	}

	allFail := []benchmark.Trial{
		trial("t", 1, false), trial("t", 2, false), trial("t", 3, false),
	}
	got, err = benchmark.Summarize("t", allFail, true)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if got.IntervalHigh-got.IntervalLow <= 0 {
		t.Fatalf("interval [%v,%v] at 0/3 has zero width", got.IntervalLow, got.IntervalHigh)
	}
	if got.IntervalHigh <= 0 {
		t.Fatalf("interval high = %v at 0/3, want a non-zero upper bound", got.IntervalHigh)
	}
	// And it stays inside [0,1].
	if got.IntervalLow < 0 || got.IntervalHigh > 1 {
		t.Fatalf("interval [%v,%v] escaped [0,1]", got.IntervalLow, got.IntervalHigh)
	}
}

// E8. A trial with no fixed revision cannot be reproduced or compared.
func TestATrialWithoutAFixedRevisionIsRefused(t *testing.T) {
	tr := trial("task-1", 1, true)
	tr.Revision = ""
	if err := tr.Validate(); err == nil {
		t.Fatal("a trial with no repository revision validated")
	}

	tr = trial("task-1", 1, true)
	tr.RouteModelID = ""
	if err := tr.Validate(); err == nil {
		t.Fatal("a trial recording no model route validated")
	}
}

// Trials from another task are not summarized under this one.
func TestTrialsFromAnotherTaskAreRefused(t *testing.T) {
	mixed := []benchmark.Trial{trial("task-1", 1, true), trial("task-2", 1, true)}
	if _, err := benchmark.Summarize("task-1", mixed, false); err == nil {
		t.Fatal("a trial from another task was summarized into this task's result")
	}
}
