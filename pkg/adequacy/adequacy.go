// Package adequacy implements verification adequacy signals and the flaky-test quarantine
// (VAD-1, VAD-2, VAD-5).
//
// Boundary: it scores how capable a test suite is of failing, and decides whether that score clears
// a policy threshold. It runs no tests, mutates no source, and knows nothing about a language — a
// runner supplies measurements and this decides what they mean.
//
// Requirements: PRD §11B VAD-1, VAD-2, VAD-5.
//
// # What the requirement is actually asking for
//
// §11B opens with the reason: "Verification currently proves that checks ran. v5.1 additionally
// requires proving that the checks are capable of failing." A green suite is evidence that nothing
// broke *or* that nothing was checked, and those are indistinguishable from the outside. An
// adequacy signal is what separates them.
//
// # Why an unknown score is not a low score
//
// The tempting model is a number that defaults to zero. It is wrong in the dangerous direction only
// once — a missing signal would read as inadequate and block a passing run, which is annoying but
// safe. The real hazard is the opposite: a signal that was never computed being treated as a
// measurement, so a suite nobody assessed clears a threshold nobody applied. `Verdict` therefore
// distinguishes *inconclusive* from *failed*, and VAD-5 makes the same distinction for a different
// reason — a flaky result is not a passing one.
package adequacy

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Method is how an adequacy signal was produced (VAD-1).
type Method string

const (
	// MethodMutationScore is the share of injected faults the suite detected. It is the strongest
	// of the three: it answers "can these tests fail" directly rather than by proxy.
	MethodMutationScore Method = "mutation_score"
	// MethodCoverageDelta is the coverage change over the changed code. It answers whether the new
	// code is exercised, not whether the assertions on it are meaningful.
	MethodCoverageDelta Method = "coverage_delta"
	// MethodAssertionDensity is assertions per changed unit. The weakest: a heuristic that a test
	// asserting nothing is inadequate, which catches the obvious case and little else.
	MethodAssertionDensity Method = "assertion_density"
)

// Methods returns the three VAD-1 signals in descending strength.
func Methods() []Method {
	return []Method{MethodMutationScore, MethodCoverageDelta, MethodAssertionDensity}
}

// Valid reports whether m is a declared method. An unknown method is refused rather than scored,
// because a signal nobody can interpret is not evidence.
func (m Method) Valid() bool {
	for _, known := range Methods() {
		if m == known {
			return true
		}
	}
	return false
}

// Measurement is one adequacy signal for one change.
type Measurement struct {
	Method Method `json:"method"`
	// Value is normalized to 0..1, where 1 means the signal found nothing lacking.
	Value float64 `json:"value"`
	// Population is how many items the signal was computed over — mutants injected, statements
	// changed, units inspected. A score over three mutants and a score over three hundred are not
	// the same evidence, and recording only the ratio would make them look identical.
	Population int `json:"population"`
	// Detail is free text for the evidence bundle. It never carries source content (R-ERR-02).
	Detail string `json:"detail,omitempty"`
}

// minPopulation is the smallest population a signal may be computed over and still be evidence.
//
// A mutation score of 1.0 over two mutants says almost nothing: the suite caught both of the two
// faults somebody happened to inject. Below this the measurement is reported as inconclusive rather
// than perfect, because a small sample producing a high ratio is the most confident-looking way to
// be wrong.
const minPopulation = 5

// Validate checks a measurement is interpretable.
func (m Measurement) Validate() error {
	switch {
	case !m.Method.Valid():
		return modberr.Newf(modberr.CodeInvalidArgument, "unknown adequacy method %q", m.Method).
			WithDetail("field", "method")
	case math.IsNaN(m.Value) || m.Value < 0 || m.Value > 1:
		// NaN is the case worth naming: it compares false against every threshold, so an unchecked
		// NaN would silently fail closed in a way nobody could debug from the number alone.
		return modberr.Newf(modberr.CodeInvalidArgument,
			"adequacy value %v is outside 0..1", m.Value).WithDetail("field", "value")
	case m.Population < 0:
		return modberr.New(modberr.CodeInvalidArgument, "a measurement has a negative population").
			WithDetail("field", "population")
	}
	return nil
}

// Verdict is the outcome of applying a threshold (VAD-2, VAD-5).
type Verdict string

const (
	// VerdictInconclusive is the zero value: adequacy could not be established.
	//
	// It is the zero deliberately, and it is not a synonym for failure. A run with no signal and a
	// run with a bad signal need different responses — the first needs the signal computed, the
	// second needs better tests — and collapsing them hides which. VAD-5 requires the same
	// distinction for flaky evidence.
	VerdictInconclusive Verdict = ""
	// VerdictInadequate means a signal was computed and fell below the threshold.
	VerdictInadequate Verdict = "inadequate"
	// VerdictAdequate means a signal was computed and cleared the threshold.
	VerdictAdequate Verdict = "adequate"
)

// Passes reports whether a mandatory claim may rely on this verdict.
//
// Only Adequate passes. VAD-2 says a mandatory claim must not pass on evidence below the threshold,
// and VAD-5 says inconsistent evidence is never `passed` — so inconclusive is not a soft yes.
func (v Verdict) Passes() bool { return v == VerdictAdequate }

// Assessment is the adequacy record for one change, written into the evidence bundle (VAD-1).
type Assessment struct {
	Verdict      Verdict       `json:"verdict"`
	Measurements []Measurement `json:"measurements"`
	// Threshold is the policy minimum applied, if any.
	Threshold *float64 `json:"threshold,omitempty"`
	// Reason explains anything other than Adequate. Required, for the reason LCD-3 requires one:
	// a verdict that blocks a run without saying why cannot be acted on.
	Reason string `json:"reason,omitempty"`
}

// Validate enforces the reason-or-adequate rule.
func (a Assessment) Validate() error {
	if a.Verdict != VerdictAdequate && strings.TrimSpace(a.Reason) == "" {
		return modberr.Newf(modberr.CodeInvalidArgument,
			"a %s assessment carries no reason", a.Verdict.describe()).WithDetail("field", "reason")
	}
	if a.Verdict == VerdictAdequate && a.Reason != "" {
		return modberr.New(modberr.CodeInvalidArgument,
			"an adequate assessment carries a failure reason").WithDetail("field", "reason")
	}
	for _, m := range a.Measurements {
		if err := m.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (v Verdict) describe() string {
	switch v {
	case VerdictAdequate:
		return "adequate"
	case VerdictInadequate:
		return "inadequate"
	default:
		return "inconclusive"
	}
}

// Assess applies a policy threshold to a set of measurements (VAD-1, VAD-2).
//
// threshold is nil when policy sets none, in which case the signals are recorded and the verdict is
// adequate — VAD-2 makes the threshold optional, and a repository that has not set one has not
// asked for a gate.
func Assess(measurements []Measurement, threshold *float64) (Assessment, error) {
	for _, m := range measurements {
		if err := m.Validate(); err != nil {
			return Assessment{}, err
		}
	}
	a := Assessment{Measurements: measurements, Threshold: threshold}

	if threshold == nil {
		a.Verdict = VerdictAdequate
		return a, nil
	}
	if *threshold < 0 || *threshold > 1 || math.IsNaN(*threshold) {
		return Assessment{}, modberr.Newf(modberr.CodeInvalidArgument,
			"adequacy threshold %v is outside 0..1", *threshold).WithDetail("field", "threshold")
	}

	// The strongest signal available decides, because a weak signal clearing a bar says less than a
	// strong one missing it. Taking the maximum across methods instead would let assertion density
	// — a heuristic — overrule a mutation score that actually measured the suite's ability to fail.
	strongest, found := strongestSignal(measurements)
	if !found {
		a.Verdict = VerdictInconclusive
		a.Reason = "no adequacy signal was computed for the changed tests"
		return a, nil
	}
	if strongest.Population < minPopulation {
		// A high ratio over a tiny population is the most confident-looking way to be wrong.
		a.Verdict = VerdictInconclusive
		a.Reason = fmt.Sprintf(
			"the %s signal was computed over %d items, below the %d needed to be evidence",
			strongest.Method, strongest.Population, minPopulation)
		return a, nil
	}
	if strongest.Value < *threshold {
		a.Verdict = VerdictInadequate
		a.Reason = fmt.Sprintf("the %s signal is %.2f, below the required %.2f",
			strongest.Method, strongest.Value, *threshold)
		return a, nil
	}
	a.Verdict = VerdictAdequate
	return a, nil
}

// strongestSignal returns the measurement with the strongest method present.
func strongestSignal(measurements []Measurement) (Measurement, bool) {
	for _, want := range Methods() { // Methods() is ordered strongest first.
		for _, m := range measurements {
			if m.Method == want {
				return m, true
			}
		}
	}
	return Measurement{}, false
}

// String renders an assessment for an evidence line.
func (a Assessment) String() string {
	names := make([]string, 0, len(a.Measurements))
	for _, m := range a.Measurements {
		names = append(names, fmt.Sprintf("%s=%.2f/n=%d", m.Method, m.Value, m.Population))
	}
	sort.Strings(names)
	if a.Reason == "" {
		return fmt.Sprintf("%s [%s]", a.Verdict.describe(), strings.Join(names, " "))
	}
	return fmt.Sprintf("%s: %s [%s]", a.Verdict.describe(), a.Reason, strings.Join(names, " "))
}
