// Package benchmark validates benchmark results before they may be reported (§37.2).
//
// Boundary: it decides whether a trial result is admissible and whether a set of them supports a
// published figure. It runs no benchmark, executes no task, and computes no model output.
//
// Requirements: PRD §37.2 benchmark requirements.
//
// # A score on visible tests is not a score
//
// §37.2 requires hidden and visible tests. The reason is that an agent optimising against tests it
// can read is measuring its own reading, and the number that results is a real number describing
// nothing. So a result computed without hidden tests is refused rather than reported with a caveat:
// a caveat is a footnote and the figure is what gets quoted.
//
// # Unattended means zero, not few
//
// §37.2 asks for "a separate unattended subset with zero corrective user messages". Zero is the
// whole claim. A subset admitting one nudge per task measures a different thing and reports it
// under the same name, and the difference is invisible in the headline — which is the same reason
// MEM-2 refuses to promote on a single trajectory and VAD refuses a mutation score over two mutants.
//
// # Why cost needs five fields
//
// A converted cost figure with no FX rate and no timestamp cannot be audited or reproduced: the
// same run reported in two currencies a month apart is two unrelated numbers. §37.2 lists all five
// parts, so all five are required and a partial conversion is refused rather than rounded off.
package benchmark

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
)

// FailureClass is §37.2's failure taxonomy.
type FailureClass string

const (
	// FailureUnclassified is the zero value and is never admissible on a failed trial. A taxonomy
	// with an "other" bucket that fills up describes nothing, and the zero value is where that
	// bucket forms.
	FailureUnclassified FailureClass = ""
	FailureVerification FailureClass = "verification"
	FailureContext      FailureClass = "context"
	FailureTooling      FailureClass = "tooling"
	FailureRouting      FailureClass = "routing"
	FailureTimeout      FailureClass = "timeout"
	FailurePolicy       FailureClass = "policy"
)

// Valid reports whether c is a declared class.
func (c FailureClass) Valid() bool {
	switch c {
	case FailureVerification, FailureContext, FailureTooling,
		FailureRouting, FailureTimeout, FailurePolicy:
		return true
	}
	return false
}

// Cost is a normalized cost figure with everything §37.2 requires to audit it.
type Cost struct {
	OriginalMicros   int64  `json:"original_micros"`
	OriginalCurrency string `json:"original_currency"`
	ReportedMicros   int64  `json:"reported_micros"`
	ReportedCurrency string `json:"reported_currency"`
	// FXSource, FXRate and FXAt are what make the conversion reproducible. A figure without them is
	// a number somebody computed once.
	FXSource string    `json:"fx_source"`
	FXRate   float64   `json:"fx_rate"`
	FXAt     time.Time `json:"fx_at"`
}

// Validate enforces §37.2's cost normalization.
func (c Cost) Validate() error {
	switch {
	case c.OriginalCurrency == "" || c.ReportedCurrency == "":
		return field("a cost figure names no currency", "currency")
	case c.OriginalMicros < 0 || c.ReportedMicros < 0:
		return field("a cost figure is negative", "micros")
	}
	if c.OriginalCurrency == c.ReportedCurrency {
		// No conversion happened, so no FX evidence is required — but the figures must agree, or
		// something converted and did not say so.
		if c.OriginalMicros != c.ReportedMicros {
			return field("a cost reported in its original currency does not match", "reported_micros")
		}
		return nil
	}
	switch {
	case strings.TrimSpace(c.FXSource) == "":
		return field("a converted cost names no FX source", "fx_source")
	case c.FXRate <= 0 || math.IsNaN(c.FXRate):
		return field("a converted cost has no usable FX rate", "fx_rate")
	case c.FXAt.IsZero():
		return field("a converted cost has no FX timestamp; the same run would convert differently later",
			"fx_at")
	}
	return nil
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// Trial is one execution of one benchmark task.
type Trial struct {
	TaskID string `json:"task_id"`
	// Seed distinguishes repeated trials of the same task.
	Seed int `json:"seed"`
	// Revision is the fixed repository revision the task ran against.
	Revision string `json:"revision"`
	// VisibleTestsPassed and HiddenTestsPassed are reported separately. A pass is both.
	VisibleTestsPassed bool `json:"visible_tests_passed"`
	HiddenTestsRun     bool `json:"hidden_tests_run"`
	HiddenTestsPassed  bool `json:"hidden_tests_passed"`
	// CorrectiveMessages counts user interventions that redirected the run.
	CorrectiveMessages int `json:"corrective_messages"`
	// Failure classifies a failed trial (§37.2 failure taxonomy).
	Failure FailureClass `json:"failure,omitempty"`
	Cost    Cost         `json:"cost"`
	// RouteProviderID and RouteModelID record the model and routing policy §37.2 requires.
	RouteProviderID string `json:"route_provider_id"`
	RouteModelID    string `json:"route_model_id"`
}

// Succeeded reports whether the trial passed. Both test sets must pass.
func (t Trial) Succeeded() bool { return t.VisibleTestsPassed && t.HiddenTestsPassed }

// Validate enforces the per-trial requirements of §37.2.
func (t Trial) Validate() error {
	switch {
	case strings.TrimSpace(t.TaskID) == "":
		return field("a trial names no task", "task_id")
	case strings.TrimSpace(t.Revision) == "":
		// Fixed repository revisions. A trial that does not say which revision it ran against cannot
		// be reproduced or compared.
		return field(fmt.Sprintf("trial %s names no repository revision", t.TaskID), "revision")
	case !t.HiddenTestsRun:
		// A score on visible tests measures the agent's reading of the tests. Refused rather than
		// caveated, because the caveat is a footnote and the figure is what gets quoted.
		return field(fmt.Sprintf(
			"trial %s ran no hidden tests; a visible-only result is not a benchmark score", t.TaskID),
			"hidden_tests_run")
	case t.CorrectiveMessages < 0:
		return field(fmt.Sprintf("trial %s has a negative intervention count", t.TaskID),
			"corrective_messages")
	case strings.TrimSpace(t.RouteProviderID) == "" || strings.TrimSpace(t.RouteModelID) == "":
		return field(fmt.Sprintf("trial %s records no model route", t.TaskID), "route")
	case !t.Succeeded() && !t.Failure.Valid():
		// An unclassified failure is where an "other" bucket forms, and a taxonomy with a full other
		// bucket describes nothing.
		return field(fmt.Sprintf("trial %s failed without a failure class", t.TaskID), "failure")
	case t.Succeeded() && t.Failure != FailureUnclassified:
		return field(fmt.Sprintf("trial %s succeeded and carries a failure class", t.TaskID), "failure")
	}
	return t.Cost.Validate()
}

// Unattended reports whether the trial belongs in §37.2's unattended subset.
//
// Zero corrective messages. Not few — a subset admitting one nudge per task measures a different
// thing and reports it under the same name.
func (t Trial) Unattended() bool { return t.CorrectiveMessages == 0 }

// MinTrials is how many trials a stochastic task needs before a rate may be published.
//
// One trial of a stochastic process is an anecdote. Three is the smallest number from which a
// confidence interval says anything, and §37.2 asks for "multiple seeds or repeated trials where
// stochasticity matters".
const MinTrials = 3

// Result is a published figure for one task.
type Result struct {
	TaskID string `json:"task_id"`
	Trials int    `json:"trials"`
	// SuccessRate is 0..1 across the trials.
	SuccessRate float64 `json:"success_rate"`
	// IntervalLow and IntervalHigh bound it (§37.2 confidence intervals). A point estimate with no
	// interval invites a comparison the data does not support.
	IntervalLow  float64 `json:"interval_low"`
	IntervalHigh float64 `json:"interval_high"`
	// Failures counts each class, so a taxonomy is reported rather than a total.
	Failures map[FailureClass]int `json:"failures,omitempty"`
	// UnattendedTrials is how many of the trials took no corrective message.
	UnattendedTrials int `json:"unattended_trials"`
}

// Summarize turns trials into a publishable result, or refuses (§37.2).
//
// stochastic marks a task whose outcome varies between runs; those need MinTrials before a rate may
// be published. A deterministic task may be reported from one trial, because repeating it adds no
// information.
func Summarize(taskID string, trials []Trial, stochastic bool) (Result, error) {
	if strings.TrimSpace(taskID) == "" {
		return Result{}, field("a result names no task", "task_id")
	}
	if len(trials) == 0 {
		return Result{}, field(fmt.Sprintf("task %s has no trials", taskID), "trials")
	}
	if stochastic && len(trials) < MinTrials {
		return Result{}, field(fmt.Sprintf(
			"task %s is stochastic and has %d trial(s); %d are needed before a rate is meaningful",
			taskID, len(trials), MinTrials), "trials")
	}

	res := Result{TaskID: taskID, Trials: len(trials), Failures: map[FailureClass]int{}}
	succeeded := 0
	for _, t := range trials {
		if t.TaskID != taskID {
			return Result{}, field(fmt.Sprintf(
				"a trial for %s was summarized under %s", t.TaskID, taskID), "task_id")
		}
		if err := t.Validate(); err != nil {
			return Result{}, err
		}
		if t.Succeeded() {
			succeeded++
		} else {
			res.Failures[t.Failure]++
		}
		if t.Unattended() {
			res.UnattendedTrials++
		}
	}

	res.SuccessRate = float64(succeeded) / float64(len(trials))
	res.IntervalLow, res.IntervalHigh = wilson(succeeded, len(trials))
	return res, nil
}

// wilson returns a 95% Wilson score interval.
//
// Wilson rather than the normal approximation because benchmark suites are small and the normal
// interval is wrong exactly where it matters: at 0 and 1 it produces a zero-width interval, which
// reports perfect certainty from three trials.
func wilson(successes, n int) (low, high float64) {
	if n == 0 {
		return 0, 0
	}
	const z = 1.96
	p := float64(successes) / float64(n)
	nf := float64(n)
	denom := 1 + z*z/nf
	centre := (p + z*z/(2*nf)) / denom
	margin := (z / denom) * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf))
	return math.Max(0, centre-margin), math.Min(1, centre+margin)
}

// UnattendedResult summarizes only the trials that took no corrective message (§37.2).
//
// It is a separate function rather than a field on Result because the unattended subset is a
// separate measurement, and computing it from the same trials without saying so is how the two
// numbers get conflated in a report.
func UnattendedResult(taskID string, trials []Trial, stochastic bool) (Result, error) {
	var subset []Trial
	for _, t := range trials {
		if t.Unattended() {
			subset = append(subset, t)
		}
	}
	if len(subset) == 0 {
		return Result{}, field(fmt.Sprintf(
			"task %s has no unattended trials, so it has no unattended result", taskID), "trials")
	}
	return Summarize(taskID, subset, stochastic)
}

// Describe renders a result for a report line.
func (r Result) Describe() string {
	classes := make([]string, 0, len(r.Failures))
	for c, n := range r.Failures {
		classes = append(classes, fmt.Sprintf("%s=%d", c, n))
	}
	sort.Strings(classes)
	line := fmt.Sprintf("%s: %.0f%% [%.0f%%-%.0f%%] over %d trials (%d unattended)",
		r.TaskID, r.SuccessRate*100, r.IntervalLow*100, r.IntervalHigh*100,
		r.Trials, r.UnattendedTrials)
	if len(classes) > 0 {
		line += " failures: " + strings.Join(classes, " ")
	}
	return line
}
