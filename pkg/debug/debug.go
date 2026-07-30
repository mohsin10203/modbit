// Package debug admits debug runs and decides when a repair is complete (DBG-1..DBG-6).
//
// Boundary: it decides whether a debug run is well-formed and whether its repair may be called
// done. It runs no reproduction, executes no command, and edits no code — a caller supplies what
// happened and this decides what it amounts to.
//
// Requirements: PRD §8.4 DBG-1 (a debug run records the reproduction command or environment), DBG-2
// (hypotheses are explicit and ranked), DBG-3 (temporary instrumentation is tracked and removed or
// identified), DBG-4 (runtime evidence is attached to the final diagnosis), DBG-5 (a repair is
// incomplete until the original reproduction no longer fails), DBG-6 (the verifier checks for new
// regressions).
//
// # The original reproduction, not a reproduction
//
// DBG-5 says the *original* reproduction must stop failing, and the word is doing work. The natural
// end of a debugging session is a narrowed-down case: the agent has found a small command that
// demonstrates the bug and fixes it until that command passes. That is a different claim from the
// one the user made, and the gap between them is where a fix that addresses the symptom lives.
//
// So the completion check compares the command by value against the one recorded at the start, and
// a run that verified something else is incomplete no matter how green it is.
//
// # Instrumentation is removed or declared, never just forgotten
//
// DBG-3 permits instrumentation to be *identified* rather than removed, which is the right
// allowance — a log line that turned out to be worth keeping should be kept. What it does not
// permit is instrumentation nobody decided about, which is what a run produces when it ends by
// getting the tests to pass. The unsupported case is permitted and must be declared.
package debug

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Reproduction is DBG-1's record of how the bug is provoked.
type Reproduction struct {
	// Command is what to run. Either this or Environment must be present, and both is better; a run
	// with neither cannot tell whether it has finished.
	Command string `json:"command"`
	// Environment names the environment the reproduction needs.
	Environment string `json:"environment"`
	// ExpectedFailure describes what going wrong looks like, so "it passed" is a claim about
	// something rather than an absence of output.
	ExpectedFailure string `json:"expected_failure"`
}

// Validate enforces DBG-1.
func (r Reproduction) Validate() error {
	if strings.TrimSpace(r.Command) == "" && strings.TrimSpace(r.Environment) == "" {
		return field(
			"a debug run records neither a reproduction command nor an environment, so it cannot tell "+
				"whether it has finished", "reproduction")
	}
	if strings.TrimSpace(r.ExpectedFailure) == "" {
		return field("a reproduction does not say what going wrong looks like", "expected_failure")
	}
	return nil
}

// SameAs reports whether another reproduction is the one this run started from (DBG-5).
//
// Compared by value rather than by "close enough". A narrowed-down case is the natural end of a
// debugging session and it is a different claim from the one the user made.
func (r Reproduction) SameAs(other Reproduction) bool {
	return strings.TrimSpace(r.Command) == strings.TrimSpace(other.Command) &&
		strings.TrimSpace(r.Environment) == strings.TrimSpace(other.Environment)
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// HypothesisState is what happened to a hypothesis (DBG-2).
type HypothesisState string

const (
	// HypothesisUntested is the zero value. Distinct from refuted, because "we thought of this and
	// ruled it out" and "we thought of this and never got to it" are different things to whoever
	// reads the diagnosis, and the second is where the real cause hides.
	HypothesisUntested  HypothesisState = ""
	HypothesisSupported HypothesisState = "supported"
	HypothesisRefuted   HypothesisState = "refuted"
)

// Hypothesis is one explicit, ranked candidate explanation (DBG-2).
type Hypothesis struct {
	Statement string `json:"statement"`
	// Rank orders the hypotheses. Lower is more likely. Explicit rather than positional, because a
	// list order is invisible in a report and gets shuffled by anything that re-serialises it.
	Rank  int             `json:"rank"`
	State HypothesisState `json:"state"`
	// Evidence is what supported or refuted it.
	Evidence string `json:"evidence,omitempty"`
}

// Instrumentation is a temporary change made to observe the bug (DBG-3).
type Instrumentation struct {
	// Location is where it was added.
	Location string `json:"location"`
	Removed  bool   `json:"removed"`
	// KeptReason explains instrumentation deliberately left in place. DBG-3 permits identifying
	// rather than removing, and this is what identifying means: somebody decided.
	KeptReason string `json:"kept_reason,omitempty"`
}

// Resolved reports whether this instrumentation has been dealt with either way.
func (i Instrumentation) Resolved() bool {
	return i.Removed || strings.TrimSpace(i.KeptReason) != ""
}

// Diagnosis is the run's conclusion (DBG-4).
type Diagnosis struct {
	Statement string `json:"statement"`
	// RuntimeEvidence is what was observed. A diagnosis without it is a hypothesis wearing a hat,
	// and it reads identically in a report.
	RuntimeEvidence []string `json:"runtime_evidence"`
}

// Validate enforces DBG-4.
func (d Diagnosis) Validate() error {
	switch {
	case strings.TrimSpace(d.Statement) == "":
		return field("a diagnosis states nothing", "statement")
	case len(d.RuntimeEvidence) == 0:
		return field(fmt.Sprintf(
			"the diagnosis %q attaches no runtime evidence; without it a diagnosis is a hypothesis and "+
				"reads identically in a report", d.Statement), "runtime_evidence")
	}
	for _, e := range d.RuntimeEvidence {
		if strings.TrimSpace(e) == "" {
			return field("the diagnosis attaches an empty piece of evidence", "runtime_evidence")
		}
	}
	return nil
}

// Verification is what the verifier observed after the repair (DBG-5, DBG-6).
type Verification struct {
	// Reproduction is the reproduction that was re-run. Compared against the recorded one.
	Reproduction Reproduction `json:"reproduction"`
	// ReproductionStillFails is what happened when it ran.
	ReproductionStillFails bool `json:"reproduction_still_fails"`
	// RegressionsChecked records that the verifier looked for new failures (DBG-6). The zero value
	// is false, so a verifier that never ran the regression pass does not silently pass one.
	RegressionsChecked bool `json:"regressions_checked"`
	// NewFailures are tests that were passing before the repair and are not now.
	NewFailures []string `json:"new_failures,omitempty"`
}

// Run is a debug session.
type Run struct {
	ID           string            `json:"id"`
	Reproduction Reproduction      `json:"reproduction"`
	Hypotheses   []Hypothesis      `json:"hypotheses"`
	Instruments  []Instrumentation `json:"instruments,omitempty"`
	Diagnosis    Diagnosis         `json:"diagnosis"`
}

// Validate enforces DBG-1, DBG-2 and DBG-4.
func (r Run) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return field("a debug run has no id", "id")
	}
	if err := r.Reproduction.Validate(); err != nil {
		return err
	}
	if len(r.Hypotheses) == 0 {
		// DBG-2. A debug run with no stated hypotheses is one whose reasoning nobody can check, and
		// the fix it produces cannot be argued with.
		return field(fmt.Sprintf("debug run %s states no hypotheses", r.ID), "hypotheses")
	}

	ranks := map[int]bool{}
	for _, h := range r.Hypotheses {
		switch {
		case strings.TrimSpace(h.Statement) == "":
			return field(fmt.Sprintf("debug run %s has an empty hypothesis", r.ID), "statement")
		case h.Rank < 1:
			return field(fmt.Sprintf(
				"the hypothesis %q has no rank; DBG-2 requires them ranked, and list order is invisible "+
					"in a report", h.Statement), "rank")
		case ranks[h.Rank]:
			// Two hypotheses at the same rank are not ranked. Whichever the reader takes as more
			// likely would be decided by serialisation order, which is the thing the rank exists to
			// stop mattering.
			return field(fmt.Sprintf(
				"debug run %s has two hypotheses at rank %d", r.ID, h.Rank), "rank")
		}
		ranks[h.Rank] = true
	}
	for _, i := range r.Instruments {
		if strings.TrimSpace(i.Location) == "" {
			return field(fmt.Sprintf("debug run %s tracks instrumentation with no location", r.ID),
				"location")
		}
	}
	return r.Diagnosis.Validate()
}

// Ranked returns the hypotheses in rank order, most likely first.
func (r Run) Ranked() []Hypothesis {
	out := append([]Hypothesis(nil), r.Hypotheses...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rank < out[j].Rank })
	return out
}

// Completion is whether a repair may be called done, and what is outstanding.
type Completion struct {
	// Complete is false in the zero value, so a Completion nobody computed does not close a bug.
	Complete bool `json:"complete"`
	// Outstanding names everything still in the way, all of it, because a debugging session that
	// reports one blocker at a time takes as many rounds as it has problems.
	Outstanding []string `json:"outstanding,omitempty"`
}

// Complete decides whether a repair is done (DBG-3, DBG-5, DBG-6).
func Complete(r Run, v Verification) (Completion, error) {
	if err := r.Validate(); err != nil {
		return Completion{}, err
	}

	var outstanding []string

	// DBG-5, and the word "original" is the requirement. A narrowed-down case is the natural end of
	// a debugging session and it is a different claim from the one the user made.
	if !r.Reproduction.SameAs(v.Reproduction) {
		outstanding = append(outstanding, fmt.Sprintf(
			"the verifier ran a different reproduction from the one recorded (%q, not %q)",
			describe(v.Reproduction), describe(r.Reproduction)))
	} else if v.ReproductionStillFails {
		outstanding = append(outstanding, "the original reproduction still fails")
	}

	// DBG-6. Checked separately from the result, because "we looked and found nothing" and "we did
	// not look" produce the same empty list.
	if !v.RegressionsChecked {
		outstanding = append(outstanding, "the verifier did not check for new regressions")
	}
	for _, f := range v.NewFailures {
		outstanding = append(outstanding, fmt.Sprintf("the repair broke %s", f))
	}

	// DBG-3. Instrumentation nobody decided about is what a run leaves behind when it ends by
	// getting the tests to pass.
	for _, i := range r.Instruments {
		if !i.Resolved() {
			outstanding = append(outstanding, fmt.Sprintf(
				"the instrumentation at %s was neither removed nor identified", i.Location))
		}
	}

	sort.Strings(outstanding)
	return Completion{Complete: len(outstanding) == 0, Outstanding: outstanding}, nil
}

func describe(r Reproduction) string {
	switch {
	case strings.TrimSpace(r.Command) != "":
		return r.Command
	case strings.TrimSpace(r.Environment) != "":
		return r.Environment
	}
	return "nothing"
}
