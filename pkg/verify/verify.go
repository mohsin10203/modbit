// Package verify decides whether a run's completion contract has been satisfied (VER-1..VER-6).
//
// Boundary: it decides what a set of verifier results means. It runs no verifier, executes no
// command, and drives no browser — a caller supplies results and this decides whether they add up
// to a completed run.
//
// Requirements: PRD §8.6 VER-1 (every Agent Profile defines a completion contract), VER-2 (evidence
// records revision, environment, command, timestamps, exit state, and relevant output), VER-3
// (browser verification artifacts), VER-4 (failures return control with bounded retries), VER-5
// (interactive takeover where supported), VER-6 (a verifier distinguishes not-run, inconclusive,
// failed, and passed).
//
// # Why four states and not two
//
// VER-6 asks for four because the three non-passing ones need different responses and collapsing
// them destroys that. A *failed* verifier found a problem: fix the code. An *inconclusive* one ran
// and could not decide: the check needs work, and treating it as a failure sends somebody hunting a
// bug that is not there. A *not-run* verifier did not execute at all: something in the wiring is
// broken, and it is the one that most looks like success, because a contract that iterates over
// results it never received finds nothing wrong with any of them.
//
// So NotRun is the zero value. A result nobody filled in is one that did not happen, which is both
// true and the answer that cannot be mistaken for a pass.
//
// # Retries are bounded and disclosed
//
// VER-4 permits bounded retries, and the boundary is what keeps a flaky verifier from becoming a
// pass by attrition. But bounding it is not enough on its own: a pass on the third attempt is a
// different fact from a pass on the first, and a contract that reports only the final state hides
// exactly the signal that would have caught the flakiness. So the attempt count travels with the
// verdict and Satisfied reports it.
package verify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
)

// State is VER-6's four-way verifier outcome.
type State string

const (
	// StateNotRun is the zero value: the verifier did not execute.
	//
	// The zero because it is the honest description of a result nobody filled in, and because it is
	// the one non-pass that most resembles success — a contract iterating over results it never
	// received finds nothing wrong with any of them.
	StateNotRun State = ""
	// StateInconclusive means the verifier ran and could not decide.
	StateInconclusive State = "inconclusive"
	// StateFailed means the verifier decided, against.
	StateFailed State = "failed"
	// StatePassed means the verifier decided, in favour. The only state that satisfies anything.
	StatePassed State = "passed"
)

// Valid reports whether s is one of the four.
func (s State) Valid() bool {
	switch s {
	case StateNotRun, StateInconclusive, StateFailed, StatePassed:
		return true
	}
	return false
}

// Ran reports whether the verifier executed. Only StateNotRun did not.
func (s State) Ran() bool { return s.Valid() && s != StateNotRun }

// Satisfies reports whether this state discharges a required verifier. Only StatePassed does.
func (s State) Satisfies() bool { return s == StatePassed }

// ExitState is how a verifier process ended.
//
// Separate from an exit code because a timed-out verifier and one that exited zero are not
// distinguishable by code alone — a killed process reports whatever the harness decided to say —
// and "it finished successfully" is the wrong reading of "we stopped waiting".
type ExitState string

const (
	// ExitUnknown is the zero value and is never admissible on a verifier that ran.
	ExitUnknown   ExitState = ""
	ExitExited    ExitState = "exited"
	ExitSignalled ExitState = "signalled"
	ExitTimedOut  ExitState = "timed_out"
)

// Valid reports whether e is a declared exit state.
func (e ExitState) Valid() bool {
	switch e {
	case ExitExited, ExitSignalled, ExitTimedOut:
		return true
	}
	return false
}

// ArtifactKind is a VER-3 browser-verification artifact.
type ArtifactKind string

const (
	ArtifactScreenshot ArtifactKind = "screenshot"
	ArtifactVideo      ArtifactKind = "video"
	ArtifactDOM        ArtifactKind = "dom_state"
	ArtifactConsoleLog ArtifactKind = "console_log"
	ArtifactNetworkLog ArtifactKind = "network_log"
)

// Artifact is a captured piece of VER-3 evidence, referenced rather than inlined.
type Artifact struct {
	Kind ArtifactKind `json:"kind"`
	// Ref locates the stored artifact. Content does not travel through this package.
	Ref string `json:"ref"`
}

// Evidence is VER-2's record of what a verifier actually did.
type Evidence struct {
	Revision    string    `json:"revision"`
	Environment string    `json:"environment"`
	Command     string    `json:"command"`
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at"`
	ExitState   ExitState `json:"exit_state"`
	ExitCode    int       `json:"exit_code"`
	// Output is the relevant output. Trimmed by the caller; this only requires that a verifier that
	// decided something can show what it decided from.
	Output    string     `json:"output"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

// Validate enforces VER-2.
func (e Evidence) Validate() error {
	switch {
	case strings.TrimSpace(e.Revision) == "":
		return field("verification evidence names no revision", "revision")
	case strings.TrimSpace(e.Environment) == "":
		return field("verification evidence names no environment", "environment")
	case strings.TrimSpace(e.Command) == "":
		return field("verification evidence names no command", "command")
	case e.StartedAt.IsZero() || e.EndedAt.IsZero():
		return field("verification evidence has no timestamps", "timestamps")
	case e.EndedAt.Before(e.StartedAt):
		return field("verification evidence ended before it started", "timestamps")
	case !e.ExitState.Valid():
		// A timed-out verifier and one that exited zero are not distinguishable by code alone, and
		// "it finished successfully" is the wrong reading of "we stopped waiting".
		return field("verification evidence has no exit state", "exit_state")
	}
	for _, a := range e.Artifacts {
		if strings.TrimSpace(a.Ref) == "" {
			return field(fmt.Sprintf("a %s artifact has no reference", a.Kind), "artifacts")
		}
	}
	return nil
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// Result is one verifier's outcome.
type Result struct {
	VerifierID string `json:"verifier_id"`
	State      State  `json:"state"`
	// Attempts is how many times the verifier ran to reach this state (VER-4). One for a first-try
	// result; zero only when it did not run.
	Attempts int `json:"attempts"`
	// Reason explains an inconclusive or not-run result. Required for both: "inconclusive" with no
	// reason is a shrug that a reader has to interpret, and it is the state most likely to be
	// skimmed past.
	Reason string `json:"reason,omitempty"`
	// Evidence is required of any verifier that ran (VER-2) and absent from one that did not.
	Evidence Evidence `json:"evidence"`
	// TakeoverSupported declares whether a user could have taken this session over (VER-5). It is
	// declared rather than inferred, so a verifier that does not support it says so instead of
	// looking like one nobody offered.
	TakeoverSupported bool `json:"takeover_supported"`
}

// Validate enforces VER-2, VER-4 and VER-6 on a single result.
func (r Result) Validate() error {
	if strings.TrimSpace(r.VerifierID) == "" {
		return field("a verifier result names no verifier", "verifier_id")
	}
	if !r.State.Valid() {
		return field(fmt.Sprintf("verifier %s reports the unrecognised state %q",
			r.VerifierID, r.State), "state")
	}
	if r.Attempts < 0 {
		return field(fmt.Sprintf("verifier %s reports a negative attempt count", r.VerifierID),
			"attempts")
	}

	if !r.State.Ran() {
		// A not-run verifier has no evidence, and manufacturing some would make the wiring bug it
		// represents indistinguishable from a real execution.
		if r.Attempts != 0 {
			return field(fmt.Sprintf(
				"verifier %s did not run but reports %d attempt(s)", r.VerifierID, r.Attempts),
				"attempts")
		}
		if strings.TrimSpace(r.Reason) == "" {
			return field(fmt.Sprintf(
				"verifier %s did not run and says why not; a silent absence looks like a pass to a reader "+
					"scanning for failures", r.VerifierID), "reason")
		}
		return nil
	}

	if r.Attempts < 1 {
		return field(fmt.Sprintf(
			"verifier %s reached %s in %d attempts", r.VerifierID, r.State, r.Attempts), "attempts")
	}
	if err := r.Evidence.Validate(); err != nil {
		return err
	}
	if r.State == StateInconclusive && strings.TrimSpace(r.Reason) == "" {
		// The same rule LCD-3 follows: an outcome short of the good one cannot be constructed
		// without an explanation, so no surface can render a shrug.
		return field(fmt.Sprintf(
			"verifier %s is inconclusive without saying why", r.VerifierID), "reason")
	}
	return nil
}

// Retried reports whether this result needed more than one attempt (VER-4).
func (r Result) Retried() bool { return r.Attempts > 1 }

// Contract is a Profile's completion contract (VER-1).
type Contract struct {
	ProfileID string `json:"profile_id"`
	// Required names the verifiers that must pass. A contract requiring nothing accepts anything,
	// which is not a contract.
	Required []string `json:"required"`
	// MaxAttempts bounds VER-4's retries per verifier. Zero selects DefaultMaxAttempts, because an
	// unbounded retry is how a flaky verifier becomes a pass by attrition.
	MaxAttempts int `json:"max_attempts"`
}

// DefaultMaxAttempts is the retry bound a contract gets when it states none.
const DefaultMaxAttempts = 3

// Validate enforces VER-1.
func (c Contract) Validate() error {
	switch {
	case strings.TrimSpace(c.ProfileID) == "":
		return field("a completion contract names no profile", "profile_id")
	case len(c.Required) == 0:
		return field(fmt.Sprintf(
			"profile %s requires no verifiers; a contract that requires nothing accepts anything",
			c.ProfileID), "required")
	case c.MaxAttempts < 0:
		return field(fmt.Sprintf("profile %s has a negative attempt bound", c.ProfileID),
			"max_attempts")
	}
	seen := map[string]bool{}
	for _, v := range c.Required {
		if strings.TrimSpace(v) == "" {
			return field(fmt.Sprintf("profile %s requires an unnamed verifier", c.ProfileID),
				"required")
		}
		if seen[v] {
			return field(fmt.Sprintf("profile %s requires %s twice", c.ProfileID, v), "required")
		}
		seen[v] = true
	}
	return nil
}

func (c Contract) attemptBound() int {
	if c.MaxAttempts == 0 {
		return DefaultMaxAttempts
	}
	return c.MaxAttempts
}

// Outcome is whether a contract was satisfied, and what stands in the way if not.
type Outcome struct {
	ProfileID string `json:"profile_id"`
	// Satisfied is true only when every required verifier passed. The zero value is false, so an
	// Outcome nobody computed does not report a completed run.
	Satisfied bool `json:"satisfied"`
	// Failed, Inconclusive and NotRun are reported separately rather than as one blocker list,
	// because they call for different responses: fix the code, fix the check, fix the wiring.
	Failed       []string `json:"failed,omitempty"`
	Inconclusive []string `json:"inconclusive,omitempty"`
	NotRun       []string `json:"not_run,omitempty"`
	// Retried names the verifiers that passed only after a retry (VER-4). A pass on the third
	// attempt is a different fact from a pass on the first, and reporting only the final state
	// hides the flakiness signal.
	Retried []string `json:"retried,omitempty"`
}

// Evaluate decides whether a contract is satisfied by a set of results (VER-1, VER-4, VER-6).
//
// A required verifier with no result at all is NotRun rather than absent. Iterating the results and
// checking the ones that arrived is the shape of this function that silently passes a run whose
// verifier never fired, so it iterates the contract instead.
func Evaluate(c Contract, results []Result) (Outcome, error) {
	if err := c.Validate(); err != nil {
		return Outcome{}, err
	}

	byID := make(map[string]Result, len(results))
	for _, r := range results {
		if err := r.Validate(); err != nil {
			return Outcome{}, err
		}
		if _, dup := byID[r.VerifierID]; dup {
			return Outcome{}, field(fmt.Sprintf(
				"verifier %s reported twice; which result stands would be decided by ordering",
				r.VerifierID), "verifier_id")
		}
		if r.Attempts > c.attemptBound() {
			// VER-4's bound. Exceeding it means the retry loop did not stop where the contract said,
			// and the result is not admissible evidence of anything.
			return Outcome{}, field(fmt.Sprintf(
				"verifier %s ran %d times against a bound of %d",
				r.VerifierID, r.Attempts, c.attemptBound()), "attempts")
		}
		byID[r.VerifierID] = r
	}

	out := Outcome{ProfileID: c.ProfileID}
	for _, id := range c.Required {
		r, reported := byID[id]
		if !reported {
			out.NotRun = append(out.NotRun, id)
			continue
		}
		switch r.State {
		case StatePassed:
			if r.Retried() {
				out.Retried = append(out.Retried, id)
			}
		case StateFailed:
			out.Failed = append(out.Failed, id)
		case StateInconclusive:
			out.Inconclusive = append(out.Inconclusive, id)
		default:
			out.NotRun = append(out.NotRun, id)
		}
	}
	sort.Strings(out.Failed)
	sort.Strings(out.Inconclusive)
	sort.Strings(out.NotRun)
	sort.Strings(out.Retried)

	out.Satisfied = len(out.Failed) == 0 && len(out.Inconclusive) == 0 && len(out.NotRun) == 0
	return out, nil
}

// Describe renders an outcome for a run summary.
//
// A satisfied outcome still names what was retried, because that is the part a reader would
// otherwise never see.
func (o Outcome) Describe() string {
	if o.Satisfied {
		if len(o.Retried) > 0 {
			return fmt.Sprintf("%s: satisfied, after retrying %s",
				o.ProfileID, strings.Join(o.Retried, ", "))
		}
		return o.ProfileID + ": satisfied"
	}
	var parts []string
	for label, ids := range map[string][]string{
		"failed": o.Failed, "inconclusive": o.Inconclusive, "not run": o.NotRun,
	} {
		if len(ids) > 0 {
			parts = append(parts, fmt.Sprintf("%s: %s", label, strings.Join(ids, ", ")))
		}
	}
	sort.Strings(parts)
	return o.ProfileID + ": not satisfied — " + strings.Join(parts, "; ")
}
