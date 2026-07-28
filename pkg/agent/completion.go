package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
)

// Completion invariants (P1–P7).
//
// VER-1 and VER-6. The contract is what decides whether a run may legitimately halt as `completed`,
// and the four verifier states exist because two would not be enough: a check that did not run and a
// check that ran and passed are the same shape to a caller that only records booleans, and that
// conflation is how unverified work ships as verified.
//
// One test each in completion_test.go. A test without a P-number, or a P-number without a test, is a
// gap.
//
//	P1 A verifier status is one of VER-6's four; the zero value is not_run, never passed.
//	P2 not_run and inconclusive never count as passed.
//	P3 A contract completes only when every required check passed.
//	P4 Evidence records revision, environment, command, timestamps, and exit state.
//	P5 Evidence output is bounded and its digest covers the whole.
//	P6 A required failure halts as failed; a required gap halts as inconclusive.
//	P7 Evidence from another revision does not satisfy a check.

// VerifierStatus is VER-6's closed set.
//
// P1. `not_run` is the zero value deliberately. A status field left unset must mean "nothing
// happened here", because the alternative — an unset field that reads as a pass — is the exact
// failure the four states exist to prevent.
type VerifierStatus string

const (
	// VerifierNotRun means the check never executed.
	VerifierNotRun VerifierStatus = ""
	// VerifierInconclusive means the check ran but could not decide. It is not a pass: the Modbit
	// agent rules require a failed runtime validation to be inconclusive unless evidence proves
	// mitigation, and the conformance suite makes the same distinction for adapters.
	VerifierInconclusive VerifierStatus = "inconclusive"
	// VerifierFailed means the check ran and the property does not hold.
	VerifierFailed VerifierStatus = "failed"
	// VerifierPassed means the check ran and the property holds.
	VerifierPassed VerifierStatus = "passed"
)

var verifierStatuses = map[VerifierStatus]bool{
	VerifierNotRun: true, VerifierInconclusive: true, VerifierFailed: true, VerifierPassed: true,
}

// Satisfies reports whether a status may be treated as a pass.
//
// P2. It is a method rather than a comparison at each call site because `== VerifierPassed` is easy
// to write and `!= VerifierFailed` is easier — and the second one silently accepts both not_run and
// inconclusive.
func (s VerifierStatus) Satisfies() bool { return s == VerifierPassed }

// MaxEvidenceBytes bounds recorded verifier output, for the reasons MaxOutputBytes is bounded.
const MaxEvidenceBytes = 16 << 10

// Evidence is the record of one verifier's execution (VER-2).
type Evidence struct {
	// Check names the contract check this evidence answers.
	Check  string         `json:"check"`
	Status VerifierStatus `json:"status"`
	// Revision is the tree state the check ran against. P7 compares it: evidence gathered before an
	// edit proves nothing about the tree after it.
	Revision string `json:"revision"`
	// Environment identifies where it ran — a worktree, a container image, a worker pool.
	Environment string `json:"environment"`
	// Command is what was executed, so a reader can reproduce it.
	Command   string    `json:"command"`
	StartedAt time.Time `json:"started_at"`
	// FinishedAt is required even for a failure: a check that timed out and one that returned
	// immediately are different findings.
	FinishedAt time.Time `json:"finished_at"`
	// ExitState is the verifier's own terminal signal, for example "exit 1" or "timeout".
	ExitState string `json:"exit_state"`
	// Output is the relevant output, truncated to MaxEvidenceBytes.
	Output    string `json:"output"`
	Truncated bool   `json:"truncated,omitempty"`
	// OutputDigest covers the whole output, so a truncated record still proves what was produced.
	OutputDigest string `json:"output_digest"`
}

// NewEvidence records a verifier execution, truncating output and digesting the whole.
//
// P4. Every VER-2 field is checked here rather than trusted, because evidence is the thing a
// completion claim rests on: evidence missing its revision cannot be matched to a tree, and evidence
// missing its command cannot be reproduced by the person asked to trust it.
func NewEvidence(check string, status VerifierStatus, revision, environment, command, exitState string, startedAt, finishedAt time.Time, output string) (Evidence, error) {
	bad := func(msg, field string) (Evidence, error) {
		return Evidence{}, modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", field)
	}
	if check == "" {
		return bad("evidence must name the check it answers", "check")
	}
	if !verifierStatuses[status] {
		return bad("evidence must carry one of the four verifier statuses", "status")
	}
	if revision == "" {
		return bad("evidence must record the revision it ran against", "revision")
	}
	if status != VerifierNotRun {
		// A check that ran must say where, what, and when. A check that did not run has none of
		// those to give, which is why the requirement is conditional rather than absolute.
		if environment == "" {
			return bad("evidence must record the environment it ran in", "environment")
		}
		if command == "" {
			return bad("evidence must record the command it executed", "command")
		}
		if startedAt.IsZero() || finishedAt.IsZero() {
			return bad("evidence must record when the check started and finished", "timestamps")
		}
		if finishedAt.Before(startedAt) {
			return bad("evidence cannot finish before it started", "timestamps")
		}
		if exitState == "" {
			return bad("evidence must record the verifier's exit state", "exit_state")
		}
	}

	e := Evidence{
		Check: check, Status: status, Revision: revision, Environment: environment,
		Command: command, StartedAt: startedAt, FinishedAt: finishedAt, ExitState: exitState,
	}
	// P5. The digest covers the whole output before truncation.
	sum := sha256.Sum256([]byte(output))
	e.OutputDigest = "sha256:" + hex.EncodeToString(sum[:])
	if len(output) > MaxEvidenceBytes {
		e.Output, e.Truncated = output[:MaxEvidenceBytes], true
	} else {
		e.Output = output
	}
	return e, nil
}

// Check is one requirement in a completion contract.
type Check struct {
	// Name is the stable identifier evidence refers to.
	Name        string `json:"name"`
	Description string `json:"description"`
	// Required marks a check that must pass before a run may complete. A non-required check is
	// reported but does not gate — useful for a signal being trialled before it is trusted.
	Required bool `json:"required"`
}

// Contract is an Agent Profile's completion contract (VER-1).
type Contract struct {
	// Profile names the Agent Profile this contract belongs to.
	Profile string  `json:"profile"`
	Checks  []Check `json:"checks"`
}

// NewContract validates a contract.
//
// A contract with no required checks is refused. VER-1 requires every profile to define one, and a
// contract that gates on nothing is indistinguishable from no verification while looking like
// governance — which is worse than admitting a profile is unverified.
func NewContract(profile string, checks ...Check) (Contract, error) {
	bad := func(msg, field string) (Contract, error) {
		return Contract{}, modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", field)
	}
	if profile == "" {
		return bad("a completion contract must name its agent profile", "profile")
	}
	if len(checks) == 0 {
		return bad("a completion contract must define at least one check", "checks")
	}
	seen := make(map[string]bool, len(checks))
	required := 0
	for _, c := range checks {
		if c.Name == "" {
			return bad("every check must be named", "checks")
		}
		if seen[c.Name] {
			return bad("check names must be unique within a contract", "checks")
		}
		seen[c.Name] = true
		if c.Required {
			required++
		}
	}
	if required == 0 {
		return bad("a completion contract must have at least one required check", "checks")
	}
	return Contract{Profile: profile, Checks: slices.Clone(checks)}, nil
}

// Outcome is a contract's verdict over a set of evidence.
type Outcome struct {
	// Halt is the run halt reason this outcome implies.
	Halt HaltReason `json:"halt"`
	// Passed, Failed, Inconclusive, and NotRun name the required checks in each state. A caller
	// reporting to a human needs the names, not just the count.
	Passed       []string `json:"passed,omitempty"`
	Failed       []string `json:"failed,omitempty"`
	Inconclusive []string `json:"inconclusive,omitempty"`
	NotRun       []string `json:"not_run,omitempty"`
	// StaleRevision names required checks whose evidence was gathered against another tree state.
	StaleRevision []string `json:"stale_revision,omitempty"`
	// Optional records the non-required checks and their statuses, for reporting.
	Optional map[string]VerifierStatus `json:"optional,omitempty"`
}

// Complete reports whether the contract was satisfied.
func (o Outcome) Complete() bool { return o.Halt == HaltCompleted }

// Evaluate decides a contract's outcome against evidence gathered at a revision.
//
// P3, P6. Completion requires every required check to have passed. A required failure halts as
// failed; a required check that did not run, was inconclusive, or was verified against another tree
// halts as inconclusive — a distinct outcome from failure, because the recovery differs: a failure
// needs the work fixed, a gap needs the check run.
func (c Contract) Evaluate(evidence []Evidence, revision string) (Outcome, error) {
	if revision == "" {
		return Outcome{}, modberr.New(modberr.CodeInvalidArgument,
			"evaluating a contract requires the revision it is being evaluated against").
			WithDetail("field", "revision")
	}

	byCheck := make(map[string]Evidence, len(evidence))
	for _, e := range evidence {
		// Later evidence for one check supersedes earlier: a re-run after a fix is the answer, not
		// an additional opinion.
		byCheck[e.Check] = e
	}

	out := Outcome{Optional: map[string]VerifierStatus{}}
	for _, check := range c.Checks {
		e, present := byCheck[check.Name]
		status := e.Status
		if !present {
			status = VerifierNotRun
		}

		if !check.Required {
			out.Optional[check.Name] = status
			continue
		}

		// P7. Evidence gathered before an edit proves nothing about the tree after it. This is
		// checked before the status, because a passing result from another revision is the most
		// convincing-looking way for stale evidence to slip through.
		if present && status != VerifierNotRun && e.Revision != revision {
			out.StaleRevision = append(out.StaleRevision, check.Name)
			continue
		}

		switch status {
		case VerifierPassed:
			out.Passed = append(out.Passed, check.Name)
		case VerifierFailed:
			out.Failed = append(out.Failed, check.Name)
		case VerifierInconclusive:
			out.Inconclusive = append(out.Inconclusive, check.Name)
		default:
			out.NotRun = append(out.NotRun, check.Name)
		}
	}

	switch {
	case len(out.Failed) > 0:
		out.Halt = HaltFailed
	case len(out.Inconclusive) > 0 || len(out.NotRun) > 0 || len(out.StaleRevision) > 0:
		// P2. Not a completion. A run that halted `completed` with a check that never ran would put
		// unverified work behind a word that means verified.
		out.Halt = HaltInconclusive
	default:
		out.Halt = HaltCompleted
	}
	return out, nil
}

// RequiredChecks returns the names of the checks that gate completion.
func (c Contract) RequiredChecks() []string {
	var out []string
	for _, check := range c.Checks {
		if check.Required {
			out = append(out, check.Name)
		}
	}
	return out
}
