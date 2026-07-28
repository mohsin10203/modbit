package agent_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/agent"
	"github.com/modbit/modbit/pkg/modberr"
)

const headRevision = "abc123"

func testContract(t *testing.T) agent.Contract {
	t.Helper()
	c, err := agent.NewContract("reviewer",
		agent.Check{Name: "tests", Description: "unit tests pass", Required: true},
		agent.Check{Name: "lint", Description: "linter is clean", Required: true},
		agent.Check{Name: "coverage", Description: "coverage did not drop", Required: false},
	)
	if err != nil {
		t.Fatalf("NewContract: %v", err)
	}
	return c
}

func evidenceFor(t *testing.T, check string, status agent.VerifierStatus, revision string) agent.Evidence {
	t.Helper()
	started := time.Unix(1700000000, 0).UTC()
	e, err := agent.NewEvidence(check, status, revision, "worktree:/repo", "go test ./...",
		"exit 0", started, started.Add(3*time.Second), "ok\tpkg/agent\t0.01s")
	if err != nil {
		t.Fatalf("NewEvidence(%s, %s): %v", check, status, err)
	}
	return e
}

// P1. `not_run` is the zero value deliberately: a status field left unset must mean "nothing
// happened here", because an unset field that reads as a pass is the failure the four states exist
// to prevent.
func TestSecurityTheZeroVerifierStatusIsNotAPass(t *testing.T) {
	var unset agent.VerifierStatus

	if unset != agent.VerifierNotRun {
		t.Fatalf("the zero status is %q, want not_run", unset)
	}
	if unset.Satisfies() {
		t.Fatal("an unset verifier status must never satisfy a check")
	}
	for _, status := range []agent.VerifierStatus{
		agent.VerifierNotRun, agent.VerifierInconclusive, agent.VerifierFailed,
	} {
		if status.Satisfies() {
			t.Fatalf("%q must not satisfy a check", status)
		}
	}
	if !agent.VerifierPassed.Satisfies() {
		t.Fatal("passed must satisfy a check")
	}
}

// P2. A run that halted `completed` with a check that never ran would put unverified work behind a
// word that means verified.
func TestSecurityNotRunAndInconclusiveNeverComplete(t *testing.T) {
	contract := testContract(t)

	cases := map[string][]agent.Evidence{
		"one check never ran": {
			evidenceFor(t, "tests", agent.VerifierPassed, headRevision),
		},
		"one check inconclusive": {
			evidenceFor(t, "tests", agent.VerifierPassed, headRevision),
			evidenceFor(t, "lint", agent.VerifierInconclusive, headRevision),
		},
		"nothing ran": {},
	}
	for name, evidence := range cases {
		t.Run(name, func(t *testing.T) {
			outcome, err := contract.Evaluate(evidence, headRevision)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if outcome.Complete() {
				t.Fatalf("contract reported complete: %+v", outcome)
			}
			if outcome.Halt != agent.HaltInconclusive {
				t.Fatalf("halt = %q, want inconclusive", outcome.Halt)
			}
		})
	}
}

// P3. Completion requires every required check to have passed — and only the required ones, so a
// non-required signal being trialled cannot block a run.
func TestCompletionRequiresEveryRequiredCheck(t *testing.T) {
	contract := testContract(t)

	outcome, err := contract.Evaluate([]agent.Evidence{
		evidenceFor(t, "tests", agent.VerifierPassed, headRevision),
		evidenceFor(t, "lint", agent.VerifierPassed, headRevision),
	}, headRevision)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !outcome.Complete() || outcome.Halt != agent.HaltCompleted {
		t.Fatalf("outcome = %+v, want completed", outcome)
	}
	if len(outcome.Passed) != 2 {
		t.Fatalf("passed = %v, want both required checks", outcome.Passed)
	}
	// The optional check never ran and must not gate.
	if got := outcome.Optional["coverage"]; got != agent.VerifierNotRun {
		t.Fatalf("optional coverage = %q, want not_run", got)
	}

	// An optional check that outright failed still must not gate: that is what "not required" means,
	// and a caller that wants it to gate should mark it required.
	outcome, err = contract.Evaluate([]agent.Evidence{
		evidenceFor(t, "tests", agent.VerifierPassed, headRevision),
		evidenceFor(t, "lint", agent.VerifierPassed, headRevision),
		evidenceFor(t, "coverage", agent.VerifierFailed, headRevision),
	}, headRevision)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !outcome.Complete() {
		t.Fatalf("an optional failure blocked completion: %+v", outcome)
	}
	if outcome.Optional["coverage"] != agent.VerifierFailed {
		t.Fatal("the optional failure was not reported")
	}
}

// P4. Evidence is what a completion claim rests on: without its revision it cannot be matched to a
// tree, and without its command it cannot be reproduced by the person asked to trust it.
func TestEvidenceRecordsEverythingVER2Requires(t *testing.T) {
	started := time.Unix(1700000000, 0).UTC()
	e, err := agent.NewEvidence("tests", agent.VerifierPassed, headRevision, "worktree:/repo",
		"go test ./...", "exit 0", started, started.Add(time.Second), "ok")
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	for name, got := range map[string]string{
		"revision": e.Revision, "environment": e.Environment, "command": e.Command,
		"exit state": e.ExitState, "digest": e.OutputDigest,
	} {
		if got == "" {
			t.Errorf("evidence records no %s", name)
		}
	}
	if e.StartedAt.IsZero() || e.FinishedAt.IsZero() {
		t.Error("evidence records no timestamps")
	}

	missing := map[string]func() (agent.Evidence, error){
		"no check": func() (agent.Evidence, error) {
			return agent.NewEvidence("", agent.VerifierPassed, headRevision, "e", "c", "x", started, started, "")
		},
		"no revision": func() (agent.Evidence, error) {
			return agent.NewEvidence("tests", agent.VerifierPassed, "", "e", "c", "x", started, started, "")
		},
		"no environment": func() (agent.Evidence, error) {
			return agent.NewEvidence("tests", agent.VerifierPassed, headRevision, "", "c", "x", started, started, "")
		},
		"no command": func() (agent.Evidence, error) {
			return agent.NewEvidence("tests", agent.VerifierPassed, headRevision, "e", "", "x", started, started, "")
		},
		"no exit state": func() (agent.Evidence, error) {
			return agent.NewEvidence("tests", agent.VerifierPassed, headRevision, "e", "c", "", started, started, "")
		},
		"no timestamps": func() (agent.Evidence, error) {
			return agent.NewEvidence("tests", agent.VerifierPassed, headRevision, "e", "c", "x", time.Time{}, time.Time{}, "")
		},
		"finished before started": func() (agent.Evidence, error) {
			return agent.NewEvidence("tests", agent.VerifierPassed, headRevision, "e", "c", "x", started, started.Add(-time.Second), "")
		},
		"unknown status": func() (agent.Evidence, error) {
			return agent.NewEvidence("tests", agent.VerifierStatus("probably"), headRevision, "e", "c", "x", started, started, "")
		},
	}
	for name, build := range missing {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); !modberr.Is(err, modberr.CodeInvalidArgument) {
				t.Fatalf("error = %v, want a refusal", err)
			}
		})
	}

	// A check that did not run has no environment, command, or timing to give, so the requirement is
	// conditional rather than absolute.
	if _, err := agent.NewEvidence("tests", agent.VerifierNotRun, headRevision, "", "", "", time.Time{}, time.Time{}, ""); err != nil {
		t.Fatalf("not-run evidence must be recordable without execution details: %v", err)
	}
}

// P5. A digest over the truncated part would make the record prove only what happened to fit.
func TestEvidenceOutputIsBoundedAndDigestsTheWhole(t *testing.T) {
	body := strings.Repeat("y", agent.MaxEvidenceBytes*2)
	started := time.Unix(1700000000, 0).UTC()

	e, err := agent.NewEvidence("tests", agent.VerifierFailed, headRevision, "worktree:/repo",
		"go test ./...", "exit 1", started, started.Add(time.Second), body)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if !e.Truncated {
		t.Fatal("oversized output was not marked truncated")
	}
	if len(e.Output) != agent.MaxEvidenceBytes {
		t.Fatalf("output = %d bytes, want %d", len(e.Output), agent.MaxEvidenceBytes)
	}
	whole := sha256.Sum256([]byte(body))
	if e.OutputDigest != "sha256:"+hex.EncodeToString(whole[:]) {
		t.Fatal("the digest does not cover the whole output")
	}
}

// P6. A failure needs the work fixed; a gap needs the check run. Collapsing them would send a run
// down the wrong recovery path.
func TestFailureAndGapAreDistinctOutcomes(t *testing.T) {
	contract := testContract(t)

	failed, err := contract.Evaluate([]agent.Evidence{
		evidenceFor(t, "tests", agent.VerifierFailed, headRevision),
		evidenceFor(t, "lint", agent.VerifierPassed, headRevision),
	}, headRevision)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if failed.Halt != agent.HaltFailed {
		t.Fatalf("halt = %q, want failed", failed.Halt)
	}
	if len(failed.Failed) != 1 || failed.Failed[0] != "tests" {
		t.Fatalf("failed = %v, want [tests]", failed.Failed)
	}

	gap, err := contract.Evaluate([]agent.Evidence{
		evidenceFor(t, "tests", agent.VerifierInconclusive, headRevision),
		evidenceFor(t, "lint", agent.VerifierPassed, headRevision),
	}, headRevision)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if gap.Halt != agent.HaltInconclusive {
		t.Fatalf("halt = %q, want inconclusive", gap.Halt)
	}

	// A failure outranks a gap: if anything is known to be broken, that is the finding to report.
	both, err := contract.Evaluate([]agent.Evidence{
		evidenceFor(t, "tests", agent.VerifierFailed, headRevision),
		evidenceFor(t, "lint", agent.VerifierInconclusive, headRevision),
	}, headRevision)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if both.Halt != agent.HaltFailed {
		t.Fatalf("halt = %q, want failed to outrank inconclusive", both.Halt)
	}
}

// P7. Evidence gathered before an edit proves nothing about the tree after it, and a *passing*
// result from another revision is the most convincing-looking way for stale evidence to slip through.
func TestSecurityStaleEvidenceDoesNotSatisfyACheck(t *testing.T) {
	contract := testContract(t)

	outcome, err := contract.Evaluate([]agent.Evidence{
		evidenceFor(t, "tests", agent.VerifierPassed, "an-older-commit"),
		evidenceFor(t, "lint", agent.VerifierPassed, headRevision),
	}, headRevision)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if outcome.Complete() {
		t.Fatalf("stale evidence completed the contract: %+v", outcome)
	}
	if outcome.Halt != agent.HaltInconclusive {
		t.Fatalf("halt = %q, want inconclusive", outcome.Halt)
	}
	if len(outcome.StaleRevision) != 1 || outcome.StaleRevision[0] != "tests" {
		t.Fatalf("stale = %v, want [tests]", outcome.StaleRevision)
	}
	// It must not be miscounted as passed, which is what a revision check applied after the status
	// switch would produce.
	for _, name := range outcome.Passed {
		if name == "tests" {
			t.Fatal("stale evidence was counted as a pass")
		}
	}

	// Re-running at the current revision resolves it, so the refusal is staleness detection rather
	// than the check being unsatisfiable.
	outcome, err = contract.Evaluate([]agent.Evidence{
		evidenceFor(t, "tests", agent.VerifierPassed, "an-older-commit"),
		evidenceFor(t, "tests", agent.VerifierPassed, headRevision),
		evidenceFor(t, "lint", agent.VerifierPassed, headRevision),
	}, headRevision)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !outcome.Complete() {
		t.Fatalf("re-running at the current revision did not resolve staleness: %+v", outcome)
	}
}

// Later evidence for one check supersedes earlier: a re-run after a fix is the answer, not an
// additional opinion.
func TestLaterEvidenceSupersedesEarlier(t *testing.T) {
	contract := testContract(t)

	outcome, err := contract.Evaluate([]agent.Evidence{
		evidenceFor(t, "tests", agent.VerifierFailed, headRevision),
		evidenceFor(t, "tests", agent.VerifierPassed, headRevision),
		evidenceFor(t, "lint", agent.VerifierPassed, headRevision),
	}, headRevision)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !outcome.Complete() {
		t.Fatalf("a passing re-run did not supersede the earlier failure: %+v", outcome)
	}
}

// A contract that gates on nothing is indistinguishable from no verification while looking like
// governance, which is worse than admitting a profile is unverified.
func TestNewContractRefusesAContractThatGatesNothing(t *testing.T) {
	if _, err := agent.NewContract(""); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal with no profile", err)
	}
	if _, err := agent.NewContract("reviewer"); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal with no checks", err)
	}
	if _, err := agent.NewContract("reviewer",
		agent.Check{Name: "coverage", Required: false},
	); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal for a contract with no required check", err)
	}
	if _, err := agent.NewContract("reviewer",
		agent.Check{Name: "", Required: true},
	); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal for an unnamed check", err)
	}
	if _, err := agent.NewContract("reviewer",
		agent.Check{Name: "tests", Required: true},
		agent.Check{Name: "tests", Required: true},
	); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal for duplicate check names", err)
	}

	c := testContract(t)
	if got := c.RequiredChecks(); len(got) != 2 {
		t.Fatalf("required checks = %v, want two", got)
	}
	if _, err := c.Evaluate(nil, ""); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal when no revision is supplied", err)
	}
}
