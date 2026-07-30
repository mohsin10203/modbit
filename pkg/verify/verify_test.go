package verify_test

import (
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/verify"
)

// VER invariants (V1–V9). One test each; a test without a V-number, or a V-number without a test,
// is a gap.
//
//	V1 VER-6: four states, the zero is not-run, and only passed satisfies.
//	V2 VER-6: not-run, inconclusive and failed are reported separately, not as one blocker list.
//	V3 VER-1: a contract requiring nothing is refused.
//	V4 VER-2: a verifier that ran carries all of the evidence; one that did not carries none.
//	V5 A required verifier with no result at all is not-run, not absent.
//	V6 VER-4: attempts beyond the contract's bound are inadmissible.
//	V7 VER-4: a pass that needed a retry is disclosed even on a satisfied outcome.
//	V8 An inconclusive or not-run result must say why.
//	V9 VER-5: takeover support is declared per verifier rather than inferred.

func evidence() verify.Evidence {
	start := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	return verify.Evidence{
		Revision: "abc123", Environment: "sha256:beef", Command: "go test ./...",
		StartedAt: start, EndedAt: start.Add(30 * time.Second),
		ExitState: verify.ExitExited, ExitCode: 0, Output: "ok",
	}
}

func passed(id string) verify.Result {
	return verify.Result{
		VerifierID: id, State: verify.StatePassed, Attempts: 1,
		Evidence: evidence(), TakeoverSupported: false,
	}
}

func contract() verify.Contract {
	return verify.Contract{
		ProfileID: "backend", Required: []string{"unit", "typecheck"}, MaxAttempts: 3,
	}
}

// V1. VER-6's four states, and only one of them satisfies.
//
// NotRun is the zero because it is the honest description of a result nobody filled in, and because
// it is the non-pass that most resembles success.
func TestSecurityOnlyAPassSatisfiesAndTheZeroStateIsNotRun(t *testing.T) {
	var zero verify.State
	if zero != verify.StateNotRun {
		t.Fatalf("the zero State is %q, want not-run", zero)
	}
	if zero.Satisfies() {
		t.Fatal("the zero State satisfies a required verifier")
	}
	if zero.Ran() {
		t.Fatal("the zero State reports that the verifier ran")
	}

	for _, s := range []verify.State{
		verify.StateNotRun, verify.StateInconclusive, verify.StateFailed,
	} {
		if s.Satisfies() {
			t.Errorf("%q satisfies a required verifier", s)
		}
	}
	if !verify.StatePassed.Satisfies() {
		t.Fatal("passed does not satisfy")
	}
	if !verify.StateInconclusive.Ran() || !verify.StateFailed.Ran() {
		t.Fatal("a verifier that decided is reported as not having run")
	}
	if verify.State("green").Valid() {
		t.Fatal("an invented state reports itself valid")
	}
}

// V2. The three non-passes are reported separately, because they call for different responses:
// fix the code, fix the check, fix the wiring.
//
// Collapsing them is what makes a broken verifier look like a failing build, which then gets
// "fixed" by retrying it.
func TestSecurityTheThreeNonPassesAreNotCollapsed(t *testing.T) {
	c := verify.Contract{
		ProfileID: "backend",
		Required:  []string{"unit", "lint", "browser", "typecheck"},
	}
	results := []verify.Result{
		passed("unit"),
		{VerifierID: "lint", State: verify.StateFailed, Attempts: 1, Evidence: evidence()},
		{
			VerifierID: "browser", State: verify.StateInconclusive, Attempts: 1,
			Evidence: evidence(), Reason: "the page never reached a stable state",
		},
		// typecheck reports nothing at all.
	}

	got, err := verify.Evaluate(c, results)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Satisfied {
		t.Fatal("a contract with a failure, an inconclusive and a missing verifier was satisfied")
	}
	if len(got.Failed) != 1 || got.Failed[0] != "lint" {
		t.Errorf("failed = %v, want [lint]", got.Failed)
	}
	if len(got.Inconclusive) != 1 || got.Inconclusive[0] != "browser" {
		t.Errorf("inconclusive = %v, want [browser]", got.Inconclusive)
	}
	if len(got.NotRun) != 1 || got.NotRun[0] != "typecheck" {
		t.Errorf("not run = %v, want [typecheck]", got.NotRun)
	}

	// Each of the three must block *on its own*. Asserting against a mixture only shows that the
	// three together block, which any one of the checks would achieve — the error that let a mutant
	// removing the inconclusive check survive the first version of this test.
	for _, blocker := range []verify.Result{
		{VerifierID: "typecheck", State: verify.StateFailed, Attempts: 1, Evidence: evidence()},
		{
			VerifierID: "typecheck", State: verify.StateInconclusive, Attempts: 1,
			Evidence: evidence(), Reason: "the type server never answered",
		},
		{VerifierID: "typecheck", State: verify.StateNotRun, Reason: "no toolchain"},
	} {
		alone, err := verify.Evaluate(contract(), []verify.Result{passed("unit"), blocker})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if alone.Satisfied {
			t.Errorf("a contract was satisfied with one verifier %s and nothing else wrong", blocker.State)
		}
	}

	// The rendering keeps them apart too, so a reader of the summary sees the distinction.
	desc := got.Describe()
	for _, want := range []string{"failed: lint", "inconclusive: browser", "not run: typecheck"} {
		if !strings.Contains(desc, want) {
			t.Errorf("describe = %q, missing %q", desc, want)
		}
	}
}

// V3. VER-1: a contract that requires nothing accepts anything.
func TestSecurityAContractRequiringNothingIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*verify.Contract){
		"no verifiers":       func(c *verify.Contract) { c.Required = nil },
		"empty list":         func(c *verify.Contract) { c.Required = []string{} },
		"unnamed verifier":   func(c *verify.Contract) { c.Required = []string{"unit", " "} },
		"duplicate verifier": func(c *verify.Contract) { c.Required = []string{"unit", "unit"} },
		"no profile":         func(c *verify.Contract) { c.ProfileID = "" },
		"negative bound":     func(c *verify.Contract) { c.MaxAttempts = -1 },
	} {
		c := contract()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: an empty contract validated", name)
		}
		if _, err := verify.Evaluate(c, nil); err == nil {
			t.Errorf("%s: an empty contract was evaluated", name)
		}
	}
	if err := contract().Validate(); err != nil {
		t.Fatalf("a real contract was refused: %v", err)
	}
}

// V4. VER-2: a verifier that decided something can show what it decided from.
//
// Each field independently, because a single witness passes an implementation checking only one.
func TestSecurityAVerifierThatRanMustCarryItsEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*verify.Evidence){
		"no revision":    func(e *verify.Evidence) { e.Revision = "" },
		"no environment": func(e *verify.Evidence) { e.Environment = " " },
		"no command":     func(e *verify.Evidence) { e.Command = "" },
		"no start":       func(e *verify.Evidence) { e.StartedAt = time.Time{} },
		"no end":         func(e *verify.Evidence) { e.EndedAt = time.Time{} },
		"ends first":     func(e *verify.Evidence) { e.EndedAt = e.StartedAt.Add(-time.Second) },
		"no exit state":  func(e *verify.Evidence) { e.ExitState = verify.ExitUnknown },
		"bad exit state": func(e *verify.Evidence) { e.ExitState = "fine" },
		"artifact without a ref": func(e *verify.Evidence) {
			e.Artifacts = []verify.Artifact{{Kind: verify.ArtifactScreenshot}}
		},
	} {
		ev := evidence()
		mutate(&ev)
		if err := ev.Validate(); err == nil {
			t.Errorf("%s: incomplete evidence validated", name)
		}
		r := passed("unit")
		r.Evidence = ev
		if err := r.Validate(); err == nil {
			t.Errorf("%s: a result with incomplete evidence validated", name)
		}
	}
	if err := evidence().Validate(); err != nil {
		t.Fatalf("complete evidence was refused: %v", err)
	}

	// A timed-out verifier is distinguishable from one that exited, whatever the code says.
	timedOut := evidence()
	timedOut.ExitState = verify.ExitTimedOut
	timedOut.ExitCode = 0
	if err := timedOut.Validate(); err != nil {
		t.Fatalf("a timed-out verifier's evidence was refused: %v", err)
	}
	if timedOut.ExitState == verify.ExitExited {
		t.Fatal("a timed-out verifier is indistinguishable from one that exited")
	}

	// A not-run verifier has no evidence, and manufacturing some would hide the wiring bug.
	notRun := verify.Result{
		VerifierID: "browser", State: verify.StateNotRun, Reason: "no browser worker was available",
	}
	if err := notRun.Validate(); err != nil {
		t.Fatalf("a properly declared not-run result was refused: %v", err)
	}
	notRun.Attempts = 1
	if err := notRun.Validate(); err == nil {
		t.Fatal("a verifier that did not run reported an attempt")
	}
}

// V5. A required verifier that reported nothing is not-run, not absent.
//
// Iterating the results and checking the ones that arrived is the shape of this function that
// silently passes a run whose verifier never fired.
func TestSecurityAVerifierThatReportedNothingIsNotRunRatherThanAbsent(t *testing.T) {
	got, err := verify.Evaluate(contract(), []verify.Result{passed("unit")})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Satisfied {
		t.Fatal("a contract was satisfied while one of its required verifiers never reported")
	}
	if len(got.NotRun) != 1 || got.NotRun[0] != "typecheck" {
		t.Fatalf("not run = %v, want [typecheck]", got.NotRun)
	}

	// A result for a verifier the contract does not require neither satisfies nor blocks it.
	extra, err := verify.Evaluate(contract(), []verify.Result{
		passed("unit"), passed("typecheck"), passed("something-else"),
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !extra.Satisfied {
		t.Fatalf("a fully passing contract was not satisfied: %s", extra.Describe())
	}

	// The same verifier reported twice is refused rather than resolved by ordering.
	if _, err := verify.Evaluate(contract(), []verify.Result{
		passed("unit"), passed("unit"), passed("typecheck"),
	}); err == nil {
		t.Fatal("a verifier reporting twice was accepted")
	}
}

// V6. VER-4: the retry bound is enforced.
//
// An unbounded retry is how a flaky verifier becomes a pass by attrition.
func TestSecurityAttemptsBeyondTheBoundAreInadmissible(t *testing.T) {
	c := contract()
	c.MaxAttempts = 2

	over := passed("unit")
	over.Attempts = 3
	if _, err := verify.Evaluate(c, []verify.Result{over, passed("typecheck")}); err == nil {
		t.Fatal("a verifier that ran past the contract's bound was accepted")
	}

	at := passed("unit")
	at.Attempts = 2
	if _, err := verify.Evaluate(c, []verify.Result{at, passed("typecheck")}); err != nil {
		t.Fatalf("a verifier at the bound was refused: %v", err)
	}

	// A contract stating no bound gets the default rather than an unbounded one.
	unstated := verify.Contract{ProfileID: "backend", Required: []string{"unit"}}
	beyondDefault := passed("unit")
	beyondDefault.Attempts = verify.DefaultMaxAttempts + 1
	if _, err := verify.Evaluate(unstated, []verify.Result{beyondDefault}); err == nil {
		t.Fatalf("a contract stating no bound accepted %d attempts", beyondDefault.Attempts)
	}

	// A verifier that ran must say it ran at least once.
	zeroAttempts := passed("unit")
	zeroAttempts.Attempts = 0
	if err := zeroAttempts.Validate(); err == nil {
		t.Fatal("a passing verifier reported zero attempts")
	}
}

// V7. VER-4: a pass that needed a retry is disclosed even when the contract is satisfied.
//
// A pass on the third attempt is a different fact from a pass on the first, and reporting only the
// final state hides exactly the signal that would have caught the flakiness.
func TestSecurityARetriedPassIsDisclosedOnASatisfiedOutcome(t *testing.T) {
	flaky := passed("unit")
	flaky.Attempts = 3

	got, err := verify.Evaluate(contract(), []verify.Result{flaky, passed("typecheck")})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !got.Satisfied {
		t.Fatalf("a contract whose verifiers all passed was not satisfied: %s", got.Describe())
	}
	if len(got.Retried) != 1 || got.Retried[0] != "unit" {
		t.Fatalf("retried = %v, want [unit]", got.Retried)
	}
	if !strings.Contains(got.Describe(), "unit") {
		t.Fatalf("describe = %q; a satisfied outcome must still name what was retried", got.Describe())
	}
	// The boundary is at two, not three. Testing only one and three leaves an off-by-one free.
	for attempts, want := range map[int]bool{1: false, 2: true, 3: true} {
		r := passed("unit")
		r.Attempts = attempts
		if got := r.Retried(); got != want {
			t.Errorf("%d attempt(s): retried = %v, want %v", attempts, got, want)
		}
	}
	twice := passed("unit")
	twice.Attempts = 2
	second, err := verify.Evaluate(contract(), []verify.Result{twice, passed("typecheck")})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(second.Retried) != 1 || second.Retried[0] != "unit" {
		t.Fatalf("retried = %v on a second-attempt pass, want [unit]", second.Retried)
	}

	// A clean outcome says so without inventing a retry list.
	clean, err := verify.Evaluate(contract(), []verify.Result{passed("unit"), passed("typecheck")})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(clean.Retried) != 0 {
		t.Fatalf("retried = %v on a first-attempt run", clean.Retried)
	}
	if clean.Describe() != "backend: satisfied" {
		t.Fatalf("describe = %q", clean.Describe())
	}
}

// V8. An inconclusive or not-run result must say why.
//
// The same rule LCD-3 follows: an outcome short of the good one cannot be constructed without an
// explanation, so no surface can render a shrug. Inconclusive is the state most likely to be
// skimmed past, which is why it is the one that must carry its reason.
func TestSecurityAnInconclusiveOrNotRunResultMustSayWhy(t *testing.T) {
	silent := verify.Result{
		VerifierID: "browser", State: verify.StateInconclusive, Attempts: 1, Evidence: evidence(),
	}
	if err := silent.Validate(); err == nil {
		t.Fatal("an inconclusive result with no reason validated")
	}
	silent.Reason = "the page never reached a stable state"
	if err := silent.Validate(); err != nil {
		t.Fatalf("an explained inconclusive result was refused: %v", err)
	}

	quiet := verify.Result{VerifierID: "browser", State: verify.StateNotRun}
	if err := quiet.Validate(); err == nil {
		t.Fatal("a not-run result with no reason validated")
	}

	// A failure needs no separate reason: its evidence is the reason, and requiring prose as well
	// would make the field a formality that gets filled with the verifier's name.
	failure := verify.Result{
		VerifierID: "lint", State: verify.StateFailed, Attempts: 1, Evidence: evidence(),
	}
	if err := failure.Validate(); err != nil {
		t.Fatalf("a failure carrying evidence was refused for having no prose reason: %v", err)
	}
}

// V9. VER-5: takeover support is declared per verifier rather than inferred.
//
// "Where supported" is only meaningful if the unsupported case is stated. A verifier that does not
// support takeover and one nobody thought about look identical otherwise.
func TestTakeoverSupportIsDeclaredPerVerifier(t *testing.T) {
	interactive := passed("browser")
	interactive.TakeoverSupported = true
	if err := interactive.Validate(); err != nil {
		t.Fatalf("an interactive verifier was refused: %v", err)
	}

	batch := passed("unit")
	if batch.TakeoverSupported {
		t.Fatal("a batch verifier defaulted to claiming takeover support")
	}
	if err := batch.Validate(); err != nil {
		t.Fatalf("a non-interactive verifier was refused: %v", err)
	}

	// The two are distinguishable, which is the whole point of declaring it.
	if interactive.TakeoverSupported == batch.TakeoverSupported {
		t.Fatal("takeover support does not distinguish the two verifiers")
	}
}
