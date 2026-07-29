package sandbox_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/sandbox"
	"github.com/modbit/modbit/pkg/sandbox/conformance"
)

func testSpec(t *testing.T, workspace string) sandbox.Spec {
	t.Helper()
	return sandbox.Spec{RunID: id.MustNew(id.Run), Workspace: workspace}
}

func processCaps() sandbox.Capabilities { return sandbox.NewProcessBackend().Capabilities() }

// X1, X2. SBX-3: a backend must not report a policy as enforced when it is advisory. The zero
// Enforcement is unsupported, so a control omitted from a capability map reads as "not enforced" —
// the only safe reading of no answer, and the same trap as taint's zero class and the zero verifier
// status.
func TestSecurityUnsupportedIsTheZeroEnforcement(t *testing.T) {
	var unset sandbox.Enforcement
	if unset != sandbox.EnforcementUnsupported {
		t.Fatalf("zero enforcement = %q, want unsupported", unset)
	}
	if unset.Enforces() {
		t.Fatal("an unset enforcement level must never count as enforced")
	}
	if sandbox.EnforcementAdvisory.Enforces() {
		t.Fatal("advisory must never count as enforced; that is exactly what SBX-3 forbids")
	}
	if !sandbox.EnforcementEnforced.Enforces() {
		t.Fatal("enforced must count as enforced")
	}

	// A control the backend never mentions reads as unsupported rather than as an unknown.
	caps := sandbox.Capabilities{ContractVersion: sandbox.ContractVersion, Controls: map[sandbox.Control]sandbox.Enforcement{}}
	for _, control := range sandbox.Controls() {
		if caps.Enforcement(control).Enforces() {
			t.Fatalf("%s reads as enforced in an empty capability map", control)
		}
	}
}

// X2. The reference backend must not claim what it cannot do. Go offers no portable way to confine a
// child's filesystem access or deny its egress, so claiming either would be the SBX-3 violation this
// backend exists to demonstrate against.
func TestSecurityProcessBackendDoesNotOverclaim(t *testing.T) {
	caps := processCaps()

	for _, control := range []sandbox.Control{
		sandbox.ControlFilesystemScope, sandbox.ControlNetworkDeny,
		sandbox.ControlCPULimit, sandbox.ControlMemoryLimit,
		sandbox.ControlProcessLimit, sandbox.ControlDiskLimit,
		sandbox.ControlProcessConfinement,
	} {
		if caps.Enforcement(control).Enforces() {
			t.Errorf("the process backend claims to enforce %s, which it cannot", control)
		}
	}
	// It does genuinely provide these, and must say so, or a run that needs only these would be
	// refused for no reason.
	for _, control := range []sandbox.Control{
		sandbox.ControlWallClockLimit, sandbox.ControlHookSuppression,
	} {
		if !caps.Enforcement(control).Enforces() {
			t.Errorf("the process backend should enforce %s", control)
		}
	}
	if caps.Strength != sandbox.StrengthProcess {
		t.Fatalf("strength = %v, want process", caps.Strength)
	}
}

// X3. SBX-6: if a mandatory control cannot be established, execution fails closed.
func TestSecurityARequiredControlFailsClosed(t *testing.T) {
	backend := sandbox.NewProcessBackend()
	dir := t.TempDir()

	spec := testSpec(t, dir)
	spec.Required = []sandbox.Control{sandbox.ControlNetworkDeny}

	if _, err := backend.Establish(context.Background(), spec); !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("error = %v, want a policy denial", err)
	}

	// Advisory is not enough either: accepting it here would make SBX-3's distinction decorative at
	// the only place it decides anything.
	spec.Required = []sandbox.Control{sandbox.ControlFilesystemScope}
	if _, err := backend.Establish(context.Background(), spec); !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("error = %v; an advisory control must not satisfy a requirement", err)
	}

	// A requirement the backend does meet establishes cleanly, so the refusals above are the gate
	// working rather than establishment being broken.
	spec.Required = []sandbox.Control{sandbox.ControlWallClockLimit, sandbox.ControlHookSuppression}
	session, err := backend.Establish(context.Background(), spec)
	if err != nil {
		t.Fatalf("a satisfiable requirement was refused: %v", err)
	}
	defer func() { _ = backend.Cleanup(context.Background(), session) }()
	if session.Degraded {
		t.Fatal("a fully satisfied spec must not be marked degraded")
	}
}

// X4. SBX-6 permits degraded isolation only where a documented policy explicitly says so. A boolean
// with no rationale is a switch somebody flips during an incident with nothing to show afterwards.
func TestSecurityDegradedIsolationRequiresARecordedRationale(t *testing.T) {
	backend := sandbox.NewProcessBackend()
	dir := t.TempDir()

	spec := testSpec(t, dir)
	spec.Required = []sandbox.Control{sandbox.ControlNetworkDeny}
	spec.AllowDegraded = true

	if _, err := backend.Establish(context.Background(), spec); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal when no rationale is given", err)
	}

	spec.Rationale = "local Ask run; no repository code is executed"
	session, err := backend.Establish(context.Background(), spec)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer func() { _ = backend.Cleanup(context.Background(), session) }()

	if !session.Degraded {
		t.Fatal("a session established without a required control must be marked degraded")
	}
	if session.Rationale != spec.Rationale {
		t.Fatalf("rationale = %q, want it recorded on the session", session.Rationale)
	}
	if len(session.Unmet) != 1 || session.Unmet[0] != sandbox.ControlNetworkDeny {
		t.Fatalf("unmet = %v, want the control that was not enforced", session.Unmet)
	}
	// The session records what is actually enforced, not what was asked for.
	if len(session.Enforced) == 0 {
		t.Fatal("the session records no enforced controls")
	}
	for _, control := range session.Enforced {
		if control == sandbox.ControlNetworkDeny {
			t.Fatal("an unmet control was listed as enforced")
		}
	}
}

// X5. A backend built against another contract may not understand a control it was asked for, and a
// silent mismatch would look like enforcement.
func TestAContractVersionMismatchIsRefused(t *testing.T) {
	caps := processCaps()
	caps.ContractVersion = sandbox.ContractVersion + 1

	_, err := sandbox.Check(caps, sandbox.Spec{RunID: id.MustNew(id.Run), Workspace: "/tmp"})
	if !modberr.Is(err, modberr.CodeUnsupportedVersion) {
		t.Fatalf("error = %v, want an unsupported-version refusal", err)
	}
}

// X6. SBX-4: a high-risk profile may require a minimum isolation strength, so "at least a container"
// has to be expressible as a comparison.
func TestSecurityAProfileCanRequireAMinimumStrength(t *testing.T) {
	caps := processCaps()

	for _, minimum := range []sandbox.Strength{sandbox.StrengthContainer, sandbox.StrengthMicroVM} {
		_, err := sandbox.Check(caps, sandbox.Spec{
			RunID: id.MustNew(id.Run), Workspace: "/tmp", MinimumStrength: minimum,
		})
		if !modberr.Is(err, modberr.CodePolicyDenied) {
			t.Fatalf("a process backend satisfied a %s minimum: %v", minimum, err)
		}
	}

	// AllowDegraded must not bypass a strength floor: strength is what a high-risk profile is
	// choosing, not a control it is trading away.
	_, err := sandbox.Check(caps, sandbox.Spec{
		RunID: id.MustNew(id.Run), Workspace: "/tmp",
		MinimumStrength: sandbox.StrengthMicroVM,
		AllowDegraded:   true, Rationale: "trying it on",
	})
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("degradation bypassed a minimum strength floor: %v", err)
	}

	if !(sandbox.StrengthNone < sandbox.StrengthProcess &&
		sandbox.StrengthProcess < sandbox.StrengthContainer &&
		sandbox.StrengthContainer < sandbox.StrengthMicroVM) {
		t.Fatal("strength must be ordered for a minimum to be expressible")
	}
}

// EXE-9. Advisory or not, the easy case is worth catching: a caller must not be able to point the
// working directory outside the workspace, including through a symlink.
func TestSecurityWorkingDirectoryCannotEscapeTheWorkspace(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh on this platform")
	}
	backend := sandbox.NewProcessBackend()
	dir := t.TempDir()

	session, err := backend.Establish(context.Background(), testSpec(t, dir))
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer func() { _ = backend.Cleanup(context.Background(), session) }()

	link := filepath.Join(dir, "out")
	if err := os.Symlink(os.TempDir(), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	for name, workdir := range map[string]string{
		"parent traversal": "..",
		"deep traversal":   filepath.Join("..", "..", ".."),
		"absolute":         os.TempDir(),
		"through symlink":  "out",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := backend.Run(context.Background(), session, sandbox.Command{
				Path: "/bin/sh", Args: []string{"-c", "true"}, Dir: workdir,
			})
			if !modberr.Is(err, modberr.CodePolicyDenied) {
				t.Fatalf("error = %v, want the escape refused", err)
			}
		})
	}

	// A directory inside the workspace still works.
	inside := filepath.Join(dir, "sub")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := backend.Run(context.Background(), session, sandbox.Command{
		Path: "/bin/sh", Args: []string{"-c", "true"}, Dir: "sub",
	}); err != nil {
		t.Fatalf("a directory inside the workspace was refused: %v", err)
	}
}

// EXE-7. A repository-defined hook is code the repository chose, and running it is what the
// requirement forbids without explicit approval.
func TestSecurityHooksAreSuppressed(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh on this platform")
	}
	backend := sandbox.NewProcessBackend()
	dir := t.TempDir()

	session, err := backend.Establish(context.Background(), testSpec(t, dir))
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer func() { _ = backend.Cleanup(context.Background(), session) }()

	// The environment is replaced, not inherited: a variable the parent holds must not reach the
	// child, because that is how a credential in the operator's shell reaches repository code.
	t.Setenv("MODBIT_SECRET_PROBE", "must-not-leak")
	result, err := backend.Run(context.Background(), session, sandbox.Command{
		Path: "/bin/sh", Args: []string{"-c", "echo [$MODBIT_SECRET_PROBE][$GIT_CONFIG_KEY_0]"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(result.Stdout, "must-not-leak") {
		t.Fatalf("the parent environment leaked into the sandbox: %q", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "core.hooksPath") {
		t.Fatalf("git hooks were not redirected: %q", result.Stdout)
	}
}

// Cancellation must reach the child's descendants, not only the process that was started.
//
// This is the case `TestCancellationStopsACommandAndReportsIt` cannot see on macOS. `sh -c "sleep
// 30"` is one process there, because bash-as-sh execs a lone trailing command, so killing the single
// PID is enough and the test passes whether or not the group is signalled. Under dash — Debian's
// /bin/sh, and what CI's Linux leg runs — the shell forks, the grandchild survives a single-PID
// kill, and because it inherited the output pipe, Wait blocks until it exits on its own.
//
// `sleep 30 & wait` forces that shape on every platform: an explicit background child, so there is
// always a descendant to lose. A command that keeps running after its caller gave up is a leaked
// process tree, and the `Setpgid` this backend performs exists precisely to make it reachable.
func TestCancellationReachesDescendantsNotJustTheChild(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh on this platform")
	}
	backend := sandbox.NewProcessBackend()
	dir := t.TempDir()

	session, err := backend.Establish(context.Background(), testSpec(t, dir))
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer func() { _ = backend.Cleanup(context.Background(), session) }()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	started := time.Now()
	result, _ := backend.Run(ctx, session, sandbox.Command{
		Path: "/bin/sh", Args: []string{"-c", "sleep 30 & wait"},
	})
	// 10 s against a 150 ms deadline and a 2 s WaitDelay backstop, and far below the 30 s a surviving
	// descendant costs — the failure this separates is an order of magnitude wide, so the bound buys
	// tolerance without weakening the assertion.
	//
	// It was 5 s, which left under 3 s of headroom. `make check` failed once on a machine also running
	// container builds and did not reproduce in 18 subsequent runs; the detail was lost to a truncated
	// pipe, so this is the most plausible candidate rather than a confirmed cause. A wall-clock bound
	// that can fail under CPU contention is a flaky gate either way (B-12), and 10 s costs nothing.
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("a cancelled command with a background descendant took %v to stop", elapsed)
	}
	if !result.TimedOut {
		t.Fatal("a cancelled command was not reported as timed out")
	}
}

// A cancelled command must stop promptly and say that it timed out, or a caller cannot tell a
// timeout from a fast failure.
func TestCancellationStopsACommandAndReportsIt(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh on this platform")
	}
	backend := sandbox.NewProcessBackend()
	dir := t.TempDir()

	session, err := backend.Establish(context.Background(), testSpec(t, dir))
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer func() { _ = backend.Cleanup(context.Background(), session) }()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	started := time.Now()
	result, _ := backend.Run(ctx, session, sandbox.Command{
		Path: "/bin/sh", Args: []string{"-c", "sleep 30"},
	})
	// 10 s for the reason given on the descendant case above: the same CPU-contention exposure, and
	// the same order-of-magnitude gap between a cancelled command and a 30 s one.
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("a cancelled command took %v to stop", elapsed)
	}
	if !result.TimedOut {
		t.Fatal("a cancelled command was not reported as timed out")
	}
}

// Cleanup removes only what the backend created. Deleting a caller-supplied workspace would destroy
// a user's checkout.
func TestSecurityCleanupRemovesOnlyWhatItCreated(t *testing.T) {
	backend := sandbox.NewProcessBackend()
	ctx := context.Background()

	supplied := t.TempDir()
	marker := filepath.Join(supplied, "user-file")
	if err := os.WriteFile(marker, []byte("mine"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	session, err := backend.Establish(ctx, testSpec(t, supplied))
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if err := backend.Cleanup(ctx, session); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("cleanup deleted a caller-supplied workspace")
	}

	// One the backend created is its to remove, and cleanup is idempotent.
	created := filepath.Join(supplied, "made-by-backend")
	session, err = backend.Establish(ctx, testSpec(t, created))
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if err := backend.Cleanup(ctx, session); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(created); err == nil {
		t.Fatal("a backend-created workspace survived cleanup")
	}
	if err := backend.Cleanup(ctx, session); err != nil {
		t.Fatalf("cleanup was not idempotent: %v", err)
	}
	// A cleaned-up session must not run anything: its workspace may be gone.
	if _, err := backend.Run(ctx, session, sandbox.Command{Path: "/bin/sh", Args: []string{"-c", "true"}}); !modberr.Is(err, modberr.CodeRunStateInvalid) {
		t.Fatalf("error = %v, want a refusal on a cleaned-up session", err)
	}
}

// X7. SBX-5 names ten areas; a case cannot be quietly dropped.
func TestSuiteCoversEverySBX5Area(t *testing.T) {
	report := conformance.Run(context.Background(), sandbox.NewProcessBackend(), conformance.Options{})

	seen := map[conformance.Area]bool{}
	for _, result := range report.Results {
		seen[result.Area] = true
	}
	for _, area := range conformance.Areas() {
		if !seen[area] {
			t.Errorf("the suite produced no result for %s", area)
		}
	}
	if len(conformance.Areas()) != 10 {
		t.Fatalf("SBX-5 names ten areas, the suite declares %d", len(conformance.Areas()))
	}
}

// X8. A declared control the suite cannot demonstrate is not a pass, and it blocks readiness. An
// honestly unsupported control is skipped, because there is no claim to check.
func TestSecurityAnUnexercisedClaimBlocksReadiness(t *testing.T) {
	// The honest backend: everything it does not do is skipped, so it can be production ready for
	// the narrow work its strength allows.
	honest := conformance.Run(context.Background(), sandbox.NewProcessBackend(), conformance.Options{})
	for _, result := range honest.Inconclusive() {
		t.Errorf("the honest backend was inconclusive on %s: %s", result.Area, result.Detail)
	}
	if !honest.ProductionReady() {
		t.Fatalf("an honest backend should pass its own claims: %s", honest.Summary())
	}

	// The over-claiming backend: it declares controls it cannot demonstrate, and the suite must
	// refuse it rather than let the declaration stand.
	over := conformance.Run(context.Background(), overclaimingBackend{sandbox.NewProcessBackend()}, conformance.Options{})
	if len(over.Inconclusive()) == 0 {
		t.Fatalf("an over-claiming backend produced no inconclusive results: %s", over.Summary())
	}
	if over.ProductionReady() {
		t.Fatalf("an over-claiming backend was reported production ready: %s", over.Summary())
	}
}

// overclaimingBackend declares every control enforced while behaving exactly like the process
// backend. It is the shape SBX-3 exists to catch.
type overclaimingBackend struct{ *sandbox.ProcessBackend }

func (o overclaimingBackend) Capabilities() sandbox.Capabilities {
	caps := o.ProcessBackend.Capabilities()
	controls := map[sandbox.Control]sandbox.Enforcement{}
	for _, control := range sandbox.Controls() {
		controls[control] = sandbox.EnforcementEnforced
	}
	caps.Controls = controls
	caps.Backend = "overclaiming"
	return caps
}

// A spec that is malformed independently of any backend is refused before a backend sees it.
func TestValidateSpecRefusesAMalformedSpec(t *testing.T) {
	cases := map[string]sandbox.Spec{
		"no run id":       {Workspace: "/tmp"},
		"no workspace":    {RunID: id.MustNew(id.Run)},
		"unknown control": {RunID: id.MustNew(id.Run), Workspace: "/tmp", Required: []sandbox.Control{"telepathy"}},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if err := sandbox.ValidateSpec(spec); !modberr.Is(err, modberr.CodeInvalidArgument) {
				t.Fatalf("error = %v, want a refusal", err)
			}
		})
	}
}
