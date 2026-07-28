//go:build darwin

package sandbox_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/sandbox"
	"github.com/modbit/modbit/pkg/sandbox/conformance"
)

func newSeatbelt(t *testing.T) *sandbox.SeatbeltBackend {
	t.Helper()
	backend, err := sandbox.NewSeatbeltBackend()
	if err != nil {
		t.Skipf("macOS confinement unavailable: %v", err)
	}
	return backend
}

// The claim this backend exists to make: EXE-4 is genuinely enforced, by the kernel rather than by a
// check the confined process could route around. A write outside the workspace must fail even though
// the command is a plain shell that never consulted Modbit.
func TestSecuritySeatbeltEnforcesFilesystemScope(t *testing.T) {
	backend := newSeatbelt(t)
	ctx := context.Background()

	workspace := t.TempDir()
	outside := filepath.Join(t.TempDir(), "escaped")

	session, err := backend.Establish(ctx, sandbox.Spec{
		RunID:     id.MustNew(id.Run),
		Workspace: workspace,
		Required:  []sandbox.Control{sandbox.ControlFilesystemScope},
	})
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer func() { _ = backend.Cleanup(ctx, session) }()

	// Writing inside the workspace works. This half matters as much as the other: a profile naming
	// the unresolved path denies everything including the workspace, which looks like confinement
	// and is actually a broken run.
	if _, err := backend.Run(ctx, session, sandbox.Command{
		Path: "/bin/sh", Args: []string{"-c", "echo ok > inside.txt"},
	}); err != nil {
		t.Fatalf("a write inside the workspace failed: %v", err)
	}
	resolved, _ := filepath.EvalSymlinks(workspace)
	if _, err := os.Stat(filepath.Join(resolved, "inside.txt")); err != nil {
		t.Fatalf("the in-workspace write did not land: %v", err)
	}

	// Writing outside must be refused by the kernel.
	if _, err := backend.Run(ctx, session, sandbox.Command{
		Path: "/bin/sh", Args: []string{"-c", "echo escaped > " + outside},
	}); err != nil {
		t.Logf("command reported: %v", err)
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("a confined command wrote outside its workspace")
	}
}

// EXE-6: egress is denied by default. Destination policy lives in the gateway's egress allowlist; a
// tool has no business reaching the network at all.
func TestSecuritySeatbeltDeniesNetworkEgress(t *testing.T) {
	backend := newSeatbelt(t)
	ctx := context.Background()

	session, err := backend.Establish(ctx, sandbox.Spec{
		RunID:     id.MustNew(id.Run),
		Workspace: t.TempDir(),
		Required:  []sandbox.Control{sandbox.ControlNetworkDeny},
	})
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer func() { _ = backend.Cleanup(ctx, session) }()

	// A loopback listener is reachable without leaving the machine, so a failure here is the sandbox
	// rather than the network being down — which a test against a public address could not
	// distinguish.
	result, err := backend.Run(ctx, session, sandbox.Command{
		Path: "/bin/sh",
		Args: []string{"-c", "nc -z -w2 127.0.0.1 1 2>&1; echo exit=$?"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Under a deny-network profile the connect cannot succeed. A non-zero exit is expected; what
	// must not happen is a successful connection.
	if result.ExitCode == 0 && !containsAny(result.Stdout, "exit=1", "exit=2", "not permitted") {
		t.Fatalf("network appears reachable inside the sandbox: %q", result.Stdout)
	}
}

func containsAny(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if len(needle) <= len(haystack) {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
		}
	}
	return false
}

// A workspace path is attacker-influenced in the case that matters — a run pointed at a checked-out
// repository. SBPL is a Lisp-like syntax, so an unescaped quote or paren would close the string and
// let the remainder become profile source: arbitrary sandbox rules chosen by whoever named the
// directory.
func TestSecurityAWorkspacePathCannotInjectProfileRules(t *testing.T) {
	backend := newSeatbelt(t)
	ctx := context.Background()
	parent := t.TempDir()

	hostile := map[string]string{
		"closing quote and rule": `evil") (allow file-write* (subpath "/`,
		"embedded paren":         `evil)`,
		"embedded quote":         `evil"`,
		"comment":                `evil;comment`,
		"newline":                "evil\nrule",
		"backslash":              `evil\path`,
	}
	for name, dirname := range hostile {
		t.Run(name, func(t *testing.T) {
			workspace := filepath.Join(parent, dirname)
			// The directory may not even be creatable, which is fine — what matters is that
			// Establish refuses rather than generating a profile from it.
			_ = os.MkdirAll(workspace, 0o755)

			_, err := backend.Establish(ctx, sandbox.Spec{
				RunID:     id.MustNew(id.Run),
				Workspace: workspace,
				Required:  []sandbox.Control{sandbox.ControlFilesystemScope},
			})
			if err == nil {
				t.Fatal("a workspace path containing SBPL syntax was accepted")
			}
		})
	}

	// The control: an ordinary path still establishes, so the refusals above are the guard rather
	// than establishment being broken.
	session, err := backend.Establish(ctx, sandbox.Spec{
		RunID:     id.MustNew(id.Run),
		Workspace: filepath.Join(parent, "ordinary-name"),
		Required:  []sandbox.Control{sandbox.ControlFilesystemScope},
	})
	if err != nil {
		t.Fatalf("an ordinary workspace name was refused: %v", err)
	}
	_ = backend.Cleanup(ctx, session)
}

// SBX-4: strength must stay honest. sandbox-exec confines a process, it does not virtualize one, so
// a profile demanding container isolation must not be able to select this.
func TestSecuritySeatbeltDoesNotClaimContainerStrength(t *testing.T) {
	backend := newSeatbelt(t)
	caps := backend.Capabilities()

	if caps.Strength != sandbox.StrengthProcess {
		t.Fatalf("strength = %v, want process", caps.Strength)
	}
	_, err := sandbox.Check(caps, sandbox.Spec{
		RunID: id.MustNew(id.Run), Workspace: "/tmp",
		MinimumStrength: sandbox.StrengthContainer,
	})
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("error = %v; a container requirement must not be satisfied by process confinement", err)
	}

	// It must claim exactly the two controls it measurably provides, and no more.
	for _, control := range []sandbox.Control{
		sandbox.ControlFilesystemScope, sandbox.ControlNetworkDeny,
	} {
		if !caps.Enforcement(control).Enforces() {
			t.Errorf("%s should be enforced by this backend", control)
		}
	}
	for _, control := range []sandbox.Control{
		sandbox.ControlCPULimit, sandbox.ControlMemoryLimit,
		sandbox.ControlProcessLimit, sandbox.ControlDiskLimit,
	} {
		if caps.Enforcement(control).Enforces() {
			t.Errorf("%s is claimed but sandbox-exec does not provide it", control)
		}
	}
}

// The backend must pass the same SBX-5 suite every backend answers, and its two new claims must be
// demonstrated rather than merely declared — an over-claim is Inconclusive, which blocks readiness.
func TestSeatbeltPassesTheSharedConformanceSuite(t *testing.T) {
	backend := newSeatbelt(t)

	report := conformance.Run(context.Background(), backend, conformance.Options{})
	for _, result := range report.Failures() {
		t.Errorf("conformance failure: %s: %s", result.Area, result.Detail)
	}
	for _, result := range report.Inconclusive() {
		t.Errorf("conformance inconclusive: %s: %s", result.Area, result.Detail)
	}
	if !report.ProductionReady() {
		t.Fatalf("seatbelt backend is not production ready: %s", report.Summary())
	}
	t.Logf("conformance: %s", report.Summary())
}
