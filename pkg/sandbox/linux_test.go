//go:build linux

package sandbox_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/sandbox"
	"github.com/modbit/modbit/pkg/sandbox/conformance"
)

// The Linux backend declares only controls it probed successfully.
//
// X1, X2, SBX-3, ADR-0107. The point of this test is that it makes no assumption about the host: CI
// containers, a developer's Ubuntu box and a hardened server all offer different subsets, and any of
// them is a valid answer. What is never valid is declaring a control the probe did not establish.
//
// Each enforced control is re-verified here against the mechanism it claims, so a probe that
// succeeded for the wrong reason is caught by a second, independent check.
func TestLinuxBackendDeclaresOnlyWhatItProbed(t *testing.T) {
	backend, err := sandbox.NewLinuxBackend()
	if err != nil {
		t.Fatalf("NewLinuxBackend: %v", err)
	}
	caps := backend.Capabilities()

	if caps.Backend != "linux" {
		t.Fatalf("backend = %q, want %q", caps.Backend, "linux")
	}
	// SBX-4: namespaces and cgroups confine a process, they do not virtualize one. Claiming container
	// strength would let a profile demanding a container select something that is not one.
	if caps.Strength != sandbox.StrengthProcess {
		t.Fatalf("strength = %v, want %v", caps.Strength, sandbox.StrengthProcess)
	}
	// X1: every control has a declared level, and the zero value is unsupported rather than absent.
	for _, control := range sandbox.Controls() {
		if _, declared := caps.Controls[control]; !declared {
			t.Errorf("%s has no declared enforcement level", control)
		}
	}

	// ADR-0107 measured filesystem scope as unreachable for an unprivileged user, because the mount
	// it needs requires CAP_SYS_ADMIN. It is never raised, on any host, and that is deliberate: a
	// probe that passed as root would make this backend promise a control it cannot deliver for the
	// user it runs as.
	if caps.Enforcement(sandbox.ControlFilesystemScope).Enforces() {
		t.Fatalf("filesystem scope is declared enforced; a bind mount needs CAP_SYS_ADMIN")
	}

	t.Logf("this host enforces: %v", caps.Enforced())

	if caps.Enforcement(sandbox.ControlNetworkDeny).Enforces() {
		assertEgressDenied(t, backend)
	}
	if caps.Enforcement(sandbox.ControlMemoryLimit).Enforces() {
		assertCgroupApplied(t, backend)
	}
}

// A backend claiming network denial must actually deny egress.
//
// The probe establishes that a network namespace can be created; this establishes that being in one
// means what the control says. They are different claims, and an earlier version of this
// investigation conflated them — a probe that read the host's interface list from inside a namespace
// reported isolation that did not exist.
func assertEgressDenied(t *testing.T, backend *sandbox.LinuxBackend) {
	t.Helper()
	session, cleanup := establish(t, backend)
	defer cleanup()

	result, err := backend.Run(context.Background(), session, sandbox.Command{
		Path: "/bin/sh",
		Args: []string{"-c", `(exec 3<>/dev/tcp/1.1.1.1/443) 2>/dev/null && echo REACHED || echo refused`},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "refused" {
		t.Fatalf("a sandbox declaring network_deny reached the network: %q", got)
	}
}

// A backend claiming resource limits must actually place the command in the limited cgroup.
//
// Reading the limit from inside is what proves it: the file existing outside says only that this
// process could write it, not that the child inherited it.
func assertCgroupApplied(t *testing.T, backend *sandbox.LinuxBackend) {
	t.Helper()
	session, cleanup := establish(t, backend)
	defer cleanup()

	result, err := backend.Run(context.Background(), session, sandbox.Command{
		Path: "/bin/sh",
		Args: []string{"-c", "cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unavailable"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := strings.TrimSpace(result.Stdout)
	if got == "unavailable" || got == "" {
		// The child sees its cgroup through its own namespace view, which a host without cgroup
		// namespaces does not provide. Not a failure of the limit, so it is reported rather than
		// asserted on.
		t.Logf("the child could not read its own cgroup view (%q); limit not observable from inside", got)
		return
	}
	if got == "max" {
		t.Fatalf("the command ran with no memory ceiling while memory_limit is declared enforced")
	}
}

// A spec requiring a control this host does not enforce fails closed.
//
// X3, SBX-6. Filesystem scope is the reliable case to test with, because ADR-0107 establishes it is
// never enforced here — so this asserts the gate without depending on what the host happens to offer.
func TestSecurityLinuxBackendRefusesAnUnenforceableRequirement(t *testing.T) {
	backend, err := sandbox.NewLinuxBackend()
	if err != nil {
		t.Fatalf("NewLinuxBackend: %v", err)
	}
	_, err = backend.Establish(context.Background(), sandbox.Spec{
		RunID:     id.MustNew(id.Run),
		Workspace: t.TempDir(),
		Required:  []sandbox.Control{sandbox.ControlFilesystemScope},
	})
	if err == nil {
		t.Fatalf("a spec requiring filesystem scope established against a backend that cannot enforce it")
	}
}

// The Linux backend answers the shared SBX-5 conformance suite.
//
// X7, X8. Whatever subset of controls a host offers, the backend must answer the same ten areas as
// every other backend, and an area it cannot demonstrate must be skipped rather than passed.
func TestLinuxBackendPassesTheSharedConformanceSuite(t *testing.T) {
	backend, err := sandbox.NewLinuxBackend()
	if err != nil {
		t.Fatalf("NewLinuxBackend: %v", err)
	}
	report := conformance.Run(context.Background(), backend, conformance.Options{})

	for _, area := range conformance.Areas() {
		var seen bool
		for _, r := range report.Results {
			if r.Area == area {
				seen = true
			}
		}
		if !seen {
			t.Errorf("the suite produced no result for %s", area)
		}
	}
	for _, r := range report.Inconclusive() {
		t.Errorf("inconclusive on %s: %s", r.Area, r.Detail)
	}
	if !report.ProductionReady() {
		t.Fatalf("the Linux backend is not production ready: %s", report.Summary())
	}
}

func establish(t *testing.T, backend *sandbox.LinuxBackend) (*sandbox.Session, func()) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh on this platform")
	}
	session, err := backend.Establish(context.Background(), sandbox.Spec{
		RunID:     id.MustNew(id.Run),
		Workspace: t.TempDir(),
		WallClock: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	return session, func() { _ = backend.Cleanup(context.Background(), session) }
}
