//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// LinuxBackend confines a command with kernel namespaces and cgroup v2.
//
// See ADR-0107 for the measurements this is built on, and for why they were taken on a stock distro
// as an ordinary user rather than in a container as root — the two environments disagree on every
// control, and only one of them is where Modbit runs.
//
// # What it enforces, and what it cannot
//
// It enforces network denial through a network namespace, process confinement through a PID
// namespace, and CPU, memory and process-count limits through the cgroup subtree systemd delegates
// to the user session. It does **not** enforce filesystem scope: that needs `mount` inside a mount
// namespace, which needs `CAP_SYS_ADMIN`, and Ubuntu's `apparmor_restrict_unprivileged_userns`
// leaves an unprivileged user namespace with no capabilities at all.
//
// So on filesystem scope the macOS backend is the stronger one, which inverts the usual expectation
// and is the argument for the container backend (`EXE-A01d`).
//
// # Why every control is probed rather than declared
//
// `apparmor_restrict_unprivileged_userns` is a sysctl an administrator can change, cgroup delegation
// depends on there being a systemd user session, and distributions differ — Fedora ships no AppArmor
// at all. A hardcoded capability map would report enforcement this build does not have on the first
// host that differs, which is SBX-3's failure reached by a different route. `NewLinuxBackend` runs
// each control's mechanism once and declares only what worked, exactly as `NewSeatbeltBackend`
// refuses when `sandbox-exec` is absent.
type LinuxBackend struct {
	process *ProcessBackend
	caps    Capabilities

	// cgroupParent is the delegated cgroup this backend may create children under. Empty when
	// delegation is unavailable, in which case the three resource controls are unsupported.
	cgroupParent string
	// namespaces are the clone flags the probe established are usable.
	namespaces uintptr

	mu       sync.Mutex
	sessions map[id.ID]string // session id -> cgroup path it owns
}

var _ Backend = (*LinuxBackend)(nil)

// NewLinuxBackend probes the host and returns a backend declaring only what it can enforce.
//
// It does not fail when controls are unavailable: a Linux host that offers none of them still gets
// the portable backend's wall-clock bound and hook suppression, and SBX-6 then refuses any spec that
// requires more. Failing here would deny a caller the weak sandbox they are entitled to.
func NewLinuxBackend() (*LinuxBackend, error) {
	process := NewProcessBackend()
	b := &LinuxBackend{
		process:  process,
		sessions: map[id.ID]string{},
	}

	// Every control gets an explicit entry, including the unsupported ones.
	//
	// The contract reads an absent control as unsupported, so omitting them would be correct — and
	// silent. X1 asks for a declared level per control precisely so that a control nobody thought
	// about is distinguishable from one deliberately declined, and the difference is invisible in a
	// map that only lists the wins. `Enforcement` returns the zero value for anything the portable
	// backend omits, so this inherits its answers without depending on how it spells them.
	base := process.Capabilities()
	controls := make(map[Control]Enforcement, len(Controls()))
	for _, control := range Controls() {
		controls[control] = base.Enforcement(control)
	}

	// Network denial. A fresh network namespace has only a down loopback and no route to anywhere,
	// which is a kernel property rather than a configuration, so establishing that the namespace can
	// be created is establishing the control. It needs no capability inside the namespace, which is
	// why it survives the AppArmor restriction that removes the rest.
	if b.probeNamespace(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET) {
		b.namespaces |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET
		controls[ControlNetworkDeny] = EnforcementEnforced
	}

	// Process confinement. A PID namespace is strictly stronger than the process group the portable
	// backend sets: descendants cannot be reparented out of it, and they are killed by the kernel
	// when the namespace's init exits.
	if b.probeNamespace(syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID) {
		b.namespaces |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID
		controls[ControlProcessConfinement] = EnforcementEnforced
	}

	// Resource limits, through the cgroup systemd delegated to this user session.
	if parent, delegated := probeCgroupDelegation(); delegated {
		b.cgroupParent = parent
		for _, c := range []Control{ControlCPULimit, ControlMemoryLimit, ControlProcessLimit} {
			controls[c] = EnforcementEnforced
		}
	}

	// ControlFilesystemScope is deliberately not probed and never raised. Enforcing it means
	// bind-mounting the workspace inside a mount namespace, and that needs CAP_SYS_ADMIN, which an
	// unprivileged user namespace does not carry on a host with the AppArmor restriction enabled.
	// Probing it would mean attempting a mount, and a probe that sometimes succeeds as root would
	// make this backend declare a control it cannot deliver for the user it actually runs as.

	b.caps = Capabilities{
		ContractVersion: ContractVersion,
		Backend:         "linux",
		// Namespaces and cgroups confine a process; they do not virtualize one. A profile demanding
		// container strength must not be able to select this (SBX-4).
		Strength: StrengthProcess,
		Controls: controls,
	}
	return b, nil
}

// identityMapping keeps the child's own uid and gid inside the user namespace.
//
// Without a mapping the child runs as the overflow id — 65534, `nobody` — which cannot enter a
// workspace created mode 0700 by the invoking user. Every command then fails with EACCES from a
// sandbox that reported itself healthy, because the namespace really was created; it was simply
// useless. CI found exactly that, on the first host where all seven controls were available.
//
// A single-entry self-map needs no capability, which matters because
// `apparmor_restrict_unprivileged_userns` leaves the namespace with none.
func identityMapping() ([]syscall.SysProcIDMap, []syscall.SysProcIDMap) {
	return []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
		[]syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}}
}

// probeNamespace reports whether a command can actually *run* with these clone flags.
//
// It executes a real binary in a real directory rather than checking that the clone succeeded. The
// distinction is the whole lesson of the CI failure this replaced: a namespace that is created but
// cannot execute anything is not a usable control, and a probe that stops at creation certifies a
// sandbox that fails on its first command.
//
// It also runs against a mode-0700 directory, because that is what a workspace is, and workspace
// access is precisely what an unmapped namespace loses.
func (b *LinuxBackend) probeNamespace(flags uintptr) bool {
	shell := probeExecutable()
	if shell == "" {
		return false
	}
	dir, err := os.MkdirTemp("", "modbit-nsprobe-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return false
	}

	uids, gids := identityMapping()
	cmd := exec.Command(shell, "-c", "exit 0")
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  flags,
		UidMappings: uids,
		GidMappings: gids,
	}
	return cmd.Run() == nil
}

// probeExecutable returns a shell the probe can run, or "" when none is present.
func probeExecutable() string {
	for _, candidate := range []string{"/bin/sh", "/system/bin/sh"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// probeCgroupDelegation finds the cgroup subtree this user may create children under.
//
// systemd delegates `user.slice/user-$UID.slice/user@$UID.service` to the session's own user, with
// the controllers it enables in `cgroup.subtree_control`. A process outside a systemd user session —
// a daemon under a system unit, or a container — has no such path, and the resource controls are
// then genuinely unavailable rather than merely unconfigured.
func probeCgroupDelegation() (string, bool) {
	uid := os.Getuid()
	parent := filepath.Join("/sys/fs/cgroup/user.slice",
		fmt.Sprintf("user-%d.slice", uid), fmt.Sprintf("user@%d.service", uid))

	enabled, err := os.ReadFile(filepath.Join(parent, "cgroup.subtree_control"))
	if err != nil {
		return "", false
	}
	// All three controllers must be delegated. Declaring two of three enforced would mean a spec
	// requiring the third establishes against a backend that silently ignores it.
	for _, want := range []string{"cpu", "memory", "pids"} {
		if !strings.Contains(string(enabled), want) {
			return "", false
		}
	}

	// Writability is not implied by the controllers being listed: the directory may be owned by
	// another user, which is the case for a process that is not in its own session. A real mkdir is
	// the only honest check.
	probe := filepath.Join(parent, "modbit-probe")
	if err := os.Mkdir(probe, 0o755); err != nil {
		return "", false
	}
	_ = os.Remove(probe)
	return parent, true
}

// Capabilities implements Backend.
func (b *LinuxBackend) Capabilities() Capabilities { return b.caps }

// Establish implements Backend.
func (b *LinuxBackend) Establish(ctx context.Context, spec Spec) (*Session, error) {
	session, err := b.process.Establish(ctx, spec)
	if err != nil {
		return nil, err
	}
	// Check runs against this backend's capabilities, not the portable backend's, so a spec
	// requiring network denial establishes here where it would have been refused there.
	unmet, err := Check(b.caps, spec)
	if err != nil {
		_ = b.process.Cleanup(ctx, session)
		return nil, err
	}
	session.Backend = b.caps.Backend
	session.Strength = b.caps.Strength
	session.Enforced = b.caps.Enforced()
	session.Unmet = unmet
	session.Degraded = len(unmet) > 0

	if b.cgroupParent != "" {
		path := filepath.Join(b.cgroupParent, "modbit-"+session.ID.String())
		if err := os.Mkdir(path, 0o755); err != nil && !os.IsExist(err) {
			_ = b.process.Cleanup(ctx, session)
			return nil, modberr.Wrap(err, modberr.CodeSandboxUnavailable,
				"the session cgroup could not be created")
		}
		b.mu.Lock()
		b.sessions[session.ID] = path
		b.mu.Unlock()
	}
	return session, nil
}

// Limits are the resource ceilings applied to every command in a session.
//
// They are deliberately fixed rather than taken from the Spec: EXE-5 requires bounds to exist, and
// the contract has no field for their values yet. Making them configurable before a requirement asks
// for it would be inventing policy.
const (
	sessionMemoryMax = 2 << 30 // 2 GiB
	sessionPidsMax   = 512
	sessionCPUMax    = "200000 100000" // 2 cores
)

// Run implements Backend.
func (b *LinuxBackend) Run(ctx context.Context, session *Session, cmd Command) (Result, error) {
	if session == nil {
		return Result{}, modberr.New(modberr.CodeInvalidArgument, "run requires an established session").
			WithDetail("field", "session")
	}
	b.mu.Lock()
	cgroupPath, hasCgroup := b.sessions[session.ID]
	b.mu.Unlock()

	// The portable backend owns workspace resolution, environment scrubbing, hook suppression and
	// the wall-clock bound. This backend adds isolation on top rather than reimplementing any of it,
	// which is what keeps the two from drifting apart.
	return b.process.runWith(ctx, session, cmd, func(c *exec.Cmd) (func(), error) {
		if b.namespaces != 0 {
			if c.SysProcAttr == nil {
				c.SysProcAttr = &syscall.SysProcAttr{}
			}
			c.SysProcAttr.Cloneflags |= b.namespaces
			// The same mapping the probe used. If these differed, the probe would be certifying a
			// configuration the command never runs under — which is how a sandbox reports itself
			// healthy and then fails EACCES on everything it is asked to do.
			c.SysProcAttr.UidMappings, c.SysProcAttr.GidMappings = identityMapping()
		}
		if !hasCgroup {
			return nil, nil
		}
		if err := applyLimits(cgroupPath); err != nil {
			return nil, err
		}
		fd, err := os.Open(cgroupPath)
		if err != nil {
			return nil, modberr.Wrap(err, modberr.CodeSandboxUnavailable,
				"the session cgroup could not be opened")
		}
		// The descriptor has to outlive Start and no longer, so it is returned as the command's
		// cleanup. Closing it on the context instead would hold one descriptor per Run for as long as
		// the caller's context lives, which for context.Background() is the life of the process.
		c.SysProcAttr.UseCgroupFD = true
		c.SysProcAttr.CgroupFD = int(fd.Fd())
		return func() { _ = fd.Close() }, nil
	})
}

func applyLimits(path string) error {
	for file, value := range map[string]string{
		"memory.max": strconv.Itoa(sessionMemoryMax),
		"pids.max":   strconv.Itoa(sessionPidsMax),
		"cpu.max":    sessionCPUMax,
	} {
		if err := os.WriteFile(filepath.Join(path, file), []byte(value), 0o644); err != nil {
			return modberr.Wrapf(err, modberr.CodeSandboxUnavailable,
				"the %s limit could not be applied", file).WithDetail("constraint", file)
		}
	}
	return nil
}

// Cleanup implements Backend.
func (b *LinuxBackend) Cleanup(ctx context.Context, session *Session) error {
	if session == nil {
		return nil
	}
	b.mu.Lock()
	path, held := b.sessions[session.ID]
	delete(b.sessions, session.ID)
	b.mu.Unlock()
	if held {
		// A cgroup with live processes refuses removal. That is the kernel reporting a leak rather
		// than an error to swallow: the portable backend's cleanup below stops the processes, and a
		// cgroup that still will not go is worth surfacing.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			_ = b.process.Cleanup(ctx, session)
			return modberr.Wrap(err, modberr.CodeUnavailable, "the session cgroup could not be removed")
		}
	}
	return b.process.Cleanup(ctx, session)
}
