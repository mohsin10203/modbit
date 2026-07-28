//go:build darwin

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// SeatbeltBackend confines a command with macOS's sandbox, via /usr/bin/sandbox-exec.
//
// See ADR-0101 for why a deprecated interface is the right one: there is no supported replacement
// for per-command confinement of a child process, and the alternative reaches the same mechanism
// through cgo. It is a Backend behind the SBX-1 contract, so replacing it is one implementation
// rather than a migration.
//
// It enforces filesystem scope (EXE-4) and network deny (EXE-6), which the portable backend cannot,
// and inherits everything else from it. Strength stays StrengthProcess: this confines a process, it
// does not virtualize one, and claiming container strength would let a profile demanding container
// isolation select something that is not one (SBX-4).
type SeatbeltBackend struct {
	process *ProcessBackend

	mu       sync.Mutex
	profiles map[id.ID]string // session id -> generated profile path
}

// sandboxExecPath is the confinement helper. It is an absolute path rather than a PATH lookup: a
// sandbox selected by PATH is one a caller's environment can redirect, which for a security control
// is the whole game.
const sandboxExecPath = "/usr/bin/sandbox-exec"

// sandboxTempDir is the workspace-relative directory confined commands use for temporary files.
const sandboxTempDir = ".modbit-tmp"

// NewSeatbeltBackend returns the macOS backend, refusing if the confinement helper is absent.
//
// SBX-6: failing closed at construction beats discovering at establishment that the sandbox this
// build advertises does not exist on this machine.
func NewSeatbeltBackend() (*SeatbeltBackend, error) {
	info, err := os.Stat(sandboxExecPath)
	if err != nil || info.IsDir() {
		return nil, modberr.Newf(modberr.CodeSandboxUnavailable,
			"%s is not present; macOS confinement is unavailable", sandboxExecPath).
			WithDetail("constraint", "sandbox_exec")
	}
	return &SeatbeltBackend{process: NewProcessBackend(), profiles: map[id.ID]string{}}, nil
}

var _ Backend = (*SeatbeltBackend)(nil)

// Capabilities implements Backend.
func (b *SeatbeltBackend) Capabilities() Capabilities {
	caps := b.process.Capabilities()
	controls := make(map[Control]Enforcement, len(caps.Controls)+2)
	for control, level := range caps.Controls {
		controls[control] = level
	}
	// Measured, not assumed — ADR-0101 records the probe. A write outside the workspace is refused
	// by the kernel, and an outbound connect under (deny network*) is refused.
	controls[ControlFilesystemScope] = EnforcementEnforced
	controls[ControlNetworkDeny] = EnforcementEnforced
	caps.Controls = controls
	caps.Backend = "seatbelt"
	return caps
}

// Establish implements Backend.
func (b *SeatbeltBackend) Establish(ctx context.Context, spec Spec) (*Session, error) {
	if err := ValidateSpec(spec); err != nil {
		return nil, err
	}
	unmet, err := Check(b.Capabilities(), spec)
	if err != nil {
		return nil, err
	}

	// The requirement check above ran against *this* backend's capabilities. Passing Required down
	// would re-run it against the process backend's weaker ones and refuse the very controls this
	// backend exists to add — the delegation must not leak the check it already satisfied.
	inner := spec
	inner.Required = nil
	inner.MinimumStrength = StrengthNone
	session, err := b.process.Establish(ctx, inner)
	if err != nil {
		return nil, err
	}
	session.Backend = "seatbelt"
	session.Enforced = b.Capabilities().Enforced()
	session.Degraded = len(unmet) > 0
	session.Unmet = unmet
	if session.Degraded {
		session.Rationale = spec.Rationale
	}

	// The profile names the symlink-resolved workspace. A profile's (subpath ...) matches the
	// resolved path, so a workspace under /var/folders is not matched by a rule naming /var/... —
	// the kernel sees /private/var/... . Writing the unresolved path produces a profile that denies
	// everything including the workspace itself: a sandbox that looks configured and breaks the run.
	resolved, err := filepath.EvalSymlinks(session.Workspace)
	if err != nil {
		_ = b.process.Cleanup(ctx, session)
		return nil, modberr.Wrap(err, modberr.CodeSandboxUnavailable,
			"workspace path could not be resolved for the sandbox profile")
	}

	profile, err := seatbeltProfile(resolved)
	if err != nil {
		_ = b.process.Cleanup(ctx, session)
		return nil, err
	}
	path, err := writeProfile(profile)
	if err != nil {
		_ = b.process.Cleanup(ctx, session)
		return nil, err
	}

	b.mu.Lock()
	b.profiles[session.ID] = path
	b.mu.Unlock()
	return session, nil
}

// Run implements Backend, wrapping the command in the confinement helper.
func (b *SeatbeltBackend) Run(ctx context.Context, session *Session, cmd Command) (Result, error) {
	if session == nil {
		return Result{}, modberr.New(modberr.CodeInvalidArgument, "run requires an established session").
			WithDetail("field", "session")
	}
	b.mu.Lock()
	profile, live := b.profiles[session.ID]
	b.mu.Unlock()
	if !live {
		return Result{}, modberr.New(modberr.CodeRunStateInvalid, "sandbox session is not established")
	}
	if cmd.Path == "" {
		return Result{}, modberr.New(modberr.CodeInvalidArgument, "a command requires a path").
			WithDetail("field", "path")
	}

	// The command becomes an argument to sandbox-exec. Delegating to the process backend keeps one
	// implementation of working-directory resolution, environment replacement, hook suppression, and
	// cancellation — a second copy would drift, and the copy that drifted would be the confined one.
	// Temporary files land inside the workspace, which is the only place writes are permitted. The
	// directory is created here rather than at establishment so a cleaned-and-reused workspace still
	// has one.
	tmp := filepath.Join(session.Workspace, sandboxTempDir)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return Result{}, modberr.Wrap(err, modberr.CodeUnavailable,
			"sandbox temporary directory could not be created")
	}
	confined := Command{
		Path: sandboxExecPath,
		Args: append([]string{"-f", profile, cmd.Path}, cmd.Args...),
		Dir:  cmd.Dir,
		Env:  append([]string{"TMPDIR=" + tmp, "TMP=" + tmp, "TEMP=" + tmp}, cmd.Env...),
	}
	return b.process.Run(ctx, session, confined)
}

// Cleanup implements Backend.
func (b *SeatbeltBackend) Cleanup(ctx context.Context, session *Session) error {
	if session == nil {
		return nil
	}
	b.mu.Lock()
	profile, live := b.profiles[session.ID]
	delete(b.profiles, session.ID)
	b.mu.Unlock()
	if live && profile != "" {
		_ = os.Remove(profile)
	}
	return b.process.Cleanup(ctx, session)
}

// sbplUnsafe reports whether a path contains a character that cannot appear in an SBPL string.
//
// SBPL is a Lisp-like syntax. An unescaped quote or paren in a path would close the string and let
// the remainder become profile *source* — arbitrary sandbox rules chosen by whoever named the
// directory, which for a run pointed at a checked-out repository is attacker-influenced input.
//
// This refuses rather than escapes. Escaping is a thing to get subtly wrong once; refusal is not,
// and a directory whose name requires escaping is not one Modbit needs to confine.
func sbplUnsafe(path string) (rune, bool) {
	for _, r := range path {
		switch r {
		case '"', '\\', '(', ')', ';', '\n', '\r', '\t', 0:
			return r, true
		}
		if r < 0x20 {
			return r, true
		}
	}
	return 0, false
}

// seatbeltProfile builds the SBPL profile confining a run to its workspace.
func seatbeltProfile(workspace string) (string, error) {
	if bad, unsafe := sbplUnsafe(workspace); unsafe {
		return "", modberr.Newf(modberr.CodePolicyDenied,
			"workspace path contains character %q, which cannot appear in a sandbox profile", bad).
			WithDetail("constraint", "filesystem_scope")
	}
	if !filepath.IsAbs(workspace) {
		return "", modberr.New(modberr.CodeInvalidArgument,
			"a sandbox profile requires an absolute workspace path").
			WithDetail("field", "workspace")
	}

	var b strings.Builder
	b.WriteString("(version 1)\n")
	// Deny by default. Every allowance below is one somebody had to write down, which is the
	// property that makes the profile reviewable.
	b.WriteString("(deny default)\n")
	// EXE-6: egress denied. Destination policy lives in the gateway's egress allowlist, not here — a
	// tool has no business reaching the network at all.
	//
	// This is defence in depth rather than the mechanism: (deny default) above already refuses
	// network, and removing this line changes no observable behaviour today. Measured both ways —
	// deny-default with no network line refuses a connect, and allow-default with only this line
	// also refuses one — so the line is what keeps egress denied if the default is ever loosened for
	// a compatibility reason. Left in deliberately, and labelled so the next reader does not delete
	// it as redundant.
	b.WriteString("(deny network*)\n")
	b.WriteString("(allow process-exec)\n")
	b.WriteString("(allow process-fork)\n")
	b.WriteString("(allow sysctl-read)\n")
	b.WriteString("(allow mach-lookup)\n")
	// Reads stay broad: a build reads toolchains, headers, and libraries from all over the system,
	// and narrowing that is a compatibility project rather than a confinement one. EXE-4 is about
	// scope of *writes*; what must not leave is covered by the egress deny above and by the
	// classifier deciding what is ever read into an index.
	b.WriteString("(allow file-read*)\n")
	b.WriteString("(allow file-write*\n  (subpath \"")
	b.WriteString(workspace)
	b.WriteString("\"))\n")
	// A process needs somewhere for temporary files. Allowing the system temp directory was the
	// first attempt and it made the enforcement claim false: the conformance suite's escape probe
	// writes to os.TempDir(), and it succeeded. Toolchains get a temp directory *inside* the
	// workspace instead, with TMPDIR pointed at it, so the claim and the profile agree.
	b.WriteString("(allow file-write-data\n  (literal \"/dev/null\")\n  (literal \"/dev/stdout\")\n  (literal \"/dev/stderr\"))\n")
	return b.String(), nil
}

func writeProfile(profile string) (string, error) {
	file, err := os.CreateTemp("", "modbit-sandbox-*.sb")
	if err != nil {
		return "", modberr.Wrap(err, modberr.CodeUnavailable, "sandbox profile could not be created")
	}
	defer file.Close()
	if _, err := file.WriteString(profile); err != nil {
		_ = os.Remove(file.Name())
		return "", modberr.Wrap(err, modberr.CodeUnavailable, "sandbox profile could not be written")
	}
	return file.Name(), nil
}
