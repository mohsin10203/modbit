package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// ProcessBackend is the portable reference backend: an ordinary child process in a workspace
// directory, with a wall-clock bound and process-group cleanup.
//
// # What it does not do, and why that is the point
//
// It declares almost every control unsupported, and that declaration is the deliverable. Go's
// standard library offers no portable way to confine a child's filesystem access, deny its network
// egress, or cap its CPU and memory: syscall.Setrlimit applies to the calling process rather than a
// child, and darwin's SysProcAttr carries no namespace, seccomp, or rlimit fields at all. A backend
// that set a working directory and called that "filesystem scope" would be reporting an advisory
// arrangement as an enforced one, which is exactly what SBX-3 forbids.
//
// So this backend is honest about being weak, and the contract makes that honesty consequential: a
// run whose profile requires filesystem scope or network deny cannot establish against it (SBX-6),
// and a profile demanding container strength cannot select it (SBX-4). Real confinement arrives with
// the native backends — Seatbelt on macOS, namespaces and seccomp on Linux, and a container or
// microVM runtime for higher strengths — each of which is a platform decision under ADR-0100 and is
// tracked separately.
//
// It remains useful: a local Ask or Plan run executes no repository code, and a developer's own
// machine running their own tests is not a confinement problem. What it must never do is let a
// higher-risk profile believe it is confined.
type ProcessBackend struct {
	mu       sync.Mutex
	sessions map[id.ID]*processSession
}

// processWaitDelay bounds how long Run may block after cancellation has been signalled.
//
// It is the backstop behind the process-group kill, not a substitute for it: a descendant that left
// the group, or one stuck in uninterruptible I/O, still holds the inherited output pipe and would
// otherwise keep Wait parked for as long as it lives. Two seconds is long enough that a process
// being killed normally is never cut short, and short enough that a caller's cancellation still
// means something. Exceeding it costs the tail of that command's output, which is the correct thing
// to lose when the alternative is not returning.
const processWaitDelay = 2 * time.Second

type processSession struct {
	workspace string
	// ownWorkspace records that this backend created the directory, so cleanup removes only what it
	// made. Deleting a caller-supplied workspace would destroy a user's checkout.
	ownWorkspace bool
}

// NewProcessBackend returns the portable backend.
func NewProcessBackend() *ProcessBackend {
	return &ProcessBackend{sessions: make(map[id.ID]*processSession)}
}

var _ Backend = (*ProcessBackend)(nil)

// Capabilities implements Backend.
//
// Every entry here is a claim the conformance suite checks. `hook_suppression` is enforced because
// it is done by clearing the child's environment and pointing git at an empty hooks path — a control
// that needs no kernel support. Process confinement is advisory rather than enforced: the child is
// put in its own process group so cleanup can kill the tree, but a determined process can leave that
// group, and saying "enforced" would be the SBX-3 violation this type exists to demonstrate against.
func (b *ProcessBackend) Capabilities() Capabilities {
	return Capabilities{
		ContractVersion: ContractVersion,
		Backend:         "process",
		Strength:        StrengthProcess,
		Controls: map[Control]Enforcement{
			ControlWallClockLimit:     EnforcementEnforced,
			ControlHookSuppression:    EnforcementEnforced,
			ControlProcessConfinement: EnforcementAdvisory,
			ControlFilesystemScope:    EnforcementAdvisory,
			// The rest are absent, which is EnforcementUnsupported. Listing them as unsupported
			// would say the same thing; leaving them out keeps the map to what this backend touches.
		},
	}
}

// Establish implements Backend.
func (b *ProcessBackend) Establish(ctx context.Context, spec Spec) (*Session, error) {
	if err := ValidateSpec(spec); err != nil {
		return nil, err
	}
	unmet, err := Check(b.Capabilities(), spec)
	if err != nil {
		return nil, err
	}

	workspace, err := filepath.Abs(spec.Workspace)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInvalidArgument, "workspace path cannot be resolved")
	}
	created := false
	if info, statErr := os.Stat(workspace); errors.Is(statErr, os.ErrNotExist) {
		if err := os.MkdirAll(workspace, 0o755); err != nil {
			return nil, modberr.Wrap(err, modberr.CodeUnavailable, "workspace could not be created")
		}
		created = true
	} else if statErr != nil {
		return nil, modberr.Wrap(statErr, modberr.CodeUnavailable, "workspace could not be inspected")
	} else if !info.IsDir() {
		return nil, modberr.New(modberr.CodeInvalidArgument, "workspace is not a directory").
			WithDetail("field", "workspace")
	}

	sessionID, err := id.New(id.WorkspaceLease)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInternal, "allocate sandbox session id")
	}
	session := &Session{
		ID: sessionID, RunID: spec.RunID, Backend: "process", Strength: StrengthProcess,
		Workspace: workspace, Enforced: b.Capabilities().Enforced(),
		Degraded: len(unmet) > 0, Unmet: unmet, CreatedAt: time.Now().UTC(),
	}
	if session.Degraded {
		session.Rationale = spec.Rationale
	}

	b.mu.Lock()
	b.sessions[sessionID] = &processSession{workspace: workspace, ownWorkspace: created}
	b.mu.Unlock()
	return session, nil
}

// Run implements Backend.
func (b *ProcessBackend) Run(ctx context.Context, session *Session, cmd Command) (Result, error) {
	return b.runWith(ctx, session, cmd, nil)
}

// runWith is Run with a hook that a native backend uses to add isolation to the prepared command.
//
// The hook runs after the workspace, environment, hook suppression and process group are set and
// before the command starts. It exists so `SeatbeltBackend` and `LinuxBackend` add confinement to
// *this* command rather than assembling their own: EXE-7's environment scrubbing and EXE-9's
// wall-clock bound are properties of every sandboxed run, and a backend that rebuilt the command
// would eventually rebuild them differently. The two would then drift apart silently, which is the
// failure SBX-1's single contract exists to prevent.
//
// The hook returns a cleanup that runs once the command has finished, whatever the outcome. That is
// what owns anything whose lifetime is the *command* rather than the session or the context — the
// cgroup descriptor `LinuxBackend` passes through `CgroupFD` is the case in point. Tying it to the
// context instead would leak a descriptor per Run whenever a caller passes `context.Background()`,
// which the conformance suite does.
//
// A hook returning an error aborts before anything is started.
func (b *ProcessBackend) runWith(
	ctx context.Context, session *Session, cmd Command, configure func(*exec.Cmd) (func(), error),
) (Result, error) {
	if session == nil {
		return Result{}, modberr.New(modberr.CodeInvalidArgument, "run requires an established session").
			WithDetail("field", "session")
	}
	b.mu.Lock()
	state, live := b.sessions[session.ID]
	b.mu.Unlock()
	if !live {
		// A cleaned-up session must not run anything: its workspace may be gone, and the caller
		// believing otherwise is how a command lands somewhere unintended.
		return Result{}, modberr.New(modberr.CodeRunStateInvalid, "sandbox session is not established")
	}
	if cmd.Path == "" {
		return Result{}, modberr.New(modberr.CodeInvalidArgument, "a command requires a path").
			WithDetail("field", "path")
	}

	dir := state.workspace
	if cmd.Dir != "" {
		resolved, err := resolveInside(state.workspace, cmd.Dir)
		if err != nil {
			return Result{}, err
		}
		dir = resolved
	}

	exec := exec.CommandContext(ctx, cmd.Path, cmd.Args...)
	exec.Dir = dir
	// EXE-7. The environment is replaced rather than inherited, and git is pointed at an empty hooks
	// directory: a repository-defined hook is code the repository chose, and running it is precisely
	// what CTX-12 and EXE-7 forbid without explicit approval.
	exec.Env = append(suppressHooks(dir), cmd.Env...)
	configureProcessGroup(exec)

	var stdout, stderr bytes.Buffer
	exec.Stdout, exec.Stderr = &stdout, &stderr

	if configure != nil {
		cleanup, err := configure(exec)
		if err != nil {
			return Result{}, err
		}
		if cleanup != nil {
			defer cleanup()
		}
	}

	started := time.Now()
	runErr := exec.Run()
	result := Result{
		Stdout: stdout.String(), Stderr: stderr.String(), Duration: time.Since(started),
	}
	if exec.ProcessState != nil {
		result.ExitCode = exec.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		result.TimedOut = true
	}
	if runErr != nil && result.ExitCode == 0 && !result.TimedOut {
		// A failure with no exit status is a start failure, not a non-zero exit, and reporting it as
		// exit 0 would let a command that never ran pass as a success.
		return result, modberr.Wrap(runErr, modberr.CodeSandboxUnavailable, "command could not be executed")
	}
	return result, nil
}

// Cleanup implements Backend.
func (b *ProcessBackend) Cleanup(_ context.Context, session *Session) error {
	if session == nil {
		return nil
	}
	b.mu.Lock()
	state, live := b.sessions[session.ID]
	delete(b.sessions, session.ID)
	b.mu.Unlock()
	if !live {
		// Idempotent: a caller unwinding through two paths must not fail the second time.
		return nil
	}
	if !state.ownWorkspace {
		// Only what this backend created is removed. Deleting a caller-supplied workspace would
		// destroy a user's checkout.
		return nil
	}
	if err := os.RemoveAll(state.workspace); err != nil {
		return modberr.Wrap(err, modberr.CodeUnavailable, "workspace could not be removed")
	}
	return nil
}

// resolveInside refuses a working directory that escapes the workspace.
//
// EXE-9. This is advisory, not enforcement, and the capability declaration says so: it stops a
// caller pointing the command outside the workspace, and does nothing about the command walking out
// once it is running. The check exists because catching the easy case is still worth doing; claiming
// it as confinement is what would not be.
func resolveInside(workspace, dir string) (string, error) {
	candidate := dir
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(workspace, dir)
	}
	resolved, err := filepath.Abs(candidate)
	if err != nil {
		return "", modberr.Wrap(err, modberr.CodeInvalidArgument, "working directory cannot be resolved")
	}
	// EvalSymlinks so a link inside the workspace pointing out of it is caught too.
	if real, err := filepath.EvalSymlinks(resolved); err == nil {
		resolved = real
	}
	root, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		root = workspace
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || filepath.IsAbs(rel) ||
		(len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator)) {
		return "", modberr.New(modberr.CodePolicyDenied,
			"working directory escapes the workspace").WithDetail("constraint", "filesystem_scope")
	}
	return resolved, nil
}

// suppressHooks builds a minimal environment that disables repository-defined git hooks (EXE-7).
func suppressHooks(dir string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		// An empty hooks path is what stops a committed hook running; core.hooksPath in the
		// repository's own config cannot override an environment override.
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=core.hooksPath",
		"GIT_CONFIG_VALUE_0=" + filepath.Join(dir, ".modbit-no-hooks"),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
	}
}
