// Package sandbox defines the execution backend contract and its conformance suite.
//
// SBX-1 requires native process isolation, containers, and microVMs to implement one versioned
// contract. SBX-3 is the reason the contract looks the way it does: a backend must not report a
// policy as enforced when it is advisory, so enforcement level is a declared, per-control value
// rather than a boolean the caller infers.
//
// # Invariants (X1–X8)
//
// One test each in sandbox_test.go. A test without an X-number, or an X-number without a test, is a
// gap.
//
//	X1 A backend declares an enforcement level for every control; there is no default.
//	X2 A control a backend cannot enforce is never reported as enforced.
//	X3 A spec requiring a control the backend does not enforce fails closed at establishment.
//	X4 Degraded isolation requires an explicit, recorded permission.
//	X5 Every backend answers one versioned contract.
//	X6 Isolation strength is ordered, so a profile can require a minimum.
//	X7 The conformance suite covers all ten SBX-5 areas.
//	X8 An unexercised conformance area is not a pass.
package sandbox

import (
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// ContractVersion is the backend contract's version (SBX-1).
//
// It is bumped when a control is added or its meaning changes, so a backend built against an older
// contract is refused rather than silently answering a question it does not understand.
const ContractVersion = 1

// Control is one isolation property a backend may provide.
//
// The set is closed: a backend cannot invent a control, because a control nothing else knows about
// cannot be required by a policy or checked by the conformance suite.
type Control string

const (
	// ControlFilesystemScope confines reads and writes to the workspace (EXE-4, EXE-9).
	ControlFilesystemScope Control = "filesystem_scope"
	// ControlNetworkDeny denies egress by default (EXE-6).
	ControlNetworkDeny Control = "network_deny"
	// ControlProcessConfinement stops a child escaping its process group (EXE-10).
	ControlProcessConfinement Control = "process_confinement"
	// ControlCPULimit bounds CPU consumption (EXE-5).
	ControlCPULimit Control = "cpu_limit"
	// ControlMemoryLimit bounds resident memory (EXE-5).
	ControlMemoryLimit Control = "memory_limit"
	// ControlProcessLimit bounds the process count (EXE-5).
	ControlProcessLimit Control = "process_limit"
	// ControlDiskLimit bounds workspace disk use (EXE-5).
	ControlDiskLimit Control = "disk_limit"
	// ControlWallClockLimit bounds elapsed time (EXE-5).
	ControlWallClockLimit Control = "wall_clock_limit"
	// ControlHookSuppression disables repository-defined hooks (EXE-7).
	ControlHookSuppression Control = "hook_suppression"
)

// Controls returns every control in a stable order, so a report or a diff is reproducible.
func Controls() []Control {
	return []Control{
		ControlFilesystemScope, ControlNetworkDeny, ControlProcessConfinement,
		ControlCPULimit, ControlMemoryLimit, ControlProcessLimit, ControlDiskLimit,
		ControlWallClockLimit, ControlHookSuppression,
	}
}

// Enforcement is how strongly a backend provides a control (SBX-3).
type Enforcement string

const (
	// EnforcementUnsupported is the zero value: the backend does not provide this control at all.
	//
	// X1, X2. It is the zero value deliberately. A capability map that omitted a control would
	// otherwise read as "no answer", and the only safe reading of no answer is "not enforced" —
	// the same reasoning that makes not_run the zero VerifierStatus and user_untrusted the class an
	// unknown provenance resolves to.
	EnforcementUnsupported Enforcement = ""
	// EnforcementAdvisory means the backend configures the control but cannot prevent a determined
	// process from defeating it. SBX-3 exists precisely so this cannot be reported as enforced.
	EnforcementAdvisory Enforcement = "advisory"
	// EnforcementEnforced means the control is imposed by the operating system or hypervisor and a
	// process inside cannot defeat it.
	EnforcementEnforced Enforcement = "enforced"
)

// Enforces reports whether the level is real enforcement.
//
// A method rather than a comparison at each call site: `!= unsupported` is the easy thing to write
// and it silently accepts advisory, which is the exact conflation SBX-3 forbids.
func (e Enforcement) Enforces() bool { return e == EnforcementEnforced }

// Strength is a backend's overall isolation strength (SBX-4).
//
// Ordered so a profile can require a minimum, which is the whole point of SBX-4 — "at least a
// container" has to be expressible as a comparison.
type Strength int

const (
	// StrengthNone is a backend providing no enforced isolation.
	StrengthNone Strength = iota
	// StrengthProcess is OS process isolation.
	StrengthProcess
	// StrengthContainer is namespace and cgroup isolation.
	StrengthContainer
	// StrengthMicroVM is hardware-virtualized isolation.
	StrengthMicroVM
)

func (s Strength) String() string {
	switch s {
	case StrengthProcess:
		return "process"
	case StrengthContainer:
		return "container"
	case StrengthMicroVM:
		return "microvm"
	default:
		return "none"
	}
}

// Capabilities is a backend's declaration of what it provides.
type Capabilities struct {
	// ContractVersion is the contract this backend answers (SBX-1).
	ContractVersion int      `json:"contract_version"`
	Backend         string   `json:"backend"`
	Strength        Strength `json:"strength"`
	// Controls maps each control to its enforcement level. A control absent from the map is
	// unsupported, which is the zero Enforcement.
	Controls map[Control]Enforcement `json:"controls"`
}

// Enforcement returns the level for a control, defaulting to unsupported.
func (c Capabilities) Enforcement(control Control) Enforcement { return c.Controls[control] }

// Enforced returns the controls this backend genuinely enforces, in stable order.
func (c Capabilities) Enforced() []Control {
	var out []Control
	for _, control := range Controls() {
		if c.Controls[control].Enforces() {
			out = append(out, control)
		}
	}
	return out
}

// Spec is a request to establish a sandbox.
type Spec struct {
	RunID id.ID
	// Workspace is the directory the run is confined to.
	Workspace string
	// Required names the controls that must be genuinely enforced. Establishment fails closed if
	// any is not (SBX-6).
	Required []Control
	// MinimumStrength is the isolation strength a high-risk profile demands (SBX-4).
	MinimumStrength Strength
	// AllowDegraded permits establishment despite an unmet requirement.
	//
	// X4. SBX-6 allows degraded isolation only where a documented policy explicitly permits it, so
	// this is paired with Rationale and both are recorded on the Session. A boolean on its own would
	// be a switch somebody flips during an incident with nothing to show for it afterwards.
	AllowDegraded bool
	// Rationale documents why degraded isolation is acceptable. Required when AllowDegraded is set.
	Rationale string
	// WallClock bounds elapsed time.
	WallClock time.Duration
}

// Session is an established sandbox.
type Session struct {
	ID        id.ID    `json:"id"`
	RunID     id.ID    `json:"run_id"`
	Backend   string   `json:"backend"`
	Strength  Strength `json:"strength"`
	Workspace string   `json:"workspace"`
	// Enforced lists the controls actually enforced, which is what evidence records rather than
	// what was asked for.
	Enforced []Control `json:"enforced"`
	// Degraded and Rationale record an establishment that proceeded without a required control.
	Degraded  bool   `json:"degraded,omitempty"`
	Rationale string `json:"rationale,omitempty"`
	// Unmet names the required controls that are not enforced, empty unless Degraded.
	Unmet     []Control `json:"unmet,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Command is something to run inside a sandbox.
type Command struct {
	Path string
	Args []string
	Dir  string
	Env  []string
}

// Result is the outcome of a command.
type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
	// TimedOut reports that the wall-clock bound stopped the command.
	TimedOut bool
	Duration time.Duration
}

// Backend is the versioned execution-backend contract (SBX-1).
type Backend interface {
	// Capabilities declares what this backend provides (SBX-3).
	Capabilities() Capabilities
	// Establish creates a sandbox, or fails closed when a required control is unavailable (SBX-6).
	Establish(ctx context.Context, spec Spec) (*Session, error)
	// Run executes a command inside an established sandbox.
	Run(ctx context.Context, session *Session, cmd Command) (Result, error)
	// Cleanup releases everything the session holds. It is safe to call more than once.
	Cleanup(ctx context.Context, session *Session) error
}

// Check validates a spec against a backend's capabilities and reports what is unmet.
//
// X3, X6. This is the fail-closed gate SBX-6 describes, factored out so a backend cannot implement
// it differently from its peers — SBX-1's "same versioned contract" is worth little if each backend
// decides for itself what "required" means.
func Check(caps Capabilities, spec Spec) (unmet []Control, err error) {
	if caps.ContractVersion != ContractVersion {
		// X5. A backend built against another contract may not understand a control it was asked
		// for, and a silent mismatch would look like enforcement.
		return nil, modberr.Newf(modberr.CodeUnsupportedVersion,
			"backend answers contract version %d, this build requires %d",
			caps.ContractVersion, ContractVersion).
			WithDetail("requested_version", strconv.Itoa(caps.ContractVersion))
	}
	if caps.Strength < spec.MinimumStrength {
		return nil, modberr.Newf(modberr.CodePolicyDenied,
			"backend isolation strength %s is below the required %s",
			caps.Strength, spec.MinimumStrength).
			WithDetail("constraint", "minimum_strength")
	}

	for _, control := range spec.Required {
		// X2. Advisory is not enforced. Accepting it here would make SBX-3's distinction decorative
		// at the only place it decides anything.
		if !caps.Enforcement(control).Enforces() {
			unmet = append(unmet, control)
		}
	}
	if len(unmet) == 0 {
		return nil, nil
	}
	if !spec.AllowDegraded {
		// SBX-6: fail closed.
		return unmet, modberr.Newf(modberr.CodePolicyDenied,
			"backend %q cannot enforce %d required control(s)", caps.Backend, len(unmet)).
			WithDetail("constraint", string(unmet[0]))
	}
	if spec.Rationale == "" {
		// X4. Degraded isolation is permitted only where a documented policy says so. A boolean with
		// no rationale is a switch somebody flips during an incident with nothing to show afterwards.
		return unmet, modberr.New(modberr.CodeInvalidArgument,
			"degraded isolation requires a recorded rationale").
			WithDetail("field", "rationale")
	}
	return unmet, nil
}

// ValidateSpec checks a spec is well formed independently of any backend.
func ValidateSpec(spec Spec) error {
	bad := func(msg, field string) error {
		return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", field)
	}
	if !spec.RunID.HasPrefix(id.Run) {
		return bad("a sandbox spec must name its run", "run_id")
	}
	if spec.Workspace == "" {
		return bad("a sandbox spec must name a workspace", "workspace")
	}
	for _, control := range spec.Required {
		if !slices.Contains(Controls(), control) {
			return bad("unknown control "+string(control), "required")
		}
	}
	return nil
}
