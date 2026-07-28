// Package agent implements the local agent run state machine.
//
// PRD §11.1 specifies a durable workflow graph rather than an unbounded chat loop. That distinction
// is the whole design: a chat loop has no phase to checkpoint, no transition to emit, and no bound
// to exhaust, so none of RUN-1 through RUN-6 can be stated about it, let alone enforced.
//
// # Invariants (A1–A9)
//
// One test each in run_test.go. A test without an A-number, or an A-number without a test, is a gap.
//
//	A1 Every transition emits exactly one event, written with the state change.
//	A2 A run halts for exactly one reason from RUN-4's closed set, and a halted run cannot transition.
//	A3 A run cannot enter a phase its mode's plan does not contain.
//	A4 Loops are bounded; exhausting the budget halts rather than spinning.
//	A5 Every phase entered produces a checkpoint.
//	A6 Resume is refused when the environment or inputs changed.
//	A7 An illegal transition is refused and emits nothing.
//	A8 A cancelled or superseded run records the phase it interrupted.
//	A9 Ask mode can never reach execute.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/modbit/modbit/pkg/event"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// Phase is a run phase. The set and order are PRD §11.1's default sequence.
type Phase string

const (
	PhaseIntake    Phase = "intake"
	PhaseClassify  Phase = "classify"
	PhaseRetrieve  Phase = "retrieve"
	PhaseClarify   Phase = "clarify_or_assume"
	PhasePlan      Phase = "plan"
	PhaseAuthorize Phase = "authorize"
	PhaseExecute   Phase = "execute"
	PhaseObserve   Phase = "observe"
	PhaseVerify    Phase = "verify"
	PhaseReview    Phase = "review"
	PhasePackage   Phase = "package_artifacts"
	PhaseComplete  Phase = "complete_or_escalate"
)

// Mode is the workflow mode a run operates in.
//
// The set matches the `agent.default_mode` settings enum exactly, because that contract is the
// authority and a type that disagreed with it would make a valid setting unrepresentable. Only ask,
// plan, and code have phase plans in this build; the rest are refused by name at construction rather
// than silently falling back to a mode the user did not choose.
type Mode string

const (
	ModeAsk    Mode = "ask"
	ModePlan   Mode = "plan"
	ModeCode   Mode = "code"
	ModeDebug  Mode = "debug"
	ModeReview Mode = "review"
	ModeVerify Mode = "verify"
)

// phasePlans map a mode to the ordered phases it runs. "Not every workflow requires every phase"
// (§11.1), and the differences are the modes' whole meaning: Ask retrieves and answers, Plan stops
// before authorization, Code runs the full sequence.
var phasePlans = map[Mode][]Phase{
	ModeAsk: {
		PhaseIntake, PhaseClassify, PhaseRetrieve, PhaseComplete,
	},
	ModePlan: {
		PhaseIntake, PhaseClassify, PhaseRetrieve, PhaseClarify, PhasePlan, PhaseComplete,
	},
	ModeCode: {
		PhaseIntake, PhaseClassify, PhaseRetrieve, PhaseClarify, PhasePlan, PhaseAuthorize,
		PhaseExecute, PhaseObserve, PhaseVerify, PhaseReview, PhasePackage, PhaseComplete,
	},
}

// loopBacks are the phases a run may return to, and from where. RUN-3 requires bounded loops; these
// are the only backward edges, and each consumes loop budget.
//
// execute→observe→verify is self-correction (COR-1..COR-5): a failing verification returns to
// execute. review→plan is the case where review concludes the plan itself was wrong.
var loopBacks = map[Phase][]Phase{
	PhaseVerify: {PhaseExecute},
	PhaseReview: {PhaseExecute, PhasePlan},
}

// HaltReason is RUN-4's closed set. A run ends for exactly one of these.
type HaltReason string

const (
	HaltCompleted             HaltReason = "completed"
	HaltFailed                HaltReason = "failed"
	HaltInconclusive          HaltReason = "inconclusive"
	HaltBudgetExhausted       HaltReason = "budget_exhausted"
	HaltPolicyDenied          HaltReason = "policy_denied"
	HaltApprovalDenied        HaltReason = "approval_denied"
	HaltCancelled             HaltReason = "cancelled"
	HaltSuperseded            HaltReason = "superseded"
	HaltInfrastructureFailure HaltReason = "infrastructure_failure"
)

var haltReasons = map[HaltReason]bool{
	HaltCompleted: true, HaltFailed: true, HaltInconclusive: true, HaltBudgetExhausted: true,
	HaltPolicyDenied: true, HaltApprovalDenied: true, HaltCancelled: true, HaltSuperseded: true,
	HaltInfrastructureFailure: true,
}

// terminalEvent maps a halt reason onto its canonical event. Completion, failure, and cancellation
// have their own types; the rest share run.halted, which carries the reason.
func (h HaltReason) terminalEvent() event.Type {
	switch h {
	case HaltCompleted:
		return event.TypeRunCompleted
	case HaltFailed, HaltInfrastructureFailure:
		return event.TypeRunFailed
	case HaltCancelled:
		return event.TypeRunCancelled
	default:
		return event.TypeRunHalted
	}
}

// Halt is the record of why and where a run ended.
//
// A8. The interrupted phase is part of the record rather than only the reason. A cancelled run that
// did not say where it stopped leaves a reviewer unable to tell one cancelled during retrieval from
// one cancelled halfway through writing files — the difference between no cleanup and a lot of it.
type Halt struct {
	Reason HaltReason `json:"reason"`
	// InterruptedAt is the phase the run was in when it ended.
	InterruptedAt Phase     `json:"interrupted_at"`
	LoopsUsed     int       `json:"loops_used"`
	Checkpoints   int       `json:"checkpoints"`
	At            time.Time `json:"at"`
}

// Environment is the state a checkpoint is valid against.
//
// RUN-5 permits resume only from a checkpoint whose environment and inputs remain valid, and RUN-6
// makes material drift force revalidation. Both need a value to compare, so the environment is
// captured rather than assumed: a resume that trusted the caller's word would be exactly the
// "resumed into a tree that moved" failure the requirement exists to prevent.
type Environment struct {
	// Revision is the repository revision the run is operating against.
	Revision string
	// WorktreePath is the checkout the run is bound to (CTX-3).
	WorktreePath string
	// ToolDigest covers the tool set and its schemas; a changed tool surface invalidates a plan
	// built against the old one.
	ToolDigest string
	// PolicySnapshotID names the settings snapshot in force.
	PolicySnapshotID id.ID
}

// Digest returns a stable digest of the environment.
func (e Environment) Digest() string {
	encoded, _ := json.Marshal(e)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Checkpoint records a run's position and the state it is valid against (RUN-2).
type Checkpoint struct {
	ID       id.ID  `json:"id"`
	RunID    id.ID  `json:"run_id"`
	Phase    Phase  `json:"phase"`
	Sequence uint64 `json:"sequence"`
	// EnvironmentDigest and InputsDigest are what RUN-5 compares on resume.
	EnvironmentDigest string    `json:"environment_digest"`
	InputsDigest      string    `json:"inputs_digest"`
	PolicySnapshotID  id.ID     `json:"policy_snapshot_id"`
	CreatedAt         time.Time `json:"created_at"`
	// LoopsUsed is carried so a resumed run cannot reset its own bound. Without it, resume would be
	// an unbounded-loop primitive: fail, resume, fail, resume.
	LoopsUsed int `json:"loops_used"`
}

// Options configure a Run.
type Options struct {
	RunID          id.ID
	OrganizationID id.ID
	SpaceID        id.ID
	Mode           Mode
	Environment    Environment
	// InputsDigest covers the request the run was created for.
	InputsDigest string
	// LoopBudget bounds backward transitions (RUN-3, COR-5). It comes from `agent.retry_limit`.
	LoopBudget int
	// Actor attributes every emitted event.
	Actor event.Actor
}

// Emitter records a transition's event together with the state change.
//
// A1. It is one call rather than "change state, then publish", because R-EVT-04 requires the two to
// be atomic and a separate publisher reintroduces the failure the rule prevents: a run that advanced
// with no event, or an event for a transition that did not happen. The gateway's Recorder exists for
// the same reason (MOD-A01j decision 32).
type Emitter interface {
	Emit(envelope event.Envelope) error
}

// Run is a single agent run's state machine.
//
// It is not safe for concurrent use: a run is a sequential workflow, and a mutex here would only
// hide a caller driving one run from two goroutines, which is a bug rather than a supported shape.
type Run struct {
	opts      Options
	builder   *event.Builder
	sequencer event.Sequencer
	emitter   Emitter

	phase       Phase
	plan        []Phase
	started     bool
	halt        *Halt
	loopsUsed   int
	checkpoints []Checkpoint
}

// New returns a run positioned before its first phase.
func New(opts Options, builder *event.Builder, sequencer event.Sequencer, emitter Emitter) (*Run, error) {
	bad := func(msg, field string) (*Run, error) {
		return nil, modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", field)
	}
	if !opts.RunID.HasPrefix(id.Run) {
		return bad("a run requires a run identifier", "run_id")
	}
	if !opts.OrganizationID.HasPrefix(id.Organization) {
		return bad("a run requires an organization", "organization_id")
	}
	if !opts.SpaceID.HasPrefix(id.Space) {
		return bad("a run requires a space", "space_id")
	}
	if builder == nil || emitter == nil || sequencer == nil {
		// A run without these is not a weaker run; it is one whose transitions leave no record,
		// which is RUN-1 with the requirement removed.
		return bad("a run requires an event builder, sequencer, and emitter", "emitter")
	}
	plan, ok := phasePlans[opts.Mode]
	if !ok {
		if opts.Mode == ModeDebug || opts.Mode == ModeReview || opts.Mode == ModeVerify {
			// Named explicitly so the refusal says "not yet" rather than "unknown", and so a
			// settings value that is valid by contract is not reported as invalid.
			return nil, modberr.Newf(modberr.CodeCapabilityUnavailable,
				"%s mode is not available in this build", opts.Mode).
				WithDetail("capability", string(opts.Mode))
		}
		return bad("unknown workflow mode", "mode")
	}
	if opts.LoopBudget < 0 {
		return bad("loop budget cannot be negative", "loop_budget")
	}
	return &Run{
		opts: opts, builder: builder, sequencer: sequencer, emitter: emitter,
		plan: slices.Clone(plan),
	}, nil
}

// Mode reports the run's workflow mode.
func (r *Run) Mode() Mode { return r.opts.Mode }

// Phase reports the current phase. It is empty before Start.
func (r *Run) Phase() Phase { return r.phase }

// Halted reports whether the run has ended, and the record of how. The second value is meaningful
// only when the first is true.
func (r *Run) Halted() (bool, Halt) {
	if r.halt == nil {
		return false, Halt{}
	}
	return true, *r.halt
}

// Plan returns the ordered phases this run will pass through.
func (r *Run) Plan() []Phase { return slices.Clone(r.plan) }

// Checkpoints returns every checkpoint taken, in order.
func (r *Run) Checkpoints() []Checkpoint { return slices.Clone(r.checkpoints) }

// LoopsUsed reports how much of the loop budget has been consumed.
func (r *Run) LoopsUsed() int { return r.loopsUsed }

// Start enters the first phase and emits run.created.
func (r *Run) Start(ctx context.Context) error {
	if r.started {
		return modberr.New(modberr.CodeRunStateInvalid, "run has already started")
	}
	if err := r.emit(ctx, event.TypeRunCreated); err != nil {
		return err
	}
	r.started = true
	return r.enter(ctx, r.plan[0])
}

// Advance moves to the next phase in the plan.
func (r *Run) Advance(ctx context.Context) error {
	next, err := r.nextPhase()
	if err != nil {
		return err
	}
	return r.To(ctx, next)
}

func (r *Run) nextPhase() (Phase, error) {
	idx := slices.Index(r.plan, r.phase)
	if idx < 0 || idx+1 >= len(r.plan) {
		return "", modberr.New(modberr.CodeRunStateInvalid,
			"run is at the last phase of its plan and cannot advance").
			WithDetail("field", "phase")
	}
	return r.plan[idx+1], nil
}

// To transitions to phase, which must be the next phase in the plan or a permitted loop-back.
//
// A7. An illegal transition is refused before anything is emitted or checkpointed, so a rejected
// transition leaves no trace of having been attempted in the run's own state — the refusal is the
// caller's to handle, not a fact about the run.
func (r *Run) To(ctx context.Context, phase Phase) error {
	if err := r.checkLive(); err != nil {
		return err
	}
	// A3, A9. The plan is the authority: a phase absent from it is unreachable for this mode, which
	// is what makes "Ask cannot execute" structural rather than a rule somebody remembers.
	if !slices.Contains(r.plan, phase) {
		return modberr.Newf(modberr.CodeRunStateInvalid,
			"%s mode has no %s phase", r.opts.Mode, phase).
			WithDetail("field", "phase")
	}

	current := slices.Index(r.plan, r.phase)
	target := slices.Index(r.plan, phase)
	switch {
	case target == current+1:
		// Ordinary forward step.
	case target <= current:
		// A4. A backward edge is a loop and must be both permitted and affordable.
		if !slices.Contains(loopBacks[r.phase], phase) {
			return modberr.Newf(modberr.CodeRunStateInvalid,
				"%s cannot return to %s", r.phase, phase).
				WithDetail("field", "phase")
		}
		if r.loopsUsed >= r.opts.LoopBudget {
			// Halting rather than refusing is the point: a run that could not loop and could not
			// stop would sit at a failing phase forever, and RUN-3's bound would be a number nothing
			// enforced. The halt is a real outcome a caller can report.
			if err := r.Halt(ctx, HaltBudgetExhausted); err != nil {
				return err
			}
			return modberr.New(modberr.CodeBudgetExhausted,
				"loop budget exhausted; the run halted").WithDetail("field", "loop_budget")
		}
		r.loopsUsed++
	default:
		// Skipping forward would step over a phase the plan requires — authorization, most
		// dangerously, which is the one phase whose omission changes what the run is allowed to do.
		return modberr.Newf(modberr.CodeRunStateInvalid,
			"cannot skip from %s to %s", r.phase, phase).
			WithDetail("field", "phase")
	}
	return r.enter(ctx, phase)
}

// enter records the transition: one event, one checkpoint, in that order.
func (r *Run) enter(ctx context.Context, phase Phase) error {
	previous := r.phase
	r.phase = phase
	if err := r.emit(ctx, event.TypeRunPhaseChanged); err != nil {
		r.phase = previous // the transition did not happen if it could not be recorded
		return err
	}
	// A5. RUN-2: every phase entered produces a checkpoint. Taking it on entry rather than on exit
	// means a run that dies mid-phase resumes at the start of that phase rather than at the end of
	// the last one, which is the difference between redoing a phase and skipping it.
	return r.checkpoint(ctx)
}

func (r *Run) checkpoint(ctx context.Context) error {
	sequence, err := r.sequencer.Next(ctx, r.opts.RunID)
	if err != nil {
		return modberr.Wrap(err, modberr.CodeInternal, "allocate checkpoint sequence")
	}
	checkpointID, err := id.New(id.Checkpoint)
	if err != nil {
		return modberr.Wrap(err, modberr.CodeInternal, "allocate checkpoint id")
	}
	cp := Checkpoint{
		ID:                checkpointID,
		RunID:             r.opts.RunID,
		Phase:             r.phase,
		Sequence:          sequence,
		EnvironmentDigest: r.opts.Environment.Digest(),
		InputsDigest:      r.opts.InputsDigest,
		PolicySnapshotID:  r.opts.Environment.PolicySnapshotID,
		CreatedAt:         time.Now().UTC(),
		LoopsUsed:         r.loopsUsed,
	}
	if err := r.emitWithSequence(event.TypeRunCheckpointCreated, sequence); err != nil {
		return err
	}
	r.checkpoints = append(r.checkpoints, cp)
	return nil
}

// Halt ends the run.
//
// A2. Exactly one reason, from the closed set, and it is recorded before the run is marked halted so
// a failure to emit does not leave a run that is over with nothing saying so.
func (r *Run) Halt(ctx context.Context, reason HaltReason) error {
	if !haltReasons[reason] {
		return modberr.Newf(modberr.CodeInvalidArgument, "unknown halt reason %q", reason).
			WithDetail("field", "halt_reason")
	}
	if r.halt != nil {
		return modberr.Newf(modberr.CodeRunStateInvalid,
			"run already halted as %s", r.halt.Reason).WithDetail("field", "halt_reason")
	}
	if err := r.emit(ctx, reason.terminalEvent()); err != nil {
		return err
	}
	r.halt = &Halt{
		Reason:        reason,
		InterruptedAt: r.phase,
		LoopsUsed:     r.loopsUsed,
		Checkpoints:   len(r.checkpoints),
		At:            time.Now().UTC(),
	}
	return nil
}

// checkLive refuses any transition on a halted or unstarted run.
func (r *Run) checkLive() error {
	if !r.started {
		return modberr.New(modberr.CodeRunStateInvalid, "run has not started")
	}
	if r.halt != nil {
		return modberr.Newf(modberr.CodeRunStateInvalid,
			"run halted as %s and cannot transition", r.halt.Reason).
			WithDetail("field", "phase")
	}
	return nil
}

// emit allocates a sequence and records one envelope.
//
// There is no payload parameter. The canonical envelope carries payloads by reference
// (Attributes.PayloadRef), not inline, so a map accepted here would be silently discarded — which
// reads as though the detail were recorded and is worse than not offering it. What a halt records
// lives in the Halt value and in the event type.
func (r *Run) emit(ctx context.Context, t event.Type) error {
	sequence, err := r.sequencer.Next(ctx, r.opts.RunID)
	if err != nil {
		return modberr.Wrap(err, modberr.CodeInternal, "allocate event sequence")
	}
	return r.emitWithSequence(t, sequence)
}

func (r *Run) emitWithSequence(t event.Type, sequence uint64) error {
	envelope, err := r.builder.New(t, r.opts.Actor, event.Attributes{
		SpaceID:            r.opts.SpaceID,
		RunID:              r.opts.RunID,
		Sequence:           sequence,
		SettingsSnapshotID: r.opts.Environment.PolicySnapshotID,
	})
	if err != nil {
		return err
	}
	return r.emitter.Emit(envelope)
}

// Resume restores a run from a checkpoint.
//
// A6. RUN-5 and RUN-6: the environment and inputs must still be the ones the checkpoint was taken
// against. Resuming into a moved tree would apply a plan built for one revision to another, and
// nothing downstream could tell — the run would look like it had simply continued.
func Resume(ctx context.Context, cp Checkpoint, opts Options, builder *event.Builder, sequencer event.Sequencer, emitter Emitter) (*Run, error) {
	if cp.RunID != opts.RunID {
		return nil, modberr.New(modberr.CodeInvalidArgument,
			"checkpoint belongs to a different run").WithDetail("field", "run_id")
	}
	if cp.EnvironmentDigest != opts.Environment.Digest() {
		// Material drift forces revalidation rather than a silent continue (RUN-6).
		return nil, modberr.New(modberr.CodeSnapshotDiverged,
			"the environment changed since the checkpoint; the run must be revalidated").
			WithDetail("resource_type", "environment")
	}
	if cp.InputsDigest != opts.InputsDigest {
		return nil, modberr.New(modberr.CodeSnapshotDiverged,
			"the run's inputs changed since the checkpoint").
			WithDetail("resource_type", "inputs")
	}

	run, err := New(opts, builder, sequencer, emitter)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(run.plan, cp.Phase) {
		return nil, modberr.Newf(modberr.CodeInvalidArgument,
			"checkpoint phase %s is not in %s mode's plan", cp.Phase, opts.Mode).
			WithDetail("field", "phase")
	}
	run.started = true
	run.phase = cp.Phase
	// The loop budget is restored, not reset. Resetting it would make resume an unbounded-loop
	// primitive: fail, resume, fail, resume, with RUN-3's bound never reached.
	run.loopsUsed = cp.LoopsUsed
	run.checkpoints = []Checkpoint{cp}
	if err := run.emit(ctx, event.TypeRunResumed); err != nil {
		return nil, err
	}
	return run, nil
}
