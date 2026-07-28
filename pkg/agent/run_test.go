package agent_test

import (
	"context"
	"errors"
	"testing"

	"github.com/modbit/modbit/pkg/agent"
	"github.com/modbit/modbit/pkg/event"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// recorder captures emitted envelopes so a test can assert on the record rather than on the run's
// own account of itself.
type recorder struct {
	envelopes []event.Envelope
	failAfter int // when > 0, Emit fails once the count is reached
	emitted   int
}

func (r *recorder) Emit(e event.Envelope) error {
	r.emitted++
	if r.failAfter > 0 && r.emitted > r.failAfter {
		return errors.New("event store unavailable")
	}
	r.envelopes = append(r.envelopes, e)
	return nil
}

func (r *recorder) types() []event.Type {
	out := make([]event.Type, 0, len(r.envelopes))
	for _, e := range r.envelopes {
		out = append(out, e.EventType)
	}
	return out
}

func (r *recorder) count(t event.Type) int {
	n := 0
	for _, e := range r.envelopes {
		if e.EventType == t {
			n++
		}
	}
	return n
}

func testEnvironment() agent.Environment {
	return agent.Environment{
		Revision:         "abc123",
		WorktreePath:     "/repo",
		ToolDigest:       "sha256:tools",
		PolicySnapshotID: id.MustNew(id.SettingsSnapshot),
	}
}

func testOptions(mode agent.Mode) agent.Options {
	return agent.Options{
		RunID:          id.MustNew(id.Run),
		OrganizationID: id.MustNew(id.Organization),
		SpaceID:        id.MustNew(id.Space),
		Mode:           mode,
		Environment:    testEnvironment(),
		InputsDigest:   "sha256:inputs",
		LoopBudget:     3,
		Actor:          event.Actor{Type: event.ActorUser, ID: "u_1"},
	}
}

func newRun(t *testing.T, opts agent.Options) (*agent.Run, *recorder) {
	t.Helper()
	rec := &recorder{}
	builder, err := event.NewBuilder(opts.OrganizationID, event.SystemClock{}, nil)
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	run, err := agent.New(opts, builder, event.NewMemorySequencer(), rec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return run, rec
}

// runTo drives a run forward to the named phase, failing the test on any refusal.
func runTo(t *testing.T, run *agent.Run, target agent.Phase) {
	t.Helper()
	if err := run.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for run.Phase() != target {
		if err := run.Advance(context.Background()); err != nil {
			t.Fatalf("Advance from %s toward %s: %v", run.Phase(), target, err)
		}
	}
}

// A1. R-EVT-04 requires the state write and the event to be one act. A run that advanced with no
// event, or an event for a transition that did not happen, is the failure the rule prevents.
func TestEveryTransitionIsRecorded(t *testing.T) {
	run, rec := newRun(t, testOptions(agent.ModeCode))
	runTo(t, run, agent.PhaseComplete)

	plan := run.Plan()
	// One run.created, then one phase.changed and one checkpoint.created per phase entered.
	if got := rec.count(event.TypeRunCreated); got != 1 {
		t.Fatalf("run.created = %d, want 1", got)
	}
	if got := rec.count(event.TypeRunPhaseChanged); got != len(plan) {
		t.Fatalf("phase.changed = %d, want %d (one per phase)", got, len(plan))
	}
	if got := rec.count(event.TypeRunCheckpointCreated); got != len(plan) {
		t.Fatalf("checkpoint.created = %d, want %d", got, len(plan))
	}

	// A transition whose event cannot be recorded did not happen. Reporting success while the record
	// is missing is precisely the divergence R-EVT-04 exists to stop.
	failing, failRec := newRun(t, testOptions(agent.ModeCode))
	if err := failing.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	before := failing.Phase()
	failRec.failAfter = failRec.emitted
	if err := failing.Advance(context.Background()); err == nil {
		t.Fatal("an unrecordable transition must be refused")
	}
	if failing.Phase() != before {
		t.Fatalf("phase advanced to %s despite the event failing; it should still be %s",
			failing.Phase(), before)
	}
}

// A1, second half: the sequence is monotonic per run, or the log cannot be reassembled
// (R-EVT-01, R-EVT-07).
func TestEventSequenceIsMonotonic(t *testing.T) {
	run, rec := newRun(t, testOptions(agent.ModeCode))
	runTo(t, run, agent.PhaseComplete)
	if err := run.Halt(context.Background(), agent.HaltCompleted); err != nil {
		t.Fatalf("Halt: %v", err)
	}

	var last uint64
	for i, e := range rec.envelopes {
		if e.Sequence <= last && i > 0 {
			t.Fatalf("sequence went backwards at %d: %d after %d", i, e.Sequence, last)
		}
		last = e.Sequence
	}
}

// A2. RUN-4's set is closed, a run halts for exactly one of them, and a halted run is over.
func TestARunHaltsOnceForOneClosedReason(t *testing.T) {
	for _, reason := range []agent.HaltReason{
		agent.HaltCompleted, agent.HaltFailed, agent.HaltInconclusive, agent.HaltBudgetExhausted,
		agent.HaltPolicyDenied, agent.HaltApprovalDenied, agent.HaltCancelled, agent.HaltSuperseded,
		agent.HaltInfrastructureFailure,
	} {
		t.Run(string(reason), func(t *testing.T) {
			run, _ := newRun(t, testOptions(agent.ModeCode))
			runTo(t, run, agent.PhaseExecute)

			if err := run.Halt(context.Background(), reason); err != nil {
				t.Fatalf("Halt(%s): %v", reason, err)
			}
			halted, halt := run.Halted()
			if !halted || halt.Reason != reason {
				t.Fatalf("halted = %v, reason = %q, want true and %q", halted, halt.Reason, reason)
			}

			// Halting twice would give one run two endings.
			if err := run.Halt(context.Background(), agent.HaltFailed); !modberr.Is(err, modberr.CodeRunStateInvalid) {
				t.Fatalf("second halt returned %v, want a refusal", err)
			}
			// A halted run cannot transition.
			if err := run.Advance(context.Background()); !modberr.Is(err, modberr.CodeRunStateInvalid) {
				t.Fatalf("advance after halt returned %v, want a refusal", err)
			}
		})
	}

	run, _ := newRun(t, testOptions(agent.ModeCode))
	runTo(t, run, agent.PhaseIntake)
	if err := run.Halt(context.Background(), "something-else"); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("an unknown halt reason returned %v, want a refusal", err)
	}
}

// A3, A9. The plan is the authority, which is what makes "Ask cannot execute" structural rather than
// a rule somebody remembers. An Ask run that could reach execute would be a read-only mode with
// write access — the exact thing a user picks Ask to avoid.
func TestSecurityAskModeCanNeverExecute(t *testing.T) {
	run, rec := newRun(t, testOptions(agent.ModeAsk))
	runTo(t, run, agent.PhaseComplete)

	for _, forbidden := range []agent.Phase{
		agent.PhaseExecute, agent.PhaseAuthorize, agent.PhaseObserve,
		agent.PhaseVerify, agent.PhaseReview, agent.PhasePackage, agent.PhasePlan,
	} {
		if err := run.To(context.Background(), forbidden); !modberr.Is(err, modberr.CodeRunStateInvalid) {
			t.Fatalf("Ask reached %s: %v", forbidden, err)
		}
	}
	// The plan itself must not contain them, or the refusal above is a runtime check standing in
	// for a structural guarantee.
	for _, phase := range run.Plan() {
		if phase == agent.PhaseExecute || phase == agent.PhaseAuthorize {
			t.Fatalf("Ask mode's plan contains %s", phase)
		}
	}

	// A7: a refused transition emits nothing.
	before := len(rec.envelopes)
	_ = run.To(context.Background(), agent.PhaseExecute)
	if len(rec.envelopes) != before {
		t.Fatalf("a refused transition emitted %d events", len(rec.envelopes)-before)
	}
}

// A3. Plan mode stops before authorization: it produces a plan and does not act on it.
func TestPlanModeStopsBeforeAuthorization(t *testing.T) {
	run, _ := newRun(t, testOptions(agent.ModePlan))
	runTo(t, run, agent.PhasePlan)

	for _, forbidden := range []agent.Phase{agent.PhaseAuthorize, agent.PhaseExecute} {
		if err := run.To(context.Background(), forbidden); !modberr.Is(err, modberr.CodeRunStateInvalid) {
			t.Fatalf("Plan reached %s: %v", forbidden, err)
		}
	}
}

// A4. RUN-3 and COR-5: loops are bounded, and exhausting the bound halts rather than spinning. A run
// that could not loop and could not stop would sit at a failing phase forever.
func TestLoopsAreBoundedAndExhaustionHalts(t *testing.T) {
	opts := testOptions(agent.ModeCode)
	opts.LoopBudget = 2
	run, _ := newRun(t, opts)
	runTo(t, run, agent.PhaseVerify)

	// Two permitted loops back to execute.
	for i := range 2 {
		if err := run.To(context.Background(), agent.PhaseExecute); err != nil {
			t.Fatalf("loop %d refused: %v", i+1, err)
		}
		if err := run.Advance(context.Background()); err != nil { // execute -> observe
			t.Fatalf("advance after loop %d: %v", i+1, err)
		}
		if err := run.Advance(context.Background()); err != nil { // observe -> verify
			t.Fatalf("advance after loop %d: %v", i+1, err)
		}
	}
	if run.LoopsUsed() != 2 {
		t.Fatalf("loops used = %d, want 2", run.LoopsUsed())
	}

	// The third exhausts the budget: it must halt, not merely refuse.
	err := run.To(context.Background(), agent.PhaseExecute)
	if !modberr.Is(err, modberr.CodeBudgetExhausted) {
		t.Fatalf("error = %v, want budget exhausted", err)
	}
	halted, halt := run.Halted()
	if !halted || halt.Reason != agent.HaltBudgetExhausted {
		t.Fatalf("halted = %v reason = %q, want a budget_exhausted halt", halted, halt.Reason)
	}
}

// A4, second half: only declared backward edges are loops at all. An arbitrary jump backwards would
// let a run re-enter authorization after executing, which is how an approved plan becomes a
// different one.
func TestOnlyDeclaredLoopBacksAreAllowed(t *testing.T) {
	run, _ := newRun(t, testOptions(agent.ModeCode))
	runTo(t, run, agent.PhaseVerify)

	for _, forbidden := range []agent.Phase{
		agent.PhaseAuthorize, agent.PhaseClarify, agent.PhaseRetrieve, agent.PhaseIntake,
	} {
		if err := run.To(context.Background(), forbidden); !modberr.Is(err, modberr.CodeRunStateInvalid) {
			t.Fatalf("verify looped back to %s: %v", forbidden, err)
		}
	}
	if run.LoopsUsed() != 0 {
		t.Fatalf("a refused loop consumed budget: %d", run.LoopsUsed())
	}
}

// A7. Skipping forward would step over a phase the plan requires — authorization most dangerously,
// since its omission changes what the run is allowed to do.
func TestSecurityAuthorizationCannotBeSkipped(t *testing.T) {
	run, rec := newRun(t, testOptions(agent.ModeCode))
	runTo(t, run, agent.PhasePlan)

	before := len(rec.envelopes)
	if err := run.To(context.Background(), agent.PhaseExecute); !modberr.Is(err, modberr.CodeRunStateInvalid) {
		t.Fatalf("plan skipped straight to execute: %v", err)
	}
	if len(rec.envelopes) != before {
		t.Fatal("a refused transition emitted an event")
	}
	if run.Phase() != agent.PhasePlan {
		t.Fatalf("phase moved to %s despite the refusal", run.Phase())
	}

	// The legal route still works, so the refusal is the skip being caught rather than the machine
	// being stuck.
	if err := run.Advance(context.Background()); err != nil {
		t.Fatalf("plan -> authorize: %v", err)
	}
	if run.Phase() != agent.PhaseAuthorize {
		t.Fatalf("phase = %s, want authorize", run.Phase())
	}
}

// A5. RUN-2: every phase entered produces a checkpoint. Taking it on entry means a run that dies
// mid-phase resumes at the start of that phase rather than at the end of the last one.
func TestEveryPhaseProducesACheckpoint(t *testing.T) {
	run, _ := newRun(t, testOptions(agent.ModeCode))
	runTo(t, run, agent.PhaseComplete)

	checkpoints := run.Checkpoints()
	plan := run.Plan()
	if len(checkpoints) != len(plan) {
		t.Fatalf("checkpoints = %d, want %d (one per phase)", len(checkpoints), len(plan))
	}
	for i, cp := range checkpoints {
		if cp.Phase != plan[i] {
			t.Fatalf("checkpoint %d is for %s, want %s", i, cp.Phase, plan[i])
		}
		if cp.RunID != run.Checkpoints()[0].RunID {
			t.Fatalf("checkpoint %d belongs to another run", i)
		}
		if cp.EnvironmentDigest == "" || cp.InputsDigest == "" {
			t.Fatalf("checkpoint %d records nothing to validate a resume against: %+v", i, cp)
		}
	}
}

// A6. RUN-5 and RUN-6: resuming into a moved tree would apply a plan built for one revision to
// another, and nothing downstream could tell — the run would look like it had simply continued.
func TestSecurityResumeIsRefusedAfterDrift(t *testing.T) {
	opts := testOptions(agent.ModeCode)
	run, _ := newRun(t, opts)
	runTo(t, run, agent.PhaseExecute)
	cp := run.Checkpoints()[len(run.Checkpoints())-1]

	build := func(o agent.Options) error {
		rec := &recorder{}
		builder, err := event.NewBuilder(o.OrganizationID, event.SystemClock{}, nil)
		if err != nil {
			return err
		}
		_, err = agent.Resume(context.Background(), cp, o, builder, event.NewMemorySequencer(), rec)
		return err
	}

	drifts := map[string]func(*agent.Options){
		"revision moved":  func(o *agent.Options) { o.Environment.Revision = "def456" },
		"worktree moved":  func(o *agent.Options) { o.Environment.WorktreePath = "/elsewhere" },
		"tools changed":   func(o *agent.Options) { o.Environment.ToolDigest = "sha256:different" },
		"policy replaced": func(o *agent.Options) { o.Environment.PolicySnapshotID = id.MustNew(id.SettingsSnapshot) },
		"inputs changed":  func(o *agent.Options) { o.InputsDigest = "sha256:other" },
	}
	for name, drift := range drifts {
		t.Run(name, func(t *testing.T) {
			drifted := opts
			drift(&drifted)
			if err := build(drifted); !modberr.Is(err, modberr.CodeSnapshotDiverged) {
				t.Fatalf("error = %v, want snapshot diverged", err)
			}
		})
	}

	// The control: an unchanged environment resumes, so the refusals above are drift detection
	// working rather than resume being broken.
	if err := build(opts); err != nil {
		t.Fatalf("an unchanged environment must resume: %v", err)
	}
}

// A6, second half: a resumed run cannot reset its own bound. Without carrying the loop count,
// resume would be an unbounded-loop primitive — fail, resume, fail, resume.
func TestSecurityResumeCannotResetTheLoopBudget(t *testing.T) {
	opts := testOptions(agent.ModeCode)
	opts.LoopBudget = 2
	run, _ := newRun(t, opts)
	runTo(t, run, agent.PhaseVerify)

	if err := run.To(context.Background(), agent.PhaseExecute); err != nil {
		t.Fatalf("loop: %v", err)
	}
	if run.LoopsUsed() != 1 {
		t.Fatalf("loops used = %d, want 1", run.LoopsUsed())
	}
	cp := run.Checkpoints()[len(run.Checkpoints())-1]
	if cp.LoopsUsed != 1 {
		t.Fatalf("checkpoint recorded %d loops, want 1", cp.LoopsUsed)
	}

	rec := &recorder{}
	builder, err := event.NewBuilder(opts.OrganizationID, event.SystemClock{}, nil)
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	resumed, err := agent.Resume(context.Background(), cp, opts, builder, event.NewMemorySequencer(), rec)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if resumed.LoopsUsed() != 1 {
		t.Fatalf("resumed run reports %d loops used, want 1 — the budget was reset", resumed.LoopsUsed())
	}
}

// A8. A cancelled run that did not say where it stopped leaves a reviewer unable to tell one
// cancelled during retrieval from one cancelled halfway through writing files.
func TestAHaltRecordsWhereItInterruptedTheRun(t *testing.T) {
	run, rec := newRun(t, testOptions(agent.ModeCode))
	runTo(t, run, agent.PhaseExecute)

	if err := run.Halt(context.Background(), agent.HaltCancelled); err != nil {
		t.Fatalf("Halt: %v", err)
	}
	_, halt := run.Halted()
	if halt.InterruptedAt != agent.PhaseExecute {
		t.Fatalf("interrupted at %q, want execute", halt.InterruptedAt)
	}
	if halt.Checkpoints == 0 {
		t.Fatal("the halt records no checkpoints; a resume would have nothing to start from")
	}
	if halt.At.IsZero() {
		t.Fatal("the halt records no time")
	}
	// Cancellation has its own canonical event; it must not be reported as an ordinary failure.
	if rec.count(event.TypeRunCancelled) != 1 {
		t.Fatalf("run.cancelled = %d, want 1: %v", rec.count(event.TypeRunCancelled), rec.types())
	}
	if rec.count(event.TypeRunFailed) != 0 {
		t.Fatal("a cancelled run also emitted run.failed")
	}
}

// Halt reasons map onto distinct canonical events, because a consumer filtering the audit log for
// failures must not also catch deliberate cancellations, and vice versa.
func TestHaltReasonsMapToDistinctEvents(t *testing.T) {
	cases := map[agent.HaltReason]event.Type{
		agent.HaltCompleted:             event.TypeRunCompleted,
		agent.HaltFailed:                event.TypeRunFailed,
		agent.HaltInfrastructureFailure: event.TypeRunFailed,
		agent.HaltCancelled:             event.TypeRunCancelled,
		agent.HaltPolicyDenied:          event.TypeRunHalted,
		agent.HaltApprovalDenied:        event.TypeRunHalted,
		agent.HaltBudgetExhausted:       event.TypeRunHalted,
		agent.HaltInconclusive:          event.TypeRunHalted,
		agent.HaltSuperseded:            event.TypeRunHalted,
	}
	for reason, want := range cases {
		t.Run(string(reason), func(t *testing.T) {
			run, rec := newRun(t, testOptions(agent.ModeAsk))
			runTo(t, run, agent.PhaseIntake)
			if err := run.Halt(context.Background(), reason); err != nil {
				t.Fatalf("Halt: %v", err)
			}
			if rec.count(want) != 1 {
				t.Fatalf("%s emitted %v, want one %s", reason, rec.types(), want)
			}
		})
	}
}

// A run assembled without its collaborators would advance leaving no record, which is RUN-1 with
// the requirement removed.
func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	valid := testOptions(agent.ModeCode)
	builder, err := event.NewBuilder(valid.OrganizationID, event.SystemClock{}, nil)
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}

	mutate := map[string]func(*agent.Options){
		"no run id":          func(o *agent.Options) { o.RunID = "" },
		"no organization":    func(o *agent.Options) { o.OrganizationID = "" },
		"no space":           func(o *agent.Options) { o.SpaceID = "" },
		"unknown mode":       func(o *agent.Options) { o.Mode = "telepathy" },
		"negative loop cost": func(o *agent.Options) { o.LoopBudget = -1 },
	}
	for name, fn := range mutate {
		t.Run(name, func(t *testing.T) {
			opts := valid
			fn(&opts)
			if _, err := agent.New(opts, builder, event.NewMemorySequencer(), &recorder{}); !modberr.Is(err, modberr.CodeInvalidArgument) {
				t.Fatalf("error = %v, want a refusal", err)
			}
		})
	}

	if _, err := agent.New(valid, nil, event.NewMemorySequencer(), &recorder{}); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("a run with no builder returned %v, want a refusal", err)
	}
	if _, err := agent.New(valid, builder, nil, &recorder{}); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("a run with no sequencer returned %v, want a refusal", err)
	}
	if _, err := agent.New(valid, builder, event.NewMemorySequencer(), nil); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("a run with no emitter returned %v, want a refusal", err)
	}
}

// A mode that is valid by contract but unimplemented must say "not yet" rather than "unknown", and
// must not silently fall back to a mode the user did not choose.
func TestUnimplementedModesAreRefusedByName(t *testing.T) {
	valid := testOptions(agent.ModeCode)
	builder, err := event.NewBuilder(valid.OrganizationID, event.SystemClock{}, nil)
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}

	for _, mode := range []agent.Mode{agent.ModeDebug, agent.ModeReview, agent.ModeVerify} {
		t.Run(string(mode), func(t *testing.T) {
			opts := valid
			opts.Mode = mode
			_, err := agent.New(opts, builder, event.NewMemorySequencer(), &recorder{})
			if !modberr.Is(err, modberr.CodeCapabilityUnavailable) {
				t.Fatalf("error = %v, want capability unavailable", err)
			}
		})
	}
}

// A run cannot be started twice, and cannot transition before it starts.
func TestARunMustStartExactlyOnce(t *testing.T) {
	run, _ := newRun(t, testOptions(agent.ModeCode))

	if err := run.Advance(context.Background()); !modberr.Is(err, modberr.CodeRunStateInvalid) {
		t.Fatalf("advance before start returned %v, want a refusal", err)
	}
	if err := run.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := run.Start(context.Background()); !modberr.Is(err, modberr.CodeRunStateInvalid) {
		t.Fatalf("second start returned %v, want a refusal", err)
	}
	if run.Phase() != agent.PhaseIntake {
		t.Fatalf("phase = %s, want intake", run.Phase())
	}
}

// Advancing past the last phase is a refusal, not a silent no-op: a caller looping on Advance would
// otherwise spin forever at complete.
func TestAdvancingPastTheLastPhaseIsRefused(t *testing.T) {
	run, _ := newRun(t, testOptions(agent.ModeAsk))
	runTo(t, run, agent.PhaseComplete)

	if err := run.Advance(context.Background()); !modberr.Is(err, modberr.CodeRunStateInvalid) {
		t.Fatalf("error = %v, want a refusal at the last phase", err)
	}
}
