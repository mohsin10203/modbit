package agent

import (
	"context"
	"slices"
	"time"

	"github.com/modbit/modbit/pkg/event"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// Steering invariants (Q1–Q8).
//
// STR-1 through STR-7. The queue exists because a message arriving mid-run has to land *somewhere*
// definite: a design that applied user input wherever the agent happened to be reading would make
// "was my correction taken into account" unanswerable, which is what STR-2 exists to prevent.
//
// One test each in steering_test.go. A test without a Q-number, or a Q-number without a test, is a
// gap.
//
//	Q1 The queue is ordered, and the order is stable across reads.
//	Q2 A message has exactly one state; pending is the only state that can change.
//	Q3 Queued steering applies only at a safe boundary.
//	Q4 An interrupt is distinct from queued steering and records what it interrupted.
//	Q5 Reordering is optimistically concurrent; a stale version is refused.
//	Q6 A message that invalidates an authorization is surfaced, never silently incorporated.
//	Q7 Message provenance is an explicit argument; automation follow-ups are not user-trusted.
//	Q8 Every state change emits a canonical event.

// MessageState is a steering message's lifecycle state (STR-2).
//
// The four states are the whole point of the requirement: a user who sent a correction needs to know
// whether it was taken, overtaken, or refused, and "the agent probably saw it" is not one of those.
type MessageState string

const (
	// MessagePending is queued and not yet applied.
	MessagePending MessageState = "pending"
	// MessageIncorporated was applied at a boundary.
	MessageIncorporated MessageState = "incorporated"
	// MessageSuperseded was overtaken by a later message before it could be applied.
	MessageSuperseded MessageState = "superseded"
	// MessageRejected was refused — by policy, or because the run ended first.
	MessageRejected MessageState = "rejected"
)

// MessageKind separates ordinary steering from an interrupt (STR-6).
type MessageKind string

const (
	// KindSteering waits for a safe boundary.
	KindSteering MessageKind = "steering"
	// KindInterrupt stops the current operation now.
	KindInterrupt MessageKind = "interrupt"
)

// Message is one entry in a run's steering queue.
type Message struct {
	ID    id.ID       `json:"id"`
	RunID id.ID       `json:"run_id"`
	Kind  MessageKind `json:"kind"`
	State MessageState
	// Body is the instruction text. It is held here rather than by reference because steering is
	// small, user-authored, and needed synchronously at a boundary.
	Body string
	// Provenance is the taint class of the body (TNT-1).
	//
	// Q7. STR-5 lets automations deliver follow-ups through this same contract, so a message is not
	// necessarily user input — and steering is, by design, content the agent acts on. taint.Class's
	// zero value is user_trusted, so a field left unset would launder an inbound integration payload
	// into the most trusted class in the lattice.
	//
	// What prevents that is Enqueue taking provenance as an explicit positional argument, which Go
	// will not let a caller omit — the same reasoning as MOD-A01 decision 10 for credentials. The
	// Valid check below is a guard against a garbage class, not against an unset one; it cannot be,
	// because user_trusted is both the zero value and a legitimate answer.
	Provenance taint.Class `json:"provenance"`
	// Supersedes names a pending message this one replaces, if any.
	Supersedes id.ID `json:"supersedes,omitempty"`
	// EnqueuedAt and ResolvedAt bound the message's visible lifecycle.
	EnqueuedAt time.Time `json:"enqueued_at"`
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
	// AppliedAt is the phase the message was incorporated at, empty until then.
	AppliedAt Phase `json:"applied_at,omitempty"`
	// InterruptedAt is the phase an interrupt stopped, empty for ordinary steering (STR-6).
	InterruptedAt Phase `json:"interrupted_at,omitempty"`
	// ConflictsWithApproval marks a message that arrived after the run was authorized (Q6).
	ConflictsWithApproval bool `json:"conflicts_with_approval,omitempty"`
}

// Pending reports whether the message is still awaiting a boundary.
func (m Message) Pending() bool { return m.State == MessagePending }

// safeBoundaries are the phases at which queued steering may be applied.
//
// Q3. STR-3 says steering lands at a safe boundary unless the user explicitly cancels the current
// operation. A boundary is safe when incorporating new instruction cannot corrupt work already in
// flight: between phases, not inside one. `execute` is deliberately absent — a message applied
// halfway through a file write changes the intent of an edit that is already partly on disk, and
// nothing downstream could tell which half belonged to which instruction.
var safeBoundaries = map[Phase]bool{
	PhaseIntake:   true,
	PhaseClassify: true,
	PhaseRetrieve: true,
	PhaseClarify:  true,
	PhasePlan:     true,
	PhaseObserve:  true,
	PhaseVerify:   true,
	PhaseReview:   true,
}

// IsSafeBoundary reports whether queued steering may be applied at a phase.
func IsSafeBoundary(p Phase) bool { return safeBoundaries[p] }

// Queue is a run's ordered steering queue (STR-1).
//
// It is not safe for concurrent use, matching Run: a run is a sequential workflow, and a mutex here
// would hide a caller driving one run from two goroutines rather than fix it.
type Queue struct {
	runID      id.ID
	messages   []Message
	byID       map[id.ID]int
	version    int
	emit       func(context.Context, event.Type) error
	authorized bool
}

// NewQueue returns an empty queue bound to a run.
//
// emit records a canonical event per state change (Q8). It is required: a queue whose transitions
// left no record would satisfy STR-2's shape while making its history unreconstructable.
func NewQueue(runID id.ID, emit func(context.Context, event.Type) error) (*Queue, error) {
	if !runID.HasPrefix(id.Run) {
		return nil, modberr.New(modberr.CodeInvalidArgument, "a steering queue requires a run").
			WithDetail("field", "run_id")
	}
	if emit == nil {
		return nil, modberr.New(modberr.CodeInvalidArgument, "a steering queue requires an emitter").
			WithDetail("field", "emit")
	}
	return &Queue{runID: runID, byID: make(map[id.ID]int), emit: emit}, nil
}

// Version is the queue's optimistic-concurrency token. It changes on every mutation.
func (q *Queue) Version() int { return q.version }

// Messages returns every message, in queue order.
func (q *Queue) Messages() []Message { return slices.Clone(q.messages) }

// Pending returns the pending messages, in queue order.
func (q *Queue) Pending() []Message {
	var out []Message
	for _, m := range q.messages {
		if m.Pending() {
			out = append(out, m)
		}
	}
	return out
}

// MarkAuthorized tells the queue the run passed its authorize phase.
//
// Q6. After this point a steering message changes the plan an approval was granted against, so it
// cannot be quietly folded in — that is the same class of problem the approval fence epoch solves
// (REF-03, decision 24), applied to instructions rather than to effects.
func (q *Queue) MarkAuthorized() { q.authorized = true }

// Enqueue appends a message (STR-1).
func (q *Queue) Enqueue(ctx context.Context, kind MessageKind, body string, provenance taint.Class, supersedes id.ID) (Message, error) {
	if kind != KindSteering && kind != KindInterrupt {
		return Message{}, modberr.Newf(modberr.CodeInvalidArgument, "unknown message kind %q", kind).
			WithDetail("field", "kind")
	}
	if body == "" {
		return Message{}, modberr.New(modberr.CodeInvalidArgument, "a message requires a body").
			WithDetail("field", "body")
	}
	if !provenance.Valid() {
		// A garbage class, not an unset one — see Message.Provenance for why the distinction cannot
		// be made here and what enforces the rest.
		return Message{}, modberr.New(modberr.CodeInvalidArgument,
			"a message must declare the provenance of its body").WithDetail("field", "provenance")
	}

	messageID, err := id.New(id.RunMessage)
	if err != nil {
		return Message{}, modberr.Wrap(err, modberr.CodeInternal, "allocate message id")
	}
	msg := Message{
		ID:                    messageID,
		RunID:                 q.runID,
		Kind:                  kind,
		State:                 MessagePending,
		Body:                  body,
		Provenance:            provenance,
		Supersedes:            supersedes,
		EnqueuedAt:            time.Now().UTC(),
		ConflictsWithApproval: q.authorized,
	}

	if supersedes != "" {
		idx, ok := q.byID[supersedes]
		if !ok {
			return Message{}, modberr.New(modberr.CodeNotFound,
				"the superseded message is not in this queue").WithDetail("field", "supersedes")
		}
		if !q.messages[idx].Pending() {
			// Superseding a message that already landed would rewrite history: the earlier
			// instruction was acted on, and relabelling it hides that.
			return Message{}, modberr.Newf(modberr.CodeConflict,
				"message is already %s and cannot be superseded", q.messages[idx].State).
				WithDetail("field", "supersedes")
		}
		if err := q.resolve(ctx, idx, MessageSuperseded); err != nil {
			return Message{}, err
		}
	}

	q.byID[msg.ID] = len(q.messages)
	q.messages = append(q.messages, msg)
	q.version++
	if err := q.emit(ctx, event.TypeRunMessageQueued); err != nil {
		return Message{}, err
	}
	return msg, nil
}

// resolve moves a pending message to a terminal state and records it.
//
// Q2. Only pending can change. A message that was incorporated and later relabelled would make the
// lifecycle a suggestion rather than a record, and STR-2's whole value is that a user can trust it.
//
// This guard is the inner of two: every caller already skips or refuses a resolved message, so
// removing either layer alone changes no observable behaviour and removing both does. That is
// deliberate rather than redundant — the callers keep the queue from *trying*, and this keeps a
// future caller from succeeding.
func (q *Queue) resolve(ctx context.Context, idx int, state MessageState) error {
	msg := &q.messages[idx]
	if !msg.Pending() {
		return modberr.Newf(modberr.CodeConflict,
			"message is already %s", msg.State).WithDetail("field", "state")
	}
	msg.State = state
	msg.ResolvedAt = time.Now().UTC()
	q.version++

	var t event.Type
	switch state {
	case MessageIncorporated:
		t = event.TypeRunMessageIncorporated
	case MessageSuperseded:
		t = event.TypeRunMessageSuperseded
	case MessageRejected:
		t = event.TypeRunMessageRejected
	default:
		return modberr.Newf(modberr.CodeInvalidArgument, "unknown message state %q", state).
			WithDetail("field", "state")
	}
	return q.emit(ctx, t)
}

// ApplyAt incorporates pending steering at a phase boundary (STR-3).
//
// Q3. A phase that is not a safe boundary yields nothing and is not an error: the run is expected to
// call this at every phase, and refusing at `execute` would push the boundary rule onto every
// caller. What must not happen is quiet incorporation mid-phase, which is what the map prevents.
//
// Q6. A message that arrived after authorization is left pending and reported, because incorporating
// it would change the plan the approval was granted against.
func (q *Queue) ApplyAt(ctx context.Context, phase Phase) (applied []Message, conflicted []Message, err error) {
	if !IsSafeBoundary(phase) {
		return nil, nil, nil
	}
	for i := range q.messages {
		msg := &q.messages[i]
		if !msg.Pending() || msg.Kind != KindSteering {
			continue
		}
		if msg.ConflictsWithApproval {
			conflicted = append(conflicted, *msg)
			continue
		}
		msg.AppliedAt = phase
		if err := q.resolve(ctx, i, MessageIncorporated); err != nil {
			return nil, nil, err
		}
		applied = append(applied, *msg)
	}
	return applied, conflicted, nil
}

// Interrupt records an immediate interruption of the phase in progress (STR-6).
//
// Q4. It is a distinct operation rather than a flag on an ordinary message, because the two have
// different consequences and different audit meaning: queued steering waits, an interrupt stops
// something that was running. The interrupted phase is recorded for the same reason a halt records
// one — a reviewer needs to know whether the run was stopped during retrieval or halfway through
// writing files.
func (q *Queue) Interrupt(ctx context.Context, body string, provenance taint.Class, phase Phase) (Message, error) {
	msg, err := q.Enqueue(ctx, KindInterrupt, body, provenance, "")
	if err != nil {
		return Message{}, err
	}
	idx := q.byID[msg.ID]
	q.messages[idx].InterruptedAt = phase
	q.messages[idx].AppliedAt = phase
	if err := q.resolve(ctx, idx, MessageIncorporated); err != nil {
		return Message{}, err
	}
	if err := q.emit(ctx, event.TypeRunInterrupted); err != nil {
		return Message{}, err
	}
	return q.messages[idx], nil
}

// Reorder rearranges the pending messages (STR-7).
//
// Q5. The version is an optimistic-concurrency token: two surfaces reordering the same queue would
// otherwise silently apply one ordering on top of the other, and the user who lost would see their
// arrangement quietly discarded rather than be told to retry.
func (q *Queue) Reorder(ctx context.Context, order []id.ID, version int) error {
	if version != q.version {
		return modberr.New(modberr.CodeConflict,
			"the queue changed since this ordering was read").
			WithDetail("field", "version")
	}

	pending := q.Pending()
	if len(order) != len(pending) {
		return modberr.New(modberr.CodeInvalidArgument,
			"an ordering must name every pending message exactly once").
			WithDetail("field", "order")
	}
	seen := make(map[id.ID]bool, len(order))
	for _, want := range order {
		idx, ok := q.byID[want]
		if !ok || !q.messages[idx].Pending() {
			return modberr.New(modberr.CodeInvalidArgument,
				"an ordering may only name pending messages in this queue").
				WithDetail("field", "order")
		}
		if seen[want] {
			return modberr.New(modberr.CodeInvalidArgument,
				"an ordering cannot name a message twice").WithDetail("field", "order")
		}
		seen[want] = true
	}

	// Resolved messages keep their positions; only the pending ones move. Reordering the whole queue
	// would rewrite the record of what was applied and when.
	reordered := make([]Message, 0, len(q.messages))
	next := 0
	for _, existing := range q.messages {
		if !existing.Pending() {
			reordered = append(reordered, existing)
			continue
		}
		reordered = append(reordered, q.messages[q.byID[order[next]]])
		next++
	}
	q.messages = reordered
	q.reindex()
	q.version++
	return q.emit(ctx, event.TypeRunMessageReordered)
}

// RejectPending refuses every pending message, used when a run ends before they could be applied.
//
// Leaving them pending forever would tell a user their correction is still coming.
func (q *Queue) RejectPending(ctx context.Context) error {
	for i := range q.messages {
		if !q.messages[i].Pending() {
			continue
		}
		if err := q.resolve(ctx, i, MessageRejected); err != nil {
			return err
		}
	}
	return nil
}

func (q *Queue) reindex() {
	clear(q.byID)
	for i, m := range q.messages {
		q.byID[m.ID] = i
	}
}
