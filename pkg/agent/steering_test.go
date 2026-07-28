package agent_test

import (
	"context"
	"testing"

	"github.com/modbit/modbit/pkg/agent"
	"github.com/modbit/modbit/pkg/event"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// eventLog records the event types a queue emits, which is how Q8 is checked without a full run.
type eventLog struct{ types []event.Type }

func (l *eventLog) emit(_ context.Context, t event.Type) error {
	l.types = append(l.types, t)
	return nil
}

func (l *eventLog) count(t event.Type) int {
	n := 0
	for _, got := range l.types {
		if got == t {
			n++
		}
	}
	return n
}

func newQueue(t *testing.T) (*agent.Queue, *eventLog) {
	t.Helper()
	log := &eventLog{}
	q, err := agent.NewQueue(id.MustNew(id.Run), log.emit)
	if err != nil {
		t.Fatalf("NewQueue: %v", err)
	}
	return q, log
}

func enqueue(t *testing.T, q *agent.Queue, body string) agent.Message {
	t.Helper()
	msg, err := q.Enqueue(context.Background(), agent.KindSteering, body, taint.UserTrusted, "")
	if err != nil {
		t.Fatalf("Enqueue(%q): %v", body, err)
	}
	return msg
}

func bodies(messages []agent.Message) []string {
	out := make([]string, 0, len(messages))
	for _, m := range messages {
		out = append(out, m.Body)
	}
	return out
}

// Q1. STR-1: an ordered durable queue. Order that varied between reads would make the pending list a
// suggestion, and STR-7's reordering meaningless.
func TestQueueOrderIsStableAcrossReads(t *testing.T) {
	q, _ := newQueue(t)
	for _, body := range []string{"first", "second", "third", "fourth"} {
		enqueue(t, q, body)
	}

	want := []string{"first", "second", "third", "fourth"}
	for range 20 {
		if got := bodies(q.Pending()); !equal(got, want) {
			t.Fatalf("pending order = %v, want %v", got, want)
		}
		if got := bodies(q.Messages()); !equal(got, want) {
			t.Fatalf("message order = %v, want %v", got, want)
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Q2. STR-2's value is that a user can trust the state. A message relabelled after it landed would
// make the lifecycle a suggestion rather than a record.
func TestOnlyPendingMessagesCanChangeState(t *testing.T) {
	q, _ := newQueue(t)
	first := enqueue(t, q, "use tabs")

	// Incorporate it at a safe boundary.
	applied, _, err := q.ApplyAt(context.Background(), agent.PhasePlan)
	if err != nil {
		t.Fatalf("ApplyAt: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("applied = %d, want 1", len(applied))
	}

	// Superseding a message that already landed would rewrite history.
	_, err = q.Enqueue(context.Background(), agent.KindSteering, "use spaces", taint.UserTrusted, first.ID)
	if !modberr.Is(err, modberr.CodeConflict) {
		t.Fatalf("error = %v, want a conflict", err)
	}

	// And a second application must not touch it again.
	applied, _, err = q.ApplyAt(context.Background(), agent.PhaseReview)
	if err != nil {
		t.Fatalf("ApplyAt: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("an already-incorporated message was applied again: %v", bodies(applied))
	}
}

// Q3. STR-3: steering lands at a safe boundary. A message applied halfway through a file write
// changes the intent of an edit already partly on disk, and nothing downstream could tell which half
// belonged to which instruction.
func TestSecuritySteeringNeverLandsMidExecution(t *testing.T) {
	q, _ := newQueue(t)
	enqueue(t, q, "actually delete the tests instead")

	// execute and authorize are not boundaries: work is in flight, or an approval is being bound.
	for _, unsafe := range []agent.Phase{agent.PhaseExecute, agent.PhaseAuthorize, agent.PhasePackage, agent.PhaseComplete} {
		applied, _, err := q.ApplyAt(context.Background(), unsafe)
		if err != nil {
			t.Fatalf("ApplyAt(%s): %v", unsafe, err)
		}
		if len(applied) != 0 {
			t.Fatalf("steering was incorporated during %s: %v", unsafe, bodies(applied))
		}
		if agent.IsSafeBoundary(unsafe) {
			t.Fatalf("%s must not be a safe boundary", unsafe)
		}
	}
	if len(q.Pending()) != 1 {
		t.Fatal("the message should still be pending")
	}

	// At a real boundary it lands, so the refusals above are the rule working rather than the queue
	// being broken.
	applied, _, err := q.ApplyAt(context.Background(), agent.PhaseVerify)
	if err != nil {
		t.Fatalf("ApplyAt: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("applied = %d at a safe boundary, want 1", len(applied))
	}
	if applied[0].AppliedAt != agent.PhaseVerify {
		t.Fatalf("applied at %q, want verify", applied[0].AppliedAt)
	}
}

// Q4. STR-6: an interrupt is distinct from queued steering. The two have different consequences and
// different audit meaning — one waits, the other stops something that was running.
func TestInterruptIsDistinctAndRecordsWhatItStopped(t *testing.T) {
	q, log := newQueue(t)
	queued := enqueue(t, q, "also update the docs")

	msg, err := q.Interrupt(context.Background(), "stop, wrong file", taint.UserTrusted, agent.PhaseExecute)
	if err != nil {
		t.Fatalf("Interrupt: %v", err)
	}

	if msg.Kind != agent.KindInterrupt {
		t.Fatalf("kind = %q, want interrupt", msg.Kind)
	}
	if msg.InterruptedAt != agent.PhaseExecute {
		t.Fatalf("interrupted at %q, want execute", msg.InterruptedAt)
	}
	if msg.State != agent.MessageIncorporated {
		t.Fatalf("state = %q; an interrupt takes effect immediately", msg.State)
	}
	if log.count(event.TypeRunInterrupted) != 1 {
		t.Fatalf("run.interrupted = %d, want 1", log.count(event.TypeRunInterrupted))
	}

	// The queued message is untouched: an interrupt stops the operation, it does not silently
	// discard instructions the user is still waiting on.
	for _, m := range q.Messages() {
		if m.ID == queued.ID && m.State != agent.MessagePending {
			t.Fatalf("the queued message became %q when an interrupt arrived", m.State)
		}
	}

	// An interrupt applies at a phase that is not a safe boundary, which is the whole point of it
	// being a separate operation.
	if agent.IsSafeBoundary(agent.PhaseExecute) {
		t.Fatal("execute must not be a safe boundary")
	}
}

// Q5. STR-7: reordering is optimistically concurrent. Two surfaces reordering the same queue would
// otherwise silently apply one ordering on top of the other, and the user who lost would see their
// arrangement discarded rather than be told to retry.
func TestReorderingUsesOptimisticConcurrency(t *testing.T) {
	q, log := newQueue(t)
	a := enqueue(t, q, "first")
	b := enqueue(t, q, "second")
	c := enqueue(t, q, "third")

	stale := q.Version()
	// Another surface enqueues, moving the version on.
	enqueue(t, q, "fourth")

	if err := q.Reorder(context.Background(), []id.ID{c.ID, b.ID, a.ID}, stale); !modberr.Is(err, modberr.CodeConflict) {
		t.Fatalf("error = %v, want a conflict on a stale version", err)
	}

	current := q.Version()
	pending := q.Pending()
	order := []id.ID{pending[3].ID, pending[2].ID, pending[1].ID, pending[0].ID}
	if err := q.Reorder(context.Background(), order, current); err != nil {
		t.Fatalf("Reorder: %v", err)
	}
	if got := bodies(q.Pending()); !equal(got, []string{"fourth", "third", "second", "first"}) {
		t.Fatalf("order after reorder = %v", got)
	}
	if q.Version() == current {
		t.Fatal("a successful reorder must move the version, or the next writer cannot detect it")
	}
	if log.count(event.TypeRunMessageReordered) != 1 {
		t.Fatalf("run.message.reordered = %d, want 1", log.count(event.TypeRunMessageReordered))
	}
}

// Q5, second half: an ordering must be a permutation of exactly the pending messages. Anything else
// would silently drop or duplicate an instruction.
func TestReorderingRefusesAnIncompleteOrdering(t *testing.T) {
	q, _ := newQueue(t)
	a := enqueue(t, q, "first")
	b := enqueue(t, q, "second")
	enqueue(t, q, "third")

	cases := map[string][]id.ID{
		"too short":  {a.ID, b.ID},
		"duplicated": {a.ID, a.ID, b.ID},
		"unknown id": {a.ID, b.ID, id.MustNew(id.RunMessage)},
	}
	for name, order := range cases {
		t.Run(name, func(t *testing.T) {
			if err := q.Reorder(context.Background(), order, q.Version()); !modberr.Is(err, modberr.CodeInvalidArgument) {
				t.Fatalf("error = %v, want a refusal", err)
			}
		})
	}
	if got := bodies(q.Pending()); !equal(got, []string{"first", "second", "third"}) {
		t.Fatalf("a refused reorder changed the queue: %v", got)
	}
}

// Q5, third half: resolved messages keep their positions. Reordering the whole queue would rewrite
// the record of what was applied and when.
func TestReorderingLeavesResolvedMessagesInPlace(t *testing.T) {
	q, _ := newQueue(t)
	enqueue(t, q, "applied")
	if _, _, err := q.ApplyAt(context.Background(), agent.PhasePlan); err != nil {
		t.Fatalf("ApplyAt: %v", err)
	}
	b := enqueue(t, q, "pending-one")
	c := enqueue(t, q, "pending-two")

	if err := q.Reorder(context.Background(), []id.ID{c.ID, b.ID}, q.Version()); err != nil {
		t.Fatalf("Reorder: %v", err)
	}
	got := bodies(q.Messages())
	if got[0] != "applied" {
		t.Fatalf("the incorporated message moved: %v", got)
	}
	if !equal(got[1:], []string{"pending-two", "pending-one"}) {
		t.Fatalf("pending messages did not reorder: %v", got)
	}
}

// Q6. A message arriving after authorization changes the plan the approval was granted against, so
// it is surfaced rather than folded in — the same class of problem the approval fence epoch solves
// (decision 24), applied to instructions rather than effects.
func TestSecurityPostAuthorizationSteeringIsSurfacedNotApplied(t *testing.T) {
	q, _ := newQueue(t)
	before := enqueue(t, q, "before authorization")
	q.MarkAuthorized()
	after := enqueue(t, q, "also push straight to main")

	applied, conflicted, err := q.ApplyAt(context.Background(), agent.PhaseVerify)
	if err != nil {
		t.Fatalf("ApplyAt: %v", err)
	}

	if len(applied) != 1 || applied[0].ID != before.ID {
		t.Fatalf("applied = %v, want only the pre-authorization message", bodies(applied))
	}
	if len(conflicted) != 1 || conflicted[0].ID != after.ID {
		t.Fatalf("conflicted = %v, want the post-authorization message", bodies(conflicted))
	}
	// It stays pending: surfacing a conflict is not the same as refusing the instruction, and a
	// user who re-authorizes should still have it.
	for _, m := range q.Messages() {
		if m.ID == after.ID && m.State != agent.MessagePending {
			t.Fatalf("a conflicting message was resolved as %q rather than surfaced", m.State)
		}
	}
}

// Q7. STR-5 lets automations deliver follow-ups through this contract, so a message is not
// necessarily user input. An automation payload recorded as user_trusted would be laundered into the
// most trusted class in the lattice.
func TestSecurityMessageProvenanceIsCarried(t *testing.T) {
	q, _ := newQueue(t)

	automation, err := q.Enqueue(context.Background(), agent.KindSteering,
		"the webhook says deploy now", taint.Integration, "")
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if automation.Provenance != taint.Integration {
		t.Fatalf("provenance = %v, want integration", automation.Provenance)
	}
	if automation.Provenance == taint.UserTrusted {
		t.Fatal("an automation follow-up must never be recorded as user-trusted")
	}

	// Provenance survives incorporation, so a downstream policy decision sees the real class.
	applied, _, err := q.ApplyAt(context.Background(), agent.PhasePlan)
	if err != nil {
		t.Fatalf("ApplyAt: %v", err)
	}
	if len(applied) != 1 || applied[0].Provenance != taint.Integration {
		t.Fatalf("provenance lost on incorporation: %+v", applied)
	}

	// A garbage class is refused rather than coerced.
	if _, err := q.Enqueue(context.Background(), agent.KindSteering, "x", taint.Class(200), ""); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal for an unknown taint class", err)
	}
}

// Q8. A queue whose transitions left no record would satisfy STR-2's shape while making its history
// unreconstructable.
func TestEveryStateChangeIsRecorded(t *testing.T) {
	q, log := newQueue(t)
	first := enqueue(t, q, "one")
	enqueue(t, q, "two")

	// Supersede the first with a third.
	if _, err := q.Enqueue(context.Background(), agent.KindSteering, "one, revised", taint.UserTrusted, first.ID); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, _, err := q.ApplyAt(context.Background(), agent.PhasePlan); err != nil {
		t.Fatalf("ApplyAt: %v", err)
	}

	if got := log.count(event.TypeRunMessageQueued); got != 3 {
		t.Fatalf("run.message.queued = %d, want 3", got)
	}
	if got := log.count(event.TypeRunMessageSuperseded); got != 1 {
		t.Fatalf("run.message.superseded = %d, want 1", got)
	}
	if got := log.count(event.TypeRunMessageIncorporated); got != 2 {
		t.Fatalf("run.message.incorporated = %d, want 2", got)
	}
}

// A run that ends with messages still queued must not leave them pending forever: that tells a user
// their correction is still coming.
func TestPendingMessagesAreRejectedWhenARunEnds(t *testing.T) {
	q, log := newQueue(t)
	enqueue(t, q, "one")
	enqueue(t, q, "two")

	if err := q.RejectPending(context.Background()); err != nil {
		t.Fatalf("RejectPending: %v", err)
	}
	if len(q.Pending()) != 0 {
		t.Fatalf("%d messages left pending after the run ended", len(q.Pending()))
	}
	for _, m := range q.Messages() {
		if m.State != agent.MessageRejected {
			t.Fatalf("message %q is %q, want rejected", m.Body, m.State)
		}
		if m.ResolvedAt.IsZero() {
			t.Fatal("a resolved message must record when it resolved")
		}
	}
	if got := log.count(event.TypeRunMessageRejected); got != 2 {
		t.Fatalf("run.message.rejected = %d, want 2", got)
	}
}

// Superseding is what makes a corrected instruction visible rather than leaving two contradictory
// messages in the queue for the agent to reconcile.
func TestSupersedingResolvesTheEarlierMessage(t *testing.T) {
	q, _ := newQueue(t)
	first := enqueue(t, q, "use tabs")
	second, err := q.Enqueue(context.Background(), agent.KindSteering, "use spaces", taint.UserTrusted, first.ID)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	pending := q.Pending()
	if len(pending) != 1 || pending[0].ID != second.ID {
		t.Fatalf("pending = %v, want only the superseding message", bodies(pending))
	}
	for _, m := range q.Messages() {
		if m.ID == first.ID && m.State != agent.MessageSuperseded {
			t.Fatalf("the superseded message is %q", m.State)
		}
	}

	// Superseding something that is not in this queue is a caller error, not a silent no-op.
	if _, err := q.Enqueue(context.Background(), agent.KindSteering, "x", taint.UserTrusted, id.MustNew(id.RunMessage)); !modberr.Is(err, modberr.CodeNotFound) {
		t.Fatalf("error = %v, want not found", err)
	}
}

// A queue assembled without its collaborators would record nothing.
func TestNewQueueRefusesAnIncompleteConfiguration(t *testing.T) {
	log := &eventLog{}
	if _, err := agent.NewQueue("", log.emit); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal with no run id", err)
	}
	if _, err := agent.NewQueue(id.MustNew(id.Space), log.emit); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal for a non-run identifier", err)
	}
	if _, err := agent.NewQueue(id.MustNew(id.Run), nil); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal with no emitter", err)
	}

	q, _ := newQueue(t)
	if _, err := q.Enqueue(context.Background(), "shouting", "x", taint.UserTrusted, ""); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal for an unknown kind", err)
	}
	if _, err := q.Enqueue(context.Background(), agent.KindSteering, "", taint.UserTrusted, ""); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal for an empty body", err)
	}
}
