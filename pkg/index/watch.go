package index

import (
	"context"
	"sync"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
)

// Watch invariants (W1–W8).
//
// The Reindexer decides *what* an index update contains; this file decides *when* one happens. The
// split matters because the two failure modes are different: a wrong ChangeSet corrupts an index,
// while a late or lost notification leaves a correct index describing a tree that no longer exists.
// CTX-2 budgets the second one (PRD §7: index freshness p95 under 10 seconds for local edits).
//
// Each invariant has one test named for it in watch_test.go. A test without a W-number, or a
// W-number without a test, is a gap.
//
//	W1 Reading the source never blocks on a scan.
//	W2 An initial Rescan precedes every flush.
//	W3 A lost-notification batch resolves to a full Rescan, never to a delta.
//	W4 Repeated losses coalesce into one Rescan.
//	W5 Pending changes are flushed no later than the policy's deadline.
//	W6 A source that stops ends the watch without losing already-observed changes.
//	W7 Cancellation stops the watch and closes the source exactly once.
//	W8 A scan failure surfaces; it is never swallowed to keep the loop alive.

// Rescan reasons explain why a source could not describe what changed. They are stable strings: an
// operator reading "the index rebuilt itself" needs to know whether the machine is under-provisioned
// or the watcher is simply unable to observe the tree.
const (
	// RescanInitial means this is the first walk, establishing the state deltas apply to.
	RescanInitial = "initial"
	// RescanQueueOverflow means the operating system dropped notifications. This is the condition
	// CTX-A01c decision 63 exists for.
	RescanQueueOverflow = "queue_overflow"
	// RescanPollInterval means the source cannot observe individual changes and rescans on a timer.
	RescanPollInterval = "poll_interval"
	// RescanSourceRestart means the source reattached and cannot vouch for what it missed.
	RescanSourceRestart = "source_restart"
)

// ChangeBatch is what a ChangeSource delivers.
//
// A batch is either a set of observed changes or an admission that the source cannot describe what
// happened. The two are deliberately one type: a source that had to signal loss through a separate
// path would let a consumer handle changes and ignore losses, which is the divergence CTX-2's
// recovery path exists to prevent.
type ChangeBatch struct {
	// Changes are the observed changes. Empty on a rescan batch.
	Changes []Change
	// Rescan reports that the source cannot account for what changed, so the tree must be walked.
	Rescan bool
	// Reason explains a Rescan batch. One of the Rescan* constants.
	Reason string
}

// ChangeSource reports filesystem changes beneath an indexed tree.
//
// It is the port every platform backend implements: FSEvents on macOS, inotify on Linux,
// ReadDirectoryChangesW on Windows. Those differ enough that the only portable contract is this one
// — deliver what you saw, and say so when you could not see.
//
// A source must close its channel when it stops, and must not send after Close returns.
type ChangeSource interface {
	// Changes delivers batches until the source stops, then closes the channel.
	Changes() <-chan ChangeBatch
	// Close stops the source and releases its resources. It is safe to call more than once.
	Close() error
}

// Watcher drives a Reindexer from a ChangeSource, applying updates on the flush policy's schedule.
//
// It owns no filesystem knowledge of its own. Everything platform-specific lives behind
// ChangeSource, and everything about what an update contains lives in the Reindexer, which is what
// makes this loop testable without a real watcher (W1–W8 are all exercised against a fake source).
type Watcher struct {
	reindexer *Reindexer
	source    ChangeSource

	// observed signals that changes arrived and the flush deadline should be recomputed. It is
	// buffered and written non-blockingly: it is a nudge, not a queue, and the Reindexer already
	// holds the changes themselves.
	observed chan struct{}
	// rescan signals that the source lost track of the tree. Buffered to one, so a burst of
	// overflows costs one walk rather than one per notification (W4).
	rescan chan string

	closeOnce sync.Once
}

// NewWatcher returns a Watcher driving reindexer from source.
func NewWatcher(reindexer *Reindexer, source ChangeSource) (*Watcher, error) {
	if reindexer == nil {
		return nil, modberr.New(modberr.CodeInvalidArgument, "watcher requires a reindexer").
			WithDetail("field", "reindexer")
	}
	if source == nil {
		// A watcher with no source would sit idle reporting a fresh index forever, which is worse
		// than no watcher at all: nothing distinguishes it from one that is working.
		return nil, modberr.New(modberr.CodeInvalidArgument, "watcher requires a change source").
			WithDetail("field", "source")
	}
	return &Watcher{
		reindexer: reindexer,
		source:    source,
		observed:  make(chan struct{}, 1),
		rescan:    make(chan string, 1),
	}, nil
}

// Apply receives one index update. Returning an error stops the watch.
type Apply func(ChangeSet, Report) error

// Run drives the reindexer until ctx is cancelled or the source stops.
//
// It performs the initial Rescan itself (W2): Flush refuses to apply deltas to a state that was
// never established, and making the caller remember to seed it would turn decision 62 into a
// convention. The source is closed on every exit path.
//
// A scan failure is returned rather than logged and swallowed (W8). A watcher that quietly retries
// a failing walk reports a fresh index while diverging from the tree, which is the silent
// degradation R-ERR-05 and SDD §15 both forbid; the caller decides whether to restart.
func (w *Watcher) Run(ctx context.Context, apply Apply) error {
	if apply == nil {
		return modberr.New(modberr.CodeInvalidArgument, "watcher requires an apply function").
			WithDetail("field", "apply")
	}
	defer w.close()

	// The reader runs in its own goroutine so that Observe never waits behind a scan (W1, and
	// CTX-A01c decision 61). A watcher stalled mid-flush stops draining the operating system's
	// notification queue, and an overflowed queue costs notifications outright — the exact failure
	// the rescan path exists to recover from, provoked by the recovery itself.
	sourceDone := make(chan struct{})
	go w.read(sourceDone)

	set, report, err := w.reindexer.Rescan(ctx)
	if err != nil {
		return err
	}
	set.RescanReason = RescanInitial
	if err := apply(set, report); err != nil {
		return err
	}

	// Go 1.23 made a stopped or reset timer's channel unbuffered, so Reset no longer needs the
	// stop-and-drain dance that used to be required here.
	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		var due <-chan time.Time
		if at := w.reindexer.DueAt(); !at.IsZero() {
			timer.Reset(time.Until(at))
			due = timer.C
		}

		select {
		case <-ctx.Done():
			return ctx.Err()

		case reason := <-w.rescan:
			// W3. A delta cannot describe a tree the source stopped tracking, so recovery is a full
			// walk. ChangeSet.FullRescan is what stops a consumer mistaking it for an ordinary
			// update (decision 63).
			set, report, err := w.reindexer.Rescan(ctx)
			if err != nil {
				return err
			}
			set.RescanReason = reason
			if err := apply(set, report); err != nil {
				return err
			}

		case <-due:
			// W5.
			set, report, err := w.reindexer.Flush(ctx)
			if err != nil {
				return err
			}
			if !worthApplying(set, report) {
				continue
			}
			if err := apply(set, report); err != nil {
				return err
			}

		case <-w.observed:
			// Changes landed; the loop recomputes the deadline on the next pass. Nothing to do here.

		case <-sourceDone:
			// W6. The source stopped. Anything already observed is still pending, so it is flushed
			// before the watch ends rather than discarded — a source that stops is not a reason to
			// lose edits the user already made.
			if _, oldest := w.reindexer.Pending(); !oldest.IsZero() {
				set, report, err := w.reindexer.Flush(ctx)
				if err != nil {
					return err
				}
				if worthApplying(set, report) {
					if err := apply(set, report); err != nil {
						return err
					}
				}
			}
			return nil
		}
	}
}

// read drains the source into the reindexer. It never scans, so it never blocks the source (W1).
func (w *Watcher) read(done chan<- struct{}) {
	defer close(done)
	for batch := range w.source.Changes() {
		if batch.Rescan {
			// Non-blocking: a second overflow while one is already queued needs no second walk, and
			// blocking here would stall the very drain that prevents further overflow (W4).
			select {
			case w.rescan <- batch.Reason:
			default:
			}
			continue
		}
		if len(batch.Changes) == 0 {
			continue
		}
		w.reindexer.Observe(batch.Changes...)
		select {
		case w.observed <- struct{}{}:
		default:
		}
	}
}

// close stops the source exactly once (W7).
func (w *Watcher) close() {
	w.closeOnce.Do(func() { _ = w.source.Close() })
}

// worthApplying reports whether an update carries anything a consumer needs to see.
//
// An empty flush is not an event. Diagnostics are, even with no changes: a walk that could not read
// an ignore file changed nothing but must still degrade visibly (R-ERR-05).
func worthApplying(set ChangeSet, report Report) bool {
	return !set.Empty() || len(report.Diagnostics) > 0 || report.Suppressed > 0
}

// PollSource is the portable ChangeSource: it cannot observe individual changes, so it asks for a
// rescan on a fixed interval.
//
// It exists so that the port has a working implementation on every platform from the start, and so
// that a deployment without a native backend degrades to something correct rather than to nothing.
// It is honest about what it is: every batch is a Rescan carrying RescanPollInterval, so a consumer
// reading ChangeSet.FullRescan can tell that this index is being rebuilt rather than updated.
//
// It does not meet CTX-2's freshness budget on a large tree, because a full walk is not free. A
// native backend is what makes that budget reachable; this is the floor, not the target.
type PollSource struct {
	interval time.Duration
	changes  chan ChangeBatch
	stop     chan struct{}
	once     sync.Once
}

// DefaultPollInterval is the portable source's rescan cadence.
//
// It is well inside CTX-2's 10-second p95 so that the walk, not the wait, is what decides whether
// the budget is met — which is the honest place for the cost to show up.
const DefaultPollInterval = 2 * time.Second

// NewPollSource returns a source that requests a rescan every interval. A non-positive interval
// selects DefaultPollInterval.
func NewPollSource(interval time.Duration) *PollSource {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	p := &PollSource{
		interval: interval,
		changes:  make(chan ChangeBatch),
		stop:     make(chan struct{}),
	}
	go p.loop()
	return p
}

func (p *PollSource) loop() {
	defer close(p.changes)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			select {
			case p.changes <- ChangeBatch{Rescan: true, Reason: RescanPollInterval}:
			case <-p.stop:
				return
			}
		}
	}
}

// Changes implements ChangeSource.
func (p *PollSource) Changes() <-chan ChangeBatch { return p.changes }

// Close implements ChangeSource.
func (p *PollSource) Close() error {
	p.once.Do(func() { close(p.stop) })
	return nil
}

var _ ChangeSource = (*PollSource)(nil)
