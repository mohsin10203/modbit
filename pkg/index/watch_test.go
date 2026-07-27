package index_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

// fakeSource is a ChangeSource the test drives by hand. Every W-invariant is about the watcher's
// timing, so the source must be controllable rather than real: a test that waited on an OS watcher
// would be testing the operating system.
type fakeSource struct {
	ch chan index.ChangeBatch

	mu     sync.Mutex
	closed int
}

func newFakeSource() *fakeSource {
	return &fakeSource{ch: make(chan index.ChangeBatch)}
}

func (f *fakeSource) Changes() <-chan index.ChangeBatch { return f.ch }

func (f *fakeSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

func (f *fakeSource) closeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// send delivers a batch, failing the test rather than hanging if the watcher is not reading.
func (f *fakeSource) send(t *testing.T, batch index.ChangeBatch) {
	t.Helper()
	select {
	case f.ch <- batch:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not read from the source within 2s")
	}
}

func (f *fakeSource) stop() { close(f.ch) }

// update is one call to the watcher's apply function.
type update struct {
	set    index.ChangeSet
	report index.Report
}

// collector accumulates updates and lets a test wait for the next one.
type collector struct {
	mu      sync.Mutex
	updates []update
	ch      chan update
	err     error
}

func newCollector() *collector { return &collector{ch: make(chan update, 32)} }

func (c *collector) apply(set index.ChangeSet, report index.Report) error {
	c.mu.Lock()
	c.updates = append(c.updates, update{set, report})
	err := c.err
	c.mu.Unlock()
	c.ch <- update{set, report}
	return err
}

func (c *collector) failWith(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func (c *collector) next(t *testing.T, why string) update {
	t.Helper()
	select {
	case u := <-c.ch:
		return u
	case <-time.After(3 * time.Second):
		t.Fatalf("no update within 3s while waiting for %s", why)
		return update{}
	}
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.updates)
}

// watchFixture wires a real reindexer over a real tree to a fake source.
type watchFixture struct {
	root    string
	source  *fakeSource
	collect *collector
	errCh   chan error
	cancel  context.CancelFunc
}

func startWatch(t *testing.T, files map[string]string, policy index.FlushPolicy) *watchFixture {
	t.Helper()
	root := tree(t, files)
	walker, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}
	reindexer, err := index.NewReindexer(walker, policy)
	if err != nil {
		t.Fatalf("NewReindexer: %v", err)
	}
	source := newFakeSource()
	watcher, err := index.NewWatcher(reindexer, source)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	collect := newCollector()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- watcher.Run(ctx, collect.apply) }()
	t.Cleanup(cancel)

	return &watchFixture{root: root, source: source, collect: collect, errCh: errCh, cancel: cancel}
}

func (f *watchFixture) write(t *testing.T, rel, contents string) {
	t.Helper()
	abs := filepath.Join(f.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(abs, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func (f *watchFixture) waitErr(t *testing.T, why string) error {
	t.Helper()
	select {
	case err := <-f.errCh:
		return err
	case <-time.After(3 * time.Second):
		t.Fatalf("Run did not return within 3s while waiting for %s", why)
		return nil
	}
}

func fastPolicy() index.FlushPolicy {
	return index.FlushPolicy{Debounce: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond}
}

// W2. Flush refuses to apply deltas to a state that was never established (decision 62), so the
// watcher seeds it. Leaving that to the caller would turn the decision into a convention.
func TestWatcherRescansBeforeApplyingAnyDelta(t *testing.T) {
	f := startWatch(t, map[string]string{"main.go": "package main\n"}, fastPolicy())

	first := f.collect.next(t, "the initial rescan")
	if !first.set.FullRescan {
		t.Fatal("the first update must be a full rescan")
	}
	if first.set.RescanReason != index.RescanInitial {
		t.Fatalf("rescan reason = %q, want %q", first.set.RescanReason, index.RescanInitial)
	}
	if len(first.set.Upserts) == 0 {
		t.Fatal("the initial rescan must carry the tree it found")
	}
}

// W5. CTX-2 budgets index freshness; a change that never reaches a flush is an index that silently
// describes a tree that no longer exists.
func TestWatcherFlushesPendingChangesByTheDeadline(t *testing.T) {
	f := startWatch(t, map[string]string{"main.go": "package main\n"}, fastPolicy())
	f.collect.next(t, "the initial rescan")

	f.write(t, "added.go", "package main\n\nfunc Added() {}\n")
	f.source.send(t, index.ChangeBatch{Changes: []index.Change{
		{Path: "added.go", Kind: index.ChangeModified, At: time.Now()},
	}})

	got := f.collect.next(t, "the flush of an observed change")
	if got.set.FullRescan {
		t.Fatal("an observed change must flush as a delta, not a full rescan")
	}
	if !hasUpsert(got.set, "added.go") {
		t.Fatalf("flush did not carry added.go: %+v", paths(got.set.Upserts))
	}
}

// W3. A source that lost notifications cannot describe the tree, so recovery is a full walk — the
// delta path would leave the index diverged with nothing to reveal it (decision 63).
func TestWatcherResolvesALostBatchToAFullRescan(t *testing.T) {
	f := startWatch(t, map[string]string{"main.go": "package main\n"}, fastPolicy())
	f.collect.next(t, "the initial rescan")

	f.write(t, "appeared.go", "package main\n\nfunc Appeared() {}\n")
	// The source never reported this file; only a full walk can find it.
	f.source.send(t, index.ChangeBatch{Rescan: true, Reason: index.RescanQueueOverflow})

	got := f.collect.next(t, "the recovery rescan")
	if !got.set.FullRescan {
		t.Fatal("a lost batch must produce a full rescan")
	}
	if got.set.RescanReason != index.RescanQueueOverflow {
		t.Fatalf("rescan reason = %q, want %q", got.set.RescanReason, index.RescanQueueOverflow)
	}
	if !hasUpsert(got.set, "appeared.go") {
		t.Fatalf("the rescan did not find the unreported file: %+v", paths(got.set.Upserts))
	}
}

// W4. A burst of overflows is one divergence, not many. Walking once per notification would turn a
// storm of dropped events into a storm of full walks, which is how a watcher makes a busy machine
// busier at exactly the wrong moment.
//
// The losses are delivered while the watcher is held inside apply, which is what makes this
// deterministic rather than a race against the scan. Counting rescans on a free-running watcher
// measures scheduling, not coalescing: if the loop keeps up, every loss legitimately earns its own
// walk. The invariant is about what happens when it cannot keep up — the case that matters.
func TestWatcherCoalescesRepeatedLosses(t *testing.T) {
	root := tree(t, map[string]string{"main.go": "package main\n"})
	walker, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}
	reindexer, err := index.NewReindexer(walker, fastPolicy())
	if err != nil {
		t.Fatalf("NewReindexer: %v", err)
	}
	source := newFakeSource()
	watcher, err := index.NewWatcher(reindexer, source)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	var (
		mu       sync.Mutex
		rescans  int
		release  = make(chan struct{})
		inApply  = make(chan struct{}, 1)
		resumed  = make(chan struct{}, 16)
		firstOne sync.Once
	)
	apply := func(set index.ChangeSet, _ index.Report) error {
		mu.Lock()
		if set.FullRescan {
			rescans++
		}
		mu.Unlock()
		firstOne.Do(func() {
			inApply <- struct{}{}
			<-release // hold the watcher so the burst lands while it cannot consume signals
		})
		resumed <- struct{}{}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = watcher.Run(ctx, apply) }()

	select {
	case <-inApply:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("watcher did not reach its initial apply within 3s")
	}

	// Eight losses arrive while the loop is blocked. The rescan signal holds one; the other seven
	// have nowhere to go and are dropped, which is the coalescing.
	for range 8 {
		source.send(t, index.ChangeBatch{Rescan: true, Reason: index.RescanQueueOverflow})
	}

	// A send completing only proves the reader *received* it, not that it finished handling it. The
	// reader loop is receive-then-handle, so a further send that it accepts proves the previous one
	// was fully handled — without this the eighth signal could still be in flight when the loop is
	// released, refill the buffer behind it, and earn a second walk. An empty batch is the right
	// probe because the reader discards it, so it is a synchronisation point and nothing else.
	// (Found flaking about once in forty runs; a sleep here would have hidden it rather than fixed
	// it.)
	source.send(t, index.ChangeBatch{})

	close(release)

	// One update for the initial rescan, one for the coalesced recovery.
	for range 2 {
		select {
		case <-resumed:
		case <-time.After(3 * time.Second):
			t.Fatal("watcher did not resume within 3s")
		}
	}
	// Nothing further should arrive: the seven dropped signals must not become seven walks.
	select {
	case <-resumed:
		t.Fatal("a surplus rescan ran; the burst did not coalesce")
	case <-time.After(300 * time.Millisecond):
	}

	mu.Lock()
	defer mu.Unlock()
	if rescans != 2 {
		t.Fatalf("rescans = %d, want 2 (the initial one and one coalesced recovery)", rescans)
	}
}

// W1. Observe must never wait behind a scan (decision 61). A watcher stalled mid-flush stops
// draining the OS notification queue, and an overflowed queue costs notifications outright — the
// recovery path provoking the very failure it recovers from.
func TestWatcherReadsTheSourceWhileScanning(t *testing.T) {
	// A slow apply models a scan the consumer is still processing. The source must stay readable
	// throughout: send fails the test if the watcher stops reading for 2s.
	root := tree(t, map[string]string{"main.go": "package main\n"})
	walker, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}
	reindexer, err := index.NewReindexer(walker, fastPolicy())
	if err != nil {
		t.Fatalf("NewReindexer: %v", err)
	}
	source := newFakeSource()
	watcher, err := index.NewWatcher(reindexer, source)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	release := make(chan struct{})
	applied := make(chan struct{}, 8)
	apply := func(index.ChangeSet, index.Report) error {
		applied <- struct{}{}
		<-release // hold the watcher inside apply
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = watcher.Run(ctx, apply) }()

	// Wait for the watcher to be blocked inside the initial apply. Bounded, not bare: a regression
	// that never applies would otherwise hang the suite instead of reporting, and a test that hangs
	// gives a worse signal than one that fails.
	select {
	case <-applied:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("watcher did not reach its initial apply within 3s")
	}

	// While it is blocked, the source must still be drained. This is the whole invariant: the
	// reader goroutine is what keeps the queue moving.
	for i := range 4 {
		source.send(t, index.ChangeBatch{Changes: []index.Change{
			{Path: "f.go", Kind: index.ChangeModified, At: time.Now().Add(time.Duration(i) * time.Millisecond)},
		}})
	}
	close(release)
}

// W6. A source that stops is not a reason to discard edits the user already made.
func TestWatcherFlushesWhatItHasWhenTheSourceStops(t *testing.T) {
	f := startWatch(t, map[string]string{"main.go": "package main\n"},
		// A long debounce guarantees the change is still pending when the source stops, which is
		// the case this invariant is about.
		index.FlushPolicy{Debounce: 30 * time.Second, MaxDelay: 60 * time.Second})
	f.collect.next(t, "the initial rescan")

	f.write(t, "late.go", "package main\n\nfunc Late() {}\n")
	f.source.send(t, index.ChangeBatch{Changes: []index.Change{
		{Path: "late.go", Kind: index.ChangeModified, At: time.Now()},
	}})

	f.source.stop()

	got := f.collect.next(t, "the final flush")
	if !hasUpsert(got.set, "late.go") {
		t.Fatalf("the final flush lost a pending change: %+v", paths(got.set.Upserts))
	}
	if err := f.waitErr(t, "the watch to end"); err != nil {
		t.Fatalf("a source stopping is an ordinary end, got: %v", err)
	}
}

// W7. Cancellation stops the watch, and the source is released exactly once however the watch ends.
func TestWatcherStopsOnCancellationAndClosesTheSourceOnce(t *testing.T) {
	f := startWatch(t, map[string]string{"main.go": "package main\n"}, fastPolicy())
	f.collect.next(t, "the initial rescan")

	f.cancel()

	err := f.waitErr(t, "cancellation")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	if n := f.source.closeCount(); n != 1 {
		t.Fatalf("source closed %d times, want exactly 1", n)
	}
}

// W7, second half: the source is closed exactly once on the ordinary path too, not only on
// cancellation. A source closed twice is a double-free in whatever holds the OS handle.
func TestWatcherClosesTheSourceOnceWhenItStopsNormally(t *testing.T) {
	f := startWatch(t, map[string]string{"main.go": "package main\n"}, fastPolicy())
	f.collect.next(t, "the initial rescan")

	f.source.stop()
	if err := f.waitErr(t, "the watch to end"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := f.source.closeCount(); n != 1 {
		t.Fatalf("source closed %d times, want exactly 1", n)
	}
}

// W8. A watcher that swallows a scan failure to keep its loop alive reports a fresh index while
// diverging from the tree — the silent degradation R-ERR-05 and SDD §15 both forbid.
func TestWatcherSurfacesAnApplyFailureInsteadOfContinuing(t *testing.T) {
	f := startWatch(t, map[string]string{"main.go": "package main\n"}, fastPolicy())
	f.collect.next(t, "the initial rescan")

	boom := errors.New("index write failed")
	f.collect.failWith(boom)

	f.write(t, "next.go", "package main\n\nfunc Next() {}\n")
	f.source.send(t, index.ChangeBatch{Changes: []index.Change{
		{Path: "next.go", Kind: index.ChangeModified, At: time.Now()},
	}})

	err := f.waitErr(t, "the apply failure to surface")
	if !errors.Is(err, boom) {
		t.Fatalf("Run returned %v, want the apply error", err)
	}
	if n := f.source.closeCount(); n != 1 {
		t.Fatalf("source closed %d times, want exactly 1", n)
	}
}

// A watcher assembled without its collaborators is not a weaker watcher; it is one that reports a
// fresh index forever while observing nothing, which is worse than having none.
func TestNewWatcherRefusesAnIncompleteConfiguration(t *testing.T) {
	root := tree(t, map[string]string{"main.go": "package main\n"})
	walker, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}
	reindexer, err := index.NewReindexer(walker, fastPolicy())
	if err != nil {
		t.Fatalf("NewReindexer: %v", err)
	}

	if _, err := index.NewWatcher(nil, newFakeSource()); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("a watcher with no reindexer must be refused, got %v", err)
	}
	if _, err := index.NewWatcher(reindexer, nil); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("a watcher with no source must be refused, got %v", err)
	}

	w, err := index.NewWatcher(reindexer, newFakeSource())
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if err := w.Run(context.Background(), nil); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("a run with no apply function must be refused, got %v", err)
	}
}

// PollSource is the floor, not the target: it cannot observe individual changes, so it says so on
// every batch rather than presenting a rebuild as an update.
func TestPollSourceAlwaysAsksForARescan(t *testing.T) {
	source := index.NewPollSource(10 * time.Millisecond)
	defer source.Close()

	for range 3 {
		select {
		case batch := <-source.Changes():
			if !batch.Rescan {
				t.Fatal("a poll source cannot observe individual changes and must say so")
			}
			if batch.Reason != index.RescanPollInterval {
				t.Fatalf("reason = %q, want %q", batch.Reason, index.RescanPollInterval)
			}
			if len(batch.Changes) != 0 {
				t.Fatalf("a poll batch cannot carry changes it did not observe: %+v", batch.Changes)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("poll source produced no batch within 2s")
		}
	}
}

// Closing a source must be idempotent and must stop delivery, or a watcher exiting through two
// paths at once would close a channel twice.
func TestPollSourceCloseIsIdempotentAndStopsDelivery(t *testing.T) {
	source := index.NewPollSource(5 * time.Millisecond)
	if err := source.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// The channel must close rather than keep delivering.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, open := <-source.Changes():
			if !open {
				return
			}
		case <-deadline:
			t.Fatal("closed poll source kept delivering")
		}
	}
}

// A poll source drives a real watcher end to end, which is what makes the port more than a shape:
// a deployment with no native backend still gets a correct, if rebuilt, index.
func TestPollSourceDrivesAWatcherEndToEnd(t *testing.T) {
	root := tree(t, map[string]string{"main.go": "package main\n"})
	walker, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}
	reindexer, err := index.NewReindexer(walker, fastPolicy())
	if err != nil {
		t.Fatalf("NewReindexer: %v", err)
	}
	source := index.NewPollSource(20 * time.Millisecond)
	watcher, err := index.NewWatcher(reindexer, source)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	collect := newCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = watcher.Run(ctx, collect.apply) }()

	collect.next(t, "the initial rescan")

	// A file the source can never report individually is still found, because every poll rescans.
	if err := os.WriteFile(filepath.Join(root, "polled.go"), []byte("package main\n\nfunc P() {}\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case u := <-collect.ch:
			if hasUpsert(u.set, "polled.go") {
				if u.set.RescanReason != index.RescanPollInterval {
					t.Fatalf("rescan reason = %q, want %q", u.set.RescanReason, index.RescanPollInterval)
				}
				return
			}
		case <-deadline:
			t.Fatal("the poll source never surfaced the new file")
		}
	}
}

func hasUpsert(set index.ChangeSet, path string) bool {
	for _, e := range set.Upserts {
		if e.Path == path {
			return true
		}
	}
	return false
}
