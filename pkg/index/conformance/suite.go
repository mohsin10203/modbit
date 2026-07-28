// Package conformance implements the shared ChangeSource conformance suite.
//
// Boundary: it exercises an index.ChangeSource against the port's contract and returns a structured
// report. It creates no files, watches no tree, and knows nothing about any platform API.
//
// Requirements: CTX-2 (file changes must become searchable within the freshness SLO), by way of the
// `ChangeSource` contract the Watcher depends on.
//
// # Why this exists
//
// W1–W8 test the *Watcher*, driven by a fake source. They prove the loop reacts correctly to a
// well-behaved source; they prove nothing about whether a real source is well-behaved. Three
// platform backends are pending — FSEvents, inotify, ReadDirectoryChangesW — and they are exactly
// the code where a channel that never closes or a Close that deadlocks would live, because that is
// what talking to an OS notification API is like.
//
// So the port's obligations are stated here as cases, once, and every backend answers them. The
// alternative is three implementations each with its own idea of what Close means.
//
// # ChangeSource invariants (D1–D8)
//
// Each has one case below. A case without a D-number, or a D-number without a case, is a gap.
//
//	D1 Changes returns the same channel every time it is called.
//	D2 The channel closes once the source is closed.
//	D3 Close is idempotent: calling it repeatedly is safe and reports no error.
//	D4 Close returns promptly with nobody draining the channel.
//	D5 Every rescan batch carries a reason from the declared set.
//	D6 A rescan batch carries no changes; the two are exclusive.
//	D7 A delta batch carries at least one change.
//	D8 Closing while a reader is blocked releases that reader.
//
// D7 is Skipped for a source that only ever rescans, which `PollSource` legitimately is. Skipped is
// not Pass: a delta path that was never exercised has not been shown to work.
package conformance

import (
	"fmt"
	"time"

	"github.com/modbit/modbit/pkg/index"
)

// SuiteVersion is recorded in every report. A qualification run is only comparable against runs of
// the same suite version.
const SuiteVersion = 1

// Status is a case outcome.
type Status string

const (
	// StatusPass means the invariant held.
	StatusPass Status = "pass"
	// StatusFail means the invariant did not hold.
	StatusFail Status = "fail"
	// StatusSkipped means the source does not exercise the path the case covers.
	StatusSkipped Status = "skipped"
)

// Result is one case outcome.
type Result struct {
	Invariant string `json:"invariant"`
	Case      string `json:"case"`
	Status    Status `json:"status"`
	// Detail explains a failure or a skip. It never carries an observed path: a conformance report
	// is written to logs, and a watched tree's contents are repository content (R-ERR-02).
	Detail string `json:"detail,omitempty"`
}

// Report is a suite run.
type Report struct {
	SuiteVersion int      `json:"suite_version"`
	Results      []Result `json:"results"`
}

// Conformant reports whether every case passed. A skip does not fail the suite, but it is not
// counted as a pass either.
func (r Report) Conformant() bool {
	for _, res := range r.Results {
		if res.Status == StatusFail {
			return false
		}
	}
	return true
}

// Options tune the suite's timing.
//
// A polling source ticks on its own schedule and a native one fires when the OS says so, which can
// be tens of milliseconds after the write. The bounds are explicit rather than hardcoded to either,
// because a suite whose timeouts suit only the fake source is a suite that fails a correct backend.
type Options struct {
	// Settle bounds how long the suite waits for a source to produce a batch.
	Settle time.Duration
	// Shutdown bounds how long Close and channel closure may take.
	Shutdown time.Duration
}

func (o Options) withDefaults() Options {
	if o.Settle <= 0 {
		o.Settle = 5 * time.Second
	}
	if o.Shutdown <= 0 {
		o.Shutdown = 2 * time.Second
	}
	return o
}

// rescanReasons is the declared set from the port. A reason outside it tells an operator nothing,
// and `ChangeSet.RescanReason` is what explains a rebuild after the fact.
var rescanReasons = map[string]bool{
	index.RescanInitial:       true,
	index.RescanQueueOverflow: true,
	index.RescanPollInterval:  true,
	index.RescanSourceRestart: true,
}

// closeBounded calls Close and reports whether it returned within d.
//
// Every Close the suite performs goes through this, not only D4's. A source whose Close blocks would
// otherwise deadlock whichever case reached it first, and the suite would hang instead of reporting
// — which in CI is a timeout with no attribution, strictly worse than a named failure. The goroutine
// is abandoned if Close never returns; the process is a test binary that is about to fail anyway.
func closeBounded(s index.ChangeSource, d time.Duration) error {
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("Close panicked: %v", r)
			}
		}()
		done <- s.Close()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		return fmt.Errorf("Close did not return within %v", d)
	}
}

// Run exercises a source against D1–D8.
//
// newSource must return a fresh, started source on each call. Several cases close the source, so
// sharing one across them would make every case after the first observe a closed channel.
//
// touch, if non-nil, makes an observable change beneath the watched tree; it is what lets D7 test
// the delta path. A source with no way to be provoked passes nil and D7 is Skipped.
func Run(newSource func() index.ChangeSource, touch func(), opts Options) Report {
	opts = opts.withDefaults()
	report := Report{SuiteVersion: SuiteVersion}
	add := func(invariant, name string, status Status, detail string) {
		report.Results = append(report.Results, Result{
			Invariant: invariant, Case: name, Status: status, Detail: detail,
		})
	}
	pass := func(invariant, name string) { add(invariant, name, StatusPass, "") }
	fail := func(invariant, name, format string, args ...any) {
		add(invariant, name, StatusFail, fmt.Sprintf(format, args...))
	}

	// D1 — one stream, not one per caller. A source that built a channel per call would split the
	// batches across them, and each reader would silently see a fraction of the changes.
	func() {
		s := newSource()
		defer closeBounded(s, opts.Shutdown) //nolint:errcheck // D4 owns Close's timeliness
		if first, second := s.Changes(), s.Changes(); first != second {
			fail("D1", "stable channel", "Changes returned a different channel on the second call")
			return
		}
		pass("D1", "stable channel")
	}()

	// D2 — the channel closes on Close. The Watcher's read loop ends when the channel closes; a
	// source that stops sending without closing leaves that goroutine parked for the process's life.
	func() {
		s := newSource()
		ch := s.Changes()
		if err := closeBounded(s, opts.Shutdown); err != nil {
			fail("D2", "channel closes", "%v", err)
			return
		}
		deadline := time.After(opts.Shutdown)
		for {
			select {
			case _, open := <-ch:
				if !open {
					pass("D2", "channel closes")
					return
				}
				// A batch already in flight is legitimate; keep draining until closure.
			case <-deadline:
				fail("D2", "channel closes", "the channel was still open %v after Close", opts.Shutdown)
				return
			}
		}
	}()

	// D3 — Close is idempotent. The Watcher closes the source on its own shutdown path and a caller
	// may reasonably close it too; a second Close that panics on a closed channel is the classic
	// way that becomes a crash during shutdown, when it is least diagnosable.
	func() {
		s := newSource()
		if err := closeBounded(s, opts.Shutdown); err != nil {
			fail("D3", "idempotent close", "the first Close: %v", err)
			return
		}
		if err := closeBounded(s, opts.Shutdown); err != nil {
			fail("D3", "idempotent close", "the second Close: %v", err)
			return
		}
		pass("D3", "idempotent close")
	}()

	// D4 — Close does not wait for a reader. This is the deadlock a native backend arrives with: a
	// send loop blocked handing over a batch, and a Close that waits for that loop to finish. The
	// Watcher closes the source from its own goroutine after it has stopped reading, so a Close that
	// needs one more receive hangs shutdown for good.
	func() {
		s := newSource()
		_ = s.Changes() // obtained and deliberately never drained
		if err := closeBounded(s, opts.Shutdown); err != nil {
			fail("D4", "close without a reader", "with nobody draining the channel, %v", err)
			return
		}
		pass("D4", "close without a reader")
	}()

	// D5/D6 — rescan batches are well formed. Both are observed over the same batches, because
	// provoking a source twice to assert two properties of one batch would be twice the flakiness
	// for no extra coverage.
	func() {
		s := newSource()
		defer closeBounded(s, opts.Shutdown) //nolint:errcheck // D4 owns Close's timeliness
		ch := s.Changes()
		if touch != nil {
			touch()
		}

		var (
			sawRescan     bool
			sawDelta      bool
			badReason     string
			rescanCarried bool
		)
		deadline := time.After(opts.Settle)
	collect:
		for {
			select {
			case batch, open := <-ch:
				if !open {
					break collect
				}
				if batch.Rescan {
					sawRescan = true
					if !rescanReasons[batch.Reason] {
						badReason = batch.Reason
					}
					if len(batch.Changes) > 0 {
						rescanCarried = true
					}
					break collect
				}
				if len(batch.Changes) > 0 {
					sawDelta = true
					break collect
				}
			case <-deadline:
				break collect
			}
		}

		switch {
		case !sawRescan && !sawDelta:
			add("D5", "rescan reason is declared", StatusSkipped,
				"the source produced no batch within the settle window")
			add("D6", "rescan carries no changes", StatusSkipped,
				"the source produced no batch within the settle window")
		case !sawRescan:
			add("D5", "rescan reason is declared", StatusSkipped, "the source produced no rescan batch")
			add("D6", "rescan carries no changes", StatusSkipped, "the source produced no rescan batch")
		default:
			if badReason != "" {
				// The reason is echoed because it is a constant from a closed set, not tree content.
				fail("D5", "rescan reason is declared",
					"a rescan batch carried reason %q, which is not one of the declared reasons", badReason)
			} else {
				pass("D5", "rescan reason is declared")
			}
			if rescanCarried {
				fail("D6", "rescan carries no changes",
					"a rescan batch also carried changes; a consumer cannot tell whether to walk the tree or apply the delta")
			} else {
				pass("D6", "rescan carries no changes")
			}
		}

		if sawDelta {
			pass("D7", "delta batches carry changes")
		} else {
			add("D7", "delta batches carry changes", StatusSkipped,
				"this source only rescans, so the delta path was not exercised")
		}
	}()

	// D8 — closing releases a blocked reader. A reader parked on a channel that never closes is the
	// same leak as D2 seen from the other side, and it is what a `for range source.Changes()` loop
	// does for the rest of the process's life.
	func() {
		s := newSource()
		ch := s.Changes()
		released := make(chan struct{})
		go func() {
			defer close(released)
			for range ch { //nolint:revive // draining until closure is the point
			}
		}()
		closeBounded(s, opts.Shutdown) //nolint:errcheck // D4 owns Close's timeliness
		select {
		case <-released:
			pass("D8", "close releases a blocked reader")
		case <-time.After(opts.Shutdown):
			fail("D8", "close releases a blocked reader",
				"a reader ranging over the channel was still blocked %v after Close", opts.Shutdown)
		}
	}()

	return report
}
