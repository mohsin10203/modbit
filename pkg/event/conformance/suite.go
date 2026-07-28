// Package conformance implements the shared event Sequencer conformance suite.
//
// Boundary: it exercises an event.Sequencer against R-EVT-01 and returns a structured report. It
// does not publish, persist, or subscribe, and it knows nothing about any particular backing store.
//
// Requirements: R-EVT-01 (run events are append-only; the per-run sequence is strictly monotonic)
// and R-EVT-07 (materialized state is rebuildable from the event log — which is only true if the
// log has no gaps and no duplicates to rebuild from).
//
// # Why this exists as a suite rather than as tests on MemorySequencer
//
// `MemorySequencer` is not the implementation that matters. The authoritative one allocates inside
// the same transaction as the state write and the outbox insert, and it is the one whose failure
// would corrupt an audit log. Writing these assertions against the in-memory implementation alone
// would mean the implementation that actually needs them is the one that never ran them.
//
// So the contract lives here, the in-memory implementation is its first subject, and a transactional
// sequencer is expected to pass the identical suite before it is used. This is the same shape as the
// inference adapter and sandbox backend suites, for the same reason.
//
// # Sequence invariants (E1–E9)
//
// Each has one case below. A case without an E-number, or an E-number without a case, is a gap.
//
//	E1 A run that has never allocated starts at 1.
//	E2 Allocation is strictly monotonic: each Next is exactly one above the last.
//	E3 The sequence has no gaps: n allocations yield exactly 1..n.
//	E4 Runs are independent; allocating for one never moves another.
//	E5 Current reports the last allocation and never advances it.
//	E6 Concurrent allocation never issues the same sequence twice.
//	E7 An identifier that is not a run is refused.
//	E8 A cancelled context refuses rather than allocating.
//	E9 Resume refuses to move a sequence backwards.
//
// E9 applies only to a sequencer that can resume from a durable log; one that cannot is Skipped
// rather than passed, because a capability that was never exercised has not been shown to work.
package conformance

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/modbit/modbit/pkg/event"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
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
	// StatusSkipped means the sequencer does not offer the capability the case covers. It is not a
	// pass: nothing was demonstrated.
	StatusSkipped Status = "skipped"
)

// Result is one case outcome.
type Result struct {
	Invariant string `json:"invariant"`
	Case      string `json:"case"`
	Status    Status `json:"status"`
	// Detail explains a failure or a skip. It never carries an allocated sequence for another
	// tenant's run, because a conformance report is written to logs (R-ERR-02).
	Detail string `json:"detail,omitempty"`
}

// Report is a suite run.
type Report struct {
	SuiteVersion int      `json:"suite_version"`
	Results      []Result `json:"results"`
}

// Conformant reports whether every case passed.
//
// A skip does not fail the suite — the capability is genuinely absent — but it is not counted as a
// pass either, which is what Skipped exists to keep visible.
func (r Report) Conformant() bool {
	for _, res := range r.Results {
		if res.Status == StatusFail {
			return false
		}
	}
	return true
}

// Resumable is the optional capability E9 covers: seeding the sequence from a durable log so that a
// resumed run continues rather than restarting.
type Resumable interface {
	Resume(runID id.ID, lastSequence uint64) error
}

// Run exercises a sequencer against E1–E9.
//
// newSequencer must return a fresh, empty sequencer on each call. Several cases depend on starting
// from nothing, and sharing one instance across them would make E1 pass only when it happened to run
// first — an ordering dependency that would eventually be "fixed" by deleting the assertion.
func Run(ctx context.Context, newSequencer func() event.Sequencer) Report {
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

	// E1 — a fresh run starts at 1. Starting at 0 would make "no events yet" and "one event"
	// indistinguishable to a consumer reading Current.
	func() {
		s := newSequencer()
		run := id.MustNew(id.Run)
		got, err := s.Next(ctx, run)
		switch {
		case err != nil:
			fail("E1", "first allocation", "Next on a fresh run returned an error: %v", err)
		case got != 1:
			fail("E1", "first allocation", "first sequence was %d, want 1", got)
		default:
			pass("E1", "first allocation")
		}
	}()

	// E2/E3 — strict monotonicity and no gaps. These are one loop because they are one property
	// observed two ways, and separating them would mean asserting the same allocations twice.
	func() {
		const n = 50
		s := newSequencer()
		run := id.MustNew(id.Run)
		monotonic, contiguous := true, true
		var previous uint64
		for i := 1; i <= n; i++ {
			got, err := s.Next(ctx, run)
			if err != nil {
				fail("E2", "monotonic allocation", "Next failed at allocation %d: %v", i, err)
				fail("E3", "gap-free allocation", "Next failed at allocation %d: %v", i, err)
				return
			}
			if got <= previous {
				monotonic = false
			}
			if got != uint64(i) {
				contiguous = false
			}
			previous = got
		}
		if monotonic {
			pass("E2", "monotonic allocation")
		} else {
			fail("E2", "monotonic allocation", "a sequence did not exceed the one before it")
		}
		if contiguous {
			pass("E3", "gap-free allocation")
		} else {
			fail("E3", "gap-free allocation",
				"%d allocations did not yield 1..%d; a gap makes the log unrebuildable (R-EVT-07)", n, n)
		}
	}()

	// E4 — runs are independent. A shared counter would still look monotonic per run while leaking
	// one run's activity rate into another's sequence numbers.
	func() {
		s := newSequencer()
		first, second := id.MustNew(id.Run), id.MustNew(id.Run)
		if _, err := s.Next(ctx, first); err != nil {
			fail("E4", "run isolation", "Next on the first run failed: %v", err)
			return
		}
		if _, err := s.Next(ctx, first); err != nil {
			fail("E4", "run isolation", "Next on the first run failed: %v", err)
			return
		}
		got, err := s.Next(ctx, second)
		switch {
		case err != nil:
			fail("E4", "run isolation", "Next on the second run failed: %v", err)
		case got != 1:
			fail("E4", "run isolation",
				"a second run started at %d; allocation for one run must not move another", got)
		default:
			pass("E4", "run isolation")
		}
	}()

	// E5 — Current observes, it does not allocate. A Current that advanced would burn a sequence
	// every time a reader asked where the log had got to, which is a gap that appears only under
	// monitoring.
	func() {
		s := newSequencer()
		run := id.MustNew(id.Run)
		before, err := s.Current(ctx, run)
		if err != nil {
			fail("E5", "current does not allocate", "Current on a fresh run failed: %v", err)
			return
		}
		if before != 0 {
			fail("E5", "current does not allocate", "Current on a fresh run reported %d, want 0", before)
			return
		}
		allocated, err := s.Next(ctx, run)
		if err != nil {
			fail("E5", "current does not allocate", "Next failed: %v", err)
			return
		}
		for range 3 {
			current, err := s.Current(ctx, run)
			if err != nil {
				fail("E5", "current does not allocate", "Current failed: %v", err)
				return
			}
			if current != allocated {
				fail("E5", "current does not allocate",
					"Current reported %d after allocating %d; reading must not advance the sequence",
					current, allocated)
				return
			}
		}
		pass("E5", "current does not allocate")
	}()

	// E6 — concurrent allocation issues each sequence once. This is the case a lock-free rewrite or
	// a read-then-write against a store gets wrong, and a duplicate sequence in an append-only log
	// is unrecoverable: two different events claim the same position.
	func() {
		const goroutines = 64
		s := newSequencer()
		run := id.MustNew(id.Run)

		var (
			wg     sync.WaitGroup
			mu     sync.Mutex
			issued []uint64
			errs   []error
		)
		start := make(chan struct{})
		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start // release together, so the allocations actually contend
				got, err := s.Next(ctx, run)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs = append(errs, err)
					return
				}
				issued = append(issued, got)
			}()
		}
		close(start)
		wg.Wait()

		if len(errs) > 0 {
			fail("E6", "concurrent allocation", "%d of %d allocations failed, first: %v",
				len(errs), goroutines, errs[0])
			return
		}
		sort.Slice(issued, func(i, j int) bool { return issued[i] < issued[j] })
		for i, got := range issued {
			if got != uint64(i+1) {
				fail("E6", "concurrent allocation",
					"%d concurrent allocations did not yield 1..%d; position %d was %d",
					goroutines, goroutines, i+1, got)
				return
			}
		}
		pass("E6", "concurrent allocation")
	}()

	// E7 — a non-run identifier is refused. Sequences are per run; allocating against a space or an
	// organization id would produce a counter nothing reads and no run could resume from.
	func() {
		s := newSequencer()
		_, err := s.Next(ctx, id.MustNew(id.Space))
		switch {
		case err == nil:
			fail("E7", "non-run identifier refused", "Next accepted a space identifier")
		case !modberr.Is(err, modberr.CodeInvalidArgument):
			fail("E7", "non-run identifier refused",
				"Next refused a space identifier with the wrong code: %v", err)
		default:
			pass("E7", "non-run identifier refused")
		}
	}()

	// E8 — a cancelled context refuses. An allocation that succeeds after its caller has gone burns
	// a sequence no event will ever occupy, and R-EVT-07 needs a log with nothing missing from it.
	func() {
		s := newSequencer()
		run := id.MustNew(id.Run)
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := s.Next(cancelled, run); err == nil {
			fail("E8", "cancelled context refused", "Next allocated a sequence for a cancelled caller")
			return
		}
		// The allocation must not have happened either — refusing to return it while still
		// consuming it would leave exactly the hole this case exists to prevent.
		current, err := s.Current(ctx, run)
		switch {
		case err != nil:
			fail("E8", "cancelled context refused", "Current failed after a cancelled allocation: %v", err)
		case current != 0:
			fail("E8", "cancelled context refused",
				"a cancelled allocation consumed sequence %d without returning it", current)
		default:
			pass("E8", "cancelled context refused")
		}
	}()

	// E9 — resume never moves a sequence backwards.
	func() {
		s := newSequencer()
		resumable, ok := s.(Resumable)
		if !ok {
			add("E9", "resume is not retrograde", StatusSkipped,
				"this sequencer cannot resume from a durable log")
			return
		}
		run := id.MustNew(id.Run)
		for range 5 {
			if _, err := s.Next(ctx, run); err != nil {
				fail("E9", "resume is not retrograde", "Next failed: %v", err)
				return
			}
		}
		if err := resumable.Resume(run, 3); err == nil {
			fail("E9", "resume is not retrograde",
				"resuming at 3 below the allocated 5 was accepted; the log position becomes ambiguous")
			return
		}
		// Resuming forward is legitimate: it is how a process picks up a run whose log advanced
		// elsewhere. Refusing it would make E9 an assertion that resume never works.
		if err := resumable.Resume(run, 9); err != nil {
			fail("E9", "resume is not retrograde", "resuming forward to 9 was refused: %v", err)
			return
		}
		next, err := s.Next(ctx, run)
		switch {
		case err != nil:
			fail("E9", "resume is not retrograde", "Next after resume failed: %v", err)
		case next != 10:
			fail("E9", "resume is not retrograde",
				"after resuming at 9 the next sequence was %d, want 10", next)
		default:
			pass("E9", "resume is not retrograde")
		}
	}()

	return report
}
