package event_test

import (
	"context"
	"runtime"
	"sync"
	"testing"

	"github.com/modbit/modbit/pkg/event"
	"github.com/modbit/modbit/pkg/event/conformance"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// TestMemorySequencerIsConformant runs the shared Sequencer suite against the in-process
// implementation.
//
// R-EVT-01. The suite is the contract; this is its first subject. A transactional sequencer must
// pass the same cases before it allocates for a real run — which is the point of the suite existing
// separately from the implementation it currently has.
func TestMemorySequencerIsConformant(t *testing.T) {
	report := conformance.Run(context.Background(), func() event.Sequencer {
		return event.NewMemorySequencer()
	})

	if report.SuiteVersion != conformance.SuiteVersion {
		t.Fatalf("report suite version = %d, want %d", report.SuiteVersion, conformance.SuiteVersion)
	}
	// Every invariant the suite documents must produce a case. A suite that silently stopped
	// running one would report Conformant while proving less than it claims.
	want := []string{"E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9"}
	seen := map[string]bool{}
	for _, r := range report.Results {
		seen[r.Invariant] = true
		if r.Status == conformance.StatusFail {
			t.Errorf("%s (%s): %s", r.Invariant, r.Case, r.Detail)
		}
	}
	for _, invariant := range want {
		if !seen[invariant] {
			t.Errorf("the suite reported no case for %s", invariant)
		}
	}

	if !report.Conformant() {
		t.Fatalf("MemorySequencer is not conformant")
	}
	// MemorySequencer implements Resume, so E9 must have been exercised rather than skipped —
	// otherwise this test would pass while the retrograde-resume guard went unmeasured.
	for _, r := range report.Results {
		if r.Invariant == "E9" && r.Status != conformance.StatusPass {
			t.Fatalf("E9 was %s for a sequencer that implements Resume: %s", r.Status, r.Detail)
		}
	}
}

// TestSecuritySequencerConformanceDetectsADuplicateAllocation checks the suite itself.
//
// A conformance suite that cannot fail is worse than no suite: it certifies whatever it is given.
// This hands it a deliberately broken sequencer — one that allocates without locking, so concurrent
// callers receive the same sequence — and requires the suite to catch it. E6 is the case that
// matters most here, because a duplicate position in an append-only log cannot be repaired.
func TestSecuritySequencerConformanceDetectsADuplicateAllocation(t *testing.T) {
	report := conformance.Run(context.Background(), func() event.Sequencer {
		return &lostUpdateSequencer{latest: map[id.ID]uint64{}}
	})

	if report.Conformant() {
		t.Fatalf("the suite passed a sequencer that issues duplicate sequences")
	}
	var caught bool
	for _, r := range report.Results {
		if r.Invariant == "E6" && r.Status == conformance.StatusFail {
			caught = true
		}
	}
	if !caught {
		t.Fatalf("E6 did not fail for a sequencer with no mutual exclusion; results: %+v", report.Results)
	}
}

// lostUpdateSequencer allocates with a read-modify-write that is not atomic.
//
// Every map access is under the mutex, so this is a *lost update* rather than a data race — which is
// deliberate. A genuine data race would be caught by `-race` before the suite ever reported on it,
// and then this test would be checking the race detector instead of the suite. This is the bug a
// store-backed sequencer actually ships with: SELECT the last sequence, add one, UPDATE, with no
// transaction holding the two together.
type lostUpdateSequencer struct {
	mu     sync.Mutex
	latest map[id.ID]uint64
}

func (s *lostUpdateSequencer) Next(ctx context.Context, runID id.ID) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, modberr.Wrap(err, modberr.CodeCancelled, "sequence allocation cancelled")
	}
	if !runID.HasPrefix(id.Run) {
		return 0, modberr.New(modberr.CodeInvalidArgument, "sequence requires a run identifier").
			WithDetail("field", "run_id")
	}
	s.mu.Lock()
	current := s.latest[runID]
	s.mu.Unlock()

	runtime.Gosched() // widen the window so the suite does not depend on scheduling luck

	s.mu.Lock()
	defer s.mu.Unlock()
	s.latest[runID] = current + 1
	return current + 1, nil
}

func (s *lostUpdateSequencer) Current(ctx context.Context, runID id.ID) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, modberr.Wrap(err, modberr.CodeCancelled, "sequence read cancelled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest[runID], nil
}
