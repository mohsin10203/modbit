package event

import (
	"context"
	"sync"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// Sequencer allocates the strictly monotonic per-run event sequence required by R-EVT-01.
//
// The interface exists at this consumer boundary (R-ARCH-05) so the orchestrator can depend on
// sequence allocation without depending on PostgreSQL. The authoritative implementation allocates
// inside the same transaction as the state write and the outbox insert (R-EVT-04); MemorySequencer
// below is for local runs, tests, and the desktop's offline path.
type Sequencer interface {
	// Next returns the next sequence for runID. Sequences start at 1.
	Next(ctx context.Context, runID id.ID) (uint64, error)
	// Current returns the last allocated sequence for runID, or 0 when none has been allocated.
	Current(ctx context.Context, runID id.ID) (uint64, error)
}

// MemorySequencer is an in-process Sequencer.
//
// Correctness depends on exactly one process allocating for a given run, which holds when the run
// holds a single active transition lease (R-EVT-06). It is not a substitute for the transactional
// sequencer in a multi-process deployment, and it deliberately does not persist: a restart must
// resume from the durable log, not from a rebuilt guess.
type MemorySequencer struct {
	mu     sync.Mutex
	latest map[id.ID]uint64
}

// NewMemorySequencer returns an empty MemorySequencer.
func NewMemorySequencer() *MemorySequencer {
	return &MemorySequencer{latest: make(map[id.ID]uint64)}
}

var _ Sequencer = (*MemorySequencer)(nil)

// Next returns the next sequence for runID.
func (s *MemorySequencer) Next(ctx context.Context, runID id.ID) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, modberr.Wrap(err, modberr.CodeCancelled, "sequence allocation cancelled")
	}
	if !runID.HasPrefix(id.Run) {
		return 0, modberr.New(modberr.CodeInvalidArgument, "sequence requires a run identifier").
			WithDetail("field", "run_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latest[runID]++
	return s.latest[runID], nil
}

// Current returns the last allocated sequence for runID.
func (s *MemorySequencer) Current(ctx context.Context, runID id.ID) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, modberr.Wrap(err, modberr.CodeCancelled, "sequence read cancelled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest[runID], nil
}

// Resume seeds the sequence for runID from the durable log, so that a resumed run continues its
// sequence rather than restarting it. It refuses to move a sequence backwards, which would make
// the append-only log ambiguous.
func (s *MemorySequencer) Resume(runID id.ID, lastSequence uint64) error {
	if !runID.HasPrefix(id.Run) {
		return modberr.New(modberr.CodeInvalidArgument, "resume requires a run identifier").
			WithDetail("field", "run_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.latest[runID]; lastSequence < current {
		return modberr.Newf(modberr.CodeSequenceConflict,
			"cannot resume run at sequence %d below the allocated %d", lastSequence, current).
			WithDetail("run_id", runID.String()).
			WithDetail("expected_sequence", formatUint(lastSequence)).
			WithDetail("actual_sequence", formatUint(current))
	}
	s.latest[runID] = lastSequence
	return nil
}

// Forget drops in-memory state for a completed run so that a long-lived process does not retain
// sequence state for every run it has ever served.
func (s *MemorySequencer) Forget(runID id.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.latest, runID)
}

func formatUint(v uint64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	return string(buf[i:])
}
