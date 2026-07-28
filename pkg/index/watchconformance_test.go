package index_test

import (
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/index/conformance"
)

// suiteOptions keep the in-process cases quick. A native backend waiting on an OS notification
// queue would pass longer bounds; nothing here waits on the kernel.
var suiteOptions = conformance.Options{Settle: 2 * time.Second, Shutdown: time.Second}

// TestPollSourceIsConformant runs the shared ChangeSource suite against the portable source.
//
// CTX-2. The suite is the contract; PollSource is its first subject. FSEvents, inotify, and
// ReadDirectoryChangesW (CTX-A01c3–c5) must pass the identical cases, which is why the contract
// lives in the suite rather than in this implementation's tests.
func TestPollSourceIsConformant(t *testing.T) {
	report := conformance.Run(
		func() index.ChangeSource { return index.NewPollSource(50 * time.Millisecond) },
		nil, // PollSource cannot be provoked; it rescans on its own schedule
		suiteOptions,
	)

	if report.SuiteVersion != conformance.SuiteVersion {
		t.Fatalf("report suite version = %d, want %d", report.SuiteVersion, conformance.SuiteVersion)
	}
	// Every documented invariant must produce a case; a suite that quietly stopped running one
	// would report Conformant while proving less than it claims.
	want := []string{"D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8"}
	seen := map[string]conformance.Status{}
	for _, r := range report.Results {
		seen[r.Invariant] = r.Status
		if r.Status == conformance.StatusFail {
			t.Errorf("%s (%s): %s", r.Invariant, r.Case, r.Detail)
		}
	}
	for _, invariant := range want {
		if _, ok := seen[invariant]; !ok {
			t.Errorf("the suite reported no case for %s", invariant)
		}
	}
	if !report.Conformant() {
		t.Fatalf("PollSource is not conformant")
	}

	// D7 must be Skipped rather than Pass: PollSource never emits a delta, and a suite that
	// reported a pass here would be certifying a path this source does not have.
	if got := seen["D7"]; got != conformance.StatusSkipped {
		t.Fatalf("D7 was %s for a rescan-only source; want %s", got, conformance.StatusSkipped)
	}
	// D5 and D6 must genuinely run — PollSource does produce rescan batches, so a skip here would
	// mean the settle window expired and the suite proved nothing.
	for _, invariant := range []string{"D5", "D6"} {
		if got := seen[invariant]; got != conformance.StatusPass {
			t.Fatalf("%s was %s for a source that rescans on a 50ms tick; want %s",
				invariant, got, conformance.StatusPass)
		}
	}
}

// TestSecurityChangeSourceConformanceDetectsALeakedReader checks the suite itself.
//
// A conformance suite that cannot fail certifies whatever it is given. This hands it a source whose
// Close stops delivery but never closes the channel — the single most likely defect in a backend
// that wraps an OS notification API, and one that leaks the Watcher's read goroutine for the life of
// the process while looking entirely correct from the outside.
func TestSecurityChangeSourceConformanceDetectsALeakedReader(t *testing.T) {
	report := conformance.Run(
		func() index.ChangeSource { return newLeakySource() },
		nil,
		conformance.Options{Settle: 200 * time.Millisecond, Shutdown: 200 * time.Millisecond},
	)

	if report.Conformant() {
		t.Fatalf("the suite passed a source that never closes its channel")
	}
	// D2 and D8 are the two views of the same leak, and both must catch it: D2 from the closer's
	// side, D8 from the parked reader's.
	for _, invariant := range []string{"D2", "D8"} {
		var caught bool
		for _, r := range report.Results {
			if r.Invariant == invariant && r.Status == conformance.StatusFail {
				caught = true
			}
		}
		if !caught {
			t.Errorf("%s did not fail for a source that never closes its channel", invariant)
		}
	}
}

// leakySource stops delivering on Close but never closes its channel.
type leakySource struct {
	changes chan index.ChangeBatch
	stop    chan struct{}
	closed  bool
}

func newLeakySource() *leakySource {
	s := &leakySource{
		changes: make(chan index.ChangeBatch),
		stop:    make(chan struct{}),
	}
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return // deliberately does not close(s.changes)
			case <-ticker.C:
				select {
				case s.changes <- index.ChangeBatch{Rescan: true, Reason: index.RescanPollInterval}:
				case <-s.stop:
					return
				}
			}
		}
	}()
	return s
}

func (s *leakySource) Changes() <-chan index.ChangeBatch { return s.changes }

func (s *leakySource) Close() error {
	if !s.closed {
		s.closed = true
		close(s.stop)
	}
	return nil
}
