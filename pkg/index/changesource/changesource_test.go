package changesource_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/index/changesource"
	"github.com/modbit/modbit/pkg/index/conformance"
	"github.com/modbit/modbit/pkg/modberr"
)

// openOptions keep both backends quick: 20 ms of FSEvents batching where there is a native source,
// a 50 ms tick where there is not.
var openOptions = changesource.Options{Latency: 20 * time.Millisecond, PollInterval: 50 * time.Millisecond}

// The source Open selects is held to the shared ChangeSource suite, whichever one it is.
//
// CTX-2, CTX-A01c3. The backend tests prove each implementation in isolation; this proves the thing
// a caller actually receives. It is the same test on every platform — macOS certifies FSEvents
// through the selector and Linux certifies the fallback through it — so neither leg of CI is
// certifying a code path the other one never runs.
func TestTheSelectedSourceIsConformant(t *testing.T) {
	root := t.TempDir()
	var writes int
	touch := func() {
		writes++
		path := filepath.Join(root, fmt.Sprintf("touched%d.go", writes))
		if err := os.WriteFile(path, []byte("package touched\n"), 0o644); err != nil {
			t.Errorf("WriteFile: %v", err)
		}
	}

	// Selection is read once outside the suite: every case builds a fresh source, and they all
	// resolve to the same backend on a given platform.
	probe, selection, err := changesource.Open(root, openOptions)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	report := conformance.Run(
		func() index.ChangeSource {
			source, _, err := changesource.Open(root, openOptions)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			return source
		},
		touch,
		// Generous relative to both cadences: a suite that fails a correct backend on a loaded CI
		// runner is a suite somebody disables.
		conformance.Options{Settle: 5 * time.Second, Shutdown: 2 * time.Second},
	)

	seen := map[string]conformance.Status{}
	for _, r := range report.Results {
		seen[r.Invariant] = r.Status
		if r.Status == conformance.StatusFail {
			t.Errorf("%s (%s): %s", r.Invariant, r.Case, r.Detail)
		}
	}
	for _, invariant := range []string{"D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9"} {
		if _, ok := seen[invariant]; !ok {
			t.Errorf("the suite reported no case for %s", invariant)
		}
	}
	if !report.Conformant() {
		t.Fatalf("the source selected on this platform (%s) is not conformant", selection.Backend)
	}

	// Degraded is a claim about behaviour, so the suite must agree with it. A non-degraded source
	// describes what changed, which is exactly what D7 exercises; a degraded one only rescans, and a
	// D7 pass there would mean Degraded was reported for a source that does produce deltas.
	if selection.Degraded {
		if got := seen["D7"]; got != conformance.StatusSkipped {
			t.Fatalf("D7 was %s for a source reported as degraded; a rescan-only source has no delta path", got)
		}
	} else if got := seen["D7"]; got != conformance.StatusPass {
		t.Fatalf("D7 was %s for a source reported as not degraded; that report claims a delta path", got)
	}
}

// A root that cannot be watched is refused identically on every platform.
//
// The two backends validate differently — FSEvents stats and resolves its root, PollSource stats
// nothing at all and simply ticks — so without a shared gate a missing directory would yield an
// error on macOS and a healthy-looking source everywhere else. A defect that reproduces on one
// developer's machine and not another's is the expensive kind.
func TestSecurityAnUnwatchableRootIsRefusedOnEveryPlatform(t *testing.T) {
	if _, _, err := changesource.Open(filepath.Join(t.TempDir(), "absent"), openOptions); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("opening a missing directory: err = %v, want CodeInvalidArgument", err)
	}

	file := filepath.Join(t.TempDir(), "a.go")
	if err := os.WriteFile(file, []byte("package a\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := changesource.Open(file, openOptions); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("opening a regular file: err = %v, want CodeInvalidArgument", err)
	}

	// The refusal must also hold when the caller asked for the fallback explicitly. ForcePoll selects
	// a source that would never have looked at the root, and skipping validation on that path is the
	// easy way to reintroduce exactly the divergence this test exists to prevent.
	forced := openOptions
	forced.ForcePoll = true
	if _, _, err := changesource.Open(filepath.Join(t.TempDir(), "absent"), forced); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("forcing the portable source at a missing directory: err = %v, want CodeInvalidArgument", err)
	}
}

// A poll selection is always reported as degraded, and a native one never is.
//
// This is the invariant a caller reads to decide whether to warn. Reporting a poll as healthy would
// make a 2 m 45 s freshness floor indistinguishable from a 49 ms one, which is the distinction
// CTX-2 is written in terms of.
func TestEveryPollSelectionIsReportedAsDegraded(t *testing.T) {
	root := t.TempDir()

	source, selection, err := changesource.Open(root, openOptions)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer source.Close() //nolint:errcheck // Close's contract is the suite's business, not this test's

	switch selection.Backend {
	case changesource.BackendPoll:
		if !selection.Degraded {
			t.Fatalf("a poll selection reported Degraded = false")
		}
		if selection.Reason == "" {
			t.Fatalf("a degraded selection carries no reason; an operator cannot act on that")
		}
	case changesource.BackendFSEvents:
		if selection.Degraded {
			t.Fatalf("a native selection reported Degraded = true")
		}
		if selection.Reason != "" {
			t.Fatalf("a healthy selection carries a reason (%q); Reason explains degradation only", selection.Reason)
		}
	default:
		t.Fatalf("Open selected an unnamed backend %q", selection.Backend)
	}
}

// Forcing the portable source is honoured, and is still degraded.
//
// The knob exists for diagnosis, so it must actually change the selection — a ForcePoll that
// silently returned the native source would make the diagnosis it enables meaningless. And the
// freshness cost does not depend on who asked for it.
func TestForcingThePortableSourceIsHonouredAndStillDegraded(t *testing.T) {
	opts := openOptions
	opts.ForcePoll = true

	source, selection, err := changesource.Open(t.TempDir(), opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer source.Close() //nolint:errcheck // as above

	if selection.Backend != changesource.BackendPoll {
		t.Fatalf("backend = %q with ForcePoll set, want %q", selection.Backend, changesource.BackendPoll)
	}
	if !selection.Degraded {
		t.Fatalf("a forced poll reported Degraded = false; the walk costs the same however it was chosen")
	}

	// On a platform that would have polled anyway, the backend name alone cannot show the knob did
	// anything — so the reason must attribute the choice. Without this, a build that ignored
	// ForcePoll entirely would look identical here, and the diagnostic knob would be a no-op nobody
	// noticed. The strings are not asserted; only that the two selections are distinguishable.
	def, defSelection, err := changesource.Open(t.TempDir(), openOptions)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer def.Close() //nolint:errcheck // as above

	if defSelection.Backend == changesource.BackendPoll && defSelection.Reason == selection.Reason {
		t.Fatalf("a forced poll and a fallback poll report the same reason (%q); "+
			"nothing distinguishes a configured choice from an unavailable backend", selection.Reason)
	}
}
