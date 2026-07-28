//go:build darwin && cgo

package fsevents_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/index/conformance"
	"github.com/modbit/modbit/pkg/index/fsevents"
	"github.com/modbit/modbit/pkg/modberr"
)

// TestFSEventsSourceIsConformant runs the shared ChangeSource suite against the macOS backend.
//
// CTX-2, CTX-A01c3. This is the first source to exercise **D7** — `PollSource` only ever rescans, so
// the delta path has been Skipped everywhere until now. A backend that produces deltas is the whole
// reason the port exists, and it is the half of the contract that was previously unproven.
func TestFSEventsSourceIsConformant(t *testing.T) {
	root := t.TempDir()
	var writes int
	touch := func() {
		writes++
		path := filepath.Join(root, fmt.Sprintf("touched%d.go", writes))
		if err := os.WriteFile(path, []byte("package touched\n"), 0o644); err != nil {
			t.Errorf("WriteFile: %v", err)
		}
	}

	report := conformance.Run(
		func() index.ChangeSource {
			s, err := fsevents.New(root, 20*time.Millisecond)
			if err != nil {
				t.Fatalf("fsevents.New: %v", err)
			}
			return s
		},
		touch,
		// FSEvents delivers through a kernel queue, so the settle window is generous relative to the
		// 20ms stream latency: a suite that fails a correct backend on a busy machine is a suite
		// somebody disables.
		conformance.Options{Settle: 5 * time.Second, Shutdown: 2 * time.Second},
	)

	seen := map[string]conformance.Status{}
	for _, r := range report.Results {
		seen[r.Invariant] = r.Status
		if r.Status == conformance.StatusFail {
			t.Errorf("%s (%s): %s", r.Invariant, r.Case, r.Detail)
		}
	}
	for _, invariant := range []string{"D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8"} {
		if _, ok := seen[invariant]; !ok {
			t.Errorf("the suite reported no case for %s", invariant)
		}
	}
	if !report.Conformant() {
		t.Fatalf("the FSEvents source is not conformant")
	}
	// D7 must genuinely pass here. A Skip would mean the backend produced no delta within the
	// settle window, which for a delta-producing source is a failure wearing a softer label.
	if got := seen["D7"]; got != conformance.StatusPass {
		t.Fatalf("D7 was %s; a source that reports per-file changes must exercise the delta path", got)
	}
}

// A watched write is reported as a repository-relative modification.
//
// The path matters as much as the timing. FSEvents delivers *resolved* absolute paths — a stream over
// a /var/... temp directory reports /private/var/... — and `Change.Path` is repository relative, so a
// backend that forgot to resolve its own root would produce paths that strip incorrectly. That is
// the same resolution trap the sandbox profile hit, on the same platform.
func TestAWriteIsReportedRelativeToTheWatchedRoot(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "pkg", "deep")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	source, err := fsevents.New(root, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("fsevents.New: %v", err)
	}
	defer source.Close()
	drain(t, source, 300*time.Millisecond) // discard events from creating the tree

	want := "pkg/deep/service.go"
	if err := os.WriteFile(filepath.Join(nested, "service.go"), []byte("package deep\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	change, ok := awaitChange(t, source, want, 5*time.Second)
	if !ok {
		t.Fatalf("no change reported for %s within the deadline", want)
	}
	if change.Kind != index.ChangeModified {
		t.Fatalf("kind = %q, want %q for a created file", change.Kind, index.ChangeModified)
	}
	if change.At.IsZero() {
		t.Fatalf("the change carries no observation time; the freshness SLO is measured against it")
	}
}

// A deleted file is reported as removed, not modified.
//
// FSEvents coalesces flags per path within a batching window, so a file that is created and then
// deleted arrives with both bits set. The filesystem is therefore the authority and the flags are
// only a hint — trusting the flags is how a deleted file stays in the index looking like a live
// result.
func TestADeletedFileIsReportedAsRemoved(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "doomed.go")
	if err := os.WriteFile(path, []byte("package doomed\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	source, err := fsevents.New(root, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("fsevents.New: %v", err)
	}
	defer source.Close()
	drain(t, source, 300*time.Millisecond)

	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	change, ok := awaitChange(t, source, "doomed.go", 5*time.Second)
	if !ok {
		t.Fatalf("no change reported for the deleted file within the deadline")
	}
	if change.Kind != index.ChangeRemoved {
		t.Fatalf("kind = %q, want %q; a path that no longer exists is removed however the flags read",
			change.Kind, index.ChangeRemoved)
	}
}

// A root that cannot be watched is refused at construction.
//
// Returning a source that reports nothing would be indistinguishable from a quiet tree, and CTX-2
// rests on being able to tell those apart.
func TestSecurityAnUnwatchableRootIsRefused(t *testing.T) {
	if _, err := fsevents.New(filepath.Join(t.TempDir(), "absent"), 0); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("watching a missing directory: err = %v, want CodeInvalidArgument", err)
	}

	file := filepath.Join(t.TempDir(), "a.go")
	if err := os.WriteFile(file, []byte("package a\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := fsevents.New(file, 0); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("watching a regular file: err = %v, want CodeInvalidArgument", err)
	}
}

func drain(t *testing.T, source index.ChangeSource, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case <-source.Changes():
		case <-deadline:
			return
		}
	}
}

func awaitChange(t *testing.T, source index.ChangeSource, path string, d time.Duration) (index.Change, bool) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case batch, open := <-source.Changes():
			if !open {
				return index.Change{}, false
			}
			for _, c := range batch.Changes {
				if c.Path == path {
					return c, true
				}
			}
		case <-deadline:
			return index.Change{}, false
		}
	}
}
