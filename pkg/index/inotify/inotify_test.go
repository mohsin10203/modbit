//go:build linux

package inotify_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/index/conformance"
	"github.com/modbit/modbit/pkg/index/inotify"
	"github.com/modbit/modbit/pkg/modberr"
)

// TestInotifySourceIsConformant runs the shared ChangeSource suite against the Linux backend.
//
// CTX-2, CTX-A01c4. It is the second source to exercise D7 — the delta path — and the first to do so
// on a platform CI can run, which until now was the leg where only the rescan-only PollSource had
// ever been certified.
func TestInotifySourceIsConformant(t *testing.T) {
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
			s, err := inotify.New(root)
			if err != nil {
				t.Fatalf("inotify.New: %v", err)
			}
			return s
		},
		touch,
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
		t.Fatalf("the inotify source is not conformant")
	}
	// D7 must genuinely pass. A Skip would mean no delta arrived inside the settle window, which for
	// a delta-producing source is a failure wearing a softer label.
	if got := seen["D7"]; got != conformance.StatusPass {
		t.Fatalf("D7 was %s; a source that reports per-file changes must exercise the delta path", got)
	}
}

// A watched write is reported as a repository-relative modification, at any depth.
//
// Depth is the case that separates inotify from FSEvents: inotify is not recursive, so a nested
// directory is only observed because the startup walk added a watch for it. A backend that watched
// the root alone would pass every shallow test and report nothing from `pkg/deep`.
func TestAWriteIsReportedRelativeToTheWatchedRoot(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "pkg", "deep")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	source, err := inotify.New(root)
	if err != nil {
		t.Fatalf("inotify.New: %v", err)
	}
	defer source.Close() //nolint:errcheck // Close's contract is the suite's business

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
// The mask is a hint and the filesystem is the authority, for the reason FSEvents needs the same
// rule: trusting the mask is how a deleted file stays in the index looking like a live result.
func TestADeletedFileIsReportedAsRemoved(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "doomed.go")
	if err := os.WriteFile(path, []byte("package doomed\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	source, err := inotify.New(root)
	if err != nil {
		t.Fatalf("inotify.New: %v", err)
	}
	defer source.Close() //nolint:errcheck // as above
	drain(t, source, 200*time.Millisecond)

	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	change, ok := awaitChange(t, source, "doomed.go", 5*time.Second)
	if !ok {
		t.Fatalf("no change reported for the deleted file within the deadline")
	}
	if change.Kind != index.ChangeRemoved {
		t.Fatalf("kind = %q, want %q; a path that no longer exists is removed however the mask reads",
			change.Kind, index.ChangeRemoved)
	}
}

// A directory created after startup is watched, and the files already inside it are reported.
//
// This is the race inotify has and FSEvents does not. A directory is populated before its watch can
// exist, so anything written between `mkdir` and `inotify_add_watch` produces no event at all. The
// source closes that window by walking what it just adopted; a backend that only added the watch
// would silently lose every file in a freshly checked-out subtree.
func TestANewDirectoryIsAdoptedWithTheFilesAlreadyInIt(t *testing.T) {
	root := t.TempDir()

	source, err := inotify.New(root)
	if err != nil {
		t.Fatalf("inotify.New: %v", err)
	}
	defer source.Close() //nolint:errcheck // as above

	// Populated before the watch can possibly exist: the directory is built complete and then moved
	// into place, so there is no interleaving in which the source could have seen the writes.
	staging := filepath.Join(t.TempDir(), "staged")
	if err := os.MkdirAll(filepath.Join(staging, "inner"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staging, "inner", "buried.go"), []byte("package inner\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Rename(staging, filepath.Join(root, "adopted")); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	if _, ok := awaitChange(t, source, "adopted/inner/buried.go", 5*time.Second); !ok {
		t.Fatalf("a file inside a newly created directory was never reported")
	}

	// And the adopted subtree must be watched from then on, or it goes quiet after one report.
	later := filepath.Join(root, "adopted", "inner", "later.go")
	if err := os.WriteFile(later, []byte("package inner\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, ok := awaitChange(t, source, "adopted/inner/later.go", 5*time.Second); !ok {
		t.Fatalf("a write inside an adopted directory was not reported; the watch was never added")
	}
}

// A root that cannot be watched is refused at construction.
//
// Returning a source that reports nothing would be indistinguishable from a quiet tree, and CTX-2
// rests on being able to tell those apart.
func TestSecurityAnUnwatchableRootIsRefused(t *testing.T) {
	if _, err := inotify.New(filepath.Join(t.TempDir(), "absent")); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("watching a missing directory: err = %v, want CodeInvalidArgument", err)
	}

	file := filepath.Join(t.TempDir(), "a.go")
	if err := os.WriteFile(file, []byte("package a\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := inotify.New(file); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("watching a regular file: err = %v, want CodeInvalidArgument", err)
	}
}

// A path outside the watched root is never reported.
//
// inotify names events relative to the watch that saw them, and the source reconstructs an absolute
// path from its own table. A reconstruction that escaped the root would turn the watcher into a way
// to observe files the index will never hold, so the relative-path guard refuses rather than trims.
func TestSecurityChangesAreConfinedToTheWatchedRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	source, err := inotify.New(root)
	if err != nil {
		t.Fatalf("inotify.New: %v", err)
	}
	defer source.Close() //nolint:errcheck // as above

	if err := os.WriteFile(filepath.Join(outside, "secret.go"), []byte("package secret\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// A write inside the root proves the source is alive, so an empty result below means "nothing was
	// reported for the outside path" rather than "nothing was reported at all".
	if err := os.WriteFile(filepath.Join(root, "inside.go"), []byte("package inside\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, ok := awaitChange(t, source, "inside.go", 5*time.Second); !ok {
		t.Fatalf("the source reported nothing for a write inside the root")
	}

	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case batch, open := <-source.Changes():
			if !open {
				return
			}
			for _, c := range batch.Changes {
				if filepath.IsAbs(c.Path) || strings.HasPrefix(c.Path, "..") {
					t.Fatalf("a change escaped the watched root: %q", c.Path)
				}
			}
		case <-deadline:
			return
		}
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
