//go:build linux

package changesource_test

import (
	"testing"

	"github.com/modbit/modbit/pkg/index/changesource"
)

// Linux gets inotify without being asked.
//
// CTX-A01c4, ADR-0106. The counterpart to the macOS case: before this, every Linux caller polled,
// which meant a full walk per tick — QA-A01c measured 2 m 45 s for a Standard-class repository
// against CTX-2's 10 seconds.
//
// It can legitimately report poll instead. `fs.inotify.max_user_watches` is commonly 8192, and a
// tree with more directories than the remaining budget cannot be watched at all; the backend reports
// that as an unavailable capability and the selector degrades. So the assertion is on the pair —
// whichever backend is selected, the degraded flag must describe it honestly — with inotify required
// whenever the watch budget did allow it.
func TestLinuxSelectsInotifyWhenTheWatchBudgetAllows(t *testing.T) {
	source, selection, err := changesource.Open(t.TempDir(), changesource.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer source.Close() //nolint:errcheck // the conformance suite owns Close's contract

	switch selection.Backend {
	case changesource.BackendInotify:
		if selection.Degraded {
			t.Fatalf("the Linux default reported Degraded = true (%q)", selection.Reason)
		}
	case changesource.BackendPoll:
		// A t.TempDir() is one directory. Falling back for a single-directory tree means the watch
		// budget is exhausted by something else on the machine, which is worth failing on rather than
		// passing quietly: it would hide a backend that always refuses.
		t.Fatalf("Linux fell back to polling for a single-directory tree: %q", selection.Reason)
	default:
		t.Fatalf("Linux selected %q", selection.Backend)
	}
}
