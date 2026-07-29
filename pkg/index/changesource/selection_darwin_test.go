//go:build darwin && cgo

package changesource_test

import (
	"testing"

	"github.com/modbit/modbit/pkg/index/changesource"
)

// macOS gets FSEvents without being asked.
//
// CTX-A01c3, ADR-0104. This is the decision the ADR asked for, written down as an assertion rather
// than as prose: before this, the backend existed and nothing selected it, so every caller got a
// 2-second poll on the platform the native source was built for. A change that removes the default
// fails here rather than showing up as an index that is quietly minutes behind.
func TestMacOSSelectsTheNativeBackendByDefault(t *testing.T) {
	source, selection, err := changesource.Open(t.TempDir(), changesource.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer source.Close() //nolint:errcheck // the conformance suite owns Close's contract

	if selection.Backend != changesource.BackendFSEvents {
		t.Fatalf("backend = %q on macOS with cgo, want %q", selection.Backend, changesource.BackendFSEvents)
	}
	if selection.Degraded {
		t.Fatalf("the macOS default reported Degraded = true (%q)", selection.Reason)
	}
}
