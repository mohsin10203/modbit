//go:build !linux && (!darwin || !cgo)

package changesource_test

import (
	"testing"

	"github.com/modbit/modbit/pkg/index/changesource"
)

// A platform with no native backend polls, and says so.
//
// CTX-2. This is Windows until CTX-A01c5 lands, and a `CGO_ENABLED=0` macOS build. The fallback is
// correct on those — there is nothing else to select — but it is not free, and a caller that cannot
// tell it is polling cannot explain why the index lags. The pairing is what matters: the source
// works, and the selection admits what it costs.
func TestAPlatformWithNoNativeBackendPolls(t *testing.T) {
	source, selection, err := changesource.Open(t.TempDir(), changesource.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer source.Close() //nolint:errcheck // the conformance suite owns Close's contract

	if selection.Backend != changesource.BackendPoll {
		t.Fatalf("backend = %q with no native source, want %q", selection.Backend, changesource.BackendPoll)
	}
	if !selection.Degraded || selection.Reason == "" {
		t.Fatalf("selection = %+v; a fallback must report itself as degraded and say why", selection)
	}
}
