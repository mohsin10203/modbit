package changesource

import (
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

// These cover the fallback policy directly, because its two branches cannot both be provoked on one
// machine: a macOS build never sees "no native backend", and a Linux build never sees a native
// backend that failed to start. Substituting the constructor is what makes both reachable on either.

// An unavailable capability falls back to the portable source.
//
// This is the non-macOS path, and it is the reason the fallback exists at all.
func TestAnUnavailableCapabilityFallsBackToPolling(t *testing.T) {
	source, selection, err := open(t.TempDir(), Options{PollInterval: 50 * time.Millisecond},
		failingNative(modberr.New(modberr.CodeCapabilityUnavailable, "no backend on this build")))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer source.Close() //nolint:errcheck // the conformance suite owns Close's contract

	if selection.Backend != BackendPoll {
		t.Fatalf("backend = %q, want %q", selection.Backend, BackendPoll)
	}
	if !selection.Degraded || selection.Reason == "" {
		t.Fatalf("fallback selection = %+v; a fallback must be degraded and say why", selection)
	}
}

// A native backend that fails for any other reason is surfaced, not replaced by a poll.
//
// This is the distinction the whole policy turns on. A backend that exists on this platform and did
// not start is a fault an operator can act on — a missing framework, an exhausted resource, a root
// that moved. Degrading it to a poll converts that into a silent freshness floor measured in
// minutes, on the platform where the native source was chosen precisely to avoid one. The index
// would be wrong, nothing would say so, and the machine would look healthy.
func TestANativeBackendFailureIsNotMaskedByTheFallback(t *testing.T) {
	for _, code := range []modberr.Code{modberr.CodeInternal, modberr.CodeInvalidArgument} {
		source, selection, err := open(t.TempDir(), Options{},
			failingNative(modberr.New(code, "the platform stream did not start")))
		if err == nil {
			if source != nil {
				source.Close() //nolint:errcheck // cleaning up after a failure this test is reporting
			}
			t.Fatalf("a %s from the backend produced a %q selection instead of an error", code, selection.Backend)
		}
		if !modberr.Is(err, code) {
			t.Fatalf("err = %v, want the backend's own %s", err, code)
		}
		if source != nil {
			t.Fatalf("a failed open returned a non-nil source")
		}
	}
}

// The selection carries the backend the constructor named.
//
// CTX-A01c4 and c5 add inotify and ReadDirectoryChangesW. A selector that hardcoded the macOS name
// would report `fsevents` on Linux, and the field exists to be trusted by whatever logs it.
func TestTheSelectionCarriesTheBackendTheConstructorNamed(t *testing.T) {
	const named Backend = "inotify"
	source, selection, err := open(t.TempDir(), Options{},
		func(string, time.Duration) (index.ChangeSource, Backend, error) {
			return newStubSource(), named, nil
		})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer source.Close() //nolint:errcheck // stub

	if selection.Backend != named {
		t.Fatalf("backend = %q, want %q", selection.Backend, named)
	}
	if selection.Degraded {
		t.Fatalf("a native selection reported Degraded = true")
	}
}

// The root is validated before any backend is started.
//
// Ordering is the point: starting a stream against a path that was never checked leaves the refusal
// up to whichever backend happens to be compiled in, which is the platform divergence the shared
// gate exists to remove.
func TestTheRootIsValidatedBeforeABackendIsStarted(t *testing.T) {
	var started bool
	_, _, err := open(t.TempDir()+"/absent", Options{},
		func(string, time.Duration) (index.ChangeSource, Backend, error) {
			started = true
			return newStubSource(), BackendFSEvents, nil
		})
	if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("err = %v, want CodeInvalidArgument", err)
	}
	if started {
		t.Fatalf("a backend was started for a root that cannot be watched")
	}
}

// A native constructor that fails returns no source at all.
//
// `fsevents.New` returns a `*fsevents.Source`, and a nil one placed in a `ChangeSource` interface is
// not a nil interface — every `source != nil` check downstream would pass and the first method call
// would panic. `open` happens to discard the source on its error branches today, so this is defence
// in depth; it is pinned here because the next backend's constructor will be written by copying this
// one, and the guard is invisible unless something asserts it.
func TestAFailedNativeConstructorReturnsNoSource(t *testing.T) {
	// Unwatchable on every platform, for a different reason on each: macOS refuses the root,
	// everything else refuses the capability. Both must yield a nil interface.
	source, _, err := nativeSource(t.TempDir()+"/absent", 0)
	if err == nil {
		t.Fatalf("the native constructor accepted a root that cannot be watched")
	}
	if source != nil {
		t.Fatalf("a failed constructor returned a non-nil ChangeSource (%T)", source)
	}
}

func failingNative(err error) nativeConstructor {
	return func(string, time.Duration) (index.ChangeSource, Backend, error) {
		return nil, BackendFSEvents, err
	}
}

// stubSource is a ChangeSource that delivers nothing and closes cleanly. The conformance suite
// covers real sources; these cases are about the selection, not about delivery.
type stubSource struct{ changes chan index.ChangeBatch }

func newStubSource() *stubSource { return &stubSource{changes: make(chan index.ChangeBatch)} }

func (s *stubSource) Changes() <-chan index.ChangeBatch { return s.changes }

func (s *stubSource) Close() error {
	close(s.changes)
	return nil
}
