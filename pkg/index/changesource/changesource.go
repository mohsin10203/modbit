// Package changesource selects the ChangeSource a platform can actually provide.
//
// Boundary: it chooses between a native backend and the portable fallback, validates the root both
// must agree on, and reports which one the caller got. It watches nothing itself and holds no
// platform knowledge beyond the choice.
//
// Requirements: CTX-2 (file changes must become searchable within the freshness SLO). ADR-0104
// decided FSEvents is the macOS backend; this package is where that decision takes effect, because
// `pkg/index` cannot import a backend that imports it.
//
// # Why the platform choice is not a build tag here
//
// The platform decision already lives in the backend, which carries `darwin && cgo` and a fallback
// that refuses with `MODBIT_CAPABILITY_UNAVAILABLE`. Repeating that tag list here would create a
// second place that can disagree with the first, and `CTX-A01c4`/`c5` will add two more backends to
// keep in step. So this package asks the backend and reads the answer. Its own logic therefore
// compiles and runs identically on every target rather than being a different function per platform,
// which is what lets one set of tests cover the selection on both legs of CI.
package changesource

import (
	"os"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/index/fsevents"
	"github.com/modbit/modbit/pkg/modberr"
)

// Backend names the implementation a caller received.
type Backend string

const (
	// BackendFSEvents is the macOS native source (ADR-0104).
	BackendFSEvents Backend = "fsevents"
	// BackendPoll is the portable source. Every batch it delivers is a full rescan.
	BackendPoll Backend = "poll"
)

// Selection reports what Open chose.
//
// It is returned rather than logged because "the index is stale" and "the index is polled" are the
// same observation from outside, and CTX-2 is the promise that they can be told apart. A caller that
// ignores this still gets a working source; a caller that surfaces it can tell an operator why
// freshness is measured in minutes rather than milliseconds.
type Selection struct {
	// Backend is the implementation in use.
	Backend Backend
	// Degraded reports that the source rescans rather than describing what changed, so freshness is
	// bounded by the cost of a full walk — QA-A01c measured that at 2 m 45 s for a Standard-class
	// repository, against CTX-2's 10-second budget.
	//
	// It is a property of the source, not of the caller's intent: a deliberately selected poll is
	// still a poll.
	Degraded bool
	// Reason explains a degraded selection. It is empty when Degraded is false.
	Reason string
}

// Options tune the selected source.
type Options struct {
	// Latency is the native backend's batching window. Zero selects the backend's default.
	Latency time.Duration
	// PollInterval is the fallback's rescan cadence. Zero selects index.DefaultPollInterval.
	PollInterval time.Duration
	// ForcePoll selects the portable source even where a native backend exists.
	//
	// It exists for diagnosis: an index that is still stale under polling is not the watcher's
	// fault. The selection it produces is reported as degraded like any other poll, because the
	// freshness cost is the same whoever asked for it.
	ForcePoll bool
}

// Open returns the best available ChangeSource for root, and the selection it made.
//
// A root that cannot be watched is refused rather than degraded into a source that reports nothing:
// "no watcher" and "no changes" must not be the same observation, which is the whole of CTX-2.
//
// The caller owns the returned source and must Close it.
func Open(root string, opts Options) (index.ChangeSource, Selection, error) {
	return open(root, opts, nativeSource)
}

// nativeConstructor builds a platform backend, reporting which one it built.
//
// Open takes it as a parameter rather than reading a package variable so that the fallback policy is
// testable without mutable package state (R-GO-06). The policy's two branches — this build has no
// backend, and the backend failed to start — cannot both be provoked on the same target, so a test
// that could not substitute a constructor could only ever cover one of them.
type nativeConstructor func(root string, latency time.Duration) (index.ChangeSource, Backend, error)

// nativeSource builds the native backend for this platform.
//
// It is one backend today. CTX-A01c4 (inotify) and CTX-A01c5 (ReadDirectoryChangesW) extend it, and
// each arrives with its own Backend name and its own build tags inside its own package.
func nativeSource(root string, latency time.Duration) (index.ChangeSource, Backend, error) {
	s, err := fsevents.New(root, latency)
	if err != nil {
		// Returning s alongside the error would hand back a non-nil interface holding a nil
		// *fsevents.Source, and every `source != nil` check downstream would pass.
		return nil, BackendFSEvents, err
	}
	return s, BackendFSEvents, nil
}

func open(root string, opts Options, newNative nativeConstructor) (index.ChangeSource, Selection, error) {
	// Validated here rather than left to each backend so that an input refused on one platform is
	// refused on every platform. PollSource stats nothing — it ticks — so without this a missing root
	// yields a healthy-looking source on Linux and an error on macOS, and the resulting defect
	// reproduces on one developer's machine and not another's.
	if err := validateRoot(root); err != nil {
		return nil, Selection{}, err
	}

	if opts.ForcePoll {
		return pollFallback(opts, "the portable source was selected by configuration")
	}

	source, backend, err := newNative(root, opts.Latency)
	switch {
	case err == nil:
		return source, Selection{Backend: backend}, nil

	case modberr.Is(err, modberr.CodeCapabilityUnavailable):
		// This build genuinely has no native backend. Falling back is correct here, and reporting it
		// is the point: the caller is running without a watcher and needs to know.
		return pollFallback(opts, "no native change source is available on this platform")

	default:
		// The backend exists on this platform and did not start. Falling back would trade a fault an
		// operator can act on for a silent freshness floor measured in minutes, on the very platform
		// where the native source is supposed to be the default. The error is the honest answer.
		return nil, Selection{}, err
	}
}

func pollFallback(opts Options, reason string) (index.ChangeSource, Selection, error) {
	return index.NewPollSource(opts.PollInterval),
		Selection{Backend: BackendPoll, Degraded: true, Reason: reason},
		nil
}

// validateRoot refuses a root no source could watch.
//
// The wording matches the FSEvents backend's own refusals deliberately: a caller must not be able to
// tell which platform refused it from the message it got back.
func validateRoot(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return modberr.Wrap(err, modberr.CodeInvalidArgument, "cannot watch a path that cannot be read").
			WithDetail("field", "root")
	}
	if !info.IsDir() {
		return modberr.New(modberr.CodeInvalidArgument, "a change source watches a directory").
			WithDetail("field", "root")
	}
	return nil
}
