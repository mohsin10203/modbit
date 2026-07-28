//go:build !darwin || !cgo

// Package fsevents implements index.ChangeSource on macOS using FSEvents.
//
// This build has no FSEvents: either the platform is not macOS, or cgo is disabled. New refuses
// rather than returning a source that reports nothing, so a caller cannot mistake "no watcher" for
// "no changes" — the distinction CTX-2 depends on. Callers fall back to index.NewPollSource.
package fsevents

import (
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

// Source is the unsupported-build placeholder. It is never constructed.
type Source struct{}

var _ index.ChangeSource = (*Source)(nil)

// New reports that this build has no FSEvents backend.
func New(root string, latency time.Duration) (*Source, error) {
	// CapabilityUnavailable, not Internal: this build genuinely does not offer the capability, and
	// the caller's correct response is to fall back to the portable source rather than to retry or
	// to report a fault.
	return nil, modberr.New(modberr.CodeCapabilityUnavailable,
		"the FSEvents change source requires macOS with cgo enabled")
}

// Changes implements index.ChangeSource.
func (s *Source) Changes() <-chan index.ChangeBatch { return nil }

// Close implements index.ChangeSource.
func (s *Source) Close() error { return nil }
