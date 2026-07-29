//go:build !linux

// Package inotify implements index.ChangeSource on Linux using inotify.
//
// This build is not Linux. New refuses rather than returning a source that reports nothing, so a
// caller cannot mistake "no watcher" for "no changes" — the distinction CTX-2 depends on. Selection
// and fallback are `pkg/index/changesource`'s business, not this package's.
package inotify

import (
	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

// Source is the unsupported-build placeholder. It is never constructed.
type Source struct{}

var _ index.ChangeSource = (*Source)(nil)

// New reports that this build has no inotify backend.
func New(root string) (*Source, error) {
	return nil, modberr.New(modberr.CodeCapabilityUnavailable,
		"the inotify change source requires Linux")
}

// Changes implements index.ChangeSource.
func (s *Source) Changes() <-chan index.ChangeBatch { return nil }

// Close implements index.ChangeSource.
func (s *Source) Close() error { return nil }
