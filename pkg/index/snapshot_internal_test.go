package index

import (
	"testing"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/settings"
)

// An upgrade leaves snapshots on disk that a previous build wrote. Those are intact — their digests
// are correct for their own contents — they are simply produced by a pipeline this build no longer
// agrees with (SDD §17, UPG-6). Simulating that needs a snapshot whose digest is valid for an older
// version, which only in-package code can construct.
func TestReuseCheckReportsAnOlderIndexerVersion(t *testing.T) {
	t.Parallel()
	config := Config{RespectGitignore: true, MaxFileBytes: 1024}
	rev := Revision{Worktree: "/repo", Branch: "main"}

	older, err := NewSnapshot(rev, config, settings.Snapshot{}, nil, id.NewGenerator(nil))
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	older.IndexerVersion = IndexerVersion - 1
	if older.Digest, err = older.computeDigest(); err != nil {
		t.Fatalf("computeDigest: %v", err)
	}

	// The snapshot is intact; it is only out of date.
	if err := older.Verify(); err != nil {
		t.Fatalf("the reconstructed snapshot does not verify: %v", err)
	}
	if got := older.ReuseCheck(rev, config); got != RebuildIndexerVersion {
		t.Errorf("ReuseCheck = %q, want indexer_version_changed", got)
	}
}

// Corruption outranks staleness: a damaged snapshot's version field is not evidence of anything.
func TestReuseCheckReportsCorruptionBeforeStaleness(t *testing.T) {
	t.Parallel()
	config := Config{RespectGitignore: true, MaxFileBytes: 1024}
	rev := Revision{Worktree: "/repo", Branch: "main"}

	snap, err := NewSnapshot(rev, config, settings.Snapshot{}, nil, id.NewGenerator(nil))
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	// Both stale and damaged, with no recomputed digest.
	snap.IndexerVersion = IndexerVersion - 1
	if got := snap.ReuseCheck(rev, config); got != RebuildCorrupt {
		t.Errorf("ReuseCheck = %q, want corrupt", got)
	}
}
