package index

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/settings"
)

// IndexerVersion is the version of the indexing pipeline that produces a manifest.
//
// It is bumped whenever a change would make a manifest built by an older build disagree with one
// built by this build — a new classification rule, a changed disposition, a different ignore
// semantic. Snapshots carry it so a version change forces a controlled rebuild rather than leaving
// two incompatible manifests in circulation (SDD §17, UPG-6).
const IndexerVersion = 1

// ManifestEntry is one path recorded in a snapshot.
//
// Excluded paths are absent by construction. A path is itself information — that is why the
// classifier refuses to record excluded ones — so a manifest listing what was *not* indexed would
// disclose exactly what the exclusion was for.
type ManifestEntry struct {
	Path        string      `json:"path"`
	Disposition Disposition `json:"disposition"`
	Size        int64       `json:"size"`
	ModTimeUnix int64       `json:"mod_time_unix"`
	Generated   bool        `json:"generated,omitempty"`
}

// Snapshot is an immutable record of what an index contained, and of everything that determined it
// (CTX-8).
//
// Snapshots are never modified. A new scan produces a new snapshot; that is what lets a retrieval
// result cite the exact state it came from, and what makes a divergence between two of them
// meaningful evidence rather than a mystery.
type Snapshot struct {
	ID id.ID `json:"id"`
	// Revision is the source revision indexed: worktree, branch, and commit (CTX-3).
	Revision Revision `json:"revision"`
	// IndexerVersion is the pipeline version that produced Manifest.
	IndexerVersion int `json:"indexer_version"`
	// PolicySnapshotID names the settings snapshot the index was built under. It is recorded for
	// traceability — it answers "which policy produced this" — but it is deliberately not what
	// decides reuse; see ConfigDigest.
	PolicySnapshotID id.ID `json:"policy_snapshot_id"`
	// ConfigDigest covers only the settings that change what gets indexed. Reuse is decided on this
	// rather than on the whole settings digest, because a change to an unrelated setting must not
	// force a repository-wide rebuild.
	ConfigDigest string          `json:"config_digest"`
	CreatedAt    time.Time       `json:"created_at"`
	Manifest     []ManifestEntry `json:"manifest"`
	// ManifestDigest identifies the *content*: the sorted manifest and nothing else. Two scans of
	// an unchanged tree produce the same value, which is what makes "did anything change between
	// these two snapshots" answerable without comparing manifests entry by entry.
	ManifestDigest string `json:"manifest_digest"`
	// Digest is the integrity check over the whole record, identifier and timestamp included. It
	// answers a different question from ManifestDigest and the two must not be conflated: this one
	// detects a snapshot that was damaged or altered, and so covers fields that legitimately differ
	// between two otherwise identical scans.
	Digest string `json:"digest"`
}

// RebuildReason explains why a snapshot cannot be reused. The empty value means it can.
type RebuildReason string

const (
	// RebuildNone means the snapshot is current and reusable.
	RebuildNone RebuildReason = ""
	// RebuildIndexerVersion means the snapshot was produced by a different pipeline version.
	RebuildIndexerVersion RebuildReason = "indexer_version_changed"
	// RebuildConfigChanged means a setting that determines what gets indexed changed.
	RebuildConfigChanged RebuildReason = "indexing_config_changed"
	// RebuildRevisionChanged means the checkout moved.
	RebuildRevisionChanged RebuildReason = "revision_changed"
	// RebuildCorrupt means the snapshot failed verification (CTX-9).
	RebuildCorrupt RebuildReason = "corrupt"
)

// Digest returns a stable digest of the settings that determine what gets indexed.
//
// Only these three participate. `context.retrieval.budget_tokens` changing must not invalidate a
// repository's index, and a digest over the whole settings snapshot would make it.
func (c Config) Digest() string {
	globs := slices.Clone(c.ExcludedGlobs)
	sort.Strings(globs)
	form := struct {
		RespectGitignore bool     `json:"respect_gitignore"`
		MaxFileBytes     int64    `json:"max_file_bytes"`
		ExcludedGlobs    []string `json:"excluded_globs"`
	}{c.RespectGitignore, c.MaxFileBytes, globs}

	encoded, err := json.Marshal(form)
	if err != nil {
		// The form is three primitive fields and a string slice; there is no input that fails.
		panic("index: indexing config is not serializable: " + err.Error())
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NewSnapshot records a completed scan.
//
// entries are the paths the scan produced; excluded ones are rejected rather than filtered, because
// a caller passing them has misunderstood what a manifest is and silently dropping them would hide
// that.
func NewSnapshot(revision Revision, config Config, policy settings.Snapshot, entries []Entry, generator *id.Generator) (Snapshot, error) {
	manifest := make([]ManifestEntry, 0, len(entries))
	for _, e := range entries {
		if e.Disposition == DispositionExclude {
			return Snapshot{}, modberr.New(modberr.CodeInvalidArgument,
				"an excluded path cannot appear in an index manifest").
				WithDetail("field", "entries")
		}
		manifest = append(manifest, ManifestEntry{
			Path:        e.Path,
			Disposition: e.Disposition,
			Size:        e.Size,
			ModTimeUnix: e.ModTime.Unix(),
			Generated:   e.Generated,
		})
	}
	// Sorted so that two scans of the same tree produce byte-identical manifests, which is what
	// makes the digest a meaningful comparison between them.
	slices.SortFunc(manifest, func(a, b ManifestEntry) int { return strings.Compare(a.Path, b.Path) })

	if generator == nil {
		generator = id.NewGenerator(nil)
	}
	snapshotID, err := generator.New(id.IndexSnapshot)
	if err != nil {
		return Snapshot{}, modberr.Wrap(err, modberr.CodeInternal, "allocate index snapshot id")
	}

	s := Snapshot{
		ID:               snapshotID,
		Revision:         revision,
		IndexerVersion:   IndexerVersion,
		PolicySnapshotID: policy.ID,
		ConfigDigest:     config.Digest(),
		CreatedAt:        time.Now().UTC(),
		Manifest:         manifest,
	}
	manifestDigest, err := digestOf(s.Manifest)
	if err != nil {
		return Snapshot{}, err
	}
	s.ManifestDigest = manifestDigest

	digest, err := s.computeDigest()
	if err != nil {
		return Snapshot{}, err
	}
	s.Digest = digest
	return s, nil
}

// canonicalForm is the integrity-digest input: every field that describes the snapshot, including
// the ones that legitimately differ between two identical scans. The identifier is covered so that
// a snapshot cannot be renamed into another's place, and the manifest enters through its own digest
// so a large manifest is not serialized twice.
type canonicalForm struct {
	ID               id.ID    `json:"id"`
	Revision         Revision `json:"revision"`
	IndexerVersion   int      `json:"indexer_version"`
	PolicySnapshotID id.ID    `json:"policy_snapshot_id"`
	ConfigDigest     string   `json:"config_digest"`
	CreatedAtUnix    int64    `json:"created_at_unix"`
	ManifestDigest   string   `json:"manifest_digest"`
}

func (s Snapshot) computeDigest() (string, error) {
	return digestOf(canonicalForm{
		ID:               s.ID,
		Revision:         s.Revision,
		IndexerVersion:   s.IndexerVersion,
		PolicySnapshotID: s.PolicySnapshotID,
		ConfigDigest:     s.ConfigDigest,
		CreatedAtUnix:    s.CreatedAt.UnixNano(),
		ManifestDigest:   s.ManifestDigest,
	})
}

func digestOf(v any) (string, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return "", modberr.Wrap(err, modberr.CodeInternal, "serialize index snapshot")
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Verify recomputes both digests and reports whether the snapshot is intact (CTX-9).
//
// The manifest is checked first. Checking only the record digest would let an altered manifest pass
// whenever the stored ManifestDigest was altered to match it, which is the shape a deliberate
// poisoning takes rather than the shape bit-rot takes.
func (s Snapshot) Verify() error {
	corrupt := func(detail string) error {
		return modberr.New(modberr.CodeConflict, "index snapshot "+detail).
			WithDetail("resource_type", "index_snapshot")
	}

	manifestDigest, err := digestOf(s.Manifest)
	if err != nil {
		return err
	}
	if manifestDigest != s.ManifestDigest {
		return corrupt("manifest does not match its digest")
	}
	digest, err := s.computeDigest()
	if err != nil {
		return err
	}
	if digest != s.Digest {
		return corrupt("digest does not match its contents")
	}
	return nil
}

// ReuseCheck reports whether an index built from this snapshot may still be served.
//
// Every negative answer is a rebuild trigger, and each is distinguishable: an operator looking at a
// rebuild needs to know whether it was an upgrade, a policy change, a branch switch, or corruption,
// because those call for different responses.
func (s Snapshot) ReuseCheck(current Revision, config Config) RebuildReason {
	switch {
	case s.Verify() != nil:
		return RebuildCorrupt
	case s.IndexerVersion != IndexerVersion:
		return RebuildIndexerVersion
	case s.ConfigDigest != config.Digest():
		return RebuildConfigChanged
	case !s.Revision.Equal(current):
		return RebuildRevisionChanged
	}
	return RebuildNone
}

// SnapshotStore persists snapshots on the local filesystem.
//
// The directory must sit outside every indexed tree. A store written inside one would be walked by
// the next scan, so the index would record its own snapshots as repository content and grow with
// each one; `**/.modbit/**` is in the shipped exclusions for that reason, and the union merge on
// that setting means no scope can remove it.
type SnapshotStore struct {
	dir string
}

const snapshotFileSuffix = ".snapshot.json"

// NewSnapshotStore opens or creates a store directory.
func NewSnapshotStore(dir string) (*SnapshotStore, error) {
	if dir == "" {
		return nil, modberr.New(modberr.CodeInvalidArgument, "snapshot store requires a directory").
			WithDetail("field", "dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, modberr.Wrap(err, modberr.CodeUnavailable, "snapshot store directory cannot be created")
	}
	return &SnapshotStore{dir: dir}, nil
}

// Write persists a snapshot.
//
// The write is atomic: the payload lands in a temporary file that is renamed into place, so a
// crash or a full disk leaves either the previous state or the complete new one, never a truncated
// file that would read as a valid but shorter manifest.
//
// An existing snapshot is never overwritten. Snapshots are immutable, and a store that accepted a
// replacement would let the record of what was indexed be rewritten after the fact.
func (s *SnapshotStore) Write(snap Snapshot) error {
	if snap.ID.IsZero() {
		return modberr.New(modberr.CodeInvalidArgument, "snapshot has no identifier").
			WithDetail("field", "id")
	}
	if err := snap.Verify(); err != nil {
		return err
	}

	final := s.path(snap.ID)
	if _, err := os.Stat(final); err == nil {
		return modberr.New(modberr.CodeConflict, "index snapshot already exists and is immutable").
			WithDetail("resource_type", "index_snapshot")
	}

	encoded, err := json.Marshal(snap)
	if err != nil {
		return modberr.Wrap(err, modberr.CodeInternal, "serialize index snapshot")
	}

	tmp, err := os.CreateTemp(s.dir, ".tmp-snapshot-*")
	if err != nil {
		return modberr.Wrap(err, modberr.CodeUnavailable, "snapshot temporary file cannot be created")
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename has succeeded

	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return modberr.Wrap(err, modberr.CodeUnavailable, "snapshot could not be written")
	}
	// Durability before visibility: a rename that becomes visible before the bytes reach the disk
	// would leave a snapshot that exists and is empty after a power loss.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return modberr.Wrap(err, modberr.CodeUnavailable, "snapshot could not be flushed")
	}
	if err := tmp.Close(); err != nil {
		return modberr.Wrap(err, modberr.CodeUnavailable, "snapshot could not be closed")
	}
	if err := os.Rename(tmpName, final); err != nil {
		return modberr.Wrap(err, modberr.CodeUnavailable, "snapshot could not be published")
	}
	return nil
}

// Read loads a snapshot and verifies it.
//
// Verification happens here rather than at the caller's discretion: an unverified snapshot is
// indistinguishable from a verified one once it is a value in memory, and CTX-9 requires corruption
// to be detected rather than merely detectable.
func (s *SnapshotStore) Read(snapshotID id.ID) (Snapshot, error) {
	contents, err := os.ReadFile(s.path(snapshotID))
	if err != nil {
		if os.IsNotExist(err) {
			return Snapshot{}, modberr.New(modberr.CodeNotFound, "index snapshot not found").
				WithDetail("resource_type", "index_snapshot")
		}
		return Snapshot{}, modberr.Wrap(err, modberr.CodeUnavailable, "index snapshot could not be read")
	}

	var snap Snapshot
	if err := json.Unmarshal(contents, &snap); err != nil {
		// Unparseable is corruption, reported the same way a digest mismatch is: the recovery is
		// identical, and a caller that has to distinguish them will get it wrong.
		return Snapshot{}, modberr.Wrap(err, modberr.CodeConflict, "index snapshot is not readable").
			WithDetail("resource_type", "index_snapshot")
	}
	if snap.ID != snapshotID {
		// The file was renamed into this identifier's place. Its digest covers the identifier, so
		// this is caught by Verify too; reporting it here names the actual problem.
		return Snapshot{}, modberr.New(modberr.CodeConflict,
			"index snapshot identifier does not match the file it was read from").
			WithDetail("resource_type", "index_snapshot")
	}
	if err := snap.Verify(); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// Latest returns the most recently created snapshot for a revision's partition, or NotFound.
//
// Snapshots are filtered by partition key rather than scanned indiscriminately: the newest snapshot
// in the directory may belong to a different branch, and serving it would be exactly the
// contamination CTX-3 forbids.
func (s *SnapshotStore) Latest(revision Revision) (Snapshot, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return Snapshot{}, modberr.Wrap(err, modberr.CodeUnavailable, "snapshot store cannot be listed")
	}

	key := revision.Key()
	var newest Snapshot
	var found bool
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), snapshotFileSuffix) {
			continue
		}
		snapshotID, err := id.ParseAs(strings.TrimSuffix(entry.Name(), snapshotFileSuffix), id.IndexSnapshot)
		if err != nil {
			continue
		}
		snap, err := s.Read(snapshotID)
		if err != nil {
			// A corrupt snapshot must not hide an intact older one. It is skipped here and reported
			// by Verify when a caller asks for it by name.
			continue
		}
		if snap.Revision.Key() != key {
			continue
		}
		if !found || snap.CreatedAt.After(newest.CreatedAt) {
			newest, found = snap, true
		}
	}
	if !found {
		return Snapshot{}, modberr.New(modberr.CodeNotFound, "no index snapshot for this revision").
			WithDetail("resource_type", "index_snapshot")
	}
	return newest, nil
}

func (s *SnapshotStore) path(snapshotID id.ID) string {
	return filepath.Join(s.dir, string(snapshotID)+snapshotFileSuffix)
}
