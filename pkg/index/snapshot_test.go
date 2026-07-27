package index_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/settings"
)

func policySnapshot(t *testing.T) settings.Snapshot {
	t.Helper()
	resolver, err := settings.NewResolver(settings.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	result, err := resolver.Resolve(nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	snap, err := settings.NewSnapshot(result, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return snap
}

func snapshotOf(t *testing.T, root string) (index.Snapshot, index.Revision) {
	t.Helper()
	w, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}
	var entries []index.Entry
	if _, err := w.Walk(context.Background(), func(e index.Entry) error {
		if e.Disposition != index.DispositionExclude {
			entries = append(entries, e)
		}
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}

	rev := index.Revision{Worktree: root, Branch: "main", Commit: oidMain}
	snap, err := index.NewSnapshot(rev, config(), policySnapshot(t), entries, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return snap, rev
}

// CTX-8: every snapshot records source revision, indexer version, and policy version.
func TestSnapshotRecordsEverythingThatDeterminedIt(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	clock.write(t, root, "docs/big.bin", "\x00\x01\x02")

	snap, rev := snapshotOf(t, root)

	if !snap.Revision.Equal(rev) {
		t.Errorf("revision = %+v, want %+v", snap.Revision, rev)
	}
	if snap.IndexerVersion != index.IndexerVersion {
		t.Errorf("indexer version = %d, want %d", snap.IndexerVersion, index.IndexerVersion)
	}
	if snap.PolicySnapshotID.IsZero() {
		t.Error("no policy snapshot recorded")
	}
	if snap.ConfigDigest == "" {
		t.Error("no indexing-config digest recorded")
	}
	if _, err := id.ParseAs(string(snap.ID), id.IndexSnapshot); err != nil {
		t.Errorf("snapshot id is not an idxs identifier: %v", err)
	}
	if err := snap.Verify(); err != nil {
		t.Errorf("a fresh snapshot does not verify: %v", err)
	}
	if len(snap.Manifest) != 2 {
		t.Errorf("manifest has %d entries, want 2", len(snap.Manifest))
	}
}

// Two scans of the same tree under the same policy must produce the same digest, or a divergence
// between two snapshots means nothing.
func TestSnapshotDigestIsStableAcrossScans(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	for _, name := range []string{"z", "a", "m"} {
		clock.write(t, root, "src/"+name+".go", "package src")
	}

	first, _ := snapshotOf(t, root)
	second, _ := snapshotOf(t, root)
	if first.ManifestDigest != second.ManifestDigest {
		t.Errorf("two scans of one tree produced different manifest digests:\n%s\n%s",
			first.ManifestDigest, second.ManifestDigest)
	}
	// The integrity digest answers a different question and must *not* match: it covers the
	// identifier and the creation time, which legitimately differ.
	if first.Digest == second.Digest {
		t.Error("two distinct snapshots share an integrity digest")
	}
	if first.ID == second.ID {
		t.Error("two snapshots share an identifier")
	}

	// A changed tree changes the content digest.
	clock.write(t, root, "src/a.go", "package src // edited")
	changed, _ := snapshotOf(t, root)
	if changed.ManifestDigest == first.ManifestDigest {
		t.Error("an edited file did not change the manifest digest")
	}
	// The manifest is sorted, so the digest does not depend on the order entries arrived in.
	for i := 1; i < len(first.Manifest); i++ {
		if first.Manifest[i-1].Path > first.Manifest[i].Path {
			t.Fatalf("manifest is not sorted: %v", first.Manifest)
		}
	}
}

// A path is itself information. A manifest listing what was *not* indexed would disclose exactly
// what the exclusion was for.
func TestSecurityExcludedPathsCannotEnterAManifest(t *testing.T) {
	t.Parallel()
	entries := []index.Entry{
		{Decision: index.Decision{Path: "src/main.go", Disposition: index.DispositionIndex}},
		{Decision: index.Decision{Path: ".env", Disposition: index.DispositionExclude,
			Reason: index.ReasonProtectedPath}},
	}
	_, err := index.NewSnapshot(index.Revision{}, config(), policySnapshot(t), entries, nil)
	if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("err = %v, want an excluded entry to be refused", err)
	}
}

// CTX-9: corruption must be detected, not merely detectable.
func TestSecuritySnapshotCorruptionIsDetected(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	snap, _ := snapshotOf(t, root)

	store, dir := newStore(t)
	if err := store.Write(snap); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// An intact snapshot reads back.
	if _, err := store.Read(snap.ID); err != nil {
		t.Fatalf("Read: %v", err)
	}

	// Tamper with the manifest, leaving the digest untouched — the shape a silent index poisoning
	// would take, and the shape bit-rot takes.
	path := findSnapshotFile(t, dir, snap.ID)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(contents, &raw); err != nil {
		t.Fatal(err)
	}
	manifest := raw["manifest"].([]any)
	manifest[0].(map[string]any)["path"] = "src/attacker-controlled.go"
	tampered, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Read(snap.ID); !modberr.Is(err, modberr.CodeConflict) {
		t.Fatalf("tampering was not detected: err = %v", err)
	}
}

func TestSnapshotStoreDetectsAnUnparseableFile(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	snap, _ := snapshotOf(t, root)

	store, dir := newStore(t)
	if err := store.Write(snap); err != nil {
		t.Fatal(err)
	}
	// A truncated file is what a crash mid-write would have produced without the atomic rename.
	if err := os.WriteFile(findSnapshotFile(t, dir, snap.ID), []byte(`{"id":"idxs_`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(snap.ID); !modberr.Is(err, modberr.CodeConflict) {
		t.Fatalf("err = %v, want corruption to be reported", err)
	}
}

// Snapshots are immutable. A store that accepted a replacement would let the record of what was
// indexed be rewritten after the fact.
func TestSnapshotsAreImmutableOnceWritten(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	snap, _ := snapshotOf(t, root)

	store, _ := newStore(t)
	if err := store.Write(snap); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(snap); !modberr.Is(err, modberr.CodeConflict) {
		t.Fatalf("err = %v, want a rewrite to be refused", err)
	}
}

// A store must not publish a snapshot whose digest does not match what it carries.
func TestSnapshotStoreRefusesAnInconsistentSnapshot(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	snap, _ := snapshotOf(t, root)
	snap.Manifest[0].Path = "src/swapped.go"

	store, _ := newStore(t)
	if err := store.Write(snap); !modberr.Is(err, modberr.CodeConflict) {
		t.Fatalf("err = %v, want the write to be refused", err)
	}
}

// Each rebuild trigger is distinguishable, because an operator seeing a rebuild needs to know
// whether it was an upgrade, a policy change, a branch switch, or corruption.
func TestReuseCheckDistinguishesEveryRebuildTrigger(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	snap, rev := snapshotOf(t, root)

	if got := snap.ReuseCheck(rev, config()); got != index.RebuildNone {
		t.Errorf("a current snapshot reported %q, want reusable", got)
	}

	other := rev
	other.Branch = "feature"
	if got := snap.ReuseCheck(other, config()); got != index.RebuildRevisionChanged {
		t.Errorf("branch switch = %q, want revision_changed", got)
	}

	changed := config()
	changed.ExcludedGlobs = append(changed.ExcludedGlobs, "**/newly-excluded/**")
	if got := snap.ReuseCheck(rev, changed); got != index.RebuildConfigChanged {
		t.Errorf("config change = %q, want indexing_config_changed", got)
	}

	corrupt := snap
	corrupt.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if got := corrupt.ReuseCheck(rev, config()); got != index.RebuildCorrupt {
		t.Errorf("corruption = %q, want corrupt", got)
	}
}

// A change to a setting that does not determine what gets indexed must not invalidate the index.
func TestUnrelatedSettingsDoNotForceARebuild(t *testing.T) {
	t.Parallel()
	base := index.Config{RespectGitignore: true, MaxFileBytes: 1024,
		ExcludedGlobs: []string{"**/dist/**", "**/node_modules/**"}}

	// Glob order is not meaningful; the same set must digest identically.
	reordered := index.Config{RespectGitignore: true, MaxFileBytes: 1024,
		ExcludedGlobs: []string{"**/node_modules/**", "**/dist/**"}}
	if base.Digest() != reordered.Digest() {
		t.Error("glob ordering changed the config digest")
	}

	for name, changed := range map[string]index.Config{
		"size limit":  {RespectGitignore: true, MaxFileBytes: 2048, ExcludedGlobs: base.ExcludedGlobs},
		"gitignore":   {RespectGitignore: false, MaxFileBytes: 1024, ExcludedGlobs: base.ExcludedGlobs},
		"new exclude": {RespectGitignore: true, MaxFileBytes: 1024, ExcludedGlobs: []string{"**/dist/**"}},
	} {
		if base.Digest() == changed.Digest() {
			t.Errorf("%s did not change the config digest", name)
		}
	}
}

// The newest snapshot in the directory may belong to another branch, and serving it would be the
// contamination CTX-3 forbids.
func TestLatestIsScopedToTheRevisionPartition(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")

	store, _ := newStore(t)

	mainRev := index.Revision{Worktree: root, Branch: "main", Commit: oidMain}
	featureRev := index.Revision{Worktree: root, Branch: "feature", Commit: oidFeature}

	mainSnap, err := index.NewSnapshot(mainRev, config(), policySnapshot(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(mainSnap); err != nil {
		t.Fatal(err)
	}
	// Written later, so it is the newest in the directory.
	time.Sleep(2 * time.Millisecond)
	featureSnap, err := index.NewSnapshot(featureRev, config(), policySnapshot(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(featureSnap); err != nil {
		t.Fatal(err)
	}

	got, err := store.Latest(mainRev)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got.ID != mainSnap.ID {
		t.Errorf("Latest returned %s, want the main-branch snapshot %s", got.ID, mainSnap.ID)
	}
	if got.Revision.Branch != "main" {
		t.Errorf("Latest returned branch %q", got.Revision.Branch)
	}

	absent := index.Revision{Worktree: root, Branch: "nothing-here"}
	if _, err := store.Latest(absent); !modberr.Is(err, modberr.CodeNotFound) {
		t.Errorf("err = %v, want NOT_FOUND for a partition with no snapshot", err)
	}
}

// A corrupt snapshot must not hide an intact older one; recovery is CTX-9's whole point.
func TestLatestSkipsACorruptSnapshot(t *testing.T) {
	t.Parallel()
	rev := index.Revision{Worktree: "/repo", Branch: "main", Commit: oidMain}
	store, dir := newStore(t)

	good, err := index.NewSnapshot(rev, config(), policySnapshot(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(good); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	newer, err := index.NewSnapshot(rev, config(), policySnapshot(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(newer); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(findSnapshotFile(t, dir, newer.ID), []byte("{ truncated"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := store.Latest(rev)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got.ID != good.ID {
		t.Errorf("Latest returned %s, want the intact older snapshot %s", got.ID, good.ID)
	}
}

func TestSnapshotStoreReportsAMissingSnapshot(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	if _, err := store.Read(id.MustNew(id.IndexSnapshot)); !modberr.Is(err, modberr.CodeNotFound) {
		t.Errorf("err = %v, want NOT_FOUND", err)
	}
	if _, err := index.NewSnapshotStore(""); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Errorf("an empty directory must be refused: %v", err)
	}
}

// A partially written snapshot must never be readable as a complete one. The temporary file the
// atomic write uses must also not be mistaken for a snapshot.
func TestSnapshotWritesAreAtomic(t *testing.T) {
	t.Parallel()
	rev := index.Revision{Worktree: "/repo", Branch: "main", Commit: oidMain}
	dir := filepath.Join(t.TempDir(), "snapshots")
	store, err := index.NewSnapshotStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := index.NewSnapshot(rev, config(), policySnapshot(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(snap); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("a temporary file survived the write: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d files, want exactly the snapshot", len(entries))
	}
}

// Modbit's own state directory must never be indexed: each scan would otherwise record the
// previous scan's output as repository content.
func TestSecurityModbitStateDirectoryIsExcludedByDefault(t *testing.T) {
	t.Parallel()
	cfg, err := index.ConfigFromSnapshot(policySnapshot(t))
	if err != nil {
		t.Fatalf("ConfigFromSnapshot: %v", err)
	}

	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	clock.write(t, root, ".modbit/snapshots/idxs_abc.snapshot.json", `{"manifest":[]}`)

	got := byPath(mustWalk(t, root, cfg))
	if _, indexed := got[".modbit/snapshots/idxs_abc.snapshot.json"]; indexed {
		t.Error("a snapshot inside the tree was walked into")
	}
	if e := got[".modbit"]; e.Disposition != index.DispositionExclude {
		t.Errorf(".modbit = %s, want exclude by the shipped default", e.Disposition)
	}
	if !got["src/main.go"].Indexable() {
		t.Error("ordinary source must still be indexed")
	}
}

// newStore returns a snapshot store and the directory backing it.
func newStore(t *testing.T) (*index.SnapshotStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "snapshots")
	store, err := index.NewSnapshotStore(dir)
	if err != nil {
		t.Fatalf("NewSnapshotStore: %v", err)
	}
	return store, dir
}

// findSnapshotFile locates a snapshot's file by identifier rather than assuming the store's layout.
func findSnapshotFile(t *testing.T, dir string, snapshotID id.ID) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), string(snapshotID)) {
			return filepath.Join(dir, e.Name())
		}
	}
	t.Fatalf("no file for snapshot %s in %s", snapshotID, dir)
	return ""
}
