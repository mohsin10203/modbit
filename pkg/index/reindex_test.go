package index_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

// fixedTime is a deterministic clock for file modification times. Writing a file twice inside one
// filesystem timestamp tick would otherwise look unchanged, which would make these tests flaky for
// a reason that has nothing to do with the behaviour under test (R-TST-03).
type fixedTime struct {
	mu sync.Mutex
	at time.Time
}

func newClock() *fixedTime {
	return &fixedTime{at: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)}
}

func (f *fixedTime) next() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.at = f.at.Add(time.Second)
	return f.at
}

// write creates or replaces a file and stamps it with a fresh modification time.
func (f *fixedTime) write(t *testing.T, root, rel, contents string) {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(abs, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
	at := f.next()
	if err := os.Chtimes(abs, at, at); err != nil {
		t.Fatalf("chtimes %s: %v", rel, err)
	}
}

func remove(t *testing.T, root, rel string) {
	t.Helper()
	if err := os.RemoveAll(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
		t.Fatalf("remove %s: %v", rel, err)
	}
}

func newReindexer(t *testing.T, root string, cfg index.Config) *index.Reindexer {
	t.Helper()
	w, err := index.NewWalker(root, classifier(t, cfg, nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}
	r, err := index.NewReindexer(w, index.FlushPolicy{})
	if err != nil {
		t.Fatalf("NewReindexer: %v", err)
	}
	return r
}

// indexed returns a reindexer whose initial index has already been established.
func indexed(t *testing.T, root string) *index.Reindexer {
	t.Helper()
	r := newReindexer(t, root, config())
	if _, _, err := r.Rescan(context.Background()); err != nil {
		t.Fatalf("initial Rescan: %v", err)
	}
	return r
}

func flush(t *testing.T, r *index.Reindexer) index.ChangeSet {
	t.Helper()
	set, _, err := r.Flush(context.Background())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	return set
}

func upsertPaths(set index.ChangeSet) []string {
	out := make([]string, len(set.Upserts))
	for i, e := range set.Upserts {
		out[i] = e.Path
	}
	return out
}

// CTX-1: the first scan establishes the index.
func TestRescanEstablishesTheInitialIndex(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	clock.write(t, root, "src/util.go", "package main")
	clock.write(t, root, ".env", "SECRET=x")

	r := newReindexer(t, root, config())
	set, report, err := r.Rescan(context.Background())
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	if !set.FullRescan {
		t.Error("the initial scan must declare itself a full rescan")
	}
	if got := upsertPaths(set); !slices.Equal(got, []string{"src/main.go", "src/util.go"}) {
		t.Errorf("upserts = %v, want the two source files", got)
	}
	// An excluded path is never an upsert; it is not index content.
	if len(set.Removals) != 0 {
		t.Errorf("removals = %v, want none on a first scan", set.Removals)
	}
	if !report.Complete() {
		t.Errorf("report incomplete: %+v", report.Diagnostics)
	}

	// A second scan of an unchanged tree changes nothing.
	again, _, err := r.Rescan(context.Background())
	if err != nil {
		t.Fatalf("second Rescan: %v", err)
	}
	if !again.Empty() {
		t.Errorf("an unchanged tree produced %+v", again)
	}
}

// Applying deltas to a state that was never established would record a tree consisting of whatever
// happened to change, and call it an index.
func TestFlushRequiresAnInitialRescan(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "a.go", "package a")

	r := newReindexer(t, root, config())
	r.Observe(index.Change{Path: "a.go", Kind: index.ChangeModified})
	if _, _, err := r.Flush(context.Background()); !modberr.Is(err, modberr.CodeRunStateInvalid) {
		t.Fatalf("err = %v, want MODBIT_RUN_STATE_INVALID", err)
	}
}

// CTX-2: an edit becomes visible through one shallow rescan of its own directory.
func TestEditedFileProducesOneUpsert(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	clock.write(t, root, "src/util.go", "package main")
	clock.write(t, root, "web/app.ts", "export const a = 1;")

	r := indexed(t, root)
	clock.write(t, root, "src/main.go", "package main // edited")
	r.Observe(index.Change{Path: "src/main.go", Kind: index.ChangeModified})

	set := flush(t, r)
	if got := upsertPaths(set); !slices.Equal(got, []string{"src/main.go"}) {
		t.Errorf("upserts = %v, want only the edited file", got)
	}
	if len(set.Removals) != 0 {
		t.Errorf("removals = %v, want none", set.Removals)
	}
	if set.FullRescan {
		t.Error("an incremental flush must not claim to be a full rescan")
	}
}

// This is CTX-4 applied to an index that already exists. An ignore rule that only stopped *future*
// indexing would leave the content it names retrievable indefinitely, which is the same disclosure
// the rule was written to prevent.
func TestSecurityAddingAnIgnoreRuleRetractsIndexedContent(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	clock.write(t, root, "secrets/prod.yaml", "database_password: hunter2")
	clock.write(t, root, "secrets/nested/staging.yaml", "token: abc")
	// A file excluded by pattern rather than by an excluded parent. It stays *visible* to the
	// rescan — the walk still reports it, now as excluded — so retracting it depends on the
	// exclusion itself being treated as a removal, not on the file having vanished.
	clock.write(t, root, "src/debug.log", "connecting with token abc")

	r := indexed(t, root)
	// Everything is indexed to begin with.
	if _, _, err := r.Rescan(context.Background()); err != nil {
		t.Fatal(err)
	}

	clock.write(t, root, ".modbitignore", "secrets/\n*.log\n")
	r.Observe(index.Change{Path: ".modbitignore", Kind: index.ChangeModified})

	set := flush(t, r)
	for _, want := range []string{"secrets/prod.yaml", "secrets/nested/staging.yaml", "src/debug.log"} {
		if !slices.Contains(set.Removals, want) {
			t.Errorf("%s was not retracted; removals = %v", want, set.Removals)
		}
	}
	for _, e := range set.Upserts {
		if strings.HasPrefix(e.Path, "secrets/") {
			t.Errorf("%s was upserted after being excluded", e.Path)
		}
	}
	// Unrelated content is untouched.
	if slices.Contains(set.Removals, "src/main.go") {
		t.Error("an unrelated file was retracted")
	}
}

// The inverse: removing the rule must bring the content back, or a user who excludes a directory by
// mistake has to know to rebuild the index by hand.
func TestRemovingAnIgnoreRuleRestoresTheContent(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, ".modbitignore", "fixtures/\n")
	clock.write(t, root, "fixtures/data.json", `{"a":1}`)
	clock.write(t, root, "src/main.go", "package main")

	r := indexed(t, root)
	clock.write(t, root, ".modbitignore", "\n")
	r.Observe(index.Change{Path: ".modbitignore", Kind: index.ChangeModified})

	set := flush(t, r)
	if !slices.Contains(upsertPaths(set), "fixtures/data.json") {
		t.Errorf("the un-ignored file was not indexed; upserts = %v", upsertPaths(set))
	}
}

func TestDeletedFileIsRemoved(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	clock.write(t, root, "src/gone.go", "package main")

	r := indexed(t, root)
	remove(t, root, "src/gone.go")
	r.Observe(index.Change{Path: "src/gone.go", Kind: index.ChangeRemoved})

	set := flush(t, r)
	if !slices.Equal(set.Removals, []string{"src/gone.go"}) {
		t.Errorf("removals = %v, want the deleted file", set.Removals)
	}
	if len(set.Upserts) != 0 {
		t.Errorf("upserts = %v, want none", upsertPaths(set))
	}
}

// Deleting a directory has to retract everything under it, not just the directory itself.
func TestDeletedDirectoryRetractsItsSubtree(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "keep/a.go", "package a")
	clock.write(t, root, "drop/b.go", "package b")
	clock.write(t, root, "drop/deep/c.go", "package c")

	r := indexed(t, root)
	remove(t, root, "drop")
	r.Observe(index.Change{Path: "drop", Kind: index.ChangeRemoved})

	set := flush(t, r)
	for _, want := range []string{"drop/b.go", "drop/deep/c.go"} {
		if !slices.Contains(set.Removals, want) {
			t.Errorf("%s was not retracted; removals = %v", want, set.Removals)
		}
	}
	if slices.Contains(set.Removals, "keep/a.go") {
		t.Error("a sibling directory was retracted")
	}
}

// A new directory arrives as a single notification. Rescanning only its parent's own entries would
// skip it, leaving everything inside unindexed until something else forced a rescan.
func TestNewDirectoryIsIndexedInFull(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")

	r := indexed(t, root)
	clock.write(t, root, "pkg/new/a.go", "package a")
	clock.write(t, root, "pkg/new/deep/b.go", "package b")
	r.Observe(index.Change{Path: "pkg", Kind: index.ChangeModified})

	set := flush(t, r)
	for _, want := range []string{"pkg/new/a.go", "pkg/new/deep/b.go"} {
		if !slices.Contains(upsertPaths(set), want) {
			t.Errorf("%s was not indexed; upserts = %v", want, upsertPaths(set))
		}
	}
}

func TestNewFileInAKnownDirectoryIsIndexed(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")

	r := indexed(t, root)
	clock.write(t, root, "src/added.go", "package main")
	r.Observe(index.Change{Path: "src/added.go", Kind: index.ChangeModified})

	if got := upsertPaths(flush(t, r)); !slices.Equal(got, []string{"src/added.go"}) {
		t.Errorf("upserts = %v, want the new file", got)
	}
}

// A path the flush never looked at was not observed to be missing. Concluding otherwise is how an
// incremental reindex silently empties an index.
func TestPathsOutsideTheScannedScopeAreNotTreatedAsDeleted(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "a/one.go", "package a")
	clock.write(t, root, "b/two.go", "package b")
	clock.write(t, root, "b/deep/three.go", "package c")
	clock.write(t, root, "top.go", "package top")

	r := indexed(t, root)
	clock.write(t, root, "a/one.go", "package a // edited")
	r.Observe(index.Change{Path: "a/one.go", Kind: index.ChangeModified})

	set := flush(t, r)
	if len(set.Removals) != 0 {
		t.Fatalf("removals = %v, want none — nothing outside a/ was examined", set.Removals)
	}
	// The unexamined content is still known: a later deletion of it is still detected.
	remove(t, root, "b/two.go")
	r.Observe(index.Change{Path: "b/two.go", Kind: index.ChangeRemoved})
	if got := flush(t, r).Removals; !slices.Equal(got, []string{"b/two.go"}) {
		t.Errorf("removals = %v, want b/two.go", got)
	}
}

// A shallow scan of a directory says nothing about its subdirectories, so their contents must
// survive it.
func TestAShallowRescanDoesNotRetractSubdirectories(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	clock.write(t, root, "src/deep/nested.go", "package deep")

	r := indexed(t, root)
	clock.write(t, root, "src/main.go", "package main // edited")
	r.Observe(index.Change{Path: "src/main.go", Kind: index.ChangeModified})

	if got := flush(t, r).Removals; len(got) != 0 {
		t.Errorf("removals = %v, want none — src/deep was never listed", got)
	}
}

// An operating-system watcher drops notifications when its queue overflows. A reindexer that kept
// applying deltas afterwards would diverge from the tree with nothing to reveal it.
func TestRescanRecoversFromDroppedNotifications(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")
	clock.write(t, root, "src/gone.go", "package main")

	r := indexed(t, root)
	// Changes that arrive at no one: the watcher dropped them.
	clock.write(t, root, "src/main.go", "package main // edited")
	clock.write(t, root, "src/added.go", "package main")
	remove(t, root, "src/gone.go")

	set, _, err := r.Rescan(context.Background())
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	if !set.FullRescan {
		t.Error("recovery must declare itself a full rescan so the degradation is visible")
	}
	if got := upsertPaths(set); !slices.Equal(got, []string{"src/added.go", "src/main.go"}) {
		t.Errorf("upserts = %v, want the edited and the added file", got)
	}
	if !slices.Equal(set.Removals, []string{"src/gone.go"}) {
		t.Errorf("removals = %v, want the deleted file", set.Removals)
	}
}

// A rescan observed the tree as it is now, so changes queued before it are already accounted for.
func TestRescanSupersedesPendingChanges(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "a.go", "package a")

	r := indexed(t, root)
	clock.write(t, root, "a.go", "package a // edited")
	r.Observe(index.Change{Path: "a.go", Kind: index.ChangeModified})
	if count, _ := r.Pending(); count != 1 {
		t.Fatalf("pending = %d, want 1", count)
	}

	if _, _, err := r.Rescan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count, oldest := r.Pending(); count != 0 || !oldest.IsZero() {
		t.Errorf("pending = %d/%v after a rescan, want none", count, oldest)
	}
	if got := flush(t, r); !got.Empty() {
		t.Errorf("a flush after a rescan produced %+v", got)
	}
}

// Freshness is measured from when a change was first seen, not from the most recent notification
// about it, or a file saved repeatedly would look perpetually fresh.
func TestObserveCollapsesRepeatsAndKeepsTheOldestObservation(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "a.go", "package a")
	r := indexed(t, root)

	base := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)
	r.Observe(index.Change{Path: "a.go", Kind: index.ChangeModified, At: base})
	r.Observe(index.Change{Path: "a.go", Kind: index.ChangeModified, At: base.Add(2 * time.Second)})
	r.Observe(index.Change{Path: "b.go", Kind: index.ChangeModified, At: base.Add(time.Second)})

	count, oldest := r.Pending()
	if count != 2 {
		t.Errorf("pending = %d, want 2 — repeats on one path collapse", count)
	}
	if !oldest.Equal(base) {
		t.Errorf("oldest = %v, want the first observation %v", oldest, base)
	}
}

// A debounce alone never fires while edits keep arriving. Without the cap, a developer typing
// continuously holds the index at the last quiet moment — stale, with nothing to show it.
func TestFlushPolicyCapsTheDebounceSoEditsCannotStarveTheIndex(t *testing.T) {
	t.Parallel()
	p := index.FlushPolicy{Debounce: 250 * time.Millisecond, MaxDelay: 3 * time.Second}
	start := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)

	// A quiet burst flushes one debounce after the last change.
	if got, want := p.DueAt(start, start), start.Add(250*time.Millisecond); !got.Equal(want) {
		t.Errorf("quiet burst due at %v, want %v", got, want)
	}
	// A stream of edits still flushes at the cap.
	if got, want := p.DueAt(start, start.Add(10*time.Second)), start.Add(3*time.Second); !got.Equal(want) {
		t.Errorf("continuous edits due at %v, want the cap %v", got, want)
	}
	// The cap keeps the index inside the SLO no matter how long editing continues.
	if p.DueAt(start, start.Add(time.Hour)).Sub(start) > 10*time.Second {
		t.Error("the flush deadline exceeded the freshness SLO")
	}

	if index.DefaultMaxDelay >= 10*time.Second {
		t.Errorf("DefaultMaxDelay %v leaves no room for the rescan inside the 10s SLO", index.DefaultMaxDelay)
	}
	if index.DefaultFlushPolicy().Debounce != index.DefaultDebounce {
		t.Error("DefaultFlushPolicy disagrees with the documented defaults")
	}
}

func TestReindexerRejectsAnIncoherentPolicy(t *testing.T) {
	t.Parallel()
	w, err := index.NewWalker(t.TempDir(), classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.NewReindexer(nil, index.FlushPolicy{}); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Errorf("a nil walker must be refused: %v", err)
	}
	bad := index.FlushPolicy{Debounce: time.Second, MaxDelay: 100 * time.Millisecond}
	if _, err := index.NewReindexer(w, bad); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Errorf("a cap shorter than the debounce must be refused: %v", err)
	}
}

// Two reindexers given the same changes must produce the same set, or an index update is not
// reproducible evidence.
func TestChangeSetOrderIsDeterministic(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	for _, name := range []string{"z", "a", "m", "b", "q"} {
		clock.write(t, root, "src/"+name+".go", "package src")
	}

	var first index.ChangeSet
	for i := 0; i < 4; i++ {
		r := newReindexer(t, root, config())
		set, _, err := r.Rescan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = set
			continue
		}
		if !slices.Equal(upsertPaths(set), upsertPaths(first)) {
			t.Fatalf("upsert order differed:\n%v\n%v", upsertPaths(first), upsertPaths(set))
		}
	}
}

// Observe must not block on a flush: a watcher stalled behind a rescan lets the operating system's
// own queue overflow, which costs notifications.
func TestObserveIsSafeDuringAFlush(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		clock.write(t, root, "src/f"+string(rune('a'+i))+".go", "package src")
	}
	r := indexed(t, root)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			r.Observe(index.Change{Path: "src/f" + string(rune('a'+i%20)) + ".go", Kind: index.ChangeModified})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if _, _, err := r.Flush(context.Background()); err != nil {
				t.Errorf("Flush: %v", err)
				return
			}
			r.Pending()
			r.DueAt()
		}
	}()
	wg.Wait()
}

func BenchmarkIncrementalFlush(b *testing.B) {
	root := b.TempDir()
	for i := 0; i < 50; i++ {
		dir := filepath.Join(root, "pkg", string(rune('a'+i%26)))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "f.go"), []byte("package f\n"), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	cl, err := index.NewClassifier(index.Config{RespectGitignore: true, MaxFileBytes: 1 << 20}, nil)
	if err != nil {
		b.Fatal(err)
	}
	w, err := index.NewWalker(root, cl, index.WalkOptions{})
	if err != nil {
		b.Fatal(err)
	}
	r, err := index.NewReindexer(w, index.FlushPolicy{})
	if err != nil {
		b.Fatal(err)
	}
	if _, _, err := r.Rescan(context.Background()); err != nil {
		b.Fatal(err)
	}
	target := filepath.Join(root, "pkg", "a", "f.go")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := os.WriteFile(target, []byte("package f // "+string(rune('a'+i%26))+"\n"), 0o644); err != nil {
			b.Fatal(err)
		}
		r.Observe(index.Change{Path: "pkg/a/f.go", Kind: index.ChangeModified})
		if _, _, err := r.Flush(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
