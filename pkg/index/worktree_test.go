package index_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

// Object ids used by the fixtures. Building checkouts by hand rather than shelling out to git keeps
// these tests deterministic and independent of whichever git is installed (R-TST-03) — and it is
// also the only way to construct the malformed states that matter here.
const (
	oidMain    = "1111111111111111111111111111111111111111"
	oidFeature = "2222222222222222222222222222222222222222"
	oidTag     = "3333333333333333333333333333333333333333"
)

type gitFixture struct {
	root      string
	gitDir    string
	commonDir string
}

// initGit lays out a primary checkout on branch main.
func initGit(t *testing.T, root string) *gitFixture {
	t.Helper()
	g := &gitFixture{root: root, gitDir: filepath.Join(root, ".git")}
	g.commonDir = g.gitDir
	if err := os.MkdirAll(filepath.Join(g.gitDir, "refs", "heads"), 0o755); err != nil {
		t.Fatal(err)
	}
	g.writeHead(t, "ref: refs/heads/main\n")
	g.writeRef(t, "refs/heads/main", oidMain)
	return g
}

func (g *gitFixture) writeHead(t *testing.T, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(g.gitDir, "HEAD"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (g *gitFixture) writeRef(t *testing.T, ref, oid string) {
	t.Helper()
	abs := filepath.Join(g.commonDir, filepath.FromSlash(ref))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(oid+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (g *gitFixture) writePackedRefs(t *testing.T, lines ...string) {
	t.Helper()
	body := "# pack-refs with: peeled fully-peeled sorted \n" + strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(g.commonDir, "packed-refs"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func revisionOf(t *testing.T, root string) index.Revision {
	t.Helper()
	w, err := index.OpenWorktree(root)
	if err != nil {
		t.Fatalf("OpenWorktree: %v", err)
	}
	rev, err := w.Revision()
	if err != nil {
		t.Fatalf("Revision: %v", err)
	}
	return rev
}

func TestWorktreeReadsBranchAndCommit(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	initGit(t, root)

	rev := revisionOf(t, root)
	if rev.Branch != "main" || rev.Commit != oidMain {
		t.Errorf("revision = %+v, want branch main at %s", rev, oidMain)
	}
	if rev.Detached || rev.Linked {
		t.Errorf("revision = %+v, want an attached primary checkout", rev)
	}
}

// A repository with many tags packs its refs, and the loose file simply is not there.
func TestWorktreeResolvesPackedRefs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	g := initGit(t, root)
	if err := os.Remove(filepath.Join(g.commonDir, "refs", "heads", "main")); err != nil {
		t.Fatal(err)
	}
	g.writePackedRefs(t,
		oidTag+" refs/tags/v1.0",
		"^"+oidFeature, // a peeled tag target, which names no reference
		oidMain+" refs/heads/main",
	)

	if rev := revisionOf(t, root); rev.Commit != oidMain {
		t.Errorf("commit = %q, want %s from packed-refs", rev.Commit, oidMain)
	}
}

func TestWorktreeDetectsADetachedHead(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	g := initGit(t, root)
	g.writeHead(t, oidFeature+"\n")

	rev := revisionOf(t, root)
	if !rev.Detached || rev.Commit != oidFeature || rev.Branch != "" {
		t.Errorf("revision = %+v, want detached at %s", rev, oidFeature)
	}
}

// `git init` with nothing committed. The branch is real and the tree is indexable.
func TestWorktreeHandlesAnUnbornBranch(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	g := initGit(t, root)
	if err := os.Remove(filepath.Join(g.commonDir, "refs", "heads", "main")); err != nil {
		t.Fatal(err)
	}

	rev := revisionOf(t, root)
	if rev.Branch != "main" || rev.Commit != "" {
		t.Errorf("revision = %+v, want branch main with no commit", rev)
	}
}

// A `git worktree add` checkout has its own HEAD but shares the repository's branches. Reading its
// branch from the wrong directory is precisely how one worktree's index comes to describe another's
// checkout.
func TestLinkedWorktreeHasItsOwnHeadButSharedRefs(t *testing.T) {
	t.Parallel()
	primary := t.TempDir()
	g := initGit(t, primary)
	g.writeRef(t, "refs/heads/feature", oidFeature)

	// The layout `git worktree add` produces.
	linkedRoot := t.TempDir()
	linkedGitDir := filepath.Join(primary, ".git", "worktrees", "feature")
	if err := os.MkdirAll(linkedGitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(linkedGitDir, "HEAD"),
		[]byte("ref: refs/heads/feature\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(linkedGitDir, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(linkedRoot, ".git"),
		[]byte("gitdir: "+linkedGitDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rev := revisionOf(t, linkedRoot)
	if rev.Branch != "feature" {
		t.Errorf("branch = %q, want feature from the linked worktree's own HEAD", rev.Branch)
	}
	if rev.Commit != oidFeature {
		t.Errorf("commit = %q, want %s resolved from the shared refs", rev.Commit, oidFeature)
	}
	if !rev.Linked {
		t.Error("the checkout should be reported as linked")
	}

	// The two checkouts must not share an index partition.
	if primaryRev := revisionOf(t, primary); primaryRev.SamePartition(rev) {
		t.Error("a linked worktree shares an index partition with the primary checkout")
	}
}

// Indexing a plain directory is supported, so this is an ordinary outcome rather than a failure.
func TestOpenWorktreeReportsANonRepositoryPlainly(t *testing.T) {
	t.Parallel()
	if _, err := index.OpenWorktree(t.TempDir()); !errors.Is(err, index.ErrNotARepository) {
		t.Fatalf("err = %v, want ErrNotARepository", err)
	}

	// A symlinked `.git` is not followed, for the same reason the walk does not follow links.
	root := t.TempDir()
	other := t.TempDir()
	if err := os.Symlink(other, filepath.Join(root, ".git")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := index.OpenWorktree(root); !errors.Is(err, index.ErrNotARepository) {
		t.Errorf("a symlinked .git should not be followed: err = %v", err)
	}
}

// A branch name is chosen by whoever can push to the repository, so it is untrusted input
// (R-SEC-01) that flows into partition keys, logs, and snapshot records.
func TestSecurityMalformedRefNamesAreRejected(t *testing.T) {
	t.Parallel()
	hostile := map[string]string{
		"path traversal":      "ref: refs/heads/../../../../etc/passwd",
		"empty component":     "ref: refs/heads//evil",
		"outside refs":        "ref: /etc/passwd",
		"reserved character":  "ref: refs/heads/a:b",
		"revision syntax":     "ref: refs/heads/a@{0}",
		"control character":   "ref: refs/heads/a\x01b",
		"lock suffix":         "ref: refs/heads/main.lock",
		"dot component":       "ref: refs/heads/.hidden",
		"backslash":           `ref: refs/heads/a\b`,
		"not an object id":    "not-a-ref-and-not-an-oid",
		"truncated object id": "11111111",
	}
	for name, head := range hostile {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			g := initGit(t, root)
			g.writeHead(t, head+"\n")

			w, err := index.OpenWorktree(root)
			if err != nil {
				t.Fatalf("OpenWorktree: %v", err)
			}
			rev, err := w.Revision()
			if err == nil {
				t.Fatalf("%q was accepted, yielding %+v", head, rev)
			}
			if !modberr.Is(err, modberr.CodeContractValidationFailed) {
				t.Errorf("err = %v, want MODBIT_CONTRACT_VALIDATION_FAILED", err)
			}
		})
	}
}

// PRD §7 budgets zero branch/worktree contamination incidents. The key is what enforces it.
func TestRevisionKeyPartitionsByWorktreeAndBranch(t *testing.T) {
	t.Parallel()
	base := index.Revision{Worktree: "/repo", Branch: "main", Commit: oidMain}

	sameBranchNewCommit := base
	sameBranchNewCommit.Commit = oidFeature
	if !base.SamePartition(sameBranchNewCommit) {
		t.Error("committing must advance the existing partition, not create a new one")
	}

	otherBranch := base
	otherBranch.Branch = "feature"
	if base.SamePartition(otherBranch) {
		t.Error("two branches must not share an index partition")
	}

	otherWorktree := base
	otherWorktree.Worktree = "/repo-2"
	if base.SamePartition(otherWorktree) {
		t.Error("two worktrees must not share an index partition")
	}

	// Detached HEADs have no branch to identify them, so the commit stands in.
	detachedA := index.Revision{Worktree: "/repo", Commit: oidMain, Detached: true}
	detachedB := index.Revision{Worktree: "/repo", Commit: oidFeature, Detached: true}
	if detachedA.SamePartition(detachedB) {
		t.Error("two detached checkouts at different commits must not share a partition")
	}
	if detachedA.SamePartition(base) {
		t.Error("a detached checkout must not share a partition with a branch")
	}
}

// A key that embedded the branch name verbatim would let a name address a partition it does not
// own, and let two different checkouts collide onto one.
func TestSecurityKeyCannotBeSteeredByABranchName(t *testing.T) {
	t.Parallel()
	victim := index.Revision{Worktree: "/repo", Branch: "main", Commit: oidMain}

	attempts := []index.Revision{
		{Worktree: "/repo", Branch: "../repo/main", Commit: oidMain},
		{Worktree: "/repo", Branch: "/repo/main", Commit: oidMain},
		{Worktree: "/", Branch: "repo/main", Commit: oidMain},
		{Worktree: "/repomain", Branch: "", Commit: oidMain},
		{Worktree: "/repo/main", Branch: "", Commit: oidMain},
	}
	for _, a := range attempts {
		if a.SamePartition(victim) {
			t.Errorf("%+v collided with the victim partition", a)
		}
		if strings.Contains(a.Key(), a.Branch) && a.Branch != "" {
			t.Errorf("the key embeds the branch name verbatim: %s", a.Key())
		}
		if strings.ContainsAny(a.Key(), "/.\\") {
			t.Errorf("the key is not opaque: %s", a.Key())
		}
	}
}

// A repository must not be able to choose how much memory reading its plumbing consumes.
func TestWorktreeBoundsPlumbingReads(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	g := initGit(t, root)
	g.writeHead(t, "ref: refs/heads/"+strings.Repeat("a", 100_000))

	w, err := index.OpenWorktree(root)
	if err != nil {
		t.Fatalf("OpenWorktree: %v", err)
	}
	if _, err := w.Revision(); err == nil {
		t.Fatal("an oversized HEAD should not resolve")
	}
}

// CTX-3 and the zero-contamination budget. A checkout rewrites the working tree far faster than a
// notification queue drains, so pending changes cannot be assumed to describe it.
func TestSecurityBranchSwitchRefusesAnIncrementalFlush(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	g := initGit(t, root)
	g.writeRef(t, "refs/heads/feature", oidFeature)
	clock.write(t, root, "src/main.go", "package main")

	w, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := index.NewReindexer(w, index.FlushPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := index.OpenWorktree(root)
	if err != nil {
		t.Fatal(err)
	}
	r.BindWorktree(worktree)
	if _, _, err := r.Rescan(context.Background()); err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	if got := r.Revision().Branch; got != "main" {
		t.Fatalf("bound revision branch = %q, want main", got)
	}

	// The checkout switches branches. Whatever the watcher managed to report is not a description
	// of that.
	g.writeHead(t, "ref: refs/heads/feature\n")
	clock.write(t, root, "src/main.go", "package feature")
	r.Observe(index.Change{Path: "src/main.go", Kind: index.ChangeModified})

	_, _, err = r.Flush(context.Background())
	if !modberr.Is(err, modberr.CodeSnapshotDiverged) {
		t.Fatalf("err = %v, want MODBIT_SNAPSHOT_DIVERGED", err)
	}
	// The changes are not lost: they are still pending for the rescan that resolves the divergence.
	if count, _ := r.Pending(); count == 0 {
		t.Error("a refused flush discarded the pending changes")
	}

	// A rescan adopts the new revision and the index proceeds on the new branch.
	set, _, err := r.Rescan(context.Background())
	if err != nil {
		t.Fatalf("Rescan after divergence: %v", err)
	}
	if !set.FullRescan {
		t.Error("recovery from a branch switch must be a full rescan")
	}
	if got := r.Revision().Branch; got != "feature" {
		t.Errorf("revision branch = %q, want feature", got)
	}
	if _, _, err := r.Flush(context.Background()); err != nil {
		t.Errorf("a flush on the adopted revision should succeed: %v", err)
	}
}

// Committing does not rewrite the working tree, but it does move HEAD. The reindexer treats any
// revision change as requiring a rescan, which is the conservative reading of CTX-3.
func TestCommitOnTheSameBranchRequiresARescan(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	g := initGit(t, root)
	clock.write(t, root, "src/main.go", "package main")

	w, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := index.NewReindexer(w, index.FlushPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := index.OpenWorktree(root)
	if err != nil {
		t.Fatal(err)
	}
	r.BindWorktree(worktree)
	if _, _, err := r.Rescan(context.Background()); err != nil {
		t.Fatal(err)
	}

	g.writeRef(t, "refs/heads/main", oidFeature)
	r.Observe(index.Change{Path: "src/main.go", Kind: index.ChangeModified})
	if _, _, err := r.Flush(context.Background()); !modberr.Is(err, modberr.CodeSnapshotDiverged) {
		t.Fatalf("err = %v, want MODBIT_SNAPSHOT_DIVERGED", err)
	}
	// The partition is unchanged, though: the index advances rather than being rebuilt elsewhere.
	before := index.Revision{Worktree: root, Branch: "main", Commit: oidMain}
	after := index.Revision{Worktree: root, Branch: "main", Commit: oidFeature}
	if !before.SamePartition(after) {
		t.Error("a commit must not move the index to a different partition")
	}
}

// A directory with no checkout is indexed without revision awareness rather than refused.
func TestReindexerWithoutAWorktreeIsUnaffected(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	clock.write(t, root, "src/main.go", "package main")

	r := indexed(t, root)
	clock.write(t, root, "src/main.go", "package main // edited")
	r.Observe(index.Change{Path: "src/main.go", Kind: index.ChangeModified})
	if got := upsertPaths(flush(t, r)); len(got) != 1 {
		t.Errorf("upserts = %v, want the edited file", got)
	}
	if rev := r.Revision(); rev.Commit != "" || rev.Branch != "" {
		t.Errorf("revision = %+v, want the zero revision", rev)
	}
}

// State gathered before a binding was never checked against a revision, so it cannot be trusted
// after one.
func TestBindWorktreeRequiresAFreshRescan(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	initGit(t, root)
	clock.write(t, root, "src/main.go", "package main")

	r := indexed(t, root)
	worktree, err := index.OpenWorktree(root)
	if err != nil {
		t.Fatal(err)
	}
	r.BindWorktree(worktree)

	r.Observe(index.Change{Path: "src/main.go", Kind: index.ChangeModified})
	if _, _, err := r.Flush(context.Background()); !modberr.Is(err, modberr.CodeRunStateInvalid) {
		t.Fatalf("err = %v, want the binding to invalidate the earlier scan", err)
	}
}

// The `.git` directory is not indexed, so a checkout's own metadata never becomes retrievable
// content — already asserted for the walk, re-asserted here against a real repository layout.
func TestSecurityRepositoryMetadataIsNotIndexed(t *testing.T) {
	t.Parallel()
	clock := newClock()
	root := t.TempDir()
	initGit(t, root)
	clock.write(t, root, "src/main.go", "package main")
	if err := os.WriteFile(filepath.Join(root, ".git", "config"),
		[]byte("[remote \"origin\"]\n\turl = https://x:ghp_notarealtoken@github.com/o/r.git\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := newReindexer(t, root, config())
	set, _, err := r.Rescan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range set.Upserts {
		if strings.HasPrefix(e.Path, ".git") {
			t.Errorf("repository metadata was indexed: %s", e.Path)
		}
	}
}
