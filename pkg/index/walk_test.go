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
	"github.com/modbit/modbit/pkg/taint"
)

// tree writes a fixture tree and returns its root. A key ending in "/" creates an empty directory.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, contents := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if strings.HasSuffix(rel, "/") {
			if err := os.MkdirAll(abs, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", rel, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(abs, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

func walkTree(t *testing.T, root string, cfg index.Config) ([]index.Entry, index.Report) {
	t.Helper()
	w, err := index.NewWalker(root, classifier(t, cfg, nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}
	var entries []index.Entry
	report, err := w.Walk(context.Background(), func(e index.Entry) error {
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return entries, report
}

func byPath(entries []index.Entry) map[string]index.Entry {
	out := make(map[string]index.Entry, len(entries))
	for _, e := range entries {
		out[e.Path] = e
	}
	return out
}

func paths(entries []index.Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Path
	}
	return out
}

// PRD §20A.10: hierarchical ignore discovery. A nested ignore file governs its own subtree and
// nothing above or beside it, and a deeper rule overrides a shallower one.
func TestWalkDiscoversIgnoreFilesHierarchically(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		".gitignore":                   "*.log\n",
		"app.log":                      "root log",
		"src/main.go":                  "package main",
		"src/.modbitignore":            "generated/\n",
		"src/generated/api.go":         "package generated",
		"src/keep.log":                 "still ignored by the root rule",
		"web/.gitignore":               "!important.log\n",
		"web/important.log":            "re-included by a deeper rule",
		"web/other.log":                "ignored by the root rule",
		"web/deep/nested/component.ts": "export const x = 1;",
	})

	entries, report := walkTree(t, root, config())
	got := byPath(entries)

	if e, ok := got["src/main.go"]; !ok || !e.Indexable() {
		t.Errorf("src/main.go = %+v, want indexable", e)
	}
	if e, ok := got["web/deep/nested/component.ts"]; !ok || !e.Indexable() {
		t.Errorf("a deeply nested file was not indexed: %+v", e)
	}
	if e := got["app.log"]; e.Disposition != index.DispositionExclude {
		t.Errorf("app.log = %s, want exclude from the root .gitignore", e.Disposition)
	}
	if e := got["src/keep.log"]; e.Disposition != index.DispositionExclude {
		t.Errorf("src/keep.log = %s — a root rule must reach into subdirectories", e.Disposition)
	}
	// A nested ignore file applies only beneath itself.
	if _, ok := got["src/generated/api.go"]; ok {
		t.Error("src/.modbitignore should have pruned src/generated before its files were reached")
	}
	if e, ok := got["src/generated"]; !ok || e.Disposition != index.DispositionExclude {
		t.Errorf("the excluded directory itself should be reported once: %+v", e)
	}
	// The deeper negation wins over the shallower exclusion.
	if e := got["web/important.log"]; e.Disposition == index.DispositionExclude {
		t.Error("a deeper .gitignore negation must override a shallower exclusion")
	}
	if e := got["web/other.log"]; e.Disposition != index.DispositionExclude {
		t.Errorf("web/other.log = %s — the negation must not re-include every log", e.Disposition)
	}
	if report.Stats.IgnoreFiles != 3 {
		t.Errorf("IgnoreFiles = %d, want 3", report.Stats.IgnoreFiles)
	}
	if !report.Complete() {
		t.Errorf("walk reported incomplete: %+v", report.Diagnostics)
	}
}

// Two sibling directories that each declare rules must not see each other's. Both inherit the same
// parent pattern slice, so appending to it in place would let whichever sibling is walked first
// write its rules into the other's inheritance.
func TestWalkKeepsSiblingIgnoreFilesIndependent(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		"pkg/.modbitignore":   "*.shared\n",
		"pkg/a/.modbitignore": "*.aaa\n",
		"pkg/a/f.aaa":         "excluded in a",
		"pkg/a/f.bbb":         "kept in a",
		"pkg/a/f.shared":      "excluded by the parent",
		"pkg/b/.modbitignore": "*.bbb\n",
		"pkg/b/f.aaa":         "kept in b",
		"pkg/b/f.bbb":         "excluded in b",
		"pkg/b/f.shared":      "excluded by the parent",
	})

	got := byPath(mustEntries(t, root))
	for path, wantExcluded := range map[string]bool{
		"pkg/a/f.aaa": true, "pkg/a/f.bbb": false, "pkg/a/f.shared": true,
		"pkg/b/f.aaa": false, "pkg/b/f.bbb": true, "pkg/b/f.shared": true,
	} {
		e, ok := got[path]
		if !ok {
			t.Errorf("%s was not reported", path)
			continue
		}
		if excluded := e.Disposition == index.DispositionExclude; excluded != wantExcluded {
			t.Errorf("%s excluded = %t, want %t — sibling rules leaked", path, excluded, wantExcluded)
		}
	}
}

func mustEntries(t *testing.T, root string) []index.Entry {
	t.Helper()
	entries, _ := walkTree(t, root, config())
	return entries
}

// CTX-4 requires exclusion *before* indexing. Pruning is what makes that true of the filesystem
// rather than only of the decision: an excluded subtree is never listed, so its contents are never
// read at all.
func TestWalkPrunesExcludedDirectoriesInsteadOfDescending(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		".modbitignore":                    "node_modules/\n",
		"node_modules/react/index.js":      "module.exports = 1;",
		"node_modules/react/deep/a/b/c.js": "nested",
		"src/app.js":                       "import 'react';",
	})

	entries, report := walkTree(t, root, config())
	for _, e := range entries {
		if strings.HasPrefix(e.Path, "node_modules/") {
			t.Errorf("walked into an excluded subtree: %s", e.Path)
		}
	}
	if got := byPath(entries)["node_modules"]; got.Disposition != index.DispositionExclude {
		t.Errorf("node_modules = %s, want a single exclude entry", got.Disposition)
	}
	if report.Stats.Pruned != 1 {
		t.Errorf("Pruned = %d, want 1", report.Stats.Pruned)
	}
	// Only the root and src were listed.
	if report.Stats.Directories != 2 {
		t.Errorf("Directories = %d, want 2 — an excluded directory must not be listed", report.Stats.Directories)
	}
}

// `.git/config` routinely holds a remote URL with an embedded token, and none of it is source.
func TestSecurityWalkPrunesVersionControlMetadata(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		".git/config": "[remote \"origin\"]\n\turl = https://x-token:ghp_notarealtoken@github.com/o/r.git\n",
		".git/HEAD":   "ref: refs/heads/main\n",
		".hg/hgrc":    "[paths]\n",
		"src/main.go": "package main",
	})

	entries, _ := walkTree(t, root, config())
	for _, e := range entries {
		if strings.HasPrefix(e.Path, ".git/") || strings.HasPrefix(e.Path, ".hg/") {
			t.Errorf("VCS metadata was walked: %s", e.Path)
		}
	}
	got := byPath(entries)
	if e := got[".git"]; e.Disposition != index.DispositionExclude || e.Reason != index.ReasonVCSMetadata {
		t.Errorf(".git = %s/%s, want exclude/vcs_metadata", e.Disposition, e.Reason)
	}
}

// A symlink committed to a repository must not become a path into the rest of the machine. The
// protected list describes a repository's own layout; it was never written to cover whatever an
// arbitrary link points at.
func TestSecurityWalkNeverFollowsSymlinks(t *testing.T) {
	t.Parallel()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "customer-data.txt"), []byte("not ours"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := tree(t, map[string]string{"src/main.go": "package main"})
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "src", "main.go"), filepath.Join(root, "alias.go")); err != nil {
		t.Fatal(err)
	}

	entries, _ := walkTree(t, root, config())
	for _, e := range entries {
		if strings.Contains(e.Path, "customer-data") {
			t.Fatalf("the walk resolved a symlink out of the tree: %s", e.Path)
		}
	}
	got := byPath(entries)
	for _, link := range []string{"escape", "alias.go"} {
		e, ok := got[link]
		if !ok {
			t.Errorf("%s was not reported at all", link)
			continue
		}
		if e.Disposition != index.DispositionExclude || e.Reason != index.ReasonSymlink {
			t.Errorf("%s = %s/%s, want exclude/symlink", link, e.Disposition, e.Reason)
		}
	}
}

// `.modbitignore` means Modbit does not read the content. Making the file unreadable proves it:
// had the walk opened it, the attempt would have failed and produced a diagnostic.
func TestSecurityModbitIgnoredFilesAreNeverOpened(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root; file permissions do not deny access")
	}
	root := tree(t, map[string]string{
		".modbitignore":    "confidential.txt\n",
		"confidential.txt": "board minutes",
		"src/main.go":      "package main",
	})
	unreadable := filepath.Join(root, "confidential.txt")
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o644) })

	entries, report := walkTree(t, root, config())
	if e := byPath(entries)["confidential.txt"]; e.Disposition != index.DispositionExclude {
		t.Errorf("confidential.txt = %s, want exclude", e.Disposition)
	}
	for _, d := range report.Diagnostics {
		if d.Reason == index.DiagFileUnreadable {
			t.Fatalf("the walk opened a .modbitignore'd file: %+v", d)
		}
	}
}

// An ignore file Modbit cannot read is an instruction Modbit cannot follow. Indexing the subtree
// anyway would index exactly the content that file existed to withhold, so the walk fails closed.
func TestWalkFailsClosedOnAnUnreadableIgnoreFile(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root; file permissions do not deny access")
	}
	root := tree(t, map[string]string{
		"src/.modbitignore": "secrets/\n",
		"src/main.go":       "package main",
		"src/secrets/k.txt": "material",
		"top.go":            "package top",
	})
	blocked := filepath.Join(root, "src", ".modbitignore")
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o644) })

	entries, report := walkTree(t, root, config())
	for _, e := range entries {
		if strings.HasPrefix(e.Path, "src/") {
			t.Errorf("src was indexed despite an unreadable ignore file: %s", e.Path)
		}
	}
	if byPath(entries)["top.go"].Disposition == "" {
		t.Error("the rest of the repository should still be indexed")
	}
	if report.Complete() {
		t.Error("a walk that skipped a subtree must not report itself complete")
	}
	var found bool
	for _, d := range report.Diagnostics {
		if d.Reason == index.DiagIgnoreFileUnreadable && d.Path == "src/.modbitignore" {
			found = true
		}
	}
	if !found {
		t.Errorf("no diagnostic named the unreadable ignore file: %+v", report.Diagnostics)
	}
}

// `.modbitindexingignore` withholds content from the indexes without hiding it. Collapsing it into
// an exclusion would make a large fixture invisible to a user who knows it is there.
func TestIndexingIgnoreYieldsReferenceNotExclusion(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		".modbitindexingignore": "fixtures/\n*.snap\n",
		"fixtures/big.json":     `{"a":1}`,
		"ui/Button.snap":        "rendered",
		"src/main.go":           "package main",
	})

	got := byPath(mustEntries(t, root))
	for _, path := range []string{"fixtures/big.json", "ui/Button.snap"} {
		e, ok := got[path]
		if !ok {
			t.Errorf("%s was not reported; .modbitindexingignore must not hide it", path)
			continue
		}
		if e.Disposition != index.DispositionReference {
			t.Errorf("%s = %s, want reference", path, e.Disposition)
		}
		if e.Reason != index.ReasonIgnoreFile {
			t.Errorf("%s reason = %q, want ignore_file", path, e.Reason)
		}
	}
	if !got["src/main.go"].Indexable() {
		t.Error("unrelated source must remain indexable")
	}
}

// An index built from one walk must be reproducible from another, which requires the walk itself
// to be ordered (CTX-8 records a snapshot against a revision).
func TestWalkOrderIsDeterministic(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		"z.go": "package z", "a.go": "package a", "m/b.go": "package b",
		"m/a.go": "package a", "b/z.go": "package z",
	})

	first, _ := walkTree(t, root, config())
	for i := 0; i < 3; i++ {
		next, _ := walkTree(t, root, config())
		if strings.Join(paths(first), "\n") != strings.Join(paths(next), "\n") {
			t.Fatalf("walk order differed:\n%v\n%v", paths(first), paths(next))
		}
	}
}

func TestWalkHonoursCancellation(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		"a/b/c/d/e/deep.go": "package deep", "a/f.go": "package a", "g.go": "package g",
	})
	w, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = w.Walk(ctx, func(index.Entry) error { return nil })
	if !modberr.Is(err, modberr.CodeCancelled) {
		t.Fatalf("err = %v, want MODBIT_CANCELLED", err)
	}
}

func TestWalkStopsOnVisitError(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{"a.go": "package a", "b.go": "package b", "c.go": "package c"})
	w, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}

	sentinel := errors.New("consumer stopped")
	var seen int
	_, err = w.Walk(context.Background(), func(index.Entry) error {
		seen++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the consumer's error unchanged", err)
	}
	if seen != 1 {
		t.Errorf("visited %d entries after the consumer stopped, want 1", seen)
	}
}

// The path rules, size limit, and content sniffing must all hold against real files on disk, not
// only against synthesized File values.
func TestWalkClassifiesRealFiles(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		"src/main.go":   "package main\n",
		"src/gen.go":    "// Code generated by tools/modbitgen. DO NOT EDIT.\n\npackage src\n",
		"src/empty.go":  "",
		"data/big.txt":  strings.Repeat("x", 2048),
		"certs/tls.pem": "-----BEGIN PRIVATE KEY-----\n",
		".env":          "API_KEY=not-a-real-key\n",
		// A NUL byte is what makes this binary; the classifier never sees the extension.
		"assets/logo.png": "\x89PNG\x00\x1a",
	})

	got := byPath(mustEntries(t, root))
	cases := []struct {
		path        string
		disposition index.Disposition
		reason      string
	}{
		{"src/main.go", index.DispositionIndex, index.ReasonIncluded},
		{"src/gen.go", index.DispositionIndex, index.ReasonGenerated},
		{"src/empty.go", index.DispositionReference, index.ReasonEmpty},
		{"data/big.txt", index.DispositionReference, index.ReasonTooLarge},
		{"assets/logo.png", index.DispositionReference, index.ReasonBinary},
		{"certs/tls.pem", index.DispositionExclude, index.ReasonProtectedPath},
		{".env", index.DispositionExclude, index.ReasonProtectedPath},
	}
	for _, tc := range cases {
		e, ok := got[tc.path]
		if !ok {
			t.Errorf("%s missing from the walk", tc.path)
			continue
		}
		if e.Disposition != tc.disposition || e.Reason != tc.reason {
			t.Errorf("%s = %s/%s, want %s/%s", tc.path, e.Disposition, e.Reason, tc.disposition, tc.reason)
		}
		if e.Provenance != taint.RepositoryUntrusted {
			t.Errorf("%s provenance = %v, want repository_untrusted", tc.path, e.Provenance)
		}
	}
	// Size and modification time come from the stat the walk already performed, so an incremental
	// reindex does not have to repeat it.
	if e := got["src/main.go"]; e.Size != int64(len("package main\n")) || e.ModTime.IsZero() {
		t.Errorf("entry metadata = size %d, mtime %v", e.Size, e.ModTime)
	}
}

func TestWalkStopsAtTheDepthLimit(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat("d/", 8) + "leaf.go"
	root := tree(t, map[string]string{deep: "package leaf", "top.go": "package top"})

	w, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{MaxDepth: 3})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}
	var entries []index.Entry
	report, err := w.Walk(context.Background(), func(e index.Entry) error {
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if _, ok := byPath(entries)[deep]; ok {
		t.Errorf("%s is past the depth limit and should not have been walked", deep)
	}
	if !byPath(entries)["top.go"].Indexable() {
		t.Error("the shallow part of the tree should still be indexed")
	}
	if report.Complete() {
		t.Error("a depth-limited walk is not complete")
	}
	var found bool
	for _, d := range report.Diagnostics {
		if d.Reason == index.DiagDepthExceeded {
			found = true
		}
	}
	if !found {
		t.Errorf("no depth diagnostic: %+v", report.Diagnostics)
	}
}

// The repository's build exclusions are not necessarily its indexing exclusions, and the walk must
// honour the same switch the classifier does.
func TestWalkRespectsTheGitignoreSetting(t *testing.T) {
	t.Parallel()
	files := map[string]string{".gitignore": "vendor/\n", "vendor/lib.go": "package lib"}

	on := config()
	on.RespectGitignore = true
	if got := byPath(mustWalk(t, tree(t, files), on)); got["vendor"].Disposition != index.DispositionExclude {
		t.Error("with respect_gitignore on, vendor should be pruned")
	}

	off := config()
	off.RespectGitignore = false
	got := byPath(mustWalk(t, tree(t, files), off))
	if !got["vendor/lib.go"].Indexable() {
		t.Errorf("with respect_gitignore off, vendor/lib.go should be indexed: %+v", got["vendor/lib.go"])
	}
}

func mustWalk(t *testing.T, root string, cfg index.Config) []index.Entry {
	t.Helper()
	entries, _ := walkTree(t, root, cfg)
	return entries
}

func TestNewWalkerRejectsAnInvalidRoot(t *testing.T) {
	t.Parallel()
	cl := classifier(t, config(), nil)

	if _, err := index.NewWalker("", cl, index.WalkOptions{}); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Errorf("empty root: err = %v", err)
	}
	if _, err := index.NewWalker(filepath.Join(t.TempDir(), "absent"), cl, index.WalkOptions{}); err == nil {
		t.Error("a missing root must be refused")
	}

	file := filepath.Join(t.TempDir(), "a.go")
	if err := os.WriteFile(file, []byte("package a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := index.NewWalker(file, cl, index.WalkOptions{}); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Errorf("a file root must be refused: err = %v", err)
	}

	root := t.TempDir()
	if _, err := index.NewWalker(root, nil, index.WalkOptions{}); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Errorf("a nil classifier must be refused: err = %v", err)
	}
	w, err := index.NewWalker(root, cl, index.WalkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Walk(context.Background(), nil); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Errorf("a nil visit function must be refused: err = %v", err)
	}
}

// Settings exclusions are held apart from the discovered rules; building two classifiers from one
// rule set used to append them twice.
func TestClassifierDoesNotMutateTheRuleSetItIsGiven(t *testing.T) {
	t.Parallel()
	rs := index.NewRuleSet(index.ParseFile("*.log\n", "", index.SourceGitignore))
	before := rs.Len()

	cfg := config()
	cfg.ExcludedGlobs = []string{"**/testdata/**"}
	if _, err := index.NewClassifier(cfg, rs); err != nil {
		t.Fatal(err)
	}
	if rs.Len() != before {
		t.Errorf("rule set grew from %d to %d — the classifier mutated its input", before, rs.Len())
	}
	if _, err := index.NewClassifier(cfg, rs); err != nil {
		t.Fatal(err)
	}
	if rs.Len() != before {
		t.Errorf("rule set grew to %d after a second classifier", rs.Len())
	}
}

func BenchmarkWalk(b *testing.B) {
	root := b.TempDir()
	for i := 0; i < 40; i++ {
		dir := filepath.Join(root, "pkg", string(rune('a'+i%26)), string(rune('a'+i/26)))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("*.log\nbuild/\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	cl, err := index.NewClassifier(index.Config{RespectGitignore: true, MaxFileBytes: 1 << 20}, nil)
	if err != nil {
		b.Fatal(err)
	}
	w, err := index.NewWalker(root, cl, index.WalkOptions{})
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Walk(context.Background(), func(index.Entry) error { return nil }); err != nil {
			b.Fatal(err)
		}
	}
}
