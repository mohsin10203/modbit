package index_test

import (
	"context"
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

// The local context pipeline, end to end: a file on disk becomes a model-visible citation.
//
// CTX-2, CTX-4, RET-6. Every stage of this path has its own tests — the walker, the classifier, the
// reindexer, the lexical index, and Cite. What none of them covers is the **seams**, and a pipeline
// can be built entirely from correct components and still not deliver its promise: a change that is
// observed but never indexed, or indexed but not citable, fails CTX-2 while every unit test passes.
//
// The existing end-to-end test stops at the ChangeSet. This carries it the rest of the way:
//
//	write → walk → classify → reindex → ChangeSet → index → search → cite
//
// PollSource drives it rather than a native backend, because this is about the seams and it must run
// on every platform. FSEvents has its own suite in pkg/index/fsevents.
type pipeline struct {
	root      string
	idx       *index.MemoryIndex
	reindexer *index.Reindexer
	walker    *index.Walker
	repo      id.ID
	gen       *id.Generator
}

func newPipeline(t *testing.T, files map[string]string) *pipeline {
	t.Helper()
	root := tree(t, files)
	walker, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}
	reindexer, err := index.NewReindexer(walker, fastPolicy())
	if err != nil {
		t.Fatalf("NewReindexer: %v", err)
	}
	return &pipeline{
		root:      root,
		idx:       index.NewMemoryIndex(),
		reindexer: reindexer,
		walker:    walker,
		repo:      id.MustNew(id.Repository),
		gen:       id.NewGenerator(nil),
	}
}

// sync runs one rescan and applies it to the lexical index, the way a watcher's apply callback does.
func (p *pipeline) sync(t *testing.T) index.ChangeSet {
	t.Helper()
	set, _, err := p.reindexer.Rescan(context.Background())
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	read := func(rel string) ([]byte, error) { return os.ReadFile(filepath.Join(p.root, rel)) }
	if err := index.ApplyChangeSet(p.idx, p.reindexer.Revision(), set, read); err != nil {
		t.Fatalf("ApplyChangeSet: %v", err)
	}
	return set
}

// snapshot builds the manifest Cite resolves against, from the same walk the index came from.
func (p *pipeline) snapshot(t *testing.T) index.Snapshot {
	t.Helper()
	// Excluded entries are *rejected* by NewSnapshot rather than filtered, so the caller drops them
	// deliberately. That is the manifest-hygiene invariant doing its job: a protected path reaching a
	// manifest would be a silent disclosure, so passing one is treated as a caller error, not tidied up.
	var entries []index.Entry
	_, err := p.walker.Walk(context.Background(), func(e index.Entry) error {
		if e.Disposition != index.DispositionExclude {
			entries = append(entries, e)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	snap, err := index.NewSnapshot(p.reindexer.Revision(), config(), settings.Snapshot{}, entries, p.gen)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return snap
}

// search returns the paths matching a query.
func (p *pipeline) search(t *testing.T, query string) []string {
	t.Helper()
	matches, err := p.idx.Search(p.reindexer.Revision(), query, 20)
	if err != nil {
		t.Fatalf("Search(%q): %v", query, err)
	}
	var paths []string
	for _, m := range matches {
		paths = append(paths, m.Path)
	}
	return paths
}

// TestAFileOnDiskBecomesACitation walks the whole path a retrieval actually takes.
func TestAFileOnDiskBecomesACitation(t *testing.T) {
	p := newPipeline(t, map[string]string{
		"pkg/svc/handler.go": "package svc\n\nfunc HandlePaymentRequest() error {\n\treturn nil\n}\n",
		"README.md":          "# docs\n",
	})
	p.sync(t)

	// The identifier is searchable by its parts, which is L6 observed from outside the index.
	matches, err := p.idx.Search(p.reindexer.Revision(), "payment", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("a file written before indexing is not searchable by a term it contains")
	}
	hit := matches[0]
	if hit.Path != "pkg/svc/handler.go" {
		t.Fatalf("matched %q, want pkg/svc/handler.go", hit.Path)
	}

	// The whole point of Match carrying a span: it must be enough to produce a citation, with no
	// second lookup and no guessing.
	body, err := os.ReadFile(filepath.Join(p.root, hit.Path))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	item, err := index.Cite(p.snapshot(t), index.Request{
		Repository:      p.repo,
		Path:            hit.Path,
		Span:            hit.Span,
		Source:          index.SourceLexical,
		RetrievalReason: index.ReasonQueryMatch,
		Content:         body[hit.Span.StartByte:hit.Span.EndByte],
	})
	if err != nil {
		t.Fatalf("a lexical match could not be cited: %v", err)
	}
	if item.Path() != hit.Path {
		t.Fatalf("cited path = %q, want %q", item.Path(), hit.Path)
	}
	if item.Revision() != p.reindexer.Revision() {
		t.Fatalf("the citation names a different revision than the index that produced it")
	}
}

// A file deleted from disk stops being searchable and stops being citable.
//
// The two halves matter separately. Search failing alone would leave a stale path citable by anything
// that remembered it; Cite failing alone would leave deleted content in retrieval results. This is
// the retraction path observed end to end rather than at either stage.
func TestSecurityADeletedFileLeavesBothTheIndexAndTheManifest(t *testing.T) {
	// Disjoint vocabulary throughout. splitIdentifier cuts on case boundaries, so a pair like
	// UniqueDoomedSymbol / UniqueKeptSymbol shares the token "unique" and every query matches both —
	// which makes a deletion look incomplete when the index is behaving correctly.
	p := newPipeline(t, map[string]string{
		"pkg/svc/doomed.go": "package svc\n\nfunc Zephyrquartz() {}\n",
		"pkg/svc/kept.go":   "package svc\n\nfunc Plumbago() {}\n",
	})
	p.sync(t)

	if got := p.search(t, "Zephyrquartz"); len(got) == 0 {
		t.Fatalf("the file is not searchable before deletion; the test proves nothing")
	}
	before := p.snapshot(t)
	doomed, err := os.ReadFile(filepath.Join(p.root, "pkg/svc/doomed.go"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if _, err := index.Cite(before, index.Request{
		Repository: p.repo, Path: "pkg/svc/doomed.go", Source: index.SourceLexical,
		RetrievalReason: index.ReasonQueryMatch,
		WholeFileReason: index.WholeFileBelowThreshold,
		Content:         doomed,
	}); err != nil {
		t.Fatalf("the file is not citable before deletion: %v", err)
	}

	if err := os.Remove(filepath.Join(p.root, "pkg/svc/doomed.go")); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	p.sync(t)

	if got := p.search(t, "Zephyrquartz"); len(got) != 0 {
		t.Fatalf("a deleted file is still searchable: %v", got)
	}
	if got := p.search(t, "Plumbago"); len(got) != 1 {
		t.Fatalf("deleting one file disturbed another: %v", got)
	}
	// The snapshot is Cite's authority, so a path absent from the manifest cannot be cited at all —
	// C1 holding across a real deletion rather than a constructed manifest.
	_, err = index.Cite(p.snapshot(t), index.Request{
		Repository: p.repo, Path: "pkg/svc/doomed.go", Source: index.SourceLexical,
		RetrievalReason: index.ReasonQueryMatch,
		WholeFileReason: index.WholeFileBelowThreshold,
		Content:         doomed,
	})
	if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("citing a deleted file: err = %v, want CodeInvalidArgument", err)
	}
}

// deletedPathError is the exact refusal an *absent* path produces, captured so the excluded-path
// case can require the same words rather than merely the same code.
const deletedPathError = "MODBIT_INVALID_ARGUMENT: path is not present in the index snapshot"

// Excluded content never becomes searchable, however it is queried.
//
// CTX-4 requires exclusion *before* indexing, and each stage tests that separately. This asserts the
// composed property: a secret present on disk throughout is absent from every result the pipeline can
// produce. A classifier that excluded correctly while the reindexer indexed the file anyway would
// pass every unit test and fail here.
func TestSecurityExcludedContentNeverReachesARetrievalResult(t *testing.T) {
	const secret = "Zephyrquartz"
	p := newPipeline(t, map[string]string{
		".env":            "TOKEN=" + secret + "\n",
		"deploy/id_rsa":   "-----BEGIN KEY-----\n" + secret + "\n",
		"certs/tls.pem":   secret + "\n",
		"pkg/svc/main.go": "package svc\n\nfunc Plumbago() {}\n",
	})
	p.sync(t)

	// Sanity: indexing happened at all. Without this the assertions below pass on an empty index.
	if got := p.search(t, "Plumbago"); len(got) != 1 {
		t.Fatalf("ordinary source is not searchable, so exclusion proves nothing: %v", got)
	}

	for _, query := range []string{secret, "TOKEN", "BEGIN"} {
		if got := p.search(t, query); len(got) != 0 {
			t.Fatalf("query %q reached protected content: %v", query, got)
		}
	}
	// And the manifest cannot be used to reach them either, so no later stage can resurrect them.
	for _, path := range []string{".env", "deploy/id_rsa", "certs/tls.pem"} {
		_, err := index.Cite(p.snapshot(t), index.Request{
			Repository: p.repo, Path: path, Source: index.SourceLexical,
			RetrievalReason: index.ReasonQueryMatch,
			WholeFileReason: index.WholeFileBelowThreshold,
			Content:         []byte("irrelevant: the manifest lookup fails first"),
		})
		if !modberr.Is(err, modberr.CodeInvalidArgument) {
			t.Fatalf("citing protected path %q: err = %v, want CodeInvalidArgument", path, err)
		}
		// C1's existence oracle, observed end to end: a protected path that exists on disk must be
		// refused in exactly the words an absent one gets, or probing the API reveals which secrets
		// a repository holds.
		if got, want := err.Error(), deletedPathError; got != want {
			t.Fatalf("protected path %q refused with %q; an absent path is refused with %q — "+
				"the difference tells a caller the file exists", path, got, want)
		}
	}
}

// An edit becomes searchable through a running watcher, within the freshness policy.
//
// This is CTX-2's promise with nothing stubbed: a real tree, a real watcher loop, and a lexical index
// updated by the watcher's own apply callback. The assertion is the user-visible one — the new text
// is findable — rather than an internal signal that an update occurred.
func TestAnEditBecomesSearchableThroughARunningWatcher(t *testing.T) {
	p := newPipeline(t, map[string]string{"pkg/svc/main.go": "package svc\n"})
	source := index.NewPollSource(20 * time.Millisecond)
	watcher, err := index.NewWatcher(p.reindexer, source)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	read := func(rel string) ([]byte, error) { return os.ReadFile(filepath.Join(p.root, rel)) }
	applied := make(chan struct{}, 64)
	apply := func(set index.ChangeSet, _ index.Report) error {
		if err := index.ApplyChangeSet(p.idx, p.reindexer.Revision(), set, read); err != nil {
			return err
		}
		select {
		case applied <- struct{}{}:
		default:
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = watcher.Run(ctx, apply) }()

	body := "package svc\n\nfunc UniqueWatchedSymbol() error {\n\treturn nil\n}\n"
	if err := os.WriteFile(filepath.Join(p.root, "pkg/svc/watched.go"), []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-applied:
			if got := p.search(t, "UniqueWatchedSymbol"); len(got) == 1 && got[0] == "pkg/svc/watched.go" {
				return
			}
		case <-deadline:
			t.Fatalf("a file written into a watched tree never became searchable")
		}
	}
}

// The pipeline never yields a match it cannot cite.
//
// RET-6 forbids model-visible content without provenance, and the shape of that guarantee is that
// every lexical result carries what Cite needs. Asserted over the whole corpus rather than one hit,
// because a single hit can be citable by luck.
func TestSecurityEveryLexicalResultIsCitable(t *testing.T) {
	p := newPipeline(t, map[string]string{
		"pkg/a/one.go":     "package a\n\nfunc SharedMarker() {}\n",
		"pkg/b/two.go":     "package b\n\nfunc SharedMarker() {}\n",
		"pkg/c/three.go":   "package c\n\nfunc SharedMarker() {}\n",
		"pkg/c/nested.go":  "package c\n\n// SharedMarker in a comment\n",
		"docs/notes.md":    "SharedMarker appears here too\n",
		"pkg/d/absent.go":  "package d\n",
		"pkg/e/present.go": "package e\n\nfunc SharedMarker() {}\n",
	})
	p.sync(t)
	snap := p.snapshot(t)

	matches, err := p.idx.Search(p.reindexer.Revision(), "SharedMarker", 50)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) < 5 {
		t.Fatalf("expected the marker in several files, got %d matches", len(matches))
	}
	for _, m := range matches {
		body, err := os.ReadFile(filepath.Join(p.root, m.Path))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", m.Path, err)
		}
		if m.Span.EndByte > int64(len(body)) {
			t.Fatalf("%s: span ends at %d, past the file's %d bytes", m.Path, m.Span.EndByte, len(body))
		}
		item, err := index.Cite(snap, index.Request{
			Repository:      p.repo,
			Path:            m.Path,
			Span:            m.Span,
			Source:          index.SourceLexical,
			RetrievalReason: index.ReasonQueryMatch,
			Content:         body[m.Span.StartByte:m.Span.EndByte],
		})
		if err != nil {
			t.Fatalf("a lexical match for %s could not be cited: %v", m.Path, err)
		}
		if !strings.HasPrefix(item.Path(), strings.Split(m.Path, "/")[0]) {
			t.Fatalf("citation path %q does not correspond to match path %q", item.Path(), m.Path)
		}
	}
}
