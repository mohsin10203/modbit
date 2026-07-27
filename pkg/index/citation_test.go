package index_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// citedBody is the content every fixture cites. Its length is what the byte span must agree with.
const citedBody = "func Handler() error { return nil }"

func testRevision() index.Revision {
	return index.Revision{
		Worktree: "/repos/modbit",
		Branch:   "main",
		Commit:   "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c",
	}
}

// citeSnapshot builds a snapshot whose manifest holds one indexed file, one reference file, and
// nothing else. Excluded entries cannot be placed in a manifest at all, which is what C1 rests on.
func citeSnapshot(t *testing.T) index.Snapshot {
	t.Helper()
	entries := []index.Entry{
		{
			Decision: index.Decision{
				Path:        "internal/handler.go",
				Disposition: index.DispositionIndex,
				Reason:      index.ReasonIncluded,
				Provenance:  taint.RepositoryUntrusted,
			},
			Size:    int64(len(citedBody)),
			ModTime: time.Unix(1700000000, 0),
		},
		{
			Decision: index.Decision{
				Path:        "testdata/corpus.bin",
				Disposition: index.DispositionReference,
				Reason:      index.ReasonBinary,
				Provenance:  taint.RepositoryUntrusted,
			},
			Size:    9 << 20,
			ModTime: time.Unix(1700000001, 0),
		},
	}
	snap, err := index.NewSnapshot(testRevision(), index.Config{MaxFileBytes: 1 << 20},
		policySnapshot(t), entries, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return snap
}

func testRepoID(t *testing.T) id.ID {
	t.Helper()
	repo, err := id.New(id.Repository)
	if err != nil {
		t.Fatalf("New repository id: %v", err)
	}
	return repo
}

// indexedRequest is a valid span citation of the indexed file.
func indexedRequest(t *testing.T) index.Request {
	t.Helper()
	return index.Request{
		Repository:      testRepoID(t),
		Path:            "internal/handler.go",
		Span:            index.Span{StartLine: 1, EndLine: 1, StartByte: 0, EndByte: int64(len(citedBody))},
		Source:          index.SourceLexical,
		RetrievalReason: index.ReasonQueryMatch,
		Content:         []byte(citedBody),
	}
}

func mustCite(t *testing.T, snap index.Snapshot, req index.Request) index.ContextItem {
	t.Helper()
	item, err := index.Cite(snap, req)
	if err != nil {
		t.Fatalf("Cite: %v", err)
	}
	return item
}

// requireCode asserts a refusal carrying the expected Modbit code and names the field.
func requireCode(t *testing.T, err error, want modberr.Code, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal, got none")
	}
	if !modberr.Is(err, want) {
		t.Fatalf("code = %v, want %s", err, want)
	}
	e, ok := err.(*modberr.Error)
	if !ok {
		t.Fatalf("expected a *modberr.Error, got %T", err)
	}
	if field != "" && e.Details()["field"] != field {
		t.Fatalf("detail field = %q, want %q", e.Details()["field"], field)
	}
}

// C1. The classifier's whole purpose is undone if a path it excluded can be cited anyway. A
// manifest cannot hold an excluded entry, so citing one fails as a lookup — and the message must not
// distinguish "excluded" from "absent", or a caller probing paths learns which protected files exist.
func TestSecurityAnExcludedPathCanNeverBeCited(t *testing.T) {
	snap := citeSnapshot(t)

	for _, path := range []string{
		".ssh/id_rsa",
		".env",
		"config/secrets.yaml",
		"internal/../.ssh/id_rsa",
	} {
		req := indexedRequest(t)
		req.Path = path
		_, err := index.Cite(snap, req)
		requireCode(t, err, modberr.CodeInvalidArgument, "path")
		if msg := err.Error(); strings.Contains(msg, "excluded") || strings.Contains(msg, "protected") {
			t.Fatalf("refusal for %q discloses why the path is absent: %s", path, msg)
		}
	}
}

// C1 end to end. The test above proves a lookup miss; this one proves the miss is not an accident of
// the fixture. A real tree containing a private key, a .env, and a gitignored build directory is
// walked, snapshotted, and then every one of those paths is cited — the full pipeline that a
// retriever would drive. Each must be refused, and the indexed file beside them must succeed, so the
// refusals cannot be passing because citation is broken.
func TestSecurityProtectedContentCannotBeCitedFromARealTree(t *testing.T) {
	root := tree(t, map[string]string{
		".gitignore":          "build/\n",
		"main.go":             "package main\n\nfunc main() {}\n",
		".ssh/id_rsa":         "-----BEGIN OPENSSH PRIVATE KEY-----\nnot a real key\n",
		".env":                "DATABASE_URL=postgres://user:hunter2@localhost/db\n",
		"build/generated.go":  "package build\n",
		"config/secrets.yaml": "token: ghp_notarealtokenbutshaped\n",
	})

	cfg := index.Config{RespectGitignore: true, MaxFileBytes: 1 << 20}
	entries, report := walkTree(t, root, cfg)
	if !report.Complete() {
		t.Fatalf("walk was incomplete, so the snapshot would not describe the tree: %+v", report)
	}

	// Pin what the walk decided, so this test cannot start passing because nothing was excluded.
	// .ssh and build are pruned whole (decision 48), so their contents never appear as entries at
	// all; .env and config/secrets.yaml are excluded individually as protected paths.
	seen := byPath(entries)
	for _, path := range []string{".env", "config/secrets.yaml"} {
		if e, ok := seen[path]; !ok || e.Disposition != index.DispositionExclude {
			t.Fatalf("%q was not excluded by the walk (%+v); the citation refusal below would prove nothing", path, e)
		}
	}
	for _, path := range []string{".ssh/id_rsa", "build/generated.go"} {
		if _, ok := seen[path]; ok {
			t.Fatalf("%q was walked; it sits under a pruned subtree and should never have been listed", path)
		}
	}

	var indexable []index.Entry
	for _, e := range entries {
		if e.Disposition != index.DispositionExclude {
			indexable = append(indexable, e)
		}
	}
	snap, err := index.NewSnapshot(index.Revision{Worktree: root, Branch: "main"}, cfg,
		policySnapshot(t), indexable, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}

	for _, path := range []string{".ssh/id_rsa", ".env", "config/secrets.yaml", "build/generated.go"} {
		_, err := index.Cite(snap, index.Request{
			Repository:      testRepoID(t),
			Path:            path,
			Source:          index.SourceExplicit,
			RetrievalReason: index.ReasonUserAttached,
			WholeFileReason: index.WholeFileUserAttached,
			Content:         []byte("whatever the caller claims"),
		})
		requireCode(t, err, modberr.CodeInvalidArgument, "path")
	}

	// The control: an ordinary source file in the same tree cites cleanly, so the refusals above are
	// the exclusion working rather than citation being broken.
	body := "package main\n\nfunc main() {}\n"
	if _, err := index.Cite(snap, index.Request{
		Repository:      testRepoID(t),
		Path:            "main.go",
		Source:          index.SourceLexical,
		RetrievalReason: index.ReasonQueryMatch,
		WholeFileReason: index.WholeFileBelowThreshold,
		Content:         []byte(body),
	}); err != nil {
		t.Fatalf("an indexed file in the same tree must be citable: %v", err)
	}
}

// C1, second half: a path that was never in the tree and a path that was excluded from it must be
// refused identically, so the refusal itself is not an existence oracle.
func TestSecurityRefusalDoesNotDistinguishExcludedFromAbsent(t *testing.T) {
	snap := citeSnapshot(t)

	absent := indexedRequest(t)
	absent.Path = "no/such/file.go"
	_, absentErr := index.Cite(snap, absent)

	excluded := indexedRequest(t)
	excluded.Path = ".env"
	_, excludedErr := index.Cite(snap, excluded)

	if absentErr == nil || excludedErr == nil {
		t.Fatal("both paths must be refused")
	}
	if absentErr.Error() != excludedErr.Error() {
		t.Fatalf("refusals differ:\n absent:   %s\n excluded: %s", absentErr, excludedErr)
	}
}

// C2. A reference file was never read, so the index has no span of it and no bytes to digest.
// Claiming either would be inventing evidence.
func TestReferenceItemsCiteWholeFilesWithNoContent(t *testing.T) {
	snap := citeSnapshot(t)

	req := index.Request{
		Repository:      testRepoID(t),
		Path:            "testdata/corpus.bin",
		Source:          index.SourceMetadata,
		RetrievalReason: index.ReasonUserAttached,
		WholeFileReason: index.WholeFileNotIndexed,
	}
	item := mustCite(t, snap, req)

	if !item.WholeFile() {
		t.Fatal("a reference item must cite the whole file")
	}
	if item.ContentDigest() != "" {
		t.Fatalf("a reference item must carry no content digest, got %q", item.ContentDigest())
	}
	if item.WholeFileReason() != index.WholeFileNotIndexed {
		t.Fatalf("whole-file reason = %q, want not_indexed", item.WholeFileReason())
	}

	withSpan := req
	withSpan.Span = index.Span{StartLine: 1, EndLine: 2, StartByte: 0, EndByte: 10}
	_, err := index.Cite(snap, withSpan)
	requireCode(t, err, modberr.CodeInvalidArgument, "span")

	withContent := req
	withContent.Content = []byte("bytes the index never read")
	_, err = index.Cite(snap, withContent)
	requireCode(t, err, modberr.CodeInvalidArgument, "content")
}

// C3. RET-6 names six fields. Each one missing is its own refusal, because a defaulted repository or
// a blank reason produces an item that satisfies the requirement's letter and tells a reviewer
// nothing.
func TestEveryRET6FieldIsRequired(t *testing.T) {
	snap := citeSnapshot(t)

	cases := []struct {
		name  string
		field string
		mutex func(*index.Request)
	}{
		{"repository", "repository", func(r *index.Request) { r.Repository = "" }},
		{"repository of the wrong kind", "repository", func(r *index.Request) { r.Repository = id.MustNew(id.Space) }},
		{"path", "path", func(r *index.Request) { r.Path = "" }},
		{"source", "source", func(r *index.Request) { r.Source = "" }},
		{"unknown source", "source", func(r *index.Request) { r.Source = index.Source("guesswork") }},
		{"retrieval reason", "retrieval_reason", func(r *index.Request) { r.RetrievalReason = "" }},
		{"unknown retrieval reason", "retrieval_reason", func(r *index.Request) { r.RetrievalReason = "because" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := indexedRequest(t)
			tc.mutex(&req)
			_, err := index.Cite(snap, req)
			requireCode(t, err, modberr.CodeInvalidArgument, tc.field)
		})
	}

	// Revision and snapshot are the remaining two RET-6 fields. They are not in Request at all —
	// they come from the snapshot — so the way to omit them is to cite an unconstructed snapshot.
	_, err := index.Cite(index.Snapshot{}, indexedRequest(t))
	requireCode(t, err, modberr.CodeInvalidArgument, "snapshot")
}

// C4. taint.Class's zero value is UserTrusted. A provenance field the caller could leave unset would
// silently promote repository content — including any instructions inside it — to the most trusted
// class in the lattice. So it is derived, and Request has nowhere to put one.
func TestSecurityProvenanceIsDerivedNotSupplied(t *testing.T) {
	snap := citeSnapshot(t)
	item := mustCite(t, snap, indexedRequest(t))

	if got := item.Provenance(); got != taint.RepositoryUntrusted {
		t.Fatalf("provenance = %v, want repository_untrusted", got)
	}
	if item.Provenance() == taint.UserTrusted {
		t.Fatal("repository content must never be cited as user-trusted")
	}

	// A reference item is repository content too — never having been read does not make it trusted.
	ref := mustCite(t, snap, index.Request{
		Repository:      testRepoID(t),
		Path:            "testdata/corpus.bin",
		Source:          index.SourceMetadata,
		RetrievalReason: index.ReasonUserAttached,
		WholeFileReason: index.WholeFileNotIndexed,
	})
	if got := ref.Provenance(); got != taint.RepositoryUntrusted {
		t.Fatalf("reference provenance = %v, want repository_untrusted", got)
	}
}

// C5. RET-9: whole-file inclusion is the largest consumer of a context budget and is invisible in
// the result, so it is the branch that must justify itself. A span-limited item carrying a reason is
// equally wrong — it would make the whole-file review list meaningless.
func TestWholeFileInclusionMustRecordItsReason(t *testing.T) {
	snap := citeSnapshot(t)

	missing := indexedRequest(t)
	missing.Span = index.Span{}
	_, err := index.Cite(snap, missing)
	requireCode(t, err, modberr.CodeInvalidArgument, "whole_file_reason")

	for reason := range map[index.WholeFileReason]bool{
		index.WholeFileBelowThreshold:  true,
		index.WholeFileNoSpanAvailable: true,
		index.WholeFileUserAttached:    true,
		index.WholeFileStructuralUnit:  true,
	} {
		req := indexedRequest(t)
		req.Span = index.Span{}
		req.WholeFileReason = reason
		item := mustCite(t, snap, req)
		if item.WholeFileReason() != reason {
			t.Fatalf("whole-file reason = %q, want %q", item.WholeFileReason(), reason)
		}
	}

	// not_indexed is a reference file's reason and must not be usable to describe an indexed one.
	borrowed := indexedRequest(t)
	borrowed.Span = index.Span{}
	borrowed.WholeFileReason = index.WholeFileNotIndexed
	_, err = index.Cite(snap, borrowed)
	requireCode(t, err, modberr.CodeInvalidArgument, "whole_file_reason")

	// A span-limited item must not claim one.
	spanned := indexedRequest(t)
	spanned.WholeFileReason = index.WholeFileBelowThreshold
	_, err = index.Cite(snap, spanned)
	requireCode(t, err, modberr.CodeInvalidArgument, "whole_file_reason")
}

// C6. A span past the end of the file is either a stale index or an invented citation. The manifest
// already records the size, so the check costs nothing and happens before the item exists.
func TestASpanMustLieInsideTheIndexedFile(t *testing.T) {
	snap := citeSnapshot(t)
	size := int64(len(citedBody))

	cases := map[string]index.Span{
		"past the end":        {StartLine: 1, EndLine: 1, StartByte: 0, EndByte: size + 1},
		"zero-based lines":    {StartLine: 0, EndLine: 1, StartByte: 0, EndByte: size},
		"inverted lines":      {StartLine: 9, EndLine: 2, StartByte: 0, EndByte: size},
		"empty byte range":    {StartLine: 1, EndLine: 1, StartByte: 5, EndByte: 5},
		"inverted bytes":      {StartLine: 1, EndLine: 1, StartByte: 9, EndByte: 2},
		"negative start byte": {StartLine: 1, EndLine: 1, StartByte: -1, EndByte: size},
	}

	for name, span := range cases {
		t.Run(name, func(t *testing.T) {
			req := indexedRequest(t)
			req.Span = span
			_, err := index.Cite(snap, req)
			requireCode(t, err, modberr.CodeInvalidArgument, "span")
		})
	}
}

// C7. The digest is taken over the bytes the caller says it cited, at construction, so the recorded
// digest and the cited content cannot disagree. A citation nothing can revalidate is a claim, not
// evidence — and the content itself is never retained, because a citation is metadata (INV-4).
func TestContentDigestCoversExactlyTheCitedBytes(t *testing.T) {
	snap := citeSnapshot(t)
	item := mustCite(t, snap, indexedRequest(t))

	sum := sha256.Sum256([]byte(citedBody))
	want := "sha256:" + hex.EncodeToString(sum[:])
	if item.ContentDigest() != want {
		t.Fatalf("digest = %q, want %q", item.ContentDigest(), want)
	}

	// Content whose length disagrees with the span is a mismatch between what was cited and what was
	// digested, which would make the citation unverifiable in exactly the case that matters.
	short := indexedRequest(t)
	short.Content = []byte(citedBody[:5])
	_, err := index.Cite(snap, short)
	requireCode(t, err, modberr.CodeInvalidArgument, "content")

	// An indexed item with no content at all cannot be revalidated.
	none := indexedRequest(t)
	none.Content = nil
	_, err = index.Cite(snap, none)
	requireCode(t, err, modberr.CodeInvalidArgument, "content")
}

// C7, second half: nothing in the item may carry the cited body. A citation is metadata and INV-4
// keeps bodies out of metadata.
func TestSecurityACitationCarriesNoContentBody(t *testing.T) {
	snap := citeSnapshot(t)
	marker := "SUPER-SECRET-MARKER-9f3a"

	req := indexedRequest(t)
	req.Content = []byte(marker + strings.Repeat("x", len(citedBody)-len(marker)))
	item := mustCite(t, snap, req)

	rendered := item.Citation() + item.ContentDigest() + item.Path() +
		string(item.Source()) + item.RetrievalReason() + string(item.WholeFileReason())
	if strings.Contains(rendered, marker) {
		t.Fatalf("cited content reached the citation record: %s", rendered)
	}
}

// C8. RET-8: retrieval must never silently mix incompatible revisions. It is silent precisely
// because an assembled prompt shows no revision at all, so the pack is the last moment the
// difference is still visible.
func TestSecurityAPackCannotMixRevisions(t *testing.T) {
	main := citeSnapshot(t)
	mainItem := mustCite(t, main, indexedRequest(t))

	other := testRevision()
	other.Branch = "feature/rewrite"
	other.Commit = "aaaabbbbccccddddeeeeffff0000111122223333"
	branchSnap, err := index.NewSnapshot(other, index.Config{MaxFileBytes: 1 << 20}, policySnapshot(t),
		[]index.Entry{{
			Decision: index.Decision{
				Path:        "internal/handler.go",
				Disposition: index.DispositionIndex,
				Reason:      index.ReasonIncluded,
				Provenance:  taint.RepositoryUntrusted,
			},
			Size:    int64(len(citedBody)),
			ModTime: time.Unix(1700000000, 0),
		}}, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	branchItem := mustCite(t, branchSnap, indexedRequest(t))

	_, err = index.NewPack(mainItem, branchItem)
	requireCode(t, err, modberr.CodeSnapshotDiverged, "")

	// The refusal must name both revisions. "These do not match" gives an operator nothing to act on,
	// and R-ERR-02's key allowlist is what decides which values may be carried.
	e, ok := err.(*modberr.Error)
	if !ok {
		t.Fatalf("expected a *modberr.Error, got %T", err)
	}
	if got := e.Details()["expected_revision"]; got != testRevision().Short() {
		t.Fatalf("expected_revision = %q, want %q", got, testRevision().Short())
	}
	if got := e.Details()["actual_revision"]; got != other.Short() {
		t.Fatalf("actual_revision = %q, want %q", got, other.Short())
	}

	if _, err := index.NewPack(mainItem); err != nil {
		t.Fatalf("a single-revision pack must be accepted: %v", err)
	}
}

// C9. A prompt assembled from one trusted file and one untrusted one is an untrusted prompt.
// Averaging, or letting the majority win, is how repository-authored instructions get treated as
// user intent.
func TestPackTaintIsThePropagationOfItsItems(t *testing.T) {
	snap := citeSnapshot(t)
	item := mustCite(t, snap, indexedRequest(t))
	ref := mustCite(t, snap, index.Request{
		Repository:      testRepoID(t),
		Path:            "testdata/corpus.bin",
		Source:          index.SourceMetadata,
		RetrievalReason: index.ReasonUserAttached,
		WholeFileReason: index.WholeFileNotIndexed,
	})

	pack, err := index.NewPack(item, ref)
	if err != nil {
		t.Fatalf("NewPack: %v", err)
	}

	want := taint.Propagate(taint.RepositoryUntrusted, taint.RepositoryUntrusted)
	if pack.Taint() != want {
		t.Fatalf("pack taint = %v, want %v", pack.Taint(), want)
	}
	if pack.Taint() == taint.UserTrusted {
		t.Fatal("a pack of repository content must never present as user-trusted")
	}
	if !pack.TaintSet().Contains(taint.RepositoryUntrusted) {
		t.Fatalf("taint set = %v, missing repository_untrusted", pack.TaintSet())
	}
}

// C10. A citation names the exact index state it came from, which is what makes a later divergence
// between two of them evidence rather than a mystery.
func TestEveryItemNamesItsSnapshotAndRevision(t *testing.T) {
	snap := citeSnapshot(t)
	item := mustCite(t, snap, indexedRequest(t))

	if item.SnapshotID() != snap.ID {
		t.Fatalf("snapshot id = %q, want %q", item.SnapshotID(), snap.ID)
	}
	if !item.Revision().Equal(snap.Revision) {
		t.Fatalf("revision = %+v, want %+v", item.Revision(), snap.Revision)
	}
	if !item.ID().HasPrefix(id.ContextItem) {
		t.Fatalf("item id = %q, want a %q identifier", item.ID(), id.ContextItem)
	}

	pack, err := index.NewPack(item)
	if err != nil {
		t.Fatalf("NewPack: %v", err)
	}
	if !pack.ID().HasPrefix(id.ContextPack) {
		t.Fatalf("pack id = %q, want a %q identifier", pack.ID(), id.ContextPack)
	}
	if !pack.Revision().Equal(snap.Revision) {
		t.Fatalf("pack revision = %+v, want %+v", pack.Revision(), snap.Revision)
	}
}

// RET-9's reporting half: assembly records the reason on each item, and the review surface needs the
// list of files that consumed the budget without anyone choosing them.
func TestWholeFileInclusionsAreReportableForReview(t *testing.T) {
	snap := citeSnapshot(t)

	spanned := mustCite(t, snap, indexedRequest(t))
	whole := indexedRequest(t)
	whole.Span = index.Span{}
	whole.WholeFileReason = index.WholeFileStructuralUnit
	wholeItem := mustCite(t, snap, whole)

	pack, err := index.NewPack(spanned, wholeItem)
	if err != nil {
		t.Fatalf("NewPack: %v", err)
	}

	inclusions := pack.WholeFileInclusions()
	if len(inclusions) != 1 {
		t.Fatalf("whole-file inclusions = %d, want 1", len(inclusions))
	}
	if inclusions[0].WholeFileReason() != index.WholeFileStructuralUnit {
		t.Fatalf("reason = %q, want structural_unit", inclusions[0].WholeFileReason())
	}
}

// A citation must be readable, and it must never render as a truncation. Evidence ending in "@" is
// indistinguishable from evidence that lost its revision.
func TestCitationsRenderReadably(t *testing.T) {
	snap := citeSnapshot(t)
	item := mustCite(t, snap, indexedRequest(t))

	got := item.Citation()
	if want := "internal/handler.go:1-1@0f1e2d3c4b5a"; got != want {
		t.Fatalf("citation = %q, want %q", got, want)
	}

	whole := indexedRequest(t)
	whole.Span = index.Span{}
	whole.WholeFileReason = index.WholeFileBelowThreshold
	wholeItem := mustCite(t, snap, whole)
	if got := wholeItem.Citation(); !strings.Contains(got, "whole-file") {
		t.Fatalf("whole-file citation = %q, want it to say so", got)
	}

	for name, rev := range map[string]index.Revision{
		"unversioned tree": {Worktree: "/tmp/plain"},
		"unborn branch":    {Worktree: "/repos/new", Branch: "main"},
	} {
		if short := rev.Short(); short == "" {
			t.Fatalf("%s: Short() is empty, so a citation would end in a bare @", name)
		}
	}
}

// The manifest is sorted, so lookup is a binary search. A pack for a monorepo cites many paths
// against one snapshot, and a linear scan per citation would be quadratic in pack size.
func TestSnapshotLookupFindsEveryManifestEntry(t *testing.T) {
	snap := citeSnapshot(t)

	for _, entry := range snap.Manifest {
		found, ok := snap.Lookup(entry.Path)
		if !ok {
			t.Fatalf("Lookup(%q) missed an entry that is in the manifest", entry.Path)
		}
		if found.Path != entry.Path {
			t.Fatalf("Lookup(%q) returned %q", entry.Path, found.Path)
		}
	}
	if _, ok := snap.Lookup("nowhere.go"); ok {
		t.Fatal("Lookup found a path that is not in the manifest")
	}
	// Lookup normalizes, so a caller passing "./internal/handler.go" resolves to the same entry
	// rather than silently missing it and being told the path is absent.
	if _, ok := snap.Lookup("./internal/handler.go"); !ok {
		t.Fatal("Lookup did not normalize a leading ./")
	}
}
