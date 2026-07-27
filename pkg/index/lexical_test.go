package index_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

func indexedEntry(path string, size int64) index.Entry {
	return index.Entry{
		Decision: index.Decision{
			Path:        path,
			Disposition: index.DispositionIndex,
			Reason:      index.ReasonIncluded,
			Provenance:  taint.RepositoryUntrusted,
		},
		Size:    size,
		ModTime: time.Unix(1700000000, 0),
	}
}

// indexFile chunks and upserts one file, failing the test on any refusal.
func indexFile(t *testing.T, idx index.LexicalIndex, rev index.Revision, path, body string) {
	t.Helper()
	docs, err := index.Chunk(indexedEntry(path, int64(len(body))), []byte(body))
	if err != nil {
		t.Fatalf("Chunk(%s): %v", path, err)
	}
	if err := idx.Upsert(rev, docs...); err != nil {
		t.Fatalf("Upsert(%s): %v", path, err)
	}
}

func searchPaths(t *testing.T, idx index.LexicalIndex, rev index.Revision, query string, k int) []string {
	t.Helper()
	matches, err := idx.Search(rev, query, k)
	if err != nil {
		t.Fatalf("Search(%q): %v", query, err)
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.Path)
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// L1. PRD §7 budgets zero branch/worktree contamination incidents. An index that answered across
// revisions would be exactly that, and it would be invisible: the results look like ordinary results.
func TestSecurityLexicalResultsNeverCrossRevisions(t *testing.T) {
	idx := index.NewMemoryIndex()
	main := index.Revision{Worktree: "/repo", Branch: "main", Commit: "aaaa1111"}
	feature := index.Revision{Worktree: "/repo", Branch: "feature", Commit: "bbbb2222"}

	// The two bodies share no searchable term. Identifiers that merely look distinct are not:
	// tokenization splits them, so MainOnlyHandler and FeatureOnlyHandler both contain "only" and
	// "handler" and would match each other for reasons that have nothing to do with partitioning.
	indexFile(t, idx, main, "auth.go", "package auth\n\nfunc Zeppelin() {}\n")
	indexFile(t, idx, feature, "auth.go", "package auth\n\nfunc Marmalade() {}\n")

	if got := searchPaths(t, idx, main, "Zeppelin", 10); len(got) != 1 {
		t.Fatalf("main should find its own content, got %v", got)
	}
	if got := searchPaths(t, idx, feature, "Zeppelin", 10); len(got) != 0 {
		t.Fatalf("feature branch reached main's content: %v", got)
	}
	if got := searchPaths(t, idx, main, "Marmalade", 10); len(got) != 0 {
		t.Fatalf("main reached the feature branch's content: %v", got)
	}

	// A revision with no partition at all returns nothing rather than falling back to another.
	other := index.Revision{Worktree: "/elsewhere", Branch: "main"}
	if got := searchPaths(t, idx, other, "Zeppelin", 10); len(got) != 0 {
		t.Fatalf("an unknown revision fell back to another partition: %v", got)
	}
}

// L2. Construction is the gate, exactly as it is for Cite. A file the classifier excluded has no
// business in a full-text index, and refusing here means no implementation of the port re-checks.
func TestSecurityOnlyIndexableContentCanBeChunked(t *testing.T) {
	body := "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n"

	for _, tc := range []struct {
		name  string
		entry index.Entry
	}{
		{"excluded", index.Entry{Decision: index.Decision{
			Path: ".ssh/id_rsa", Disposition: index.DispositionExclude, Reason: index.ReasonProtectedPath,
		}}},
		{"reference", index.Entry{Decision: index.Decision{
			Path: "testdata/big.bin", Disposition: index.DispositionReference, Reason: index.ReasonBinary,
		}}},
		{"directory", index.Entry{Decision: index.Decision{
			Path: "src", Disposition: index.DispositionIndex, Reason: index.ReasonIncluded,
		}, IsDir: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docs, err := index.Chunk(tc.entry, []byte(body))
			if err == nil {
				t.Fatalf("chunking a %s entry must be refused, got %d documents", tc.name, len(docs))
			}
			if !modberr.Is(err, modberr.CodeInvalidArgument) {
				t.Fatalf("error = %v, want invalid argument", err)
			}
			if strings.Contains(err.Error(), "BEGIN OPENSSH") {
				t.Fatal("the refusal echoed the file's contents")
			}
		})
	}
}

// L3. A posting left behind after a removal keeps returning a match for content the index no longer
// holds — which for a deleted secret is the disclosure the deletion was meant to end.
func TestRemovedPathsDisappearFromResults(t *testing.T) {
	idx := index.NewMemoryIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	indexFile(t, idx, rev, "a.go", "package a\n\nfunc Aardvark() {}\n")
	indexFile(t, idx, rev, "b.go", "package b\n\nfunc Barnacle() {}\n")

	if got := searchPaths(t, idx, rev, "Aardvark", 10); !contains(got, "a.go") {
		t.Fatalf("a.go should be found before removal, got %v", got)
	}
	if err := idx.Remove(rev, "a.go"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if got := searchPaths(t, idx, rev, "Aardvark", 10); len(got) != 0 {
		t.Fatalf("a removed path still matches: %v", got)
	}
	// The neighbour must survive; a removal that took out the whole partition would also pass the
	// assertion above.
	if got := searchPaths(t, idx, rev, "Barnacle", 10); !contains(got, "b.go") {
		t.Fatalf("removing a.go also lost b.go: %v", got)
	}
}

// L4. Re-indexing replaces. Accumulating instead would return one path several times for one query
// and let text deleted from a file stay searchable forever.
func TestReindexingAPathReplacesItsDocuments(t *testing.T) {
	idx := index.NewMemoryIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	indexFile(t, idx, rev, "a.go", "package a\n\nfunc OriginalName() {}\n")
	indexFile(t, idx, rev, "a.go", "package a\n\nfunc RenamedThing() {}\n")

	if got := searchPaths(t, idx, rev, "OriginalName", 10); len(got) != 0 {
		t.Fatalf("text removed from the file is still searchable: %v", got)
	}
	got := searchPaths(t, idx, rev, "RenamedThing", 10)
	if len(got) != 1 || got[0] != "a.go" {
		t.Fatalf("re-indexed content = %v, want exactly [a.go]", got)
	}
}

// L5. Map iteration is random, so an unbroken tie reorders between runs and a recorded retrieval
// stops being reproducible evidence — the same reason routing is deterministic (MOD-A01 decision 6).
func TestRankingIsDeterministicAcrossRuns(t *testing.T) {
	build := func() ([]index.Match, error) {
		idx := index.NewMemoryIndex()
		rev := index.Revision{Worktree: "/repo", Branch: "main"}
		// Identical bodies guarantee identical scores, so ordering is decided entirely by the
		// tiebreak. Without one this test fails within a handful of runs.
		for _, path := range []string{"e.go", "c.go", "a.go", "d.go", "b.go"} {
			indexFile(t, idx, rev, path, "package p\n\nfunc Handler() error { return nil }\n")
		}
		return idx.Search(rev, "Handler", 10)
	}

	first, err := build()
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(first) != 5 {
		t.Fatalf("expected 5 matches, got %d", len(first))
	}
	for range 40 {
		next, err := build()
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		for i := range first {
			if next[i].Path != first[i].Path {
				t.Fatalf("ranking is unstable: position %d was %q then %q", i, first[i].Path, next[i].Path)
			}
		}
	}
}

// L6. A plain word splitter would make getUserName one term, so "user name" would miss the function
// that defines it and the identifier would miss get_user_name in the file beside it.
func TestIdentifiersMatchTheirParts(t *testing.T) {
	idx := index.NewMemoryIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	indexFile(t, idx, rev, "camel.go", "package p\n\nfunc getUserName() string { return \"\" }\n")
	indexFile(t, idx, rev, "snake.py", "def get_user_name():\n    return ''\n")
	indexFile(t, idx, rev, "acronym.go", "package p\n\ntype HTTPServerConfig struct{}\n")

	for _, tc := range []struct {
		query string
		want  string
	}{
		{"getUserName", "camel.go"},
		{"user", "camel.go"},
		{"name", "camel.go"},
		{"get_user_name", "snake.py"},
		{"user", "snake.py"},
		{"HTTPServerConfig", "acronym.go"},
		{"http", "acronym.go"},
		{"server", "acronym.go"},
		{"config", "acronym.go"},
	} {
		t.Run(tc.query+"->"+tc.want, func(t *testing.T) {
			if got := searchPaths(t, idx, rev, tc.query, 10); !contains(got, tc.want) {
				t.Fatalf("query %q did not find %s, got %v", tc.query, tc.want, got)
			}
		})
	}

	// The three spellings of one name find each other, which is the point of splitting at all.
	got := searchPaths(t, idx, rev, "user name", 10)
	if !contains(got, "camel.go") || !contains(got, "snake.py") {
		t.Fatalf("a parts query did not reach both spellings: %v", got)
	}
}

// L7. A match that cannot become a citation is content with no provenance, which RET-6 forbids
// reaching a model. The span must be usable: inside the file, and exactly the bytes it names.
func TestMatchesCarryASpanACitationCanUse(t *testing.T) {
	idx := index.NewMemoryIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}
	body := "package p\n\nfunc DistinctiveName() error {\n\treturn nil\n}\n"

	indexFile(t, idx, rev, "svc.go", body)

	matches, err := idx.Search(rev, "DistinctiveName", 5)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.Path != "svc.go" {
		t.Fatalf("path = %q", m.Path)
	}
	if m.Span.StartLine < 1 || m.Span.EndLine < m.Span.StartLine {
		t.Fatalf("span lines are unusable: %+v", m.Span)
	}
	if m.Span.EndByte > int64(len(body)) || m.Span.StartByte < 0 || m.Span.EndByte <= m.Span.StartByte {
		t.Fatalf("span bytes are unusable against a %d-byte file: %+v", len(body), m.Span)
	}
	// The span must name the bytes it claims, or a citation built from it would digest the wrong
	// region and fail revalidation.
	cited := body[m.Span.StartByte:m.Span.EndByte]
	if !strings.Contains(cited, "DistinctiveName") {
		t.Fatalf("the cited span does not contain the matched term: %q", cited)
	}
	if m.Score <= 0 {
		t.Fatalf("score = %v, want a positive score", m.Score)
	}
}

// L8. A query of punctuation matches nothing. Returning the corpus would spend a whole retrieval
// budget on arbitrary content and present it as a result, which is worse than an empty answer
// because it looks like one.
//
// This one holds structurally in MemoryIndex — with no terms the scoring loop accumulates nothing —
// so deleting the guard does not fail this test. It is kept for the implementations the port exists
// to admit: a match-all path for an empty query is a reasonable-looking thing for a Tantivy or
// OpenSearch adapter to inherit from its engine, and this is what would catch it.
func TestAQueryWithNoTermsReturnsNothing(t *testing.T) {
	idx := index.NewMemoryIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}
	indexFile(t, idx, rev, "a.go", "package a\n\nfunc Something() {}\n")

	for _, query := range []string{"", "   ", "!!! ??? ...", "\n\t"} {
		matches, err := idx.Search(rev, query, 10)
		if err != nil {
			t.Fatalf("Search(%q): %v", query, err)
		}
		if len(matches) != 0 {
			t.Fatalf("query %q returned %d matches; a query with no terms must match nothing", query, len(matches))
		}
	}

	if _, err := idx.Search(rev, "Something", 0); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("a non-positive result count must be refused, got %v", err)
	}
}

// ApplyChangeSet is the wiring between the reindexer and the lexical channel. Removals precede
// upserts because a rename that replaces a file with a directory puts one path in both.
func TestApplyChangeSetIndexesUpsertsAndDropsRemovals(t *testing.T) {
	idx := index.NewMemoryIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	bodies := map[string]string{
		"keep.go": "package p\n\nfunc Pelican() {}\n",
		"new.go":  "package p\n\nfunc Trombone() {}\n",
	}
	read := func(path string) ([]byte, error) {
		body, ok := bodies[path]
		if !ok {
			return nil, errors.New("no such file")
		}
		return []byte(body), nil
	}

	indexFile(t, idx, rev, "gone.go", "package p\n\nfunc Kumquat() {}\n")

	set := index.ChangeSet{
		Upserts: []index.Entry{
			indexedEntry("keep.go", int64(len(bodies["keep.go"]))),
			indexedEntry("new.go", int64(len(bodies["new.go"]))),
			// A reference entry is citable but has no text; it must be skipped, not refused.
			{Decision: index.Decision{
				Path: "big.bin", Disposition: index.DispositionReference, Reason: index.ReasonBinary,
			}},
		},
		Removals: []string{"gone.go"},
	}
	if err := index.ApplyChangeSet(idx, rev, set, read); err != nil {
		t.Fatalf("ApplyChangeSet: %v", err)
	}

	if got := searchPaths(t, idx, rev, "Kumquat", 10); len(got) != 0 {
		t.Fatalf("a removed path survived the change set: %v", got)
	}
	for query, want := range map[string]string{"Pelican": "keep.go", "Trombone": "new.go"} {
		if got := searchPaths(t, idx, rev, query, 10); !contains(got, want) {
			t.Fatalf("query %q did not find %s: %v", query, want, got)
		}
	}
}

// A file that cannot be read is a file the user cannot find by searching for text they know is in
// it. The rest of the batch must still be indexed, and the shortfall must be reported (R-ERR-05).
func TestApplyChangeSetReportsUnreadableFilesWithoutLosingTheBatch(t *testing.T) {
	idx := index.NewMemoryIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	read := func(path string) ([]byte, error) {
		if path == "locked.go" {
			return nil, errors.New("permission denied")
		}
		return []byte("package p\n\nfunc ReadableSymbol() {}\n"), nil
	}
	set := index.ChangeSet{Upserts: []index.Entry{
		indexedEntry("locked.go", 10),
		indexedEntry("readable.go", 40),
	}}

	err := index.ApplyChangeSet(idx, rev, set, read)
	if !modberr.Is(err, modberr.CodeContextDegraded) {
		t.Fatalf("error = %v, want a visible degradation", err)
	}
	// The readable file after the failure must still be indexed: one unreadable file must not cost
	// the rest of the batch.
	if got := searchPaths(t, idx, rev, "ReadableSymbol", 10); !contains(got, "readable.go") {
		t.Fatalf("an unreadable file cost the rest of the batch: %v", got)
	}
}

// Emptying a file must retract what it held. Otherwise the deleted text stays searchable, which is
// the same disclosure decision 57 closes for the classifier.
func TestApplyChangeSetRetractsAFileThatBecameEmpty(t *testing.T) {
	idx := index.NewMemoryIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	indexFile(t, idx, rev, "a.go", "package p\n\nfunc VanishingSymbol() {}\n")
	if got := searchPaths(t, idx, rev, "VanishingSymbol", 10); len(got) != 1 {
		t.Fatalf("precondition failed: %v", got)
	}

	set := index.ChangeSet{Upserts: []index.Entry{indexedEntry("a.go", 0)}}
	read := func(string) ([]byte, error) { return nil, nil }
	if err := index.ApplyChangeSet(idx, rev, set, read); err != nil {
		t.Fatalf("ApplyChangeSet: %v", err)
	}
	if got := searchPaths(t, idx, rev, "VanishingSymbol", 10); len(got) != 0 {
		t.Fatalf("emptying a file left its text searchable: %v", got)
	}
}

// Chunks must tile the file: every byte belongs to at most one chunk, and the spans must be exact,
// or a citation built from one would digest a region the file does not contain.
func TestChunksTileTheFileWithExactSpans(t *testing.T) {
	var b strings.Builder
	for i := range index.DefaultChunkLines * 3 {
		b.WriteString("line ")
		b.WriteString(strings.Repeat("x", i%7+1))
		b.WriteByte('\n')
	}
	body := b.String()

	docs, err := index.Chunk(indexedEntry("big.go", int64(len(body))), []byte(body))
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if len(docs) < 2 {
		t.Fatalf("a %d-line file produced %d chunks; it should be split", index.DefaultChunkLines*3, len(docs))
	}

	prevEnd := int64(0)
	for i, d := range docs {
		if d.Span.StartByte != prevEnd {
			t.Fatalf("chunk %d starts at %d, leaving a gap or overlap after %d", i, d.Span.StartByte, prevEnd)
		}
		if d.Span.EndByte > int64(len(body)) {
			t.Fatalf("chunk %d ends past the file: %+v", i, d.Span)
		}
		if got := body[d.Span.StartByte:d.Span.EndByte]; got != d.Text {
			t.Fatalf("chunk %d text does not match the bytes its span names", i)
		}
		if d.Span.StartLine < 1 || d.Span.EndLine < d.Span.StartLine {
			t.Fatalf("chunk %d has unusable lines: %+v", i, d.Span)
		}
		prevEnd = d.Span.EndByte
	}
	if prevEnd != int64(len(body)) {
		t.Fatalf("chunks covered %d of %d bytes", prevEnd, len(body))
	}
}
