package index_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

const goSource = `// Package svc serves requests.
package svc

import (
	"context"
	"strings"
)

// MaxRetries bounds the retry loop.
const MaxRetries = 3

var defaultTimeout = 30

// Handler processes one request.
type Handler interface {
	Serve(ctx context.Context) error
}

// Server is the concrete handler.
type Server struct {
	name string
}

// Serve implements Handler.
func (s *Server) Serve(ctx context.Context) error {
	_ = strings.TrimSpace(s.name)
	return nil
}

func unexportedHelper() {}

const (
	alpha = 1
	Beta  = 2
)
`

func extractGo(t *testing.T, path, source string) ([]index.Symbol, []index.Edge) {
	t.Helper()
	symbols, edges, err := index.GoExtractor{}.Extract(indexedEntry(path, int64(len(source))), []byte(source))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	return symbols, edges
}

func symbolNamed(symbols []index.Symbol, qualified string) (index.Symbol, bool) {
	for _, s := range symbols {
		if s.Qualified() == qualified {
			return s, true
		}
	}
	return index.Symbol{}, false
}

// The extractor must find every kind of declaration, because a symbol channel that silently omits
// one kind is worse than none: a search for a type that exists returns nothing and the user
// concludes the code does not exist.
func TestGoExtractorFindsEveryDeclarationKind(t *testing.T) {
	symbols, _ := extractGo(t, "svc/server.go", goSource)

	want := map[string]index.SymbolKind{
		"MaxRetries":       index.SymbolConst,
		"defaultTimeout":   index.SymbolVar,
		"Handler":          index.SymbolInterface,
		"Server":           index.SymbolStruct,
		"Server.Serve":     index.SymbolMethod,
		"unexportedHelper": index.SymbolFunction,
		"alpha":            index.SymbolConst,
		"Beta":             index.SymbolConst,
	}
	for qualified, kind := range want {
		s, ok := symbolNamed(symbols, qualified)
		if !ok {
			t.Fatalf("symbol %q was not extracted; got %v", qualified, qualifiedNames(symbols))
		}
		if s.Kind != kind {
			t.Errorf("%q kind = %q, want %q", qualified, s.Kind, kind)
		}
	}

	if s, _ := symbolNamed(symbols, "Server.Serve"); s.Container != "Server" {
		t.Errorf("method container = %q, want Server; a pointer receiver must resolve to its type", s.Container)
	}
	if s, _ := symbolNamed(symbols, "MaxRetries"); !s.Exported {
		t.Error("MaxRetries must be marked exported")
	}
	if s, _ := symbolNamed(symbols, "unexportedHelper"); s.Exported {
		t.Error("unexportedHelper must not be marked exported")
	}
}

func qualifiedNames(symbols []index.Symbol) []string {
	out := make([]string, 0, len(symbols))
	for _, s := range symbols {
		out = append(out, s.Qualified())
	}
	return out
}

// G7. A citation of a function without its doc comment routinely omits the one sentence that answers
// the question being asked, so the span covers both — and it must be exact, or the citation digests
// a region the file does not contain.
func TestSymbolSpansCoverTheDocCommentAndAreExact(t *testing.T) {
	symbols, edges := extractGo(t, "svc/server.go", goSource)

	s, ok := symbolNamed(symbols, "Server.Serve")
	if !ok {
		t.Fatal("Server.Serve was not extracted")
	}
	cited := goSource[s.Span.StartByte:s.Span.EndByte]
	if !strings.Contains(cited, "// Serve implements Handler.") {
		t.Fatalf("the span omits the doc comment:\n%s", cited)
	}
	if !strings.Contains(cited, "func (s *Server) Serve") {
		t.Fatalf("the span omits the declaration:\n%s", cited)
	}

	// A grouped constant must claim only its own line, not the whole block's comment.
	beta, _ := symbolNamed(symbols, "Beta")
	betaCited := goSource[beta.Span.StartByte:beta.Span.EndByte]
	if strings.Contains(betaCited, "alpha") {
		t.Fatalf("a grouped const claimed its neighbour's span:\n%s", betaCited)
	}

	for _, s := range symbols {
		if s.Span.StartLine < 1 || s.Span.EndLine < s.Span.StartLine {
			t.Errorf("%q has unusable lines: %+v", s.Qualified(), s.Span)
		}
		if s.Span.StartByte < 0 || s.Span.EndByte > int64(len(goSource)) || s.Span.EndByte <= s.Span.StartByte {
			t.Errorf("%q has unusable bytes: %+v", s.Qualified(), s.Span)
		}
	}
	for _, e := range edges {
		if e.Span.EndByte > int64(len(goSource)) || e.Span.EndByte <= e.Span.StartByte {
			t.Errorf("edge to %q has an unusable span: %+v", e.To, e.Span)
		}
	}
}

// CTX-7: cross-repository links must be explicit and attributable. An edge names the line that
// creates the dependency, which is what a reviewer needs.
func TestImportEdgesAreExtractedWithTheirSpans(t *testing.T) {
	_, edges := extractGo(t, "svc/server.go", goSource)

	found := map[string]index.Edge{}
	for _, e := range edges {
		if e.Kind != index.EdgeImports {
			t.Fatalf("unexpected edge kind %q", e.Kind)
		}
		if e.From != "svc/server.go" {
			t.Fatalf("edge from = %q, want svc/server.go", e.From)
		}
		found[e.To] = e
	}
	for _, want := range []string{"context", "strings"} {
		e, ok := found[want]
		if !ok {
			t.Fatalf("import %q was not extracted; got %v", want, found)
		}
		cited := goSource[e.Span.StartByte:e.Span.EndByte]
		if !strings.Contains(cited, want) {
			t.Fatalf("the edge span does not name its import: %q", cited)
		}
	}
}

// G2. A file the classifier excluded must not be parsed, for the same reason it must not be chunked.
func TestSecurityExcludedContentIsNeverParsed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry index.Entry
	}{
		{"excluded", index.Entry{Decision: index.Decision{
			Path: "secrets.go", Disposition: index.DispositionExclude, Reason: index.ReasonProtectedPath,
		}}},
		{"reference", index.Entry{Decision: index.Decision{
			Path: "vendored.go", Disposition: index.DispositionReference, Reason: index.ReasonTooLarge,
		}}},
		{"directory", index.Entry{Decision: index.Decision{
			Path: "svc", Disposition: index.DispositionIndex, Reason: index.ReasonIncluded,
		}, IsDir: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := index.GoExtractor{}.Extract(tc.entry, []byte(goSource))
			if !modberr.Is(err, modberr.CodeInvalidArgument) {
				t.Fatalf("error = %v, want a refusal", err)
			}
		})
	}
}

// G8. A repository mid-edit routinely holds a file that does not parse. It must degrade visibly
// rather than crash the extractor or pass silently, and the error must not echo the source.
func TestUnparseableFilesDegradeVisibly(t *testing.T) {
	broken := "package svc\n\nfunc Broken( {\n\tsecretLiteral := \"AKIAIOSFODNN7EXAMPLE\"\n"

	_, _, err := index.GoExtractor{}.Extract(indexedEntry("broken.go", int64(len(broken))), []byte(broken))
	if !modberr.Is(err, modberr.CodeContextDegraded) {
		t.Fatalf("error = %v, want a visible degradation", err)
	}
	if strings.Contains(err.Error(), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("the parse error echoed the source line: %v", err)
	}
}

// G1. Same rule as every other channel: PRD §7 budgets zero branch contamination.
func TestSecuritySymbolLookupsNeverCrossRevisions(t *testing.T) {
	idx := index.NewMemorySymbolIndex()
	main := index.Revision{Worktree: "/repo", Branch: "main"}
	feature := index.Revision{Worktree: "/repo", Branch: "feature"}

	mainSyms, mainEdges := extractGo(t, "a.go", "package p\n\nfunc MainSide() {}\n")
	featSyms, featEdges := extractGo(t, "a.go", "package p\n\nimport \"os\"\n\nfunc FeatureSide() { _ = os.Args }\n")

	if err := idx.Upsert(main, "a.go", mainSyms, mainEdges); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := idx.Upsert(feature, "a.go", featSyms, featEdges); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if got, _ := idx.Lookup(main, "MainSide"); len(got) != 1 {
		t.Fatalf("main should find its own symbol, got %v", got)
	}
	if got, _ := idx.Lookup(feature, "MainSide"); len(got) != 0 {
		t.Fatalf("the feature branch reached main's symbols: %v", got)
	}
	if got, _ := idx.Lookup(main, "FeatureSide"); len(got) != 0 {
		t.Fatalf("main reached the feature branch's symbols: %v", got)
	}
	// Edges are partitioned too; an import only the feature branch declares must not appear on main.
	if got, _ := idx.Dependents(main, "os"); len(got) != 0 {
		t.Fatalf("main reached the feature branch's edges: %v", got)
	}
	if got, _ := idx.Dependents(feature, "os"); len(got) != 1 {
		t.Fatalf("the feature branch lost its own edge: %v", got)
	}
}

// G4. A symbol left behind keeps answering lookups for a file that no longer exists.
func TestRemovedPathsDisappearFromTheSymbolIndex(t *testing.T) {
	idx := index.NewMemorySymbolIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	aSyms, aEdges := extractGo(t, "a.go", "package p\n\nimport \"context\"\n\nfunc Alpha(c context.Context) {}\n")
	bSyms, bEdges := extractGo(t, "b.go", "package p\n\nimport \"context\"\n\nfunc Bravo(c context.Context) {}\n")
	idx.Upsert(rev, "a.go", aSyms, aEdges)
	idx.Upsert(rev, "b.go", bSyms, bEdges)

	if err := idx.Remove(rev, "a.go"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if got, _ := idx.Lookup(rev, "Alpha"); len(got) != 0 {
		t.Fatalf("a removed path still answers lookups: %v", got)
	}
	if got, _ := idx.Dependencies(rev, "a.go"); len(got) != 0 {
		t.Fatalf("a removed path still declares dependencies: %v", got)
	}
	// The reverse edge index must drop a.go's contribution without losing b.go's.
	dependents, _ := idx.Dependents(rev, "context")
	if len(dependents) != 1 || dependents[0].From != "b.go" {
		t.Fatalf("dependents of context = %v, want only b.go", dependents)
	}
	if got, _ := idx.Lookup(rev, "Bravo"); len(got) != 1 {
		t.Fatalf("removing a.go also lost b.go: %v", got)
	}
}

// G5. Re-indexing replaces. Accumulating would answer a lookup with a declaration the file no longer
// contains, at a span that now points somewhere else entirely.
func TestReindexingAPathReplacesItsSymbols(t *testing.T) {
	idx := index.NewMemorySymbolIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	before, beforeEdges := extractGo(t, "a.go", "package p\n\nimport \"context\"\n\nfunc Original(c context.Context) {}\n")
	idx.Upsert(rev, "a.go", before, beforeEdges)

	after, afterEdges := extractGo(t, "a.go", "package p\n\nimport \"strings\"\n\nfunc Renamed(s string) {}\n")
	idx.Upsert(rev, "a.go", after, afterEdges)

	if got, _ := idx.Lookup(rev, "Original"); len(got) != 0 {
		t.Fatalf("a superseded symbol is still returned: %v", got)
	}
	if got, _ := idx.Lookup(rev, "Renamed"); len(got) != 1 {
		t.Fatalf("the new symbol was not indexed: %v", got)
	}
	if got, _ := idx.Dependents(rev, "context"); len(got) != 0 {
		t.Fatalf("a superseded import edge survived: %v", got)
	}
	if got, _ := idx.Dependents(rev, "strings"); len(got) != 1 {
		t.Fatalf("the new import edge was not indexed: %v", got)
	}
	if got, _ := idx.Dependencies(rev, "a.go"); len(got) != 1 {
		t.Fatalf("dependencies accumulated instead of replacing: %v", got)
	}
}

// A qualified lookup must distinguish two methods sharing a name on different types, which is the
// case a bare-name index gets wrong and the one a user hits constantly.
func TestQualifiedLookupsDistinguishSameNamedMethods(t *testing.T) {
	idx := index.NewMemorySymbolIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	syms, edges := extractGo(t, "a.go", `package p

type Reader struct{}

func (r *Reader) Close() error { return nil }

type Writer struct{}

func (w *Writer) Close() error { return nil }
`)
	idx.Upsert(rev, "a.go", syms, edges)

	all, _ := idx.Lookup(rev, "Close")
	if len(all) != 2 {
		t.Fatalf("bare lookup = %d symbols, want 2", len(all))
	}
	readerClose, _ := idx.Lookup(rev, "Reader.Close")
	if len(readerClose) != 1 || readerClose[0].Container != "Reader" {
		t.Fatalf("qualified lookup = %v, want exactly Reader.Close", readerClose)
	}
	if got, _ := idx.Lookup(rev, "Nothing.Close"); len(got) != 0 {
		t.Fatalf("a qualified lookup on an absent container matched: %v", got)
	}
}

// G6. Repeating one build would prove nothing: both accessors read a single slice appended in
// upsert order, so they would be repeatable with no sort at all. What the sort buys is independence
// from *indexing order* — two machines that walked the same tree in a different sequence must answer
// a lookup identically, or a recorded retrieval is not reproducible evidence (MOD-A01 decision 6).
func TestSymbolResultsAreIndependentOfIndexingOrder(t *testing.T) {
	build := func(paths []string) ([]string, []string) {
		idx := index.NewMemorySymbolIndex()
		rev := index.Revision{Worktree: "/repo", Branch: "main"}
		for _, p := range paths {
			syms, edges := extractGo(t, p, "package p\n\nimport \"context\"\n\nfunc Shared(c context.Context) {}\n")
			if err := idx.Upsert(rev, p, syms, edges); err != nil {
				t.Fatalf("Upsert: %v", err)
			}
		}
		found, _ := idx.Lookup(rev, "Shared")
		names := make([]string, 0, len(found))
		for _, s := range found {
			names = append(names, s.Path)
		}
		deps, _ := idx.Dependents(rev, "context")
		froms := make([]string, 0, len(deps))
		for _, e := range deps {
			froms = append(froms, e.From)
		}
		return names, froms
	}

	wantSyms, wantEdges := build([]string{"a.go", "b.go", "c.go", "d.go", "e.go"})
	if len(wantSyms) != 5 || len(wantEdges) != 5 {
		t.Fatalf("expected 5 of each, got %d symbols and %d edges", len(wantSyms), len(wantEdges))
	}

	for _, order := range [][]string{
		{"e.go", "d.go", "c.go", "b.go", "a.go"},
		{"c.go", "a.go", "e.go", "b.go", "d.go"},
		{"b.go", "e.go", "a.go", "d.go", "c.go"},
	} {
		gotSyms, gotEdges := build(order)
		for i := range wantSyms {
			if gotSyms[i] != wantSyms[i] {
				t.Fatalf("indexing order changed symbol results at %d: %q vs %q\n want %v\n got  %v",
					i, wantSyms[i], gotSyms[i], wantSyms, gotSyms)
			}
		}
		for i := range wantEdges {
			if gotEdges[i] != wantEdges[i] {
				t.Fatalf("indexing order changed edge results at %d: %q vs %q\n want %v\n got  %v",
					i, wantEdges[i], gotEdges[i], wantEdges, gotEdges)
			}
		}
	}
}

// ExtractChangeSet is the wiring between the reindexer and the symbol channel.
func TestExtractChangeSetIndexesUpsertsAndDropsRemovals(t *testing.T) {
	idx := index.NewMemorySymbolIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	stale, staleEdges := extractGo(t, "gone.go", "package p\n\nfunc Doomed() {}\n")
	idx.Upsert(rev, "gone.go", stale, staleEdges)

	body := "package p\n\nimport \"context\"\n\nfunc Fresh(c context.Context) {}\n"
	read := func(string) ([]byte, error) { return []byte(body), nil }

	set := index.ChangeSet{
		Upserts: []index.Entry{
			indexedEntry("new.go", int64(len(body))),
			// A non-Go file must be skipped by this extractor, not refused.
			indexedEntry("README.md", 12),
			// A reference entry has no parseable content.
			{Decision: index.Decision{
				Path: "big.bin", Disposition: index.DispositionReference, Reason: index.ReasonBinary,
			}},
		},
		Removals: []string{"gone.go"},
	}
	if err := index.ExtractChangeSet(idx, index.GoExtractor{}, rev, set, read); err != nil {
		t.Fatalf("ExtractChangeSet: %v", err)
	}

	if got, _ := idx.Lookup(rev, "Doomed"); len(got) != 0 {
		t.Fatalf("a removed path survived the change set: %v", got)
	}
	if got, _ := idx.Lookup(rev, "Fresh"); len(got) != 1 {
		t.Fatalf("the new symbol was not indexed: %v", got)
	}
	if got, _ := idx.Dependencies(rev, "README.md"); len(got) != 0 {
		t.Fatalf("a non-Go file was parsed as Go: %v", got)
	}
}

// G8, through the wiring: one unparseable file must cost its own symbols, not the batch's, and the
// stale symbols it used to hold must be retracted rather than left answering lookups.
func TestExtractChangeSetSurvivesAnUnparseableFile(t *testing.T) {
	idx := index.NewMemorySymbolIndex()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	previous, previousEdges := extractGo(t, "broken.go", "package p\n\nfunc WasValid() {}\n")
	idx.Upsert(rev, "broken.go", previous, previousEdges)

	good := "package p\n\nfunc StillGood() {}\n"
	read := func(p string) ([]byte, error) {
		if p == "broken.go" {
			return []byte("package p\n\nfunc Broken( {\n"), nil
		}
		if p == "unreadable.go" {
			return nil, errors.New("permission denied")
		}
		return []byte(good), nil
	}
	set := index.ChangeSet{Upserts: []index.Entry{
		indexedEntry("broken.go", 24),
		indexedEntry("unreadable.go", 24),
		indexedEntry("good.go", int64(len(good))),
	}}

	err := index.ExtractChangeSet(idx, index.GoExtractor{}, rev, set, read)
	if !modberr.Is(err, modberr.CodeContextDegraded) {
		t.Fatalf("error = %v, want a visible degradation", err)
	}
	// The file after the failures must still be indexed.
	if got, _ := idx.Lookup(rev, "StillGood"); len(got) != 1 {
		t.Fatalf("a broken file cost the rest of the batch: %v", got)
	}
	// The broken file's previous symbols are now wrong and must not survive.
	if got, _ := idx.Lookup(rev, "WasValid"); len(got) != 0 {
		t.Fatalf("stale symbols survived a failed re-parse: %v", got)
	}
}
