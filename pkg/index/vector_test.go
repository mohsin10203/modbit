package index_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

// fakeEmbedder produces deterministic vectors so a test can reason about distance exactly.
//
// It is a stand-in for the Model Gateway, which is where real embedding happens (V10). Its Embed
// never touches a network, which is the point: nothing in pkg/index may.
type fakeEmbedder struct {
	model string
	// vectors maps a text to its embedding. Anything absent gets a deterministic fallback.
	vectors map[string]index.Vector
	err     error
	// countMismatch makes Embed return the wrong number of vectors.
	countMismatch bool
	calls         int
}

func (f *fakeEmbedder) Model() string { return f.model }

func (f *fakeEmbedder) Embed(_ context.Context, texts []string) ([]index.Vector, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := make([]index.Vector, 0, len(texts))
	for _, text := range texts {
		if v, ok := f.vectors[text]; ok {
			out = append(out, v)
			continue
		}
		out = append(out, deterministicVector(text))
	}
	if f.countMismatch && len(out) > 0 {
		out = out[:len(out)-1]
	}
	return out, nil
}

// deterministicVector derives a stable 8-dimensional vector from a string, so an unseeded fixture
// still produces something with a direction.
func deterministicVector(text string) index.Vector {
	v := make(index.Vector, 8)
	for i, r := range text {
		v[i%8] += float32(r%13) + 1
	}
	// Guarantee a non-zero magnitude even for an empty string.
	v[0] += 1
	return v
}

func vectorSpace(branch, model string) index.VectorSpace {
	return index.VectorSpace{
		Revision: index.Revision{Worktree: "/repo", Branch: branch},
		Model:    model,
	}
}

func embeddedDoc(path string, v index.Vector) index.EmbeddedDocument {
	return index.EmbeddedDocument{
		Document: index.Document{
			Path: path,
			Span: index.Span{StartLine: 1, EndLine: 3, StartByte: 0, EndByte: 40},
			Text: "package p\n\nfunc Handler() {}\n",
		},
		Vector: v,
	}
}

func vectorPaths(t *testing.T, idx index.VectorIndex, space index.VectorSpace, q index.Vector, k int) []string {
	t.Helper()
	matches, err := idx.Search(space, q, k)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.Path)
	}
	return out
}

// V1. Same rule the lexical channel obeys: PRD §7 budgets zero branch/worktree contamination, and a
// semantic hit from another branch looks exactly like a legitimate one.
func TestSecurityVectorResultsNeverCrossRevisions(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	main := vectorSpace("main", "embed-v1")
	feature := vectorSpace("feature", "embed-v1")

	idx.Upsert(main, embeddedDoc("main-only.go", index.Vector{1, 0, 0, 0}))
	idx.Upsert(feature, embeddedDoc("feature-only.go", index.Vector{1, 0, 0, 0}))

	query := index.Vector{1, 0, 0, 0}
	if got := vectorPaths(t, idx, main, query, 10); len(got) != 1 || got[0] != "main-only.go" {
		t.Fatalf("main = %v, want [main-only.go]", got)
	}
	if got := vectorPaths(t, idx, feature, query, 10); len(got) != 1 || got[0] != "feature-only.go" {
		t.Fatalf("feature = %v, want [feature-only.go]", got)
	}
	if got := vectorPaths(t, idx, vectorSpace("nonexistent", "embed-v1"), query, 10); len(got) != 0 {
		t.Fatalf("an unknown revision fell back to another partition: %v", got)
	}
}

// V2. dev-06: re-embedding on model change is a versioned rebuild. Two models place the same text at
// different coordinates, so a cosine between them is meaningless — and, worse, plausible-looking.
func TestSecurityVectorsFromDifferentModelsAreNeverCompared(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	oldModel := vectorSpace("main", "embed-v1")
	newModel := vectorSpace("main", "embed-v2")

	idx.Upsert(oldModel, embeddedDoc("a.go", index.Vector{1, 0, 0, 0}))

	query := index.Vector{1, 0, 0, 0}
	if got := vectorPaths(t, idx, oldModel, query, 10); len(got) != 1 {
		t.Fatalf("the indexing model should find its own vectors, got %v", got)
	}
	if got := vectorPaths(t, idx, newModel, query, 10); len(got) != 0 {
		t.Fatalf("a query embedded by a different model reached v1's vectors: %v", got)
	}

	// A model revision roll is a different model too: providers change models under one identifier
	// (MOD-A01 decision 18), which is exactly what this guards.
	rolled := vectorSpace("main", "embed-v1@2026-07-01")
	if got := vectorPaths(t, idx, rolled, query, 10); len(got) != 0 {
		t.Fatalf("a rolled model revision reached the old vectors: %v", got)
	}
}

// V3. Chunk is the gate, so a protected file cannot reach an embedding provider — which matters more
// here than anywhere else, because embedding is the one code path that reads every file and sends it
// off the machine.
func TestSecurityExcludedContentIsNeverEmbedded(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	embedder := &fakeEmbedder{model: "embed-v1"}
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	read := func(string) ([]byte, error) {
		return []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nsecret material\n"), nil
	}
	set := index.ChangeSet{Upserts: []index.Entry{
		{Decision: index.Decision{
			Path: ".ssh/id_rsa", Disposition: index.DispositionExclude, Reason: index.ReasonProtectedPath,
		}},
		{Decision: index.Decision{
			Path: "big.bin", Disposition: index.DispositionReference, Reason: index.ReasonBinary,
		}},
	}}

	if err := index.EmbedChangeSet(context.Background(), idx, embedder, rev, set, read); err != nil {
		t.Fatalf("EmbedChangeSet: %v", err)
	}
	if embedder.calls != 0 {
		t.Fatalf("the embedder was called %d times for non-indexable content; nothing should have left the machine", embedder.calls)
	}
}

// V4. A retracted vector must be gone, not merely unlinked: an embedding of deleted content still
// answers queries about it.
func TestVectorRemovalDropsEveryVectorForAPath(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	space := vectorSpace("main", "embed-v1")

	idx.Upsert(space, embeddedDoc("a.go", index.Vector{1, 0, 0, 0}))
	idx.Upsert(space, embeddedDoc("b.go", index.Vector{0, 1, 0, 0}))

	if err := idx.Remove(space, "a.go"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if got := vectorPaths(t, idx, space, index.Vector{1, 0, 0, 0}, 10); contains(got, "a.go") {
		t.Fatalf("a removed path still matches: %v", got)
	}
	if got := vectorPaths(t, idx, space, index.Vector{0, 1, 0, 0}, 10); !contains(got, "b.go") {
		t.Fatalf("removing a.go also lost b.go: %v", got)
	}
}

// V5. Re-indexing replaces. Accumulating would return one path several times for one query and keep
// an embedding of text the file no longer contains.
func TestReindexingAPathReplacesItsVectors(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	space := vectorSpace("main", "embed-v1")

	idx.Upsert(space, embeddedDoc("a.go", index.Vector{1, 0, 0, 0}))
	idx.Upsert(space, embeddedDoc("a.go", index.Vector{0, 0, 0, 1}))

	matches, err := idx.Search(space, index.Vector{1, 0, 0, 0}, 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("a re-indexed path produced %d entries, want 1", len(matches))
	}
	// The old vector pointed straight at this query; the new one is orthogonal to it.
	if matches[0].Score > 0.001 {
		t.Fatalf("score = %v; the superseded vector is still being compared", matches[0].Score)
	}
}

// V6. Identical vectors produce identical scores, so ordering is decided entirely by the tiebreak.
//
// Repeating one build would prove nothing here: unlike the lexical channel, which ranks out of a map
// and so genuinely varies run to run, this index scans a slice in ordinal order and would be
// repeatable with no tiebreak at all. What the tiebreak actually buys is independence from
// *insertion order* — two machines that indexed the same tree in a different sequence, or one index
// rebuilt after removals recycled its ordinals, must rank identically or a recorded retrieval is not
// reproducible evidence (MOD-A01 decision 6).
func TestVectorRankingIsIndependentOfInsertionOrder(t *testing.T) {
	build := func(paths []string, churn bool) []string {
		idx := index.NewMemoryVectorIndex()
		space := vectorSpace("main", "embed-v1")
		if churn {
			// Index and retract throwaway paths first, so the free list hands out ordinals in an
			// order the fresh index would never produce.
			for _, p := range []string{"tmp1.go", "tmp2.go", "tmp3.go"} {
				if err := idx.Upsert(space, embeddedDoc(p, index.Vector{0, 0, 1, 0})); err != nil {
					t.Fatalf("Upsert: %v", err)
				}
			}
			if err := idx.Remove(space, "tmp1.go", "tmp2.go", "tmp3.go"); err != nil {
				t.Fatalf("Remove: %v", err)
			}
		}
		for _, path := range paths {
			if err := idx.Upsert(space, embeddedDoc(path, index.Vector{1, 1, 0, 0})); err != nil {
				t.Fatalf("Upsert: %v", err)
			}
		}
		return vectorPaths(t, idx, space, index.Vector{1, 1, 0, 0}, 10)
	}

	want := build([]string{"a.go", "b.go", "c.go", "d.go", "e.go"}, false)
	if len(want) != 5 {
		t.Fatalf("expected 5 matches, got %d", len(want))
	}
	for _, tc := range []struct {
		name  string
		paths []string
		churn bool
	}{
		{"reversed", []string{"e.go", "d.go", "c.go", "b.go", "a.go"}, false},
		{"shuffled", []string{"c.go", "a.go", "e.go", "b.go", "d.go"}, false},
		{"after ordinal churn", []string{"d.go", "b.go", "e.go", "a.go", "c.go"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := build(tc.paths, tc.churn)
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("insertion order changed the ranking: position %d was %q, now %q\n want %v\n got  %v",
						i, want[i], got[i], want, got)
				}
			}
		})
	}
}

// V7. A match that cannot become a citation is content with no provenance (RET-6).
func TestVectorMatchesCarryASpanACitationCanUse(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	space := vectorSpace("main", "embed-v1")
	idx.Upsert(space, embeddedDoc("svc.go", index.Vector{1, 0, 0, 0}))

	matches, err := idx.Search(space, index.Vector{1, 0, 0, 0}, 5)
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
	if m.Span.StartLine < 1 || m.Span.EndLine < m.Span.StartLine || m.Span.EndByte <= m.Span.StartByte {
		t.Fatalf("span is unusable for a citation: %+v", m.Span)
	}
	// An exact match of a unit vector with itself is a cosine of 1.
	if math.Abs(m.Score-1) > 1e-6 {
		t.Fatalf("score = %v, want 1 for an identical vector", m.Score)
	}
}

// V8. Coercing a mismatched vector — truncating or zero-padding — produces a cosine that is
// arithmetically valid and semantically meaningless, which is the failure nobody notices.
func TestMalformedVectorsAreRefusedNotCoerced(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	space := vectorSpace("main", "embed-v1")

	if err := idx.Upsert(space, embeddedDoc("a.go", index.Vector{1, 0, 0, 0})); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	for name, v := range map[string]index.Vector{
		"too narrow":     {1, 0},
		"too wide":       {1, 0, 0, 0, 0},
		"zero magnitude": {0, 0, 0, 0},
		"empty":          {},
		"NaN":            {float32(math.NaN()), 0, 0, 0},
		"infinity":       {float32(math.Inf(1)), 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if err := idx.Upsert(space, embeddedDoc("bad.go", v)); !modberr.Is(err, modberr.CodeInvalidArgument) {
				t.Fatalf("upserting a %s vector returned %v, want a refusal", name, err)
			}
			if _, err := idx.Search(space, v, 5); !modberr.Is(err, modberr.CodeInvalidArgument) {
				t.Fatalf("searching with a %s vector returned %v, want a refusal", name, err)
			}
		})
	}

	// The refused batch must not have been half-applied.
	if got := vectorPaths(t, idx, space, index.Vector{1, 0, 0, 0}, 10); contains(got, "bad.go") {
		t.Fatalf("a refused vector was indexed anyway: %v", got)
	}
}

// V8, second half: a batch is all-or-nothing. One bad vector among good ones must not leave the good
// ones applied, or a retry would double-index them.
func TestABatchWithOneBadVectorIsRefusedWhole(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	space := vectorSpace("main", "embed-v1")

	err := idx.Upsert(space,
		embeddedDoc("good.go", index.Vector{1, 0, 0, 0}),
		embeddedDoc("bad.go", index.Vector{0, 0, 0, 0}),
	)
	if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal", err)
	}
	if got := vectorPaths(t, idx, space, index.Vector{1, 0, 0, 0}, 10); len(got) != 0 {
		t.Fatalf("a partially applied batch left %v indexed", got)
	}
}

// V9. The index holds vectors and locations. A semantic index that kept chunk bodies would be a
// second copy of the repository outside the classifier's reach, surviving every retraction.
//
// This holds structurally in MemoryVectorIndex — Match has no field to put text in — so the test
// cannot fail against this implementation. It is kept for the pgvector adapter the port exists to
// admit: there the row being selected from does hold the chunk, and returning it would be one column
// away from an accident.
func TestSecurityVectorIndexRetainsNoText(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	space := vectorSpace("main", "embed-v1")

	marker := "SEMANTIC-MARKER-b41f"
	doc := embeddedDoc("a.go", index.Vector{1, 0, 0, 0})
	doc.Text = marker + " package p"
	if err := idx.Upsert(space, doc); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	matches, err := idx.Search(space, index.Vector{1, 0, 0, 0}, 5)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	for _, m := range matches {
		rendered := m.Path + m.Span.String()
		if strings.Contains(rendered, marker) {
			t.Fatalf("chunk text reached a search result: %s", rendered)
		}
	}
}

// EmbedChangeSet is the wiring between the reindexer and the semantic channel.
func TestEmbedChangeSetIndexesUpsertsAndDropsRemovals(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	embedder := &fakeEmbedder{model: "embed-v1"}
	rev := index.Revision{Worktree: "/repo", Branch: "main"}
	space := index.VectorSpace{Revision: rev, Model: "embed-v1"}

	body := "package p\n\nfunc Kept() {}\n"
	read := func(string) ([]byte, error) { return []byte(body), nil }

	idx.Upsert(space, embeddedDoc("gone.go", index.Vector{1, 0, 0, 0, 0, 0, 0, 0}))

	set := index.ChangeSet{
		Upserts:  []index.Entry{indexedEntry("keep.go", int64(len(body)))},
		Removals: []string{"gone.go"},
	}
	if err := index.EmbedChangeSet(context.Background(), idx, embedder, rev, set, read); err != nil {
		t.Fatalf("EmbedChangeSet: %v", err)
	}

	matches, err := idx.Search(space, deterministicVector(body), 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	for _, m := range matches {
		if m.Path == "gone.go" {
			t.Fatal("a removed path survived the change set")
		}
	}
	if len(matches) != 1 || matches[0].Path != "keep.go" {
		t.Fatalf("matches = %+v, want exactly keep.go", matches)
	}
	// One call per file, not one per chunk: a provider round trip per chunk would make indexing a
	// repository a per-chunk billing event.
	if embedder.calls != 1 {
		t.Fatalf("embedder called %d times for one file", embedder.calls)
	}
}

// An embedding failure has several causes with different recoveries — a DLP refusal, a budget
// ceiling, a provider outage — so it surfaces with its cause rather than being retried here.
func TestEmbeddingFailureSurfacesAsAVisibleDegradation(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	boom := errors.New("dlp blocked the payload")
	embedder := &fakeEmbedder{model: "embed-v1", err: boom}
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	read := func(string) ([]byte, error) { return []byte("package p\n\nfunc F() {}\n"), nil }
	set := index.ChangeSet{Upserts: []index.Entry{indexedEntry("a.go", 30)}}

	err := index.EmbedChangeSet(context.Background(), idx, embedder, rev, set, read)
	if !modberr.Is(err, modberr.CodeContextDegraded) {
		t.Fatalf("error = %v, want a visible degradation", err)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("the cause was lost: %v", err)
	}
}

// A provider returning a different number of vectors than texts would pair each chunk with a
// neighbour's embedding: every result subtly wrong, nothing failing.
func TestAVectorCountMismatchIsRefused(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	embedder := &fakeEmbedder{model: "embed-v1", countMismatch: true}
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	var b strings.Builder
	for range index.DefaultChunkLines * 2 {
		b.WriteString("some source line here\n")
	}
	read := func(string) ([]byte, error) { return []byte(b.String()), nil }
	set := index.ChangeSet{Upserts: []index.Entry{indexedEntry("a.go", int64(b.Len()))}}

	err := index.EmbedChangeSet(context.Background(), idx, embedder, rev, set, read)
	if !modberr.Is(err, modberr.CodeContextDegraded) {
		t.Fatalf("error = %v, want a refusal", err)
	}
}

// An embedder with no model identity would put every rebuild into one partition, which is V2's
// failure with no way to notice it.
func TestAnEmbedderWithNoModelIdentityIsRefused(t *testing.T) {
	idx := index.NewMemoryVectorIndex()
	embedder := &fakeEmbedder{model: ""}
	rev := index.Revision{Worktree: "/repo", Branch: "main"}
	read := func(string) ([]byte, error) { return []byte("package p\n"), nil }

	err := index.EmbedChangeSet(context.Background(), idx, embedder, rev, index.ChangeSet{}, read)
	if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal", err)
	}
}
