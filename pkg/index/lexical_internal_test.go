package index

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/taint"
)

// indexEntryForTest mirrors the external suite's indexedEntry; the internal package cannot import
// the test helper across the package boundary.
func indexEntryForTest(path string, size int) Entry {
	return Entry{
		Decision: Decision{
			Path:        path,
			Disposition: DispositionIndex,
			Reason:      ReasonIncluded,
			Provenance:  taint.RepositoryUntrusted,
		},
		Size:    int64(size),
		ModTime: time.Unix(1700000000, 0),
	}
}

// referenceSearch scores exhaustively: every term against every posting, every candidate sorted.
// It is the definition L9 is measured against — deliberately the slow, obvious implementation, with
// no MaxScore threshold and no partial selection, so that a bug in either shows up as a difference
// rather than being reproduced identically on both sides.
func referenceSearch(m *MemoryIndex, revision Revision, query string, k int) []Match {
	terms := tokenize(query)
	if len(terms) == 0 || k <= 0 {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	p := m.partitionFor(revision, false)
	if p == nil || p.liveCount == 0 {
		return nil
	}
	avgLen := float64(p.totalLen) / float64(p.liveCount)

	scores := map[int]float64{}
	for _, term := range dedupeTerms(terms) {
		posting := p.postings[term]
		if posting == nil || len(posting.docs) == 0 {
			continue
		}
		idf := idfFor(p.liveCount, len(posting.docs))
		for ordinal, freq := range posting.docs {
			d := p.docs[ordinal]
			if !d.live {
				continue
			}
			scores[ordinal] += idf * bm25Norm(freq, d.length, avgLen)
		}
	}

	matches := make([]Match, 0, len(scores))
	for ordinal, score := range scores {
		d := p.docs[ordinal]
		matches = append(matches, Match{Path: d.path, Span: d.span, Score: score})
	}
	slices.SortFunc(matches, func(a, b Match) int {
		if c := cmp.Compare(b.Score, a.Score); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return cmp.Compare(a.Span.StartByte, b.Span.StartByte)
	})
	if len(matches) > k {
		matches = matches[:k]
	}
	return matches
}

// L9. MaxScore and quickselect are optimisations, and an optimisation that changes a ranking is a
// silent retrieval-quality regression: nothing fails, the agent simply sees different context. The
// only way to hold that down is to keep an exhaustive implementation and require the fast one to
// agree with it exactly — scores included, not just paths.
//
// The corpus is built to be the adversarial case rather than an average one. `common` is in every
// file, so its idf is near zero and its posting list is the whole corpus; the per-file identifiers
// are rare. A query mixing the two is where the threshold engages, and it is also the query shape a
// user actually types — `Handle4217Item3` tokenizes into exactly that mix.
//
// Mutation results, so the next reader knows what this does and does not hold down. Caught: sealing
// without checking the threshold; sealing on the maximum instead of the k-th score; understating a
// term's bound; dropping the current term from the suffix sum; removing top-k selection. Three
// mutants survive, and none of them should fail here:
//
//   - `>` weakened to `>=` in the threshold. Wrong only when a score equals the suffix bound exactly.
//     Reaching that needs contrived bit-exact float equality, and a test built to hit it would be
//     testing the fixture rather than the invariant.
//   - the sealed path ignoring posting membership. An absent key yields freq 0, and bm25Norm(0, …)
//     is 0, so the mutant adds nothing — genuinely equivalent, just wasteful.
//   - terms scored in ascending bound order. Sealing then almost never fires, which is slower and
//     equally correct. That is BenchmarkLexicalQueryShape's job, not L9's.
func TestSkippingWorkNeverChangesTheAnswer(t *testing.T) {
	const files = 120
	rev := Revision{Worktree: "/repo", Branch: "main"}
	idx := NewMemoryIndex()
	for i := range files {
		// Three populations, shaped so that sealing too early is *observable* rather than merely
		// wrong. A corpus-wide term alone cannot do that: its idf is near zero, so documents it
		// would have introduced could never have placed anyway, and skipping them changes nothing.
		//
		// So `alpha` (50 files, once each) and `beta` (60 files, twenty times each) have comparable
		// idf but very different term frequency. `alpha` sorts first on bound while `beta` scores
		// higher in fact — which means a threshold that seals after `alpha` silently drops the
		// documents that should have won.
		var marker string
		switch {
		case i < 50:
			marker = "alpha"
		case i < 110:
			marker = strings.TrimSpace(strings.Repeat("beta ", 20))
		}
		body := fmt.Sprintf("package common\n\n// common %s\nfunc handleRequest%d() error {\n"+
			"\treturn validateItem%d()\n}\n", marker, i, i%7)
		docs, err := Chunk(indexEntryForTest(fmt.Sprintf("pkg/p%d/f%d.go", i%10, i), len(body)), []byte(body))
		if err != nil {
			t.Fatalf("Chunk: %v", err)
		}
		if err := idx.Upsert(rev, docs...); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	queries := []string{
		"common",                // corpus-wide only: nothing to prune, every document is a candidate
		"handleRequest7",        // rare only: the threshold seals almost immediately
		"handleRequest7 common", // the mix the optimisation exists for
		"alpha beta",            // the discriminating case: bound order and score order disagree
		"alpha beta common",
		"validateItem3 common", // a mid-frequency term with a corpus-wide one
		"handleRequest7 validateItem3 common",
		"handleRequest7 handleRequest8 handleRequest9",
		"absent",        // no postings at all
		"common absent", // one term contributes nothing
	}
	assertAgreesWithExhaustive(t, idx, rev, queries)

	// A second corpus, for the threshold rather than for the ordering. Here one document carries
	// `gamma` fifty times while the other twenty-nine carry it once, so the *best* score after the
	// first term is far above the *k-th* score. A threshold that reads the maximum instead of the
	// k-th seals on the outlier and drops the `delta` documents, which genuinely place. The first
	// corpus cannot show this: its scores are too evenly spread for max and k-th to disagree.
	outlier := NewMemoryIndex()
	for i := range 120 {
		var marker string
		switch {
		case i == 0:
			marker = strings.TrimSpace(strings.Repeat("gamma ", 50))
		case i < 30:
			marker = "gamma"
		case i < 70:
			marker = strings.TrimSpace(strings.Repeat("delta ", 10))
		}
		body := fmt.Sprintf("package p\n\n// %s\nfunc f%d() {}\n", marker, i)
		docs, err := Chunk(indexEntryForTest(fmt.Sprintf("pkg/q%d/g%d.go", i%10, i), len(body)), []byte(body))
		if err != nil {
			t.Fatalf("Chunk: %v", err)
		}
		if err := outlier.Upsert(rev, docs...); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}
	assertAgreesWithExhaustive(t, outlier, rev, []string{"gamma delta", "gamma", "delta", "gamma delta p"})
}

// assertAgreesWithExhaustive is L9's assertion: for every query and every k, the optimised search
// returns what an exhaustive scan returns.
func assertAgreesWithExhaustive(t *testing.T, idx *MemoryIndex, rev Revision, queries []string) {
	t.Helper()
	// k spans both sides of the candidate count: the threshold cannot engage until k accumulators
	// exist, so a k larger than the corpus must still produce the same answer by the slow path.
	for _, k := range []int{1, 2, 3, 5, 20, 100, 500} {
		for _, q := range queries {
			got, err := idx.Search(rev, q, k)
			if err != nil {
				t.Fatalf("Search(%q, %d): %v", q, k, err)
			}
			want := referenceSearch(idx, rev, q, k)
			if len(got) != len(want) {
				t.Fatalf("Search(%q, k=%d) returned %d matches, exhaustive scoring returned %d",
					q, k, len(got), len(want))
			}
			for i := range want {
				// Path and span must match exactly: those identify *which* documents were
				// returned and in what order, which is the whole of what L9 protects. Every
				// mutation that breaks pruning or selection surfaces here, as a different
				// document at some rank.
				if got[i].Path != want[i].Path || got[i].Span != want[i].Span {
					t.Fatalf("Search(%q, k=%d) rank %d = %s %v, exhaustive scoring = %s %v",
						q, k, i, got[i].Path, got[i].Span, want[i].Path, want[i].Span)
				}
				// Scores are compared with a relative tolerance rather than for equality, because
				// MaxScore sorts the terms by bound and therefore accumulates them in a different
				// order than a naive scan does. Float addition is not associative, so the two
				// orders can land one ULP apart — observed here as 0.011662276945695767 against
				// 0.01166227694569577 for the same document. That is a reassociation, not a
				// scoring difference, and asserting equality would be asserting something BM25
				// never promised. A wrong score is wrong by far more than this.
				if d := math.Abs(got[i].Score - want[i].Score); d > 1e-12*math.Abs(want[i].Score)+1e-15 {
					t.Fatalf("Search(%q, k=%d) rank %d scored %v, exhaustive scoring gave %v (delta %v)",
						q, k, i, got[i].Score, want[i].Score, d)
				}
			}
		}
	}
}
