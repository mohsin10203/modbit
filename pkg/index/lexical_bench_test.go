package index_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/index"
)

// synthDoc builds a document with realistic code-shaped vocabulary: a mix of shared tokens (package,
// func, error) and per-file identifiers, which is what decides posting-list size in a real corpus.
func synthDoc(i int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "package svc%d\n\nimport (\n\t\"context\"\n\t\"errors\"\n)\n\n", i%400)
	for j := range 12 {
		fmt.Fprintf(&b, "// Handler%d_%d processes a request and returns an error.\n", i, j)
		fmt.Fprintf(&b, "func (s *Server%d) Handle%dItem%d(ctx context.Context, id string) error {\n", i%400, i, j)
		fmt.Fprintf(&b, "\tif err := s.validate%d(ctx, id); err != nil {\n\t\treturn errors.New(\"invalid\")\n\t}\n\treturn nil\n}\n\n", j)
	}
	return b.String()
}

// BenchmarkLexicalIndexScale reports the cost of the in-process lexical index at increasing corpus
// sizes. It exists to answer one decision-relevant question: at what point does an in-memory,
// exhaustive index stop being the right answer? Reported per document so the numbers extrapolate.
func BenchmarkLexicalIndexScale(b *testing.B) {
	for _, docs := range []int{1000, 10000, 50000} {
		b.Run(fmt.Sprintf("docs=%d", docs), func(b *testing.B) {
			rev := index.Revision{Worktree: "/repo", Branch: "main"}

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)

			idx := index.NewMemoryIndex()
			for i := range docs {
				body := synthDoc(i)
				entry := indexedEntry(fmt.Sprintf("pkg/svc%d/file%d.go", i%400, i), int64(len(body)))
				chunks, err := index.Chunk(entry, []byte(body))
				if err != nil {
					b.Fatalf("Chunk: %v", err)
				}
				if err := idx.Upsert(rev, chunks...); err != nil {
					b.Fatalf("Upsert: %v", err)
				}
			}

			runtime.GC()
			runtime.ReadMemStats(&after)
			heap := after.HeapAlloc - before.HeapAlloc

			b.ResetTimer()
			for b.Loop() {
				if _, err := idx.Search(rev, "Handler validate error context", 20); err != nil {
					b.Fatalf("Search: %v", err)
				}
			}
			b.StopTimer()
			// Reported after the timed loop: metrics registered before it are discarded.
			b.ReportMetric(float64(heap)/float64(docs), "B/doc")
			b.ReportMetric(float64(heap)/(1<<20), "heapMB")
		})
	}
}
