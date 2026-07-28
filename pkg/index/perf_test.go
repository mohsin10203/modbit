//go:build perf

// Performance gates for the local Context Engine (QA-A01c).
//
// Separate from the unit suite behind a build tag, and run by `make perf-gate` rather than
// `make check`: building a Standard-class corpus takes tens of seconds, and a gate that makes the
// ordinary edit-test loop slow is a gate people stop running.
//
// These are wall-clock budgets, so they need a quiet machine: a first run of this gate reported
// LCX-4 at 286 ms against its 50 ms budget, and the real figure on an idle machine was 21 ms. The
// difference was concurrent benchmark processes, nothing in the index. Treat a failure here as a
// question about the host before treating it as a regression.
//
// Two things distinguish this from the benchmarks in lexical_bench_test.go. Benchmarks report a mean
// over a fixed query; PRD §8A.3 states its budgets as **p95 over retrieval**, so these measure a
// distribution and take the 95th percentile. And benchmarks report a number, where a gate has to
// decide — so each budget names the requirement it enforces and whether it is enforced today.
package index_test

import (
	"fmt"
	"maps"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
)

// repoClass is PRD §8A.3's repository classification. The file counts are the ceilings the PRD
// defines, and a gate that measured some other size would not be measuring the published budget.
type repoClass struct {
	name  string
	files int
}

var (
	classSmall    = repoClass{"Small", 10_000}
	classStandard = repoClass{"Standard", 100_000}
)

// budgetStatus records whether a budget is a commitment or an acknowledged gap.
//
// A gate with only the budgets it already meets is a gate that measures nothing, and a gate that
// fails on every run stops being read. So a known gap is reported loudly, does not fail the build,
// and *does* fail if it starts passing — because at that point it is a commitment nobody recorded,
// and the next regression would be silent.
type budgetStatus int

const (
	enforced budgetStatus = iota
	knownGap
)

// check reports a measured p95 against a budget.
func check(t *testing.T, requirement, what string, class repoClass, measured, budget time.Duration, status budgetStatus) {
	t.Helper()
	within := measured <= budget
	switch {
	case status == enforced && !within:
		t.Errorf("%s: %s on a %s repository took %v at p95, over the %v budget",
			requirement, what, class.name, measured.Round(time.Microsecond), budget)
	case status == knownGap && within:
		t.Errorf("%s: %s on a %s repository now meets the %v budget at %v — promote it to enforced,"+
			" or the next regression goes unnoticed",
			requirement, what, class.name, budget, measured.Round(time.Microsecond))
	case status == knownGap:
		t.Logf("%s: KNOWN GAP — %s on a %s repository took %v at p95, budget %v",
			requirement, what, class.name, measured.Round(time.Microsecond), budget)
	default:
		t.Logf("%s: ok — %s on a %s repository took %v at p95, budget %v",
			requirement, what, class.name, measured.Round(time.Microsecond), budget)
	}
}

func p95(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := slices.Clone(samples)
	slices.Sort(sorted)
	// Nearest-rank: the smallest value at or above the 95th percentile position.
	i := (len(sorted)*95 + 99) / 100
	return sorted[min(i, len(sorted))-1]
}

// shapeName labels the query shapes so a failure says which kind of query is slow.
func shapeName(i int) string {
	return [...]string{"full_identifier", "rare_token", "two_selective", "selective+common", "all_common"}[i%5]
}

// queryMix is the distribution p95 is taken over.
//
// LCX-1 requires a published query mix, and this is it — declared rather than derived, because the
// product has no retrieval telemetry yet. It is deliberately not weighted towards the shapes the
// index is good at: a mix of only selective identifiers would report microseconds and prove nothing.
//
// The weighting is the honest caveat. One entry in five is the worst case an index can be handed, so
// the 95th percentile lands inside that bucket and p95 here is effectively worst-case rather than
// typical. Real code search is far more selective than this. The mix is kept deliberately harsh
// because the alternative — tuning it until the number goes green — would be choosing the
// measurement to fit the result, and the per-shape breakdown gives the honest picture either way.
func queryMix(i int) string {
	switch i % 5 {
	case 0:
		return fmt.Sprintf("Handle%dItem3", i%400) // a full identifier: the common case
	case 1:
		return fmt.Sprintf("handle%d", i%400) // one rare token
	case 2:
		return fmt.Sprintf("Server%d validate%d", i%400, i%12) // two moderately selective terms
	case 3:
		return fmt.Sprintf("validate%d error", i%12) // selective plus corpus-wide
	default:
		return "Handler validate error context" // the worst case: everything is a candidate
	}
}

func buildCorpus(t *testing.T, class repoClass) (*index.MemoryIndex, index.Revision, time.Duration, uint64) {
	t.Helper()
	rev := index.Revision{Worktree: "/repo", Branch: "main"}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	start := time.Now()
	idx := index.NewMemoryIndex()
	for i := range class.files {
		body := synthDoc(i)
		entry := indexedEntry(fmt.Sprintf("pkg/svc%d/file%d.go", i%400, i), int64(len(body)))
		chunks, err := index.Chunk(entry, []byte(body))
		if err != nil {
			t.Fatalf("Chunk: %v", err)
		}
		if err := idx.Upsert(rev, chunks...); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}
	elapsed := time.Since(start)

	runtime.GC()
	runtime.ReadMemStats(&after)
	return idx, rev, elapsed, after.HeapAlloc - before.HeapAlloc
}

// TestPerformanceBudgetLocalContext enforces PRD §8A.3's local Context budgets.
//
// LCX-1 requires benchmarks to publish hardware, language mix, file distribution, warm/cold state,
// and storage, so the run logs them. The corpus is synthetic Go with code-shaped vocabulary; the
// index is warm and memory-resident; there is no storage tier to report until CTX-A01d2 lands.
func TestPerformanceBudgetLocalContext(t *testing.T) {
	t.Logf("LCX-1 conditions: goos=%s goarch=%s cpus=%d go=%s; corpus=synthetic Go, warm, in-process",
		runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())

	for _, tc := range []struct {
		class     repoClass
		retrieval budgetStatus
		indexing  budgetStatus
	}{
		// Small is the class the in-process index is expected to serve, so its budgets are
		// commitments. Standard is where the memory-resident design runs out — the same finding
		// ADR-0102 records — and is carried as an acknowledged gap rather than quietly untested.
		{classSmall, enforced, enforced},
		{classStandard, knownGap, knownGap},
	} {
		t.Run(tc.class.name, func(t *testing.T) {
			idx, rev, buildTime, heap := buildCorpus(t, tc.class)
			t.Logf("corpus: %d files, %.1f MB resident, built in %v",
				tc.class.files, float64(heap)/(1<<20), buildTime.Round(time.Millisecond))

			// LCX-2: initial local indexing within 90 seconds on reference hardware. Measured here
			// as in-process index construction only — it excludes the filesystem walk and file
			// reads, so it is a floor on the real figure, not the real figure.
			check(t, "LCX-2", "initial indexing", tc.class, buildTime, 90*time.Second, tc.indexing)

			// LCX-4: warm local candidate retrieval within 50 ms p95, before reranking.
			//
			// Measured per shape as well as in aggregate. A single p95 over the mix reports one red
			// number and gives nobody anything to do with it; per shape says which queries are the
			// problem, and here they are exactly the ones ADR-0102 predicted — the aggregate is
			// carried by the corpus-wide entry, while selective queries are orders of magnitude
			// inside the budget.
			const samples = 200
			retrieval := make([]time.Duration, 0, samples)
			byShape := map[string][]time.Duration{}
			for i := range samples {
				q := queryMix(i)
				start := time.Now()
				if _, err := idx.Search(rev, q, 20); err != nil {
					t.Fatalf("Search(%q): %v", q, err)
				}
				d := time.Since(start)
				retrieval = append(retrieval, d)
				byShape[shapeName(i)] = append(byShape[shapeName(i)], d)
			}
			for _, shape := range slices.Sorted(maps.Keys(byShape)) {
				got := p95(byShape[shape])
				verdict := "ok"
				if got > 50*time.Millisecond {
					verdict = "OVER"
				}
				t.Logf("LCX-4 by shape: %-22s p95 %-12v %s", shape, got.Round(time.Microsecond), verdict)
			}
			check(t, "LCX-4", "warm candidate retrieval", tc.class,
				p95(retrieval), 50*time.Millisecond, tc.retrieval)

			// LCX-3: an incremental edit becomes retrievable within 500 ms p95. Measured end to end
			// — re-index the file, then confirm a query actually returns it, because an Upsert that
			// returned quickly without the document becoming findable would satisfy a timer and not
			// the requirement.
			const edits = 50
			incremental := make([]time.Duration, 0, edits)
			for i := range edits {
				path := fmt.Sprintf("pkg/svc%d/file%d.go", i%400, i)
				body := synthDoc(i) + fmt.Sprintf("\nfunc EditedMarker%d() {}\n", i)
				entry := indexedEntry(path, int64(len(body)))
				chunks, err := index.Chunk(entry, []byte(body))
				if err != nil {
					t.Fatalf("Chunk: %v", err)
				}
				start := time.Now()
				if err := idx.Upsert(rev, chunks...); err != nil {
					t.Fatalf("Upsert: %v", err)
				}
				matches, err := idx.Search(rev, fmt.Sprintf("EditedMarker%d", i), 5)
				if err != nil {
					t.Fatalf("Search after edit: %v", err)
				}
				incremental = append(incremental, time.Since(start))
				if len(matches) == 0 {
					t.Fatalf("LCX-3: %s was re-indexed but its new content is not retrievable", path)
				}
			}
			check(t, "LCX-3", "incremental edit retrievable", tc.class,
				p95(incremental), 500*time.Millisecond, enforced)
		})
	}
}
