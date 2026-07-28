# ADR-0102 — Local lexical search engine

- **Status:** Proposed
- **Date:** 2026-07-28
- **Owner:** Knowledge
- **Supersedes:** none
- **Resolves:** ADR-0100 open decision 2 ("Production vector/search engine beyond initial adapters"),
  lexical half only

> **Status is Proposed, not Accepted.** Every option below except one commits the repository to a
> dependency it does not have — in two cases to a non-Go runtime. That is a decision for the owner,
> not for the change that surfaced it. What this ADR contributes is the measurement that makes the
> choice decidable.

## Context

`CTX-A01d` shipped `LexicalIndex` as a port with an in-process BM25 implementation. SDD §2 names
"Tantivy locally; OpenSearch-compatible adapter for server", and `CTX-A01d2` was left open on the
grounds that Tantivy is Rust and therefore an ADR.

The question this ADR has to answer first is not "which engine" but **"does the shipped
implementation actually need replacing, and at what size?"** — because the answer decides how much
dependency is worth taking on.

## Measurement

`BenchmarkLexicalIndexScale` builds a synthetic corpus with code-shaped vocabulary — shared tokens
(`package`, `func`, `error`, `context`) mixed with per-file identifiers, because that mix is what
decides posting-list length in a real repository. Measured on the development machine, Go 1.24:

| documents | search latency | heap | bytes/document |
|---|---|---|---|
| 1,000 | 1.5 ms | 9.2 MB | 9,663 |
| 10,000 | 19.4 ms | 90 MB | 9,454 |
| 50,000 | 228 ms | 417 MB | 8,746 |

**Memory is linear** at roughly 9 KB per document and does not improve with scale — the index holds
every posting in maps, and a map of maps has no compression to gain.

**Latency is superlinear.** Ten times the documents costs thirteen times the latency; five times
again costs twelve times. Scoring walks every posting for every query term, so the work grows with
corpus size and the constant grows with term frequency.

**Extrapolated to the target.** A 100,000-file repository chunked at the current 60-line window is on
the order of 500,000 documents: **~4.4 GB resident and multi-second queries**. PRD §9.6 (MRS)
targets a 10M-file benchmark, which is another twenty times that. The in-process index is not close,
and no constant-factor tuning closes a gap of that shape.

**So the honest reading of `CTX-A01d`'s floor:** it is correct, it has 100% recall, it is the right
reference for measuring an engine against (RET-10), and it is genuinely fine for a single service or
a small repository. It is not a monorepo index and was never going to become one.

## What actually needs fixing

The algorithm is not the problem — BM25 is the right ranking function and the implementation agrees
with it. Two structural properties are the problem:

1. **The index is memory-resident.** It is rebuilt from scratch on every start and its size is bounded
   by RAM rather than by disk.
2. **Query evaluation is exhaustive.** There is no skip structure, so a common term costs a full walk
   of its posting list.

Both are solved by an on-disk segmented inverted index with skip lists — which is what every option
below is, differing in who wrote it.

## Options

| Option | Dependency cost | Notes |
|---|---|---|
| **Tantivy via cgo** | Rust toolchain in the build, cgo everywhere, cross-compilation becomes a project | SDD §2's named choice. Fastest of the options. Go bindings are third-party and thin; a crash in Rust is a crash in the process. |
| **Tantivy as a sidecar** | A second process to supervise, an IPC contract to version | Keeps the Rust out of the Go build and the crash out of the process. Costs a deployment component on a desktop product, which `EXE-A01` deliberately avoided. |
| **Bleve (pure Go)** | ~20 transitive modules | No cgo, no second runtime, cross-compiles. Slower than Tantivy and less actively developed. Would be the repository's second through twenty-first direct dependencies. |
| **SQLite FTS5** | cgo, or `modernc.org/sqlite` (pure Go, large) | Mature, on-disk, transactional, and the local metadata store is already SQLite in PRD §6.1's "local retrieval stack" — so this may be a dependency the product takes anyway. |
| **Write a segmented index** | None | Weeks of work to reach parity on a solved problem, and the failure modes (corrupt segment, bad merge) are ones an established engine has already found. |

## Recommendation

**SQLite FTS5, contingent on SQLite already being adopted for local metadata.**

PRD §6.1 specifies "SQLite for metadata" in the local retrieval stack. If that lands — and nothing
in the repository has committed to it yet — then FTS5 is on-disk, transactional, incremental, and
free of a *marginal* dependency, because the driver is already present for a reason that has nothing
to do with search. That changes the calculus completely: it is the only option whose cost may
already be paid.

If SQLite is not adopted, **Bleve** is the fallback: pure Go and cross-compilable, at the cost of a
large dependency surface. Tantivy-via-cgo is the option to take only if measured search latency
becomes the binding constraint, because it is the only one that makes cross-compilation a project.

**What should not happen** is adopting an engine before the local metadata store is decided. The two
questions are coupled, and answering the smaller one first would likely force the larger one.

## Consequences either way

- `LexicalIndex` does not change. `CTX-A01d` deliberately put the contract in front of the engine,
  and L1–L7 are the acceptance tests any adapter must pass.
- The in-process implementation stays. It is the RET-10 reference an approximate or engine-backed
  index is measured against, and it is what a small repository or a test uses.
- `BenchmarkLexicalIndexScale` stays as the gate: an engine that does not beat these numbers has not
  earned its dependency.
