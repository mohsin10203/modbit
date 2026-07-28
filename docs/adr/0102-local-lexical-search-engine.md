# ADR-0102 — Local lexical search engine

- **Status:** Proposed
- **Date:** 2026-07-28 (revised same day — see *Revision history*)
- **Owner:** Knowledge
- **Supersedes:** none
- **Resolves:** ADR-0100 open decision 2 ("Production vector/search engine beyond initial adapters"),
  lexical half only
- **Depends on:** ADR-0103 (local metadata store and SQLite driver)

> **Status is Proposed, not Accepted.** The engine options commit the repository to a dependency it
> does not have — in one case to a non-Go toolchain. That is a decision for the owner. What this ADR
> contributes is the measurement that makes the choice decidable, including a measurement that
> **overturned this ADR's own first recommendation**.

## Context

`CTX-A01d` shipped `LexicalIndex` as a port with an in-process BM25 implementation. PRD §40.2 fixes
the local retrieval stack, and `CTX-A01d2` was left open on the grounds that the named engine is Rust
and therefore an ADR.

The question is not "which engine" but **"does the shipped implementation need replacing, and
where?"** — because the answer decides how much dependency is worth taking.

## Measurement

`BenchmarkLexicalIndexScale` and `BenchmarkLexicalQueryShape` build a synthetic corpus with
code-shaped vocabulary — shared tokens (`package`, `func`, `error`, `context`) mixed with per-file
identifiers, because that mix decides posting-list length in a real repository. Apple M2, Go 1.24.

Note that the corpus counter is **files**; `Chunk`'s 60-line window makes it two documents per file.

### Scale

| files | chunks | search (common terms) | heap | bytes/file |
|---|---|---|---|---|
| 1,000 | 2,000 | 1.5 ms | 9.2 MB | 9,663 |
| 10,000 | 20,000 | 19.4 ms | 90 MB | 9,454 |
| 50,000 | 100,000 | 228 ms | 417 MB | 8,746 |

**Memory is linear** at ~9 KB/file and does not improve with scale — the index holds every posting in
maps, and a map of maps has no compression to gain. Extrapolated to a 100,000-file repository:
**~880 MB**; PRD §9.6 (MRS) targets a 10M-file benchmark, which is far beyond it. The index is also
rebuilt from scratch on every start.

### Query shape — the measurement that changed the recommendation

Scale alone is measured with one query. That turned out to hide the real behaviour, so the query
itself became a variable. At 50,000 files / 100,000 chunks:

| query | in-process | FTS5 (cgo, pre-tokenized) |
|---|---|---|
| `Handler validate error context` — four corpus-wide terms | **182 ms** | 362 ms |
| `handle4217` — one rare token | **12.5 µs** | 115 µs |
| `Handle4217Item3` — the full identifier a user types | **75.5 ms** | 115 µs |

The in-process index is not generally slow. On a rare token it is **9× faster than FTS5**, because it
is RAM and FTS5 pays for disk and a SQL round trip. On four corpus-wide terms it is **2× faster**,
because when everything is a candidate there is nothing for an index structure to skip.

**It collapses on the third row, and that row is the realistic one.** `splitIdentifier` cuts on case
and underscore, so `Handle4217Item3` indexes and queries as `handle4217item3` + `handle4217` +
`item3`. Two of those are rare. `item3` is in every file. The scoring loop walks every posting of
every query term, so the query costs what its **worst** term costs — 75.5 ms — despite containing a
term that would answer it in 12.5 µs.

That is the finding: **cost tracks the query's most common term rather than its rarest.** FTS5 is not
winning on raw speed; it is winning because its cost tracks the best term.

### Tokenization is a compatibility constraint, not just a performance one

L6 requires identifiers to match their parts. FTS5's built-in tokenizers were measured against it:

| stored as | `item` | `handle` | `http` | `server` | `handleitemrequest` |
|---|---|---|---|---|---|
| raw text (`unicode61`) | MISS | MISS | MISS | MISS | hit |
| pre-tokenized stream | hit | hit | hit | hit | hit |

`unicode61` splits `snake_case` on the underscore but **does not split `camelCase`** — so storing raw
source satisfies half of L6 and silently fails the other half. `porter` and `ascii` behave the same;
`trigram` matches substrings and has no usable term ranking.

A custom FTS5 tokenizer is a C callback registered through `sqlite3_fts5_create_tokenizer`. It is
reachable only under cgo and is not exposed by the pure-Go driver at all.

**The fix does not need one.** Because indexing is ours, the existing `tokenize` — already tested for
L6, already emitting the whole identifier alongside its parts — can run before insert, and FTS5 then
stores a token stream that `unicode61` merely splits on spaces. Measured above: every part matches,
acronym runs included (`parseHTTPServerName` → `parse http server name`), and the whole identifier
survives as its own selective term. Nothing is lost, because `Match` carries path, span, and score —
snippets come from the file through `Cite`, never from the index.

## What actually needs fixing

The algorithm is not the problem — BM25 is right and the implementation agrees with it. The two
problems are separate, and **conflating them is what produced this ADR's first recommendation**:

1. **No early termination.** Query cost tracks the most common term. This is a defect in the query
   loop, not a reason to adopt an engine — see below.
2. **The index is memory-resident** and rebuilt on every start, bounded by RAM rather than disk.

## Options

| Option | Dependency cost | Notes |
|---|---|---|
| **MaxScore / WAND in the existing index** | none | Fixes problem 1 only. Standard, exact — same results, less work. Would take the realistic query toward the 12.5 µs row, i.e. **faster than FTS5**. |
| **SQLite FTS5** | shares ADR-0103's driver | Fixes problem 2, and problem 1 as a side effect. On-disk, transactional, incremental. Needs pre-tokenization for L6. |
| **Tantivy via cgo** | Rust toolchain in the build; cross-compilation becomes a project | Fastest option. Go bindings are third-party and thin; a crash in Rust is a crash in the process. |
| **Tantivy as a sidecar** | a process to supervise, an IPC contract to version | Keeps Rust out of the build and the crash out of the process. Costs a deployment component `EXE-A01` deliberately avoided. |
| **Bleve (pure Go)** | ~20 modules | No cgo, cross-compiles. Slower than Tantivy, less actively developed. |
| **Write a segmented index** | none | Weeks to reach parity on a solved problem, with failure modes an established engine has already found. |

## Recommendation

**Two decisions, not one — and they were previously collapsed into one.**

1. **Implement early termination in the in-process index now.** It needs no dependency, no ADR, and
   no owner decision. It is the difference between 75.5 ms and roughly 12.5 µs on the query a user
   actually types, and it makes the in-process index *faster than any engine here* on selective
   queries. It should happen whether or not an engine is ever adopted, and it should happen first —
   an engine adopted to fix a latency problem that early termination solves for free would be a
   dependency bought for nothing. Tracked as `CTX-A01d3`.

2. **Then SQLite FTS5 for the persistence problem**, contingent on ADR-0103 adopting SQLite. Memory
   is the constraint early termination cannot touch: ~880 MB at 100,000 files, rebuilt from scratch on
   every start. FTS5 is on-disk, transactional, and incremental, and if the driver is already present
   for local metadata then the marginal dependency is zero.

If ADR-0103 does not adopt SQLite, **Bleve** is the fallback. Tantivy-via-cgo is for when measured
latency is the binding constraint — and after decision 1, it will not be.

**What should not happen** is adopting an engine before early termination is measured. The first
version of this ADR recommended exactly that, on a single-query measurement that made the engine look
necessary for latency. It is not.

## Consequences

- `LexicalIndex` does not change. `CTX-A01d` put the contract in front of the engine, and L1–L8 are
  the acceptance tests any adapter must pass — including the FTS5 adapter, which needs
  pre-tokenization specifically to pass L6.
- The in-process implementation stays. It is the RET-10 reference an engine is measured against, it
  is what a small repository and every test uses, and after `CTX-A01d3` it is the faster option on
  selective queries.
- `BenchmarkLexicalQueryShape` is the gate, and it must stay a **shape** benchmark. A single query
  measured this decision wrong once already.

## Revision history

Revised the day it was written, before acceptance. The original recommended SQLite FTS5 on the
strength of a scale measurement taken with one query, and cited "PRD §6.1" for the local retrieval
stack. Two corrections:

- **The citation was wrong.** The local retrieval stack is **PRD §40.2** ("Resolved implementation
  defaults"); §6.1 is "Release A — Cursor-compatible IDE foundation". The distinction matters: §40 is
  *locked*, so SQLite for local metadata was never the open question this ADR treated it as. See
  ADR-0103.
- **The recommendation was wrong.** Measuring a second query shape showed the latency gap is caused by
  a missing early-termination loop, not by the index being in-process — and that the in-process index
  already beats FTS5 by 9× where early termination applies. The engine is still warranted, but for
  memory and persistence, not for speed.
