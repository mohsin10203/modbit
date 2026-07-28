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

### Query shape — the measurement that changed the recommendation twice

Scale alone is measured with one query. That hid the real behaviour, so the query became a variable.
At 50,000 files / 100,000 chunks, after `CTX-A01d3` added early termination and top-k selection:

| query | in-process | FTS5 (cgo, pre-tokenized) |
|---|---|---|
| `Handler validate error context` — four corpus-wide terms | **119 ms** | 323 ms |
| `handle4217` — one rare token, 2 hits | **13.9 µs** | 83 µs |
| `Handle4217Item3` — the full identifier a user types | **40.9 ms** | 110 ms |

**The in-process index is faster on every shape** — 2.7×, 6×, and 2.7×. It is RAM; FTS5 pays for disk
and a SQL round trip on every one of them.

The third row is the interesting one. `splitIdentifier` cuts on case and underscore, so
`Handle4217Item3` becomes `handle4217item3` + `handle4217` + `item3`. The first two are rare; `item3`
is in every file. Before `CTX-A01d3` this cost 75.5 ms — the price of the *worst* term. Early
termination halves it, but cannot remove it, and the reason is worth stating precisely:

> MaxScore can only stop scanning once **k** candidates exist. Two documents contain the rare terms,
> and the query asks for twenty. The remaining eighteen can only come from `item3`, so its posting
> list has to be walked. **This is inherent to returning k results**, not a defect — no index
> structure avoids it, and FTS5 does not either.

That last point is where this ADR's second version went wrong; see *Revision history*.

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

The algorithm is not the problem — BM25 is right and the implementation agrees with it. **Latency is
not the problem either**, which took two revisions to establish. One thing remains:

**The index is memory-resident and rebuilt on every start.** Early termination cannot touch this, and
it is the entire remaining case for an engine.

`QA-A01c`'s gate has since measured a Standard-class repository directly rather than by
extrapolation, and it is worse than the projection on the axis that matters least and confirms it on
the axis that matters most:

| PRD §8A.3 budget | Standard (100k files) | verdict |
|---|---|---|
| Resident memory | **994 MB** | confirms the ~880 MB projection |
| LCX-2 initial indexing, 90 s | 2 m 45 s | over |
| LCX-4 warm retrieval p95, 50 ms | 383 ms | over |
| LCX-3 incremental edit p95, 500 ms | 7.4 ms | within |

The per-shape breakdown confirms this ADR's diagnosis exactly: at 100k files a rare token still
answers in **797 µs** while four corpus-wide terms take 484 ms. Selectivity decides retrieval cost,
not corpus size — which is why LCX-4's aggregate is carried entirely by the worst query shape.

## Options

| Option | Dependency cost | Notes |
|---|---|---|
| **MaxScore / WAND in the existing index** | none | **Done — `CTX-A01d3`.** Exact: L9 requires the ranking to equal an exhaustive scan's, mutation-verified. 1.5–1.9× across shapes. |
| **SQLite FTS5** | shares ADR-0103's driver | Fixes memory and persistence. On-disk, transactional, incremental. Needs pre-tokenization for L6, and **costs ~2.7× latency**. |
| **Tantivy via cgo** | Rust toolchain in the build; cross-compilation becomes a project | Fastest option. Go bindings are third-party and thin; a crash in Rust is a crash in the process. |
| **Tantivy as a sidecar** | a process to supervise, an IPC contract to version | Keeps Rust out of the build and the crash out of the process. Costs a deployment component `EXE-A01` deliberately avoided. |
| **Bleve (pure Go)** | ~20 modules | No cgo, cross-compiles. Slower than Tantivy, less actively developed. |
| **Write a segmented index** | none | Weeks to reach parity on a solved problem, with failure modes an established engine has already found. |

## Recommendation

**Adopt FTS5 for memory and persistence, knowingly paying latency for it — or do not adopt it yet.**

`CTX-A01d3` is done, and it removed latency from the argument entirely. The in-process index is now
faster than FTS5 on every measured shape, so an engine is no longer something to reach for; it is a
trade with a stated price:

| | in-process | SQLite FTS5 |
|---|---|---|
| Resident memory, 100k files | ~880 MB | ~0 |
| Survives a restart | no — full rebuild | yes |
| Incremental update | full re-index of a path | transactional |
| Query latency | **1×** | ~2.7× slower |
| Dependencies | none | ADR-0103's driver |

**The recommendation is FTS5, and the reason is memory, not speed.** ~880 MB of resident heap for a
100,000-file repository is not acceptable in a desktop IDE that also hosts an editor, extensions, and
a language server — and PRD §9.6 targets far larger. Paying 2.7× on a 40 ms query to get that back,
and to stop rebuilding the whole index at every launch, is the right trade. But it is a trade, and
the previous two versions of this ADR both presented it as a straight win.

**Contingent on ADR-0103**, which is where the driver — and the cgo question — actually lives. If
ADR-0103 does not adopt SQLite, **Bleve** is the fallback. Tantivy is now hard to justify at all: its
advantage was speed, and speed is no longer the binding constraint.

**A defensible alternative is to do nothing more.** For repositories below roughly 20,000 files the
in-process index costs under 200 MB and answers in tens of milliseconds, which is fine. If Release A
ships to individual developers on ordinary repositories, deferring the engine — and its first cgo
dependency — until scale is a real complaint is a reasonable call. That decision belongs to the owner;
this ADR's job was to make sure it is made on measurements rather than on the assumption that the
first implementation must be too slow.

## Consequences

- `LexicalIndex` does not change. `CTX-A01d` put the contract in front of the engine, and L1–L9 are
  the acceptance tests any adapter must pass — including the FTS5 adapter, which needs
  pre-tokenization specifically to pass L6.
- The in-process implementation stays regardless. It is the RET-10 reference an engine is measured
  against, it is what a small repository and every test uses, and it is the faster option.
- `BenchmarkLexicalQueryShape` is the gate, and it must stay a **shape** benchmark, with both engines
  answering the **same** query. Getting that wrong is what produced the second revision below.

## Revision history

Twice-revised the day it was written, before acceptance. Recording both, because the errors are
instructive and the numbers in the original are still quoted elsewhere.

**First revision — citation and diagnosis.**

- **The citation was wrong.** The local retrieval stack is **PRD §40.2** ("Resolved implementation
  defaults"); §6.1 is "Release A — Cursor-compatible IDE foundation". §40 is *locked*, so SQLite for
  local metadata was never the open question this ADR treated it as. See ADR-0103.
- **The diagnosis was wrong.** Scale had been measured with a single query. A second query shape
  showed the latency gap came from a missing early-termination loop, not from the index being
  in-process.

**Second revision — the comparison was not comparing the same query.** The first revision reported
FTS5 answering the realistic identifier query in 115 µs against the in-process index's 75.5 ms, and
projected that early termination would close it to ~12.5 µs. Both figures were wrong:

- **FTS5 was answering a different question.** It stored raw text, where `Handle4217Item3` is a single
  token matching 2 documents. The in-process index tokenizes it into three terms, one of which is
  corpus-wide, and must fill k=20. Given the *same* three-term query and the same k, FTS5 takes
  **110 ms** — not 115 µs. A comparison across two different tokenizations is not a comparison.
- **The projection was wrong.** MaxScore cannot begin skipping until k candidates exist, and only two
  documents carry the rare terms. Measured result: 75.5 ms → **40.9 ms**, a 1.85× gain, not 6000×.

Corrected, the in-process index is faster than FTS5 on every shape, and the case for an engine rests
on memory alone. The lesson worth keeping: **an engine comparison must hold the query fixed**, and a
projected speedup is not a measured one.
