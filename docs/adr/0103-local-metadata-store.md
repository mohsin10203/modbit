# ADR-0103 — Local metadata store and SQLite driver

- **Status:** Proposed
- **Date:** 2026-07-28
- **Owner:** Platform
- **Supersedes:** none
- **Resolves:** the store half of ADR-0102's contingency; unblocks `CTX-A01d2` and `CTX-A01f2`

> **Two questions look like one here.** *Which store* is already answered by the locked pack and this
> ADR only records it. *Which driver* is genuinely open, is a repository decision under R-GO-09, and
> is where the measurement below applies.

## Context: the store is not an open question

ADR-0102 treated "is SQLite adopted for local metadata?" as undecided. That was a misreading of the
document pack, and correcting it is half of this ADR's purpose.

**PRD §40.2, "Resolved implementation defaults":**

> **Local retrieval stack:** SQLite for metadata, Tantivy-compatible lexical search, and an embedded
> vector adapter selected from supported implementations; the API remains portable.

The section's preamble governs the whole list:

> The following implementation defaults are **locked unless an ADR proves a compatibility-preserving
> correction is required**.

So SQLite for local metadata is locked. ADR-0102 cited "PRD §6.1" — that section is "Release A —
Cursor-compatible IDE foundation" and says nothing about storage.

### The apparent contradiction elsewhere in the pack

Two other places read as if the store were open:

| Location | Text |
|---|---|
| §24.1 Local all-in-one mode | "Embedded or local PostgreSQL-compatible store" |
| Appendix A — Local distribution | "SQLite **or** embedded PostgreSQL-compatible option for local metadata" |

Appendix A opens by disclaiming itself: *"These are architectural recommendations, not mandatory
product requirements."* §24.1 is a packaging inventory, not a defaults list. §40 is the section whose
stated job is resolving implementation defaults, and it is the only one of the three that claims to be
locked. **§40.2 governs**; the other two are permissive restatements, consistent with ADR-0100's
treatment of non-normative material.

Worth recording because the next reader will hit the same three passages: the pack is not
inconsistent, but it is only unambiguous if you notice which section is normative.

### What "Tantivy-compatible" constrains

§40.2 names SQLite as a product but writes "Tantivy-**compatible**" for lexical search — the same
construction as "OpenSearch-compatible" (§40.3) and "PostgreSQL-compatible" (§24.1, Appendix A).
Where the pack wanted a specific product it named one. Where it wrote *-compatible* it named a
compatibility class, and the trailing clause "the API remains portable" states the intent directly.

`LexicalIndex.Search(revision, query string, k int)` takes an opaque query string, and no requirement
in the pack asks for fuzzy matching, wildcards, or a Lucene query grammar — RET-1 asks only that
lexical retrieval be one channel of hybrid retrieval. So the constraint is BM25-ranked tokenized
retrieval behind a portable port, which `CTX-A01d` already satisfies and FTS5 also satisfies.

## Decision 1 — the store

**SQLite, per PRD §40.2.** Recorded rather than decided. No correction is proposed: nothing measured
so far gives a compatibility-preserving reason to deviate, which is the only bar §40 accepts.

## Decision 2 — the driver, which the pack does not name

Both candidates were measured, not compared from documentation. Corpus and method as ADR-0102;
50,000 files / 100,000 chunks; Apple M2, Go 1.24; SQLite 3.53.3 in both.

| | `modernc.org/sqlite` (pure Go) | `mattn/go-sqlite3` (cgo) |
|---|---|---|
| Non-stdlib packages compiled in | **37** (25 are `modernc.org/libc`) | **1** |
| Modules added to the build | 5 | 1 |
| Pulls `net` | **yes** | no |
| Pulls `os/exec` | **yes** | no |
| Cross-compilation | works everywhere | C toolchain per target |
| FTS5 | built in | needs `-tags sqlite_fts5` |
| Custom FTS5 tokenizer | not exposed | available (C callback) |
| Index build, 50k files | 31.8 s | 10.9–13.1 s |
| Query, four common terms | 1,318 ms | 326–362 ms |
| Query, selective token | — | 115 µs |

Two results are worth stating plainly because both cut against the intuitive reading.

**The pure-Go driver is 3–4× slower.** `modernc.org/sqlite` is SQLite's C transpiled to Go over an
emulated libc, and the emulation is not free. This is not a rounding difference.

**The pure-Go driver expands the trusted surface; the cgo one does not.** `modernc.org/libc` emulates
a C standard library including sockets and process control, so it drags in `net` and `os/exec`
whether or not SQLite ever calls them. The cgo driver adds one Go package and neither import.

That matters more here than in most projects:

- `pkg/index/boundary_test.go` already fails the build on `net`, `os/exec`, and `database/sql`,
  the last two annotated *"subprocess execution, which is also how CTX-12 gets violated"*.
- **LCL-4** requires Local Private and Offline modes to pass *automated zero-egress qualification*.
  An import of `net` is not an egress, and libc's sockets are unreachable from SQLite's query path —
  but the repository's boundary discipline is import-based precisely because "we never call it" is a
  convention while the import graph is a fact. A zero-egress audit of a binary containing a
  networking-capable emulated libc is a conversation this project should not have to have.

**Recommendation: `mattn/go-sqlite3` (cgo), with pure-Go retained as a build-tagged fallback.**

The cost is real and should not be understated: cgo makes cross-compilation a per-target build
problem for a product that ships on macOS, Linux, and Windows, and it is the reason to reconsider.
But it is a *build-infrastructure* cost — solvable with per-target runners, which `EXE-A01c` will need
anyway — whereas the pure-Go alternative is a *runtime and audit-surface* cost in the exact dimension
LCL-4 is measured on. Build infrastructure is the cheaper thing to pay.

If cross-compilation proves worse than expected, the fallback is real: both drivers implement
`database/sql`, so the switch is a build tag and an import, and no calling code changes.

## Consequences

- **The SQLite-backed `LexicalIndex` cannot live in `pkg/index`.** Its own boundary test forbids
  `database/sql`. The port stays where it is; the adapter goes in a sibling package (`pkg/index/sqlite`)
  and `pkg/index` keeps its no-I/O guarantee. This is the port pattern working as intended — the
  boundary held and named the constraint before any code was written against it.
- **FTS5 needs pre-tokenization to satisfy L6**, per ADR-0102's measurement. Under the cgo driver a
  custom tokenizer is *also* available, but pre-tokenization should be preferred anyway: it reuses the
  `tokenize` already tested against L6, and it keeps the fallback driver viable.
- **`CTX-A01d2` and `CTX-A01f2` unblock** once this is Accepted — but `CTX-A01d3` (early termination)
  should land first, for the reason ADR-0102 gives.
- **This is the repository's first cgo dependency**, and its second dependency overall. `make check`
  gains a requirement for a C toolchain, and CI needs a per-target build matrix.
- Nothing here commits the *server* store. PRD §40.3 names PostgreSQL/pgvector, and that is a
  separate decision.

## What was measured, and what was not

Measured: FTS5 presence and `bm25()` availability in both drivers, tokenizer behaviour against L6,
index build time, query latency by query shape, on-disk size, resident heap, package and module
counts, and the `net`/`os/exec` import edges.

**Not measured: cross-compilation.** The central cost of the recommended option is the one thing this
ADR asserts rather than demonstrates — no Windows or Linux target was built, for the same reason
`EXE-A01c` is still open. That is the weakest claim here and the first thing to verify before this ADR
is accepted.
