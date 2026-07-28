# ADR-0104 — macOS change source: FSEvents via cgo

- **Status:** Proposed
- **Date:** 2026-07-28
- **Owner:** Knowledge
- **Supersedes:** none
- **Resolves:** `CTX-A01c3`; the watcher-dependency finding recorded under `CTX-A01c2`

> **What is committed and what is not.** The source is implemented, behind `darwin && cgo` build
> tags, with a clean fallback and no new module in `go.mod`. Nothing selects it: the watcher still
> gets `PollSource` unless a caller asks for FSEvents. **Making it the default on macOS is the
> decision this ADR asks for** — the code exists so the decision can be made against measurements
> rather than against a proposal.

## Context

`CTX-A01c2` shipped `ChangeSource` as a port with `PollSource`, which is honest about being a floor:
every batch is a full `Rescan`, so the consumer walks the tree on a fixed interval. CTX-2 requires
changes to become searchable within the freshness SLO, and `QA-A01c` measured what a walk costs at
scale — 2 m 45 s to index a Standard-class repository. Polling is not a watcher.

## Why not a portable watcher library

The obvious move is a Go watcher library, and the earlier finding against it is now measured rather
than asserted:

```
kern.maxfilesperproc = 10240
```

Portable Go watchers use **kqueue** on macOS, which needs an open file descriptor per watched
*file*. That design tops out around ten thousand files — and PRD §8A.3 puts the Small/Standard
repository boundary at exactly 10,000. A watcher that fails at the size where the product's own
scale targets begin is not a watcher, and the failure is silent: descriptors run out, watches are
dropped, and the index goes quietly stale.

This is why the port exists. kqueue's limitation is macOS-specific, and `fsnotify` remains
adoptable for Linux (`CTX-A01c4`) and Windows (`CTX-A01c5`), where the underlying APIs are inotify
and ReadDirectoryChangesW.

## Measurement

Measured on macOS 26.5, Apple M2, against a nested temporary tree.

| property | FSEvents | `PollSource` |
|---|---|---|
| Watches for a whole tree, any depth | **1** | n/a |
| File descriptors per watched file | **0** | 0 |
| Notification latency, median | **49 ms** | 2 s tick, then a full walk |
| Notification latency, max over 10 edits | 58 ms | — |
| Delivery | per-file deltas | every batch a full `Rescan` |
| 500 rapid writes | 501 callbacks | 1 rescan, 1 full walk |

Against CTX-2's 10-second budget the median leaves roughly 200× margin, and the cost is a delta
rather than a walk. The stream latency parameter dominates the measurement — 49 ms observed at a
50 ms setting — so the knob is real and the kernel is not the bottleneck.

## Decision

**FSEvents, through cgo, in its own package, selected at build time with a fallback.**

1. **`pkg/index/fsevents`, not `pkg/index`.** `pkg/index` has a boundary test that fails the build on
   `net`, `os/exec`, and `database/sql`, and it is the package the whole Context Engine sits on. It
   stays cgo-free. This is the same conclusion ADR-0103 reached for the SQLite adapter, and the
   boundary named the constraint before the code was written in both cases.
2. **Build-tagged with a refusing fallback.** `!darwin || !cgo` gets a `New` that returns
   `MODBIT_CAPABILITY_UNAVAILABLE`. It refuses rather than returning a source that reports nothing,
   because "no watcher" and "no changes" must not be the same observation — that distinction is the
   whole of CTX-2.
3. **Held to the shared suite.** It passes D1–D9 and is the first source to exercise **D7**: the
   delta path was Skipped everywhere while `PollSource` was the only implementation.

### Dependency cost

**No new module.** CoreServices is a system framework; `go.mod` is unchanged at one dependency. The
cost is cgo on macOS builds, and `make cross-check` verifies that `CGO_ENABLED=0` still builds every
target — darwin/arm64, darwin/amd64, linux/amd64, linux/arm64, windows/amd64.

That check earned itself immediately: the fallback referenced `modberr.CodeUnimplemented`, a code
that does not exist. It compiles only when cgo is off, so nothing local would have caught it.

## What the two sources prove between them

Neither alone covers the contract, and saying so is more useful than a green tick:

| | D5, D6 (rescan) | D7 (delta) |
|---|---|---|
| `PollSource` | **pass** | skipped — it only rescans |
| FSEvents | skipped — no kernel overflow to provoke on demand | **pass** |

FSEvents maps `kFSEventStreamEventFlagMustScanSubDirs`, `UserDropped` and `KernelDropped` onto
`RescanQueueOverflow`, and `RootChanged` onto `RescanSourceRestart`. Those paths are implemented and
unit-reachable but not provoked by the suite, because forcing a kernel queue overflow on demand is
not something a test can do reliably. **They are the least-proven part of this backend.**

## Two things the platform got wrong for free

Both were caught by writing the tests rather than by reading the documentation, and both are
recorded because the next backend author will meet them.

- **FSEvents reports resolved paths.** A stream over `/var/folders/x` delivers
  `/private/var/folders/x`. `Change.Path` is repository relative, so a root that is not resolved
  strips nothing and the source silently reports no changes at all. This is the same trap the
  sandbox profile hit in `EXE-A01b` (B-14), on the same platform, for the same reason: macOS
  resolves symlinks before it matches.
- **Per-path flags are coalesced, so the filesystem is the authority.** A file created and then
  deleted inside one batching window arrives with both bits set, and a rename sets neither
  reliably on both ends. The source therefore `Lstat`s the path and lets the flags hint. Trusting
  the flags is how a deleted file stays in the index looking like a live result.

## Consequences

- `ChangeSource` does not change. `CTX-A01c2` put the contract in front of the platform, and D1–D9
  are what any backend answers.
- `PollSource` stays. It is the fallback for every non-macOS build until `CTX-A01c4`/`c5` land, and
  it is what a `CGO_ENABLED=0` build gets.
- **This is the repository's first shipped cgo code**, ahead of ADR-0103's driver decision. It is
  the cheaper precedent — a system framework rather than a third-party module — and it makes the
  per-target build matrix ADR-0103 needs a thing the project requires anyway rather than a cost that
  decision introduces alone.
- `make cross-check` is now a standing gate.

## Not measured

- **Behaviour under kernel queue overflow.** The mapping is implemented; provoking it is not
  something the suite can do on demand. A soak test that generates changes faster than the stream
  drains would settle it, and is the obvious follow-up.
- **A large real repository.** Latency was measured on a small synthetic tree. FSEvents costs no
  per-file descriptor, so there is no reason to expect it to degrade with file count, but that is
  an argument rather than a measurement.
- **The default.** Nothing wires FSEvents into the watcher yet; that is the decision above.
