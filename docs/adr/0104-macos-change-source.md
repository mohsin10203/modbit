# ADR-0104 — macOS change source: FSEvents via cgo

- **Status:** Accepted
- **Date:** 2026-07-28 (accepted 2026-07-29)
- **Owner:** Knowledge
- **Supersedes:** none
- **Resolves:** `CTX-A01c3`; the watcher-dependency finding recorded under `CTX-A01c2`

> **What is committed.** FSEvents is the macOS backend, and `pkg/index/changesource` is where that
> takes effect: `Open` returns the native source on macOS and the portable source elsewhere, and
> reports which one it chose. `TestMacOSSelectsTheNativeBackendByDefault` is the default written as
> an assertion.
>
> **What is not.** No deployable assembles a `Watcher` yet — nothing in the repository outside tests
> calls `NewWatcher`. So `Open` is the selection point, not a running default; the first component
> that watches a tree calls it, and gets FSEvents on macOS without asking. That is the whole of the
> change. See *Selection*, below, for what it does and does not decide.

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

### Selection

`pkg/index` cannot import a backend that imports it, so the choice lives in `pkg/index/changesource`,
one level down from both. Four things it decides, and one it deliberately does not:

1. **The platform choice is not a build tag here.** The tags already live in the backend, which
   refuses with `MODBIT_CAPABILITY_UNAVAILABLE` off macOS. The selector asks and reads the answer, so
   there is one place that knows which platforms have a native source rather than two that can
   disagree — and `CTX-A01c4`/`c5` add two more backends to keep in step. The consequence worth
   having is that the selector's own logic compiles and runs identically on every target, so one set
   of tests covers it on both legs of CI.

2. **Only an unavailable capability falls back.** A backend that exists on this platform and did not
   start returns its error. This is the load-bearing half of the policy. Falling back on any error
   would trade a fault an operator can act on — an exhausted resource, a root that moved — for a
   silent freshness floor bounded by a full walk, which `QA-A01c` measured at 2 m 45 s for a
   Standard-class repository against CTX-2's 10 seconds. On the one platform where a native source
   was chosen precisely to avoid that, the machine would look healthy and the index would be minutes
   behind.

3. **A poll is reported as degraded.** `Selection` is returned, not logged. From outside, "the index
   is stale" and "the index is polled" are the same observation, and CTX-2 is the promise that they
   can be told apart. `Reason` distinguishes a configured poll from an unavailable backend, so the
   diagnostic knob is visible in the report rather than only in its effect.

4. **The root is validated once, above both backends.** FSEvents stats and resolves its root;
   `PollSource` stats nothing and simply ticks. Left to the backends, a missing directory would be an
   error on macOS and a healthy-looking source everywhere else — a defect that reproduces on one
   developer's machine and not another's. The shared gate refuses in the same words on every
   platform.

What it does not decide is when a `Watcher` exists. Nothing outside tests constructs one yet; the
selector is the point at which the first one will get FSEvents without asking for it.

The mutation pass on the policy is worth one line, because it names the platform-parity gap this
section exists to close. Seven mutants, all caught — but the one that lets a regular file through
the root check is caught **only** on the non-macOS leg, because on macOS `fsevents.New` refuses it
independently. That is the shared gate doing exactly the job it was added for, and it is only
visible because CI runs both legs.

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
| FSEvents | skipped *in the suite* — covered directly instead, below | **pass** |

FSEvents maps `kFSEventStreamEventFlagMustScanSubDirs`, `UserDropped` and `KernelDropped` onto
`RescanQueueOverflow`, and `RootChanged` onto `RescanSourceRestart`.

This ADR first recorded those as the least-proven part of the backend, on the grounds that a kernel
queue overflow cannot be provoked on demand. That was half right. The *kernel's* `MustScanSubDirs`
still cannot be forced — but the source's own bounded queue can, and both arrive at the same place:
a `RescanQueueOverflow` batch carrying no changes. A burst of 6,000 writes against a queue depth of
4,096, with the consumer deliberately not reading, provokes it reliably — verified over ten
consecutive runs under the race detector.

That is not an artificial consumer, either. A reindexer busy walking a tree is exactly what stops
reading, and exactly when a burst is most likely.

So the overflow *contract* — loss is reported, never dropped — is now proven for this source, and
only the kernel's own flag path remains unexercised. `RootChanged` is still unprovoked.

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
  it is what a `CGO_ENABLED=0` build gets. Both selection paths now run under test on every commit —
  CI's `check` and `suites` jobs each run on macOS and Linux, so the native branch and the fallback
  branch each have a leg. The `CGO_ENABLED=0` leg was verified locally; CI covers the same code path
  through Linux.
- **`CTX-A01c4` and `c5` are now smaller than they look.** Each is a package implementing
  `ChangeSource`, a line in `nativeSource`, and a build-tag flip in the two selection tests. The
  fallback policy, the shared root gate, and the degraded reporting are already written and already
  tested against a substituted backend.
- **This is the repository's first shipped cgo code**, ahead of ADR-0103's driver decision. It is
  the cheaper precedent — a system framework rather than a third-party module — and it makes the
  per-target build matrix ADR-0103 needs a thing the project requires anyway rather than a cost that
  decision introduces alone.
- `make cross-check` is now a standing gate.

## Not measured

- **The kernel's own `MustScanSubDirs`, and `RootChanged`.** The source's queue overflow is now
  covered by a test; these two remain reachable only by outrunning the kernel or by moving the
  watched root out from under a live stream. Both are implemented and neither is exercised.
- **A large real repository.** Latency was measured on a small synthetic tree. FSEvents costs no
  per-file descriptor, so there is no reason to expect it to degrade with file count, but that is
  an argument rather than a measurement.
- **The native failure branch on a real failure.** That a backend error surfaces instead of
  degrading is proven against a substituted constructor, not against FSEvents actually failing to
  start. A `FSEventStreamCreate` that returns null cannot be provoked on demand, which is the same
  limit the kernel's `MustScanSubDirs` runs into. The policy is tested; the specific error reaching
  it is inferred.
