# ADR-0106 — Linux change source: inotify via the standard library

- **Status:** Accepted
- **Date:** 2026-07-29
- **Owner:** Knowledge
- **Supersedes:** none
- **Resolves:** `CTX-A01c4`
- **Follows:** ADR-0104 (macOS change source), whose selection policy this backend plugs into unchanged

> **What is committed.** inotify is the Linux backend, selected by `pkg/index/changesource.Open`
> without being asked, and held to the same D1–D9 suite as every other source. `go.mod` is unchanged
> at one dependency. What is *not* committed is a `Watcher` in any deployable — nothing outside tests
> constructs one yet, on any platform. This changes which source the first one will get on Linux.

## Context

ADR-0104 recorded that `fsnotify` "remains adoptable for Linux (`CTX-A01c4`) and Windows
(`CTX-A01c5`), where the underlying APIs are inotify and ReadDirectoryChangesW". That was true and it
is no longer the cheapest option, because the reason to reach for a module disappeared once the port
existed.

## Why the standard library rather than a watcher module

`syscall` carries the entire inotify interface on Linux — `InotifyInit1`, `InotifyAddWatch`,
`InotifyRmWatch`, `InotifyEvent`, and every flag this backend maps. There is nothing a third-party
module adds except its own portability layer, and the portability layer is precisely what
`ChangeSource` replaced. Adopting one would mean carrying a second abstraction over the same
syscalls, plus a dependency whose macOS backend this repository already rejected on measurement
(ADR-0104's kqueue ceiling).

**No new module.** `go.mod` still holds one direct dependency, `gopkg.in/yaml.v3`, after seven
capabilities and two native backends.

Unlike ADR-0104's decision, this one costs no cgo either: the Linux backend is pure Go, so
`CGO_ENABLED=0` builds get a real watcher where macOS gets the portable fallback.

## Measurement

Measured on linux/amd64 (kernel 6.12, container), against a nested tree.

| property | inotify | FSEvents (ADR-0104) | `PollSource` |
|---|---|---|---|
| Watches for a whole tree | **one per directory** | 1 | n/a |
| File descriptors per watched file | 0 | 0 | 0 |
| Notification latency, median | **42 µs** | 49 ms | 2 s tick, then a full walk |
| Notification latency, max over 10 edits | 4.6 ms | 58 ms | — |
| Delivery | per-file deltas | per-file deltas | every batch a full `Rescan` |

The three-orders-of-magnitude gap against FSEvents is not a defect in either: FSEvents was configured
with a deliberate 50 ms coalescing window, and inotify has no equivalent — the kernel delivers per
event and coalescing is the `Watcher`'s flush policy rather than the source's. Against CTX-2's
10-second budget both have margin that makes the difference irrelevant; what matters is that neither
is a walk.

## Decision

**inotify, through `syscall`, in its own package, selected by the existing policy.**

1. **`pkg/index/inotify`, not `pkg/index`.** Symmetry with `pkg/index/fsevents`, and the same reason:
   `pkg/index` has a boundary test that fails the build on `net`, `os/exec`, and `database/sql`, and
   it is the package the whole Context Engine sits on.
2. **Build-tagged with a refusing fallback.** `!linux` gets a `New` that returns
   `MODBIT_CAPABILITY_UNAVAILABLE`, so "no watcher" and "no changes" stay distinguishable.
3. **Selected through `changesource`, which did not change.** It gained one entry in a candidate
   table. ADR-0104 predicted `c4` would reduce to "a package, a line in `nativeSource`, and a
   build-tag flip in two tests"; that held, with the single addition of a `linux` selection test.
4. **Held to the shared suite.** D1–D9 pass, including **D7** — the second source to exercise the
   delta path, and the first to do so on a platform CI can run.

### What inotify costs that FSEvents does not

**It is not recursive.** One watch covers one directory, so the tree is walked at startup and every
directory created afterwards adds its own watch. Two consequences had to be decided rather than
inherited:

- **Watch descriptors are a budget**, though a larger one than this ADR first claimed. It originally
  said `fs.inotify.max_user_watches` is "commonly 8192 on desktop distributions". That was written
  from memory and is **wrong**: the kernel derives the default from available memory rather than
  using a fixed constant. Measured on stock Ubuntu 24.04.4 (kernel 6.17, 8 GB): **62593**. A tree
  with more directories than the remaining budget still cannot be watched, but the budget scales with
  the machine and the fallback is correspondingly rarer than stated here at acceptance.
- **A new directory is populated before its watch can exist.** Anything written between `mkdir` and
  `inotify_add_watch` produces no event. The window is small and a `git checkout` lands inside it
  routinely.

**ENOSPC is handled twice, differently, and the difference is the point.**

| when | response | why |
|---|---|---|
| at construction | `MODBIT_CAPABILITY_UNAVAILABLE` | A caller can still fall back. `changesource` degrades to polling and reports it — worse, but complete and *stated*. |
| adding a watch mid-run | `RescanQueueOverflow` | There is nobody left to fall back to. The source cannot describe what it missed, so it says exactly that. |

Reusing ADR-0104's fallback policy for the first case is what makes it work: only
`MODBIT_CAPABILITY_UNAVAILABLE` degrades, so a watch-budget failure becomes an honest poll while any
other construction failure still surfaces as a fault.

**The adoption race is closed by walking, not by hoping.** A newly created directory is watched *and*
enumerated, and the files found inside it are reported as changes. Past `newDirectoryFileCap` (1024)
the source asks for a rescan instead: beyond that size a walk is the cheaper answer anyway, and
claiming a partial list would be worse than admitting the source cannot enumerate it.

## What the mutation pass proved, and what it did not

Seven mutants. Six caught:

| # | mutant | caught by |
|---|---|---|
| I1 | only the root is watched, not the tree | the nested-write and adoption tests |
| I2 | an adopted directory is watched but never enumerated | the adoption test |
| I3 | an adopted directory is enumerated but never watched | the adoption test's second write |
| I4 | the mask is trusted instead of the filesystem | the deletion test |
| I5 | `Close` leaves the descriptor open | D2 and D8, from the closer's and the parked reader's side |
| I7 | a kernel queue overflow is ignored | the burst test |

**I6 survived: the guard that refuses a path outside the watched root.** inotify names events
relative to a watch this source installed, and every watch is inside the root, so no reachable input
produces an escaping path. It is structural defence in depth and is recorded as such rather than
counted as covered — the same treatment L8 and V9 got in `CTX-A01d`/`f`.

The overflow case is worth one line because ADR-0104 could not prove its equivalent. FSEvents'
kernel `MustScanSubDirs` still cannot be forced. inotify's **can**: the reader parks in `send` as soon
as nothing consumes, stops draining the descriptor, and the kernel fills
`fs.inotify.max_queued_events` (16384) and sets `IN_Q_OVERFLOW`. So on Linux the property that
matters — loss is reported as a rescan, never dropped — is proven against the kernel's own signal
rather than against a bounded queue standing in for it.

## Consequences

- `ChangeSource` does not change. Two native backends and the portable source now answer the same
  D1–D9.
- **CI's Linux leg now runs a native backend**, where before it only ever certified the rescan-only
  `PollSource`. D7 was Skipped on that leg until this landed.
- `CTX-A01c5` (ReadDirectoryChangesW) is the last one, and it is now one candidate-table entry plus
  its package.
- `PollSource` remains the fallback for Windows, for a `CGO_ENABLED=0` macOS build, and for a Linux
  tree that exceeds the watch budget.

## Not measured

- **A large real repository.** Latency was measured on a small nested tree. The watch budget is the
  scaling question, and the honest statement is arithmetic rather than measurement: one watch per
  directory means a repository with more directories than `max_user_watches` cannot be watched, and
  the backend degrades to polling instead of failing.
- **`.git` watch pressure.** The source watches every directory beneath the root, including `.git`,
  which the walker prunes and the index never holds. That spends watches on changes guaranteed to be
  discarded. It is left alone deliberately — the port's contract is "deliver what you saw", and a
  backend that silently omits a subtree is the confusion `ChangeSource` exists to prevent — but it is
  the first thing to measure if the budget ever binds.
- **Watch-budget exhaustion end to end.** The ENOSPC construction path returns a code the selector
  turns into a poll; that policy is tested against a substituted constructor, not against a kernel
  that actually ran out.
