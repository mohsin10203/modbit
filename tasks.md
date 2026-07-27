# Modbit Implementation Tracker

> **Authority:** PRD v5.1 (`modbit docs/modbit-platform-prd-v5.1.md`). Every task references a
> locked requirement or docket id (R-DOC-01).
>
> **Update rule:** the change that completes a task updates this file in the same commit
> (R-DOC-02). Never delete a task to defer it — move its milestone (R-DOC-04).
>
> **Status values:** `Proposed` → `Ready` → `In Progress` → `Blocked` → `Review` → `Qualified` →
> `Released`. No task is `Qualified` without Capability Registry and acceptance evidence.

**Last updated:** 2026-07-28

---

## Legend

| Marker | Meaning |
|---|---|
| ✅ | Complete and evidenced |
| 🚧 | In progress |
| ⬜ | Not started |
| ⛔ | Blocked |

---

## Phase 0 — Governance (complete)

| ID | Task | Status | Evidence |
|---|---|---|---|
| GOV-01 | `.agents.md` — repository agent instruction set | ✅ Released | `.agents.md` |
| GOV-02 | `rules.md` — enumerated engineering rule catalog | ✅ Released | `rules.md` |
| GOV-03 | `.skills/` — repeatable agent procedures | ✅ Released | `.skills/README.md` + 7 skills |
| GOV-04 | `tasks.md` — implementation tracker | ✅ Released | this file |

---

## Phase 1 — Foundation (critical path items 1–3)

Docket: `SET-A01`, `QA-A01` precursors. PRD: §20A (settings), §26 (API/events), §33 (data model),
§12A (taint), §12.2 (side-effect classes).

| ID | Task | Requirements | Status | Evidence |
|---|---|---|---|---|
| FND-01 | Monorepo scaffolding, Go module, stable `make` targets | `.agents.md` §8 | ✅ Qualified | `Makefile`, `go.mod` |
| FND-02 | `contracts/` layout: settings, events, errors, capabilities | R-CTR-01 | ✅ Qualified | `contracts/` — 43 error codes, 110 event types, 54 settings, 2 capabilities |
| FND-03 | `pkg/id` — opaque prefixed identifiers + prefix registry | R-ID-01..05 | ✅ Qualified | `pkg/id`, 22 tests, 89 prefixes |
| FND-04 | `pkg/modberr` — stable error codes, structured error model | §6 API errors, R-ERR-01/02 | ✅ Qualified | `pkg/modberr`, 16 tests |
| FND-05 | `pkg/event` — canonical envelope, catalog, sequence authority | INV-5, R-EVT-01..08 | ✅ Qualified | `pkg/event`, 21 tests |
| FND-06 | `pkg/settings` — registry, scopes, merge strategies, resolver | SET-1..7, §20A.3–20A.5 | ✅ Qualified | `pkg/settings`, 29 tests |
| FND-07 | `tools/modbitgen` — Go + TS generation from `contracts/` | R-CTR-02/03 | ✅ Qualified | `tools/modbitgen`, 20 validation tests |
| FND-08 | `pkg/taint` — provenance classes, lattice, propagation, ledger | TNT-1, TNT-2, TNT-6 | ✅ Qualified | `pkg/taint`, 24 tests |
| FND-09 | `pkg/policy` — side-effect classes, decision engine, taint escalation | SFX-1..5, TNT-3/4 | ✅ Qualified | `pkg/policy`, 34 tests incl. TNT-7 adversarial suite |
| FND-10 | `make check` wiring + generated-code drift gate + error-contract freeze | R-CTR-03, R-CTR-04 | ✅ Qualified | `make check` green — 417 assertions, `-race` clean |

### FND acceptance

- [x] `make generate` is idempotent; a second run produces no diff.
- [x] Settings resolution returns effective value, source map, locks, diagnostics, change effect.
      → `TestSourceMapExplainsEveryContribution`, `TestChangeEffectIsReported`
- [x] A lower scope cannot weaken a higher-scope security setting; the attempt is diagnosed.
      → `TestLowerScopeCannotWeakenHigherScope`, `TestPolicyLockOverridesEveryPreference`,
      `TestPolicyCeilingClampsAPermissivePreference`, `TestNonPolicyScopeCannotPublishConstraints`
- [x] Unknown settings keys survive a round trip and are reported.
      → `TestUnknownKeysArePreservedAndReported`
- [x] Canonical envelope validation rejects a missing `organization_id` on a tenant-scoped event.
      → `TestTenantScopedEventRequiresAnOrganization`, `TestScopeDrivenRequiredIdentifiers`
- [x] Per-run sequence is monotonic under concurrent emitters.
      → `TestSequencerIsMonotonicPerRun`, `TestSequencerIsSafeUnderConcurrentAllocation`
- [x] Unknown provenance resolves to the highest-risk taint class.
      → `TestUnknownProvenanceFailsClosed`
- [x] Tainted context escalates approval class for compensatable and irreversible operations
      unless pre-declared in the approved plan.
      → `TestTaintEscalatesExternalOperations`, `TestPlanDeclarationCarveOutDependsOnOrdering`,
      `TestSecurityTaintBypassAttemptsAreRefused`
- [x] `go test -race ./...` clean.

### FND decisions taken

| # | Decision | Rationale |
|---|---|---|
| 1 | Product defaults are a **fallback**, not a bound, for selective merges (`override`, `most_restrictive`, `minimum`, `maximum`, `intersection`); they remain a **baseline** for additive merges (`union`, `union_deny`, `append_unique`, `deep_merge`) | Folding the default into a selective merge made every shipped default an unreachable ceiling — no organization could raise a cost cap or select `unrestricted`. Hard bounds belong in policy constraints. Found by `TestBaseApprovalClassByModeAndSideEffect`. |
| 2 | Taint class risk ordering is a Modbit default, not a PRD fact | The PRD fixes class names and the TNT-4 trigger set but does not rank classes. Documented in `pkg/taint` package comment; policy selects triggers explicitly. |
| 3 | Error `detail_keys` are an allowlist enforced at generation and at runtime | Makes R-ERR-02 mechanical rather than a review convention. Rejected keys are named, never valued. |
| 4 | `duration` dropped from the settings type set | No contract used it; an untested type is worse than an explicit `int` with a unit-suffixed key. |

### FND bug fixes (2026-07-27)

Five defects found by a review pass over the foundation. All five are now regression tested.

| # | Defect | Impact | Fix |
|---|---|---|---|
| B-1 | `ApprovalNotify` was documented as "run and notify" but `Evaluate` mapped it to `require_approval` | Contradiction, and worse: under `unrestricted` mode an externally compensatable operation sits at `ApprovalNone`, so a TNT-4 escalation landed on a rung that (per its own docs) did not gate — taint confinement was decorative exactly where it mattered most | Ladder collapsed to `none → single_approver → two_person`, so every escalation step is a real gate. `auto-review` + locally destructive now maps to `single_approver`, matching PRD §12.2 "approval and backup". Locked by `TestEveryEscalationStepIsARealGate` and `TestEffectAndApprovalClassAgree` |
| B-2 | `NewRegistry` did not validate merge/type compatibility | A plugin registering a namespaced schema (SET-6) bypasses the generator; a `union` merge on a `string` type reached the merge switch and panicked on a type assertion — a panic on a request path (R-GO-08) | `validateMergeForType` at construction plus defensive coercion in the merge switch. `TestRegistryRejectsIncompatibleMergeAndType` |
| B-3 | A failing custom merger silently fell back to the product default | Silent fallback violates SET-2 | Returns a `custom_merge_failed` error diagnostic. `TestCustomMergerFailureIsDiagnosed` |
| B-4 | Clamp diagnostics and `Resolution.Source` hardcoded `product_safety` | "Narrowed by policy" with no attribution is unactionable; the source map named the wrong scope | `Envelope` now records `AllowedFrom`/`DeniedFrom`/`MinFrom`/`MaxFrom`/`CeilingFrom`. `TestClampDiagnosticsNameTheResponsibleScope` |
| B-5 | `Envelope.Validate` iterated a map to check optional identifier prefixes | An envelope with two malformed identifiers reported a different field per run — irreproducible failures | Ordered slice. `TestValidationFieldOrderIsDeterministic` |

### FND gaps carried forward

- Settings catalog covers 54 keys across 5 namespaces (`agent`, `model`, `execution`, `context`,
  `taint`). PRD §20A.10 enumerates roughly 20 categories; the remainder land with their owning
  capability, not as a bulk import (R-DOC-04: not deferred, sequenced).
- `contracts/schemas/` (Structured Output Contracts) is created but empty — first contract lands
  with REV-B02/Verify.
- `db-migrate`, `db-rollback-check`, `api-breaking-check` are stubs; Phase 1 has no persistent
  store or published API surface. They become real in SRV-C01 and the API workstream.
- The repository is **not under version control**. `make generate-check` degrades to a no-op
  without `.git`, so the drift gate is inactive until `git init`.

---

## Repository infrastructure

| ID | Task | Status | Evidence |
|---|---|---|---|
| INF-01 | Version control initialized; foundation and gate commits on `main` | ✅ Released | `git log` |
| INF-02 | Drift gate active — hard-fails without `.git`, compares against `HEAD` so staged staleness cannot slip through | ✅ Qualified | verified by committing a tampered generated file and confirming rejection |
| INF-03 | Error-contract freeze — `contracts/errors/catalog.lock`, sha256 per code over wire-visible semantics | ✅ Qualified | verified in three directions: rename fails, retryability flip fails, addition passes |

**Why the freeze exists.** The drift gate proves generated code matches the contract; it cannot
prove the contract only ever grew. A renamed code, a flipped `retryable` flag, or a dropped detail
key silently breaks every peer, SDK, and stored audit record carrying the old semantics. The lock
digests `http_status`, `retryable`, `deprecated`, and the sorted detail-key allowlist, excluding
descriptions, which are prose and may be improved.

---

## ADR-0100 adoptions — engineering-specifications.md as secondary reference

`engineering-specifications.md` ("Agent Harness v2.2") is a **secondary engineering reference**, not
a requirements source. See `docs/adr/0100`. It is not in `MANIFEST-v5.1.md`, describes a narrower
product (no CodeWiki, Security Swarm, ACU, or Trust Portal), and conflicts with locked Modbit
taxonomies — error namespace, side-effect classes, run phases. Where they conflict, Modbit wins.

Three additive items adopted under that ADR:

| ID | Item | Modbit requirement served | Status | Evidence |
|---|---|---|---|---|
| REF-01 | Taint **sink** matrix + sticky `known_secret` class | TNT-1 ("minimum classes" permits addition), TNT-3, INV-11 | ✅ Qualified | `pkg/policy/sink.go`, `pkg/taint`, `TestSecurityKnownSecretCannotReachAnExternalSink` |
| REF-02 | `MODBIT_SNAPSHOT_DIVERGED`, `MODBIT_EFFECT_RECONCILIATION_REQUIRED`, `MODBIT_CONTEXT_DEGRADED` | RCV-4/5, SDD §15 "index failures degrade visibly", R-ERR-05 | ✅ Qualified | `contracts/errors/catalog.yaml`, 46 codes |
| REF-03 | Fence epoch in approval binding | SFX-3, SFX-4, R-EVT-06 | ✅ Qualified | `pkg/policy/approval.go`, `TestApprovalBindingInvalidation` |

**Decisions taken**

| # | Decision | Rationale |
|---|---|---|
| 19 | `known_secret` sits **above** every provenance class, but `Unknown()` resolves to `mcp_result`, not `known_secret` | The classes answer different questions: provenance describes where content came from, `known_secret` describes what it contains. Failing closed means assuming the worst *origin*, not asserting a fact we do not have — and classifying unknown content as a secret would make it permanently undeclassifiable. |
| 20 | `known_secret` is **sticky**: `Declassify` refuses it; only `RedactSecret` lowers it, and only with a verification artifact | A declassification asserts a judgement; a redaction asserts a fact something else checked. A secret that can be argued away with a rationale is not confined at all. |
| 21 | Sink denial runs **before** the approval ladder and returns deny, not escalate | No approval class makes a detected credential in a commit acceptable. `TestSinkDenialPrecedesTheApprovalLadder` proves a valid two-person approval does not unlock it. |
| 22 | `secret_denied_sinks` is **not** a setting | Every other taint control here is configurable because risk appetite legitimately differs, but a config surface for "do not send a detected credential to a third party" exists only to be switched off during an incident — exactly when it matters most. Same class as the NG1 no-training rule. |
| 23 | `SinkToolArgument` is deliberately **absent** from the denied set | A secret reaching a tool argument is often the point — a broker handing a leased credential to the operation that needs it. That path is governed by the Task Secret contract, not by taint confinement. |
| 24 | The field is `fence_epoch`, not `fence_token` | The R-ERR-02 key guard rejected `fence_token`, and it was right to. Two things are conflated in the literature: the fencing value is a monotonic counter and is not secret, while a lease *token* is bearer material that must never appear in an error. The fix was to name the non-secret value precisely rather than carve an exception into the control. |
| 25 | An expired approval returns `MODBIT_APPROVAL_REQUIRED`, a mismatched one returns `MODBIT_APPROVAL_INVALIDATED` | Different recovery: one needs a fresh lease or a fresh ask, the other needs a new approval showing the changed effect. |
| 26 | A presented-but-invalid approval is **reported**, not ignored | Silently falling back to "approval required" would hide that a stale grant was attempted. |

### MOD-A01i streaming protocol (S1–S10)

Stated as numbered invariants in `pkg/gateway/streaming.go`, one test each in `streaming_test.go`.
A test without an S-number, or an S-number without a test, is a gap.

| # | Invariant |
|---|---|
| S1 | Preparation is synchronous; a refused call returns `(nil, err)` with no channel allocated |
| S2 | No egress precedes DLP — no credential leased, no provider stream opened |
| S3 | The channel is closed exactly once, on every exit path |
| S4 | Exactly one terminal event, always before close |
| S5 | A terminal event carries a `Result` or an `Err`, never both, never neither |
| S6 | Metadata recorded exactly once on every termination, cancellation included |
| S7 | Cancellation abandons the upstream rather than draining it |
| S8 | Backpressure reaches the provider; the gateway holds no buffer |
| S9 | A stalled consumer cannot leak the pump; it is abandoned after `ConsumerStallTimeout` |
| S10 | Redaction and declared losses behave identically to the non-streaming path |

**Decisions**

| # | Decision | Rationale |
|---|---|---|
| 27 | The terminal send does **not** select on `ctx.Done()` | Cancelling the work must not cancel the notification that the work ended. Selecting on an already-closed context makes delivery a coin flip between two ready `select` cases, so a cancelled stream would *sometimes* close without a terminal event. Found by the `drain` helper enforcing S4 on every use — the cancellation test had been passing by luck. |
| 28 | The output channel is unbuffered | Every event the consumer has not taken is one the pump has not read from the provider, so backpressure reaches the upstream instead of accumulating in a queue whose depth nobody chose. |
| 29 | Failover stops at the first byte | A second provider cannot resume another's partial response, and re-running from the start would either duplicate deltas the caller already rendered or silently discard them. Establishment failures fail over; mid-stream failures are terminal. |
| 30 | A provider stream closing with no terminal event is a **failure**, not a success | Reporting it as success would let a truncated answer pass as a whole one. |
| 31 | `buildCall` is shared by `Complete` and the pump | Divergence would mean the same call recorded two different ways depending on which surface the caller used. |

### MOD-A01j event emission

| # | Decision | Rationale |
|---|---|---|
| 32 | `Recorder.Record` takes the metadata **and** its events, written as one act | R-EVT-04 requires the state write and event publication to be atomic. The gateway's state write *is* the `ModelCall`, so a separate publisher would reintroduce exactly the failure the rule prevents: a recorded call with no event, or an event for a call never recorded. |
| 33 | Only **terminal** events are emitted — not `model.requested`, `model.routed`, or `model.stream.delta` | A delta event per token would put a durable, sequenced, tenant-scoped envelope in the log for every few characters, all carrying content the log is forbidden to hold (INV-4); deltas are a live-observation concern served by the streaming surface. `requested` and `routed` carry nothing the `ModelCall` does not already hold, and emitting them before the outcome creates orphans a consumer cannot distinguish from a call still in flight. |
| 34 | A `Recorder` without a `Sequencer` is refused at construction | Run-scoped events without a monotonic sequence produce a log that cannot be reassembled (R-EVT-01, R-EVT-07). Refusing at construction beats discovering it on the first call. |
| 35 | Revision drift emits an **organization-scoped** event | A revision roll affects every run routed to that model, not just the one that happened to notice. |

### MOD-A01k egress control

**MOD-A01 is now complete.** Every sub-item a–k is Qualified.

| # | Decision | Rationale |
|---|---|---|
| 36 | The egress allowlist is a **library** control, not only a deployment one | A pod network policy is the outer fence and should exist, but it is applied by a different team in a different repository, is absent in desktop and local deployments entirely, and cannot distinguish one provider's traffic from another's. `Guard` sits in the adapter's own transport, so an adapter cannot reach a destination its capability record does not declare. |
| 37 | Resolved **addresses** are checked, not just hostnames | The host check alone is satisfied by a DNS rebind: an allowlisted name whose record points at an internal address. Blocked ranges cover loopback, RFC1918, link-local (169.254.169.254 — the standard escalation from request forgery to credential compromise), IPv6 equivalents, IPv4-mapped forms, carrier-grade NAT, multicast, and unspecified. |
| 38 | The check runs **per hop** | Each redirect is its own `RoundTrip`, so a chain starting at an allowed host and ending elsewhere is caught where it leaves the allowlist. |
| 39 | An empty or `*` allowlist is refused at construction | Both would look configured while permitting everything. |
| 40 | An unresolvable destination fails closed | It cannot be address-checked, so allowing it through unverified would defeat the rebind defence. |
| 41 | Loopback and plaintext are opt-in **per provider** | Ollama, vLLM, and LM Studio-compatible endpoints legitimately live on 127.0.0.1, so the capability must exist — scoped to providers that declare it, and never inherited by a hosted one. |

**Still deployment-level:** no filesystem mounts on the gateway workload, and the pod-level network
policy. Neither is expressible in a Go library; both belong to DEP-C01.

### Bug sweep (2026-07-27)

| # | Defect | Impact | Fix |
|---|---|---|---|
| B-6 | `buildCall` swallowed a failed identifier allocation and emitted an empty `ModelCall.ID` | A regression from the `Complete`/`Stream` refactor: the pre-refactor code returned `MODBIT_INTERNAL`. An unreferenceable metadata record is a silent degradation (R-ERR-05). | The call identifier is now allocated in `prepare`, before any provider is contacted. It cannot fail late, and it gives events something to correlate on from the first moment — which MOD-A01j needed anyway. |
| B-7 | Terminal stream event dropped on cancellation | `sendTerminal` selected on `ctx.Done()`; with an already-closed context `select` picks randomly between ready cases, so a cancelled stream *sometimes* closed with no terminal event. The cancellation test had been passing by luck. | Terminal delivery no longer consults the context, bounded only by the stall timer. Caught by the `drain` helper enforcing S4 on every use. |
| B-8 | A non-streaming candidate consumed a failover attempt | Two non-streaming candidates could exhaust the attempt budget before any provider was contacted, since the check performs no I/O. | Capability mismatches are filtered before the budget is charged. |
| B-9 | `cap` shadowed the builtin in `checkBudget` | Legal but a trap for the next reader. | Renamed to `ceiling`. |
| B-10 | Three hand-rolled integer formatters (`formatUint` ×2, `itoa`) | Each reimplements `strconv` and is a place a subtle bug can hide for no benefit. | Replaced with `strconv`. |
| B-11 | `observedRevision` took an unused `candidate` parameter | Dead weight that implies a dependency that does not exist. | Removed. |

**Deferred to later ADRs:** retrieval ranking and coverage-constrained packing · routing utility and
bandit calibration · memory scoring and decay · planner portfolio · effect reconciliation protocol ·
benchmark factory and judge calibration · Pareto-safe promotion and canary rollback.

---

## Phase 2 — Release A: Cursor-compatible IDE foundation

PRD §6.1. Docket §3.

| ID | Task | Status |
|---|---|---|
| IDE-A01 | Code OSS baseline: fork/rebase strategy, branding, update service, process isolation, marketplace, startup/memory telemetry | ⬜ Proposed |
| IDE-A02 | Settings import from VS Code/Cursor with mapping report and rollback | ⬜ Proposed |
| SET-A01 | Settings Registry core — definition schema, TS/Go generation, scope resolver, UI metadata, local files, validation, change effects | 🚧 In Progress — resolver, generation, and validation done (FND-06/07); local files, UI metadata, and sync outstanding |
| CTX-A01 | Local indexing — ignore/classification, watcher, lexical/vector/symbol, branch/worktree, status, citations | 🚧 In Progress — see breakdown below. Classification, walk, incremental reindex, worktree awareness, snapshots, and citations Qualified; the OS change source and the three indexes remain |
| MOD-A01 | Model Gateway v1 — canonical IR, hosted adapter, OpenAI-compatible local endpoint, DLP, metadata, streaming, cost | 🚧 In Progress — see MOD-A01 breakdown below |
| IDE-A03 | Tab completion — FIM, multiline, next edit, latency budget, settings, acceptance telemetry | ⬜ Proposed |
| IDE-A04 | Inline edit — selection/cursor, diff preview, accept/reject/refine, escalation to Code run | ⬜ Proposed |
| AGT-A01 | Local agent — Ask/Plan/Code, typed tools, events, checkpoints, steering, worktree, completion contract | ⬜ Proposed |
| EXE-A01 | Native local sandbox — backend contract, filesystem/network/resource controls, conformance | ⬜ Proposed |
| IDE-A05 | Diff zones — per hunk/file/group, checkpoint comparison, artifact link | ⬜ Proposed |
| BRS-A01 | Local preview browser — server detection, element selection, console errors, screenshot, origin policy | ⬜ Proposed |
### CTX-A01 breakdown

Capability registry entry: `contracts/capabilities/context.classification.yaml`.

**Dependency posture (decided 2026-07-28).** Well-scoped third-party Go dependencies may be adopted
for the indexing stack when they are the standard choice, each recorded as an ADR carrying the
justification R-GO-09 requires. Two constraints survive it: a parser must not execute repository
code (CTX-12), and a new datastore, transport, or runtime still needs an ADR under R-ARCH-01 rather
than a dependency note. `go.mod` still holds one direct dependency, `gopkg.in/yaml.v3`.

**Why `fsnotify` was not adopted for `CTX-A01c2`.** It was the expected choice and it failed
inspection. fsnotify's macOS backend is kqueue, and `watchDirectoryFiles` opens **a file descriptor
per file**, not per directory — their README states it plainly and `backend_kqueue.go` confirms it.
On the machine this was measured on, `kern.maxfilesperproc` is 10240, so fsnotify caps out at
roughly ten thousand watched files on the primary developer platform, against a product that targets
a 10M-file benchmark (MRS-01..04). Linux and Windows are fine; macOS is not, and macOS is where an
IDE lives.

The resolution is the port pattern the repository already uses for pgvector and Tantivy: define
`ChangeSource`, ship a portable implementation now, and add native backends per platform as
`CTX-A01c3`–`c5`. `go.mod` stays at one dependency, and the backend that macOS actually needs
(FSEvents — recursive, one watch per tree) was never what fsnotify offered.

| ID | Task | Requirements | Status | Evidence |
|---|---|---|---|---|
| CTX-A01a | Ignore/classification filter — gitignore-compatible matching, hierarchical sources, protected paths, binary/generated/size classification, provenance assignment | CTX-4, CTX-12, TNT-1 | ✅ Qualified | `pkg/index`, 38 assertions |
| CTX-A01b | Hierarchical ignore discovery over a real tree (walking `.gitignore`/`.modbitignore`/`.modbitindexingignore` per directory) | §20A.10 | ✅ Qualified | `pkg/index/walk.go`, 19 tests incl. 4 security suites |
| CTX-A01c | File watcher and incremental reindex within the freshness SLO | CTX-1, CTX-2 | ✅ Qualified | `pkg/index/reindex.go` + `watch.go`, 29 tests. Reindex engine, scoped rescan, flush policy, and the watcher loop are complete; native backends are tracked separately as CTX-A01c3–c5 |
| CTX-A01c2 | `ChangeSource` port + `Watcher` driver + portable `PollSource`, incl. queue-overflow → `Rescan` | CTX-2 | ✅ Qualified | `pkg/index/watch.go`, 12 tests; W1–W8 mutation-verified |
| CTX-A01c3 | Native macOS change source (FSEvents) | CTX-2 | ⬜ Ready | Recursive, one watch per tree. The only backend that meets CTX-2 on a large tree on the primary developer platform — see the watcher dependency finding below |
| CTX-A01c4 | Native Linux change source (inotify) | CTX-2 | ⬜ Ready | `fsnotify` is adoptable here; needs a watch per directory and must handle `max_user_watches` exhaustion as `RescanQueueOverflow` |
| CTX-A01c5 | Native Windows change source (ReadDirectoryChangesW) | CTX-2 | ⬜ Ready | Natively recursive; `fsnotify` is adoptable here |
| CTX-A01d | Lexical index — `LexicalIndex` port, code-aware tokenizer, in-process BM25, chunker | CTX-5, RET-1 | ✅ Qualified | `pkg/index/lexical.go`, 12 tests; L1–L7 mutation-verified, L8 documented as structural |
| CTX-A01d2 | Native lexical engine behind the port (Tantivy local / OpenSearch server) | CTX-5 | ⬜ Ready | Engine choice needs an ADR under R-ARCH-01: Tantivy is Rust, so it means cgo or a sidecar |
| CTX-A01e | Symbol extraction and dependency graph | CTX-5 | ⬜ Ready | |
| CTX-A01f | Semantic index — `VectorIndex` port, `Embedder` port, model-scoped partitions, in-process cosine | CTX-5, RET-1 | ✅ Qualified | `pkg/index/vector.go`, 14 tests; V1–V8 and V10 mutation-verified, V9 documented as structural |
| CTX-A01f2 | pgvector/HNSW behind the port | CTX-5 | ⬜ Ready | Datastore choice needs an ADR under R-ARCH-01 |
| CTX-A01g | Branch, revision, and worktree awareness | CTX-3 | ✅ Qualified | `pkg/index/worktree.go`, 26 assertions incl. ref-name and partition-key security suites |
| CTX-A01h | Immutable index snapshots recording source revision, indexer version, policy version | CTX-8, CTX-9 | ✅ Qualified | `pkg/index/snapshot.go`, 20 tests incl. tamper detection and partition scoping |
| CTX-A01i | Citations and context-item provenance | RET-6, RET-8, RET-9 | ✅ Qualified | `pkg/index/citation.go`, 15 tests incl. 6 security suites; C1–C10 mutation-verified |

**CTX-A01a decisions**

| # | Decision | Rationale |
|---|---|---|
| 42 | The protected-path list is **hardcoded**, checked before every other rule | Every other exclusion is a preference about noise and cost; this one is INV-11. A repository must not be able to opt *into* having its deploy keys embedded in a vector index by omitting them from `.gitignore`, and an administrator must not be able to switch it off during an incident. `TestProtectedPathsOutrankEveryOtherRule` proves a `!` negation cannot reach a private key. |
| 43 | Three dispositions, not two: `index`, `reference`, `exclude` | A large fixture or a binary asset still exists and is legitimately citable; parsing or embedding it would waste budget and produce noise. Collapsing `reference` into `exclude` would make those files invisible to a user who knows they are there. Oversized, binary, and empty files are `reference`. |
| 44 | A negation cannot re-include a file under an excluded directory | Matches git exactly. Without it, one `!` line in a nested ignore file could pull an entire excluded tree back into the index. |
| 45 | `.gitignore` is honoured only when policy says so; `.modbitignore` always applies | A repository's build exclusions are not necessarily its indexing exclusions. Modbit's own ignore files are not subject to that switch. |
| 46 | The classifier receives a byte **prefix**, never a reader or a path to open | Keeps it pure and makes CTX-12 structural: it cannot execute repository code because it never holds a handle to anything. |
| 47 | Provenance is assigned even on excluded files | A zero-valued `taint.Class` reads as `user_trusted`. A later decision must never see an unset class on repository content. |

**CTX-A01b decisions**

| # | Decision | Rationale |
|---|---|---|
| 48 | An excluded directory is **pruned**, not walked and filtered | This is what makes CTX-4's "excluded *before* indexing" true of the filesystem rather than only of the decision record. Content in a pruned subtree is never listed, never opened, and never read. It is also the difference between one entry and several million for a `node_modules`. |
| 49 | The walk reports directories only when they are **excluded** | A pruned subtree collapses into the single line that explains it, which is exactly what the context health view needs to answer "why is this file missing". Reporting included directories would bury that line under the tree it describes. |
| 50 | Classification is split into a path phase and a content phase | `.modbitignore` means Modbit does not read the file. A classifier that demanded a byte prefix up front made that unenforceable — the bytes were already read by the time the rule was consulted. `TestSecurityModbitIgnoredFilesAreNeverOpened` proves it by making the file unreadable: an attempted open would have produced a diagnostic. |
| 51 | An unreadable or oversized ignore file **prunes its subtree** | An ignore file Modbit cannot read is an instruction Modbit cannot follow. Indexing the subtree under whichever rules happened to be readable would index precisely the content that file existed to withhold. Failing the whole walk instead would let one unreadable directory deny the user an index of the repository, so the loss is scoped to the subtree and recorded as a diagnostic (R-ERR-05). |
| 52 | Symbolic links are recorded and never resolved | A link committed to the repository would otherwise pull arbitrary filesystem content in under a repository-relative path — a path the protected list was never written to cover, since that list describes a repository's layout, not the machine's. Excluding rather than referencing keeps a later stage from resolving the path on the index's authority. |
| 53 | Irregular files are excluded from the directory entry, before any open | Opening a FIFO blocks until a writer appears. Any contributor can commit one, so an indexer that opened whatever it found would hang on a path chosen by someone else. |
| 54 | `.git`, `.hg`, `.svn`, `.bzr` are pruned by name | None of it is source, it dwarfs the tree it sits in, and `.git/config` routinely carries a remote URL with an embedded token — indexing one would put a credential into a retrievable index (INV-11). |
| 55 | Walk limits (depth, ignore-file size, diagnostics) are constants, not settings | None is a policy choice. A tree that trips one is malformed or hostile, not merely large, and making them configurable would only offer an operator a way to turn a bound off. |

**CTX-A01c decisions**

| # | Decision | Rationale |
|---|---|---|
| 56 | Rescan scope is derived from *what changed*: a file rescans its directory shallowly, an ignore file or a directory rescans a subtree | An edited file cannot affect any listing but its own directory's, so a subtree walk would be work with no possible effect. An ignore file changes every verdict beneath it. A notification naming a directory says nothing about what appeared inside it, so a shallow parent scan would leave a newly created tree unindexed until something else forced a rescan. |
| 57 | A newly excluded path is a **removal**, never an upsert | This is CTX-4 applied to an index that already exists. A rule that only stopped *future* indexing would leave the content it names retrievable indefinitely — the same disclosure the rule was written to prevent. `TestSecurityAddingAnIgnoreRuleRetractsIndexedContent` covers both shapes: a file excluded by pattern, which the rescan still sees, and a subtree under a newly excluded directory, which it no longer reaches. |
| 58 | A path outside the scanned scopes is never concluded missing | Absence from a scan that never looked is not evidence of deletion. Treating it as one is how an incremental reindex silently empties an index; `inScopes` makes the distinction explicit and two tests pin it. |
| 59 | Retraction is driven by what a scan **observed**, never by what a notification claimed | A removal notification for a directory that still exists would otherwise retract its whole subtree. The state cannot distinguish "was a directory" from "never seen" — an included directory is never reported on its own — so a removal rescans the parent in full unless the state positively says the path was a file. |
| 60 | The flush deadline is the **earlier** of the debounce and a max-delay cap | A debounce alone never fires while edits keep arriving, so continuous typing would hold the index at the last quiet moment: stale, with nothing to show it. The cap (3s, against the 10s p95 SLO in PRD §7) bounds the wait regardless of activity and leaves room for the rescan and index write. |
| 61 | `Observe` never blocks on a flush | A watcher stalled behind a rescan lets the operating system's own notification queue overflow, which costs notifications outright. Scans run without the lock; a change landing mid-scan stays pending for the next flush, which the freshness budget accounts for. |
| 62 | `Flush` before an initial `Rescan` is an error, not an empty index | Applying deltas to a state that was never established would record a tree consisting of whatever happened to change, and report it as an index. |
| 63 | `ChangeSet.FullRescan` marks recovery explicitly | A watcher that dropped notifications leaves the reindexer diverged from the tree with nothing to reveal it. Recovery is a full walk, and the flag is what stops a consumer from mistaking it for an ordinary delta (SDD §15: index failures degrade visibly). |

**CTX-A01g decisions**

Requirement: CTX-3. Budget: PRD §7 "Branch/worktree contamination incidents — 0".

| # | Decision | Rationale |
|---|---|---|
| 64 | Git state is read from the **plumbing files**, never by running `git` | A security decision before a dependency one. Repository-controlled configuration can make git execute programs it names — hooks, `core.fsmonitor`, aliases, credential helpers — so invoking git inside a repository the user has merely opened would put CTX-12 ("indexing must not execute repository code") at the mercy of that repository's own config. `safe.directory` exists because this is a real class of attack. Reading files keeps CTX-12 structural. |
| 65 | The partition key covers worktree and branch, **not** the commit | Committing advances the index it is in; it does not move it elsewhere. Keying on the commit would create a fresh partition per commit and make incremental indexing pointless. A detached HEAD has no branch to identify it, so the commit stands in. |
| 66 | The partition key is a **digest**, not the names | A branch name is chosen by whoever can push, so it is untrusted input (R-SEC-01) flowing into a partition key. A key that embedded `../other-space` verbatim would let a branch name address a partition it does not own. Hashing makes that structurally impossible while staying injective. `TestSecurityKeyCannotBeSteeredByABranchName` covers five collision and traversal attempts. |
| 67 | Ref names are validated against git's own `check-ref-format` rules | Those rules exist precisely to stop a name being read as something other than a name. The name flows into keys, status displays, logs, and snapshot records, so it is checked once at the boundary rather than trusted at each. |
| 68 | **Any** revision change refuses an incremental flush | A checkout rewrites the working tree in bulk, far faster than a notification queue drains, so the pending changes cannot be assumed to describe it — applying them merges one branch's content into the other's index, and nothing downstream can tell afterwards. The conservative rule costs a full rescan after a plain `git commit`, which does not touch the working tree. That is the accepted price of the zero-contamination budget; distinguishing the two cases from HEAD alone is not reliable. |
| 69 | A tree with no checkout is indexed **without** revision awareness, not refused | `ErrNotARepository` is an ordinary outcome. Modbit indexes plain directories, and refusing them would trade a real capability for a guarantee nobody asked for. |
| 70 | A revision that cannot be read is an **error**, not a zero `Revision` | Two empty revisions compare equal, and two different tree states comparing equal is exactly the contamination the type exists to prevent. |

**CTX-A01h decisions**

Requirements: CTX-8 (record source revision, indexer version, policy version), CTX-9 (corruption detectable and recoverable through rebuild), SDD §17 / UPG-6 (indexer-version change triggers a controlled rebuild).

| # | Decision | Rationale |
|---|---|---|
| 71 | **Two** digests, for two different questions | `ManifestDigest` covers the sorted manifest alone and is the *content* identity: two scans of an unchanged tree produce the same value, which answers "did anything change" without an entry-by-entry comparison. `Digest` covers the whole record including identifier and timestamp, and is the *integrity* check CTX-9 needs. Conflating them was the first attempt and it failed immediately: the record digest covers fields that legitimately differ between two identical scans, so it could never serve as content identity. |
| 72 | `Verify` checks the manifest digest **first**, not only the record digest | The record digest covers the *stored* `ManifestDigest`, not the manifest itself, so a record-only check passes whenever both were altered together — the shape deliberate poisoning takes, as opposed to the shape bit-rot takes. A mutation test confirms the manifest check is the only thing standing between a tampered manifest and a clean read. |
| 73 | Reuse is decided on `ConfigDigest`, but `PolicySnapshotID` is still recorded | CTX-8 asks for the policy version, so it is recorded for traceability. Deciding reuse on it would rebuild the whole index whenever any unrelated setting changed — `context.retrieval.budget_tokens` must not invalidate a repository's index. `ConfigDigest` covers exactly the three settings that determine what gets indexed. |
| 74 | Every rebuild trigger is distinguishable | An operator seeing a rebuild needs to know whether it was an upgrade, a policy change, a branch switch, or corruption, because those call for different responses. Corruption outranks staleness: a damaged snapshot's version field is not evidence of anything. |
| 75 | `Read` verifies rather than offering verification | An unverified snapshot is indistinguishable from a verified one once it is a value in memory. CTX-9 requires corruption to be *detected*, not merely detectable, so there is no path that returns an unchecked snapshot. `Read` also rejects a file whose internal identifier does not match the one requested, which is what renaming one snapshot over another looks like. |
| 76 | Writes are atomic and snapshots are never overwritten | A crash mid-write would otherwise leave a truncated file that reads as a valid but shorter manifest. The payload is fsynced before the rename, so durability precedes visibility. Immutability is enforced rather than assumed: a store that accepted a replacement would let the record of what was indexed be rewritten after the fact. |
| 77 | `Latest` is scoped to the revision's partition and skips corrupt snapshots | The newest snapshot in the directory may belong to another branch, and serving it is exactly the contamination CTX-3 forbids. A corrupt snapshot must not hide an intact older one — recovery is CTX-9's whole point. |
| 78 | Excluded paths are **rejected** from a manifest, not filtered out | A path is itself information, which is why the classifier refuses to record excluded ones. A caller passing one has misunderstood what a manifest is, and silently dropping it would hide that. |
| 79 | `**/.modbit/**` added to the shipped `excluded_globs` default | The snapshot store lives there. Indexing it would make each scan record the previous scan's output as repository content, growing without bound. The `union` merge on that setting means no scope can remove the exclusion. |

**CTX-A01c2 watch protocol (W1–W8)**

The `Reindexer` decides *what* an index update contains; the `Watcher` decides *when* one happens.
The two failure modes differ: a wrong `ChangeSet` corrupts an index, while a late or lost
notification leaves a correct index describing a tree that no longer exists. CTX-2 budgets the
second (PRD §7: index freshness p95 under 10 seconds for local edits).

Stated as numbered invariants in `pkg/index/watch.go`, one test each in `watch_test.go`. All eight
were mutation-verified.

| # | Invariant |
|---|---|
| W1 | Reading the source never blocks on a scan |
| W2 | An initial `Rescan` precedes every flush |
| W3 | A lost-notification batch resolves to a full `Rescan`, never to a delta |
| W4 | Repeated losses coalesce into one `Rescan` |
| W5 | Pending changes are flushed no later than the policy's deadline |
| W6 | A source that stops ends the watch without losing already-observed changes |
| W7 | Cancellation stops the watch and closes the source exactly once |
| W8 | A scan failure surfaces; it is never swallowed to keep the loop alive |

| # | Decision | Rationale |
|---|---|---|
| 91 | The platform layer is a **port**, not a dependency choice | The three operating systems differ enough that the only portable contract is "deliver what you saw, and say so when you could not see". That contract is also what let W1–W8 be tested against a controllable fake rather than against an operating system, which is the difference between a test suite and a flake generator. |
| 92 | Observed changes and lost notifications are **one type**, not two paths | A source signalling loss through a separate channel would let a consumer handle changes and ignore losses. That is the divergence CTX-2's recovery path exists to prevent, so the type makes ignoring it impossible. |
| 93 | The reader runs in its own goroutine | Decision 61 said `Observe` must never block on a flush; this is what makes it true end to end. A watcher stalled mid-scan stops draining the operating system's queue, and an overflowed queue costs notifications outright — the recovery path provoking the very failure it recovers from. |
| 94 | The rescan signal is buffered to **one**, and the send is non-blocking | Eight dropped-notification reports are one divergence, not eight walks. Blocking to deliver the second would stall the drain that prevents further overflow. |
| 95 | `ChangeSet.RescanReason` accompanies `FullRescan` | The flag tells a consumer how to apply the set; the reason tells an operator whether the machine is dropping notifications, whether no native watcher is available, or whether this is simply the initial index. Those call for different responses and do not collapse into one bit. |
| 96 | A scan or apply failure **returns** from `Run` | A loop that retried quietly would report a fresh index while diverging from the tree — the silent degradation R-ERR-05 and SDD §15 both forbid. The caller decides whether to restart, because only the caller knows whether a failing walk is transient. |
| 97 | A source that stops flushes what it already has | A watcher shutting down is not a reason to discard edits the user already made. |
| 98 | `PollSource` declares itself on every batch | It cannot observe individual changes, so every batch is a `Rescan` carrying `poll_interval`. Presenting a rebuild as an update would hide that this deployment has no native watcher — and it is the floor, not the target: a full walk does not meet CTX-2 on a large tree. |

**CTX-A01d lexical protocol (L1–L8)**

CTX-5's lexical channel and RET-1's `bm25` term. Same port pattern as the watcher: SDD §2 names
Tantivy locally and OpenSearch on the server, both engine choices belonging in an ADR, and what must
not wait for that decision is the contract — what a lexical channel may hold, what it may return,
and which revision it answers for.

| # | Invariant |
|---|---|
| L1 | A document indexed for one revision is never returned to a query on another |
| L2 | Only indexable content becomes a document; construction is the gate |
| L3 | A removed path never appears in a later result |
| L4 | Re-indexing a path replaces its documents rather than accumulating them |
| L5 | Ranking is deterministic: the same corpus and query always produce the same order |
| L6 | Identifiers match their parts, so camelCase and snake_case are searchable |
| L7 | Every match carries the path and span a citation needs |
| L8 | A query with no usable terms returns nothing, never everything |

L1–L7 are mutation-verified. **L8 is not, and is documented as such**: with no terms the scoring
loop accumulates nothing, so deleting the guard does not fail its test. It is a property of this
implementation rather than an enforced invariant, and the test is kept for the implementations the
port exists to admit — a match-all-on-empty-query path is a reasonable-looking thing for a Tantivy
or OpenSearch adapter to inherit from its engine.

| # | Decision | Rationale |
|---|---|---|
| 99 | A document is a **span**, not a file | A retrieval budget is spent in spans and a citation names one (RET-6). dev-06 places one BM25 document per chunk for the same reason. It also means a `Match` converts to a `ContextItem` without a second lookup. |
| 100 | `Chunk` refuses a non-indexable entry, mirroring `Cite` | Construction is the gate in both places. A file the classifier excluded has no business in a full-text index, and refusing at construction means no implementation of the port has to re-check — which matters precisely because the other implementations are third-party engines. A `reference` file is refused too: Modbit never read it, so any text would be fabricated. |
| 101 | The index stores tokens and postings, never bodies | An index holding document text would be a second copy of the repository sitting outside the classifier's reach, and it would survive the retraction that decision 57 exists to guarantee. |
| 102 | Tokenization splits identifiers **and** keeps the whole form | A plain word splitter makes `getUserName` one term, so "user name" misses the function that defines it and the identifier misses `get_user_name` beside it. Splitting happens before lowercasing, because the case boundary *is* the delimiter; an acronym run is cut before its last capital so `HTTPServer` yields `http`+`server` rather than `httpserve`+`r`. |
| 103 | Ranking has a total order, not just a score sort | Map iteration is random, so an unbroken tie reorders between runs and a recorded retrieval stops being reproducible evidence — the same reason routing is deterministic (MOD-A01 decision 6). Path then span start makes it total. |
| 104 | BM25 `k1`/`b` are constants, not settings | A ranking-model detail with no operator-meaningful interpretation. Exposing it would invite tuning that RET-10's benchmark, not a preference, should drive. |
| 105 | One unreadable file does not abort the batch | Aborting would leave every later file unindexed too, turning one missing document into an arbitrary number the caller cannot enumerate. The batch completes and the shortfall returns `MODBIT_CONTEXT_DEGRADED` carrying the channel, not the paths — a path is itself information (decision 78). |
| 106 | A file that chunks to nothing is **retracted** | An edit that empties a file must not leave its old text searchable. This is decision 57 applied to the lexical channel. |

**CTX-A01f vector protocol (V1–V10)**

CTX-5's semantic channel and RET-1's `ann` term. Same port pattern; dev-06 places pgvector with HNSW
behind it, which is a datastore choice and therefore an ADR under R-ARCH-01.

| # | Invariant |
|---|---|
| V1 | A vector indexed for one revision is never returned to a query on another |
| V2 | Vectors from one embedding model are never compared against another's |
| V3 | Only indexable content is embedded; `Chunk` is the gate |
| V4 | A removed path never appears in a later result |
| V5 | Re-indexing a path replaces its vectors rather than accumulating them |
| V6 | Ranking is deterministic |
| V7 | Every match carries the path and span a citation needs |
| V8 | A vector of the wrong width or of zero magnitude is refused, never coerced |
| V9 | The index holds vectors and locations, never text |
| V10 | The index never contacts a provider; embedding is the gateway's job |

V1–V8 and V10 are mutation-verified. **V9 is not, and says so**: `Match` has no field to put text in,
so its test cannot fail against this implementation. It is kept for the pgvector adapter, where the
row being selected from does hold the chunk and returning it would be one column away.

| # | Decision | Rationale |
|---|---|---|
| 107 | A partition is keyed by revision **and embedding model** | Two models place the same text at different coordinates, so a cosine between them is meaningless — and, worse, plausible-looking. dev-06 calls re-embedding on model change a versioned rebuild (SDD §17, UPG-6). The model string carries the provider's revision too, because MOD-A01 decision 18 exists precisely because providers roll models silently. |
| 108 | `Embedder` is a port, and the package is **proved** unable to reach the network | Embedding is egress of repository content, so dev-06 routes it through the Model Gateway for the credential boundary (INV-2), DLP (INV-3), and cost metering. A port is only worth having if nothing can go around it, and the way it gets gone around is somebody adding an HTTP client for one urgent case. `TestSecurityIndexPackageCannotReachTheNetwork` walks the transitive dependency set and fails on `net/http`, `crypto/tls`, `os/exec`, and the gateway and inference packages. This package is also the one component that opens every file in a repository, which is the difference between a network capability being a bug and being an exfiltration primitive. |
| 109 | Vectors are normalized **on admission**, and a zero-magnitude one is refused | Normalizing on the way in is what makes a dot product a cosine, so every comparison is on one scale regardless of what a provider returned. A zero vector has no direction: its similarity to everything is zero, so it would sit in the index as a document that silently never matches. NaN and infinity are refused for the stronger version of the same reason — one NaN turns the whole partition's ordering into nonsense. |
| 110 | A batch containing one bad vector is refused **whole** | Normalization happens before the lock and before any mutation. A half-applied batch would be double-indexed by the retry that follows it. |
| 111 | Vector width is fixed by the first vector and enforced after | Coercing — truncating or zero-padding — yields a cosine that is arithmetically valid and semantically meaningless, which is the failure mode nobody notices. |
| 112 | Brute-force scan, not an approximate index | dev-06 specifies HNSW, which is what pgvector brings. Exhaustive scan is the honest floor: correct at every size, fast enough for one repository, and never pretending to be an ANN structure it is not. Recall is 100% by construction, which also makes it the reference an approximate index is measured against (RET-10). |
| 113 | The embedder is called once per **file**, not once per chunk | A provider round trip per chunk would make indexing a repository a per-chunk billing event. |
| 114 | A vector-count mismatch from a provider is refused | Returning fewer vectors than texts would pair each chunk with a neighbour's embedding: every result subtly wrong, nothing failing. |

**CTX-A01i citation protocol (C1–C10)**

Requirements: RET-6 (repository, path, revision, span, source, retrieval reason on every
model-visible item), RET-8 (never silently mix incompatible revisions), RET-9 (record why whole-file
inclusion was required). Metrics gate: `testing-and-acceptance` §7 "provenance 100%".

Stated as numbered invariants in `pkg/index/citation.go`, one test each in `citation_test.go`. A
test without a C-number, or a C-number without a test, is a gap. All ten were mutation-verified:
each invariant was broken in turn and the named test failed.

| # | Invariant |
|---|---|
| C1 | An excluded path can never become a context item |
| C2 | A `reference` item cites a whole file and carries no span and no content digest |
| C3 | All six RET-6 fields are present; a missing one is refused at construction |
| C4 | Provenance is derived from the index, never supplied by the caller |
| C5 | Whole-file inclusion carries a reason; a span-limited item must not carry one |
| C6 | A cited span lies inside the file the manifest recorded |
| C7 | The content digest covers exactly the bytes cited |
| C8 | A pack never mixes revisions |
| C9 | A pack's taint is the propagation of its items' classes |
| C10 | Every item names the snapshot it was retrieved from |

| # | Decision | Rationale |
|---|---|---|
| 80 | `Cite` is the **only** constructor; `ContextItem` has unexported fields | This file is the boundary between what was indexed and what a model may see. Three fields are guarantees rather than data — disposition decides whether the path may be cited at all, provenance must not be able to default, and revision and snapshot must come from the index rather than from what the caller believed was current. A struct literal would let a retriever assert all three. |
| 81 | Citing an excluded path fails as a **lookup miss**, and the message does not say why | A refusal that distinguished "excluded" from "absent" would be an existence oracle: a caller probing paths would learn which protected files a repository holds, which is the disclosure the exclusion was written to prevent. `TestSecurityRefusalDoesNotDistinguishExcludedFromAbsent` compares the two messages byte for byte. |
| 82 | Provenance is **derived**, and `Request` has nowhere to put one | `taint.Class`'s zero value is `user_trusted` (decision 47). A caller-supplied field left unset would silently promote repository content — including any instructions inside it — to the most trusted class in the lattice, which is precisely how repository-authored text gets executed as though the user had typed it. |
| 83 | A `reference` item cites the whole file and carries no digest | Modbit never read it, so it has no span to offer and no bytes to digest. Claiming either would be inventing evidence. This is what makes decision 43's third disposition coherent: the file stays citable without the index pretending to know its contents. |
| 84 | Whole-file inclusion must justify itself; a span-limited item must not | RET-9 exists because whole-file inclusion is the largest consumer of a context budget and is invisible in the result — a whole file and a well-chosen span look identical to the model. Requiring the reason on one branch and refusing it on the other is what keeps `WholeFileInclusions()` a meaningful review list rather than a field everyone fills in. |
| 85 | The content digest is taken **inside** `Cite`, over the bytes the caller says it cited | A caller-supplied digest can disagree with the content, and it would disagree exactly when something is wrong. Taking it here makes a citation revalidatable: a validator re-reading the file at this revision and span must arrive at this value. The content itself is never retained — a citation is metadata, and INV-4 keeps bodies out of metadata. |
| 86 | Span carries lines **and** bytes | They answer different questions. Lines are what a person checks and a UI renders; bytes are what makes the region exact, since a line range says nothing about line endings or encoding and a digest over "lines 40–60" is not reproducible. |
| 87 | `Pack` is where RET-8 is enforced, not `ContextItem` | A single item cannot mix revisions, so the requirement is unenforceable at item level. By the time items are serialized into a prompt it is too late to notice that two describe different branches — and it is silent precisely because an assembled prompt shows no revision at all. |
| 88 | A mixed-revision pack names **both** revisions in the error | "These do not match" gives an operator nothing to act on. Both values are safe to show because a ref name is validated against `check-ref-format` at the boundary it enters through (decision 67), so it cannot be read here as anything but a name. The R-ERR-02 key allowlist rejected `field` and was right to: `expected_revision` and `actual_revision` are the keys that carry meaning. |
| 89 | `Revision.Short()` never renders empty | A citation ending in a bare `@` reads as a truncation, which is the one thing evidence must not look like. A tree with no checkout says `unversioned` instead. |
| 90 | C9 is tested in-package, because the public API cannot yet build a heterogeneous pack | Every item `Cite` produces is `repository_untrusted`, and `Propagate` over a homogeneous set is indistinguishable from "take the first item's class" — the mutation proving it survived the external test suite untouched. The case is not hypothetical: a DLP-flagged file is `known_secret` and an editor selection is `user_trusted`, and both are the moment a "take the first" implementation would under-report what a prompt carries. Testing it where it is reachable beats claiming an invariant nothing exercises. |

**CTX-A01i bug fix**

| # | Defect | Impact | Fix |
|---|---|---|---|
| B-12 | `TestCancellationOnAnAlreadyCompletedStreamIsInconclusive` failed roughly **1 run in 10** | Found by `make check` on unrelated work. The fake's `emit` runs in a goroutine, so a large `StreamBuffer` did not produce "already completed" — whether the terminal event landed before the suite cancelled was a race. The check then reported `pass` instead of `inconclusive`, which is the exact gap the test was written to close (a fast adapter that ignores cancellation shipping as verified). A conformance suite whose verdict depends on goroutine scheduling makes ADP-6 evidence nondeterministic, the same class as B-5. | `fake.CompleteBeforeReturn` emits the whole stream, terminal event included, before `Stream` returns, with the channel sized to the known event count so emitting inline cannot deadlock. Stable over 200 runs and 20 race-enabled suite runs; mutating the check still fails the test. |

**CTX-A01g bug fix**

| # | Bug | Why it mattered | Fix |
|---|---|---|---|
| B-11 | A linked worktree's `.git` **file** was indexed as source | `vcsMetadataDirs` was only consulted for directories, but `git worktree add` writes `.git` as a file holding an absolute path to the repository's git directory. That path was being indexed and would have been embedded — a local filesystem path published into retrievable content. Found by probing the walker against a real linked-worktree layout, not by a failing test. | The check now covers files as well as directories, renamed `vcsMetadataNames`. `TestSecurityLinkedWorktreeGitFileIsNotIndexed`. |

**CTX-A01b bug fixes**

| # | Bug | Why it mattered | Fix |
|---|---|---|---|
| B-7 | `.modbitindexingignore` produced `exclude`, identical to `.modbitignore` | The two files exist precisely to be different: one withholds content from the indexes, the other withholds it from Modbit entirely. Collapsing them made a large fixture invisible to a user who knew it was there, and made decision 43's third disposition unreachable from an ignore file. | The disposition is now chosen by source; `TestIndexingIgnoreYieldsReferenceNotExclusion` pins it. |
| B-8 | `NewClassifier` appended settings exclusions **into the caller's** `RuleSet` | Two classifiers built from one rule set applied every settings glob twice, and the walker had nothing to preserve across a per-directory rule swap. | Settings exclusions are held in their own set. `TestClassifierDoesNotMutateTheRuleSetItIsGiven` covers it. |
| B-9 | `IgnoreFileNames` was a **map**, so the order the three ignore files applied in was random | Resolution is last-match-wins, so map iteration order decided which file won when two disagreed — a repository could get different indexing decisions on consecutive runs. | Replaced by the ordered `IgnoreFiles` slice; the order is now documented as contract. |
| B-10 | Classification cost ~90µs and **146 allocations per file** | The walker made this matter: a 100k-file repository spent ~9s and ~680 MB of churn on path matching alone, against CTX-2's freshness SLO. `BenchmarkClassify` had recorded the number since CTX-A01a, but nothing had read it. | Two changes, both behaviour-preserving. `RuleSet.Match` splits the path once and slices it for each ancestor instead of re-splitting per pattern per ancestor. Pattern segments are classified at parse time, so literals compare with `==` and `*.ext` globs with `HasSuffix`; only segments carrying a real metacharacter reach `path.Match`, which the profile showed was 58% of the time. Now ~16µs and 3 allocations — 5.6× faster, 49× fewer allocations, with `TestGlobFormsAgreeWithGlobSemantics` pinning all three branches against `path.Match`. |

| QA-A01 | Foundation qualification — Capability Registry, client/API event conformance, secret tests, performance gates, benchmark smoke | ⬜ Proposed |

### MOD-A01 breakdown

Capability registry entry: `contracts/capabilities/model.canonical-ir.yaml`.

| ID | Task | Requirements | Status | Evidence |
|---|---|---|---|---|
| MOD-A01a | Canonical IR — closed content union, tool-call pairing, media by reference, taint propagation into the prompt | ADP-1, ADP-2, §14.1.1 | ✅ Qualified | `pkg/inference/ir.go`, 68 assertions |
| MOD-A01b | Normalized capability schema — every §14.2 field including governance | §14.2, MOD-1, MOD-5 | ✅ Qualified | `pkg/inference/capability.go` |
| MOD-A01c | Lossy-translation contract — `Loss` as a returned value recorded on model-call metadata | ADP-3 | ✅ Qualified | `TestCheckDistinguishesUnsupportedFromDowngraded` |
| MOD-A01d | Adapter interface + alias registry with deterministic candidate ordering | §14.1, ADP-4 | ✅ Qualified | `pkg/inference/adapter.go` |
| MOD-A01e | Shared adapter conformance suite | ADP-5, ADP-6 | ✅ Qualified | `pkg/inference/conformance` (16 cases, all 12 ADP-5 areas) + `pkg/inference/fake`; wired into `make test-conformance` |
| MOD-A01f | Gateway pipeline: settings/policy validation → classification → DLP → route → adapter → usage → immutable metadata | §10 SDD, INV-1, INV-3 | ✅ Qualified (non-streaming) | `pkg/gateway`, 25 assertions. Streaming pipeline and canonical event emission outstanding — see MOD-A01i/j |
| MOD-A01g | First provider adapter + OpenAI-compatible local endpoint | §14.1 | ⬜ Ready | |
| MOD-A01h | Provider credential boundary | INV-2, SDD §10 | ✅ Qualified | `pkg/inference/credential.go`, `TestCredentialResistsAccidentalDisclosure` |
| MOD-A01i | Gateway streaming pipeline: S1–S10 protocol, cancellation, backpressure, stall abandonment | SDD §10 | ✅ Qualified | `pkg/gateway/streaming.go`, 16 protocol tests + `stream_terminal_contract` conformance case |
| MOD-A01j | Canonical event emission, written atomically with the metadata | INV-5, R-EVT-04, OEV-1 | ✅ Qualified | `pkg/gateway/events.go`, 9 assertions |
| MOD-A01k | Provider egress allowlist enforced in-process; no-filesystem-mounts remains deployment-level | SDD §10 | ✅ Qualified | `pkg/gateway/egress.go`, 22 assertions incl. metadata-endpoint and DNS-rebind suites |

**MOD-A01e — conformance suite design**

| Aspect | Decision |
|---|---|
| Coverage | All 12 ADP-5 areas, asserted by `TestSuiteCoversEveryADP5Area` so a case cannot be quietly dropped |
| Output | A structured, JSON-serializable `Report`, not test assertions — ADP-6 needs a recorded evidence artifact, and CI needs a machine-readable gate |
| Scope | Verifies the **adapter's** contract conformance, never the model's behaviour. An adapter cannot make a provider emit two tool calls, so behaviour-dependent cases assert conditionally. A suite that fails for reasons the author cannot fix is a suite that gets disabled. |
| `Inconclusive` status | A declared capability whose path the provider did not exercise is **not** a pass. `ProductionReady()` refuses failures *and* inconclusive results; `Skipped` (capability not declared at all) is fine. |
| Timeouts | `Options{StreamTimeout, CancelTimeout}` — a live provider needs 30s where a fake needs 300ms; hardcoding either makes the suite unusable for the other |
| Redaction | Report details carry the Modbit code and message only, never the cause chain. `TestReportDetailsCarryNoUpstreamContent` seeds a fake API key and address into an upstream error and asserts neither reaches the report (R-ERR-02). |

**Two gaps the suite's own tests exposed in the suite**

| Gap | Fix |
|---|---|
| Cancellation reported `pass` against a stream that had already completed — a provider whose response is fully buffered locally can never demonstrate cancellation, so "it stopped" proved nothing | The check now tracks whether the terminal event arrived anyway and reports `inconclusive` in that case. `TestCancellationOnAnAlreadyCompletedStreamIsInconclusive` |
| A `content_types` violation was undetectable because the fake had no way to refuse a modality its record declared | Added the `RejectMedia` fault; the suite now catches a capability record and adapter that disagree |

**MOD-A01f/h — gateway and credential boundary**

Capability registry entry: `contracts/capabilities/model.gateway.yaml`.

| # | Decision | Rationale |
|---|---|---|
| 8 | Missing DLP inspector or credential broker is a **construction** error, not a runtime degradation | A gateway assembled without them is not a weaker gateway; it is a different product with none of the guarantees. INV-3 has no opt-out, so `NewPatternInspector` also rejects an empty rule set — an inspector that inspects nothing is a silently disabled control. |
| 9 | `inference.Credential` implements `Stringer`, `GoStringer`, `json.Marshaler`, and `slog.LogValuer`, all yielding a redaction marker | Go cannot stop a package reading a value it was given, so the protection is making *accidental* disclosure impossible. A raw string leaks the moment anyone writes `%v`, `json.Marshal`, or `slog.Any` on a struct containing it — that is how credentials actually escape. The secret is reachable only through `Secret()`, a call site a reviewer can grep and a linter can flag. |
| 10 | Adapter methods take the credential as an explicit parameter | An ambient or context-carried credential is exactly how INV-2 gets violated by accident. The signature makes every boundary crossing visible. |
| 11 | Credentials are leased **after** DLP and routing, only for the chosen provider | A payload that DLP blocks must never cause a credential to be minted. `TestCredentialIsLeasedOnlyForTheChosenProvider` and `TestDLPFailureFailsClosedAndNeverCallsAProvider` assert both halves. |
| 12 | DLP default rules **block** credential-shaped content rather than redacting it | A redacted credential still discloses its shape, and its presence usually means the caller assembled context it should not have. Only connection-string passwords redact. |
| 13 | Findings record the rule and location, never the matched value | A finding carrying the match moves the secret from the prompt into the audit log — the same disclosure with extra steps. |
| 14 | `ModelCall` has nowhere to put a prompt or completion body | That is how INV-4 survives contact with a real system. Permitted bodies are separate artifacts on their own retention schedule. `TestRecordedMetadataCarriesNoPromptOrCompletionBody` seeds a marker and asserts it never appears. |
| 15 | An unenforceable control is treated as unsatisfied | A spend lookup that fails refuses the call: an unenforceable cap is not a cap. Same for DLP and credential leases. |
| 16 | Failover only on a **retryable** class, bounded by an attempt budget | Every candidate already satisfied the same capability, residency, retention, and budget envelope, so §14.4 equivalence holds by construction. Failing over on a deterministic rejection would only spend budget reproducing the same refusal. |
| 17 | A recording failure surfaces on `Result.RecordingErr` without failing the call | The completion already happened; pretending otherwise would be dishonest. The caller decides whether missing evidence blocks its completion contract (INV-8). |
| 18 | `ModelCall` keeps **both** declared and observed revision | Their divergence is what makes a silent provider model change detectable (MOD-6) and gives OEV-1 canary gating something to compare. |

**MOD-A01 decisions taken**

| # | Decision | Rationale |
|---|---|---|
| 1 | Content parts are a closed tagged union, not an interface | An interface lets an adapter silently drop a part it does not recognize — that is how a prompt loses an image and the model answers the wrong question. A closed union forces exhaustive switches and `Part.Validate` rejects payload/kind mismatches. |
| 2 | Media is always an object-store reference with a digest; the IR never carries bytes | Prompt bodies are metadata-only by default (INV-4); a representation that could hold inline base64 makes that unenforceable the first time a request is traced. |
| 3 | `Loss` is a returned value, not a log line | The gateway records it on immutable model-call metadata, so a Verify workflow can refuse to treat a completion as evidence when a loss touched the property it was meant to prove. A logged gap is invisible to both. |
| 4 | Capability gaps split into error (unsupported) vs `Loss` (downgraded) | Collapsing them either blocks routes needlessly or lets a silent downgrade pass as a clean completion. |
| 5 | Governance — residency, retention, NG1 no-training — is ineligibility, never a declared loss | There is no "degraded" version of exceeding a retention limit. `TrainsOnCustomerData` makes a model ineligible for every route. |
| 6 | Candidate ordering is fully deterministic | Two gateway replicas given the same inputs must propose the same route, or a recorded routing decision is not reproducible evidence. |
| 7 | Cost estimates round up | A budget that can be exceeded by rounding is not a budget. |

---

## Phase 3 — Release B: Autonomous engineering agent

PRD §6.2. Docket §4. Includes v5.1 families **TNT** and **VAD** (docket placement table).

| ID | Task | Status |
|---|---|---|
| AGT-B01 | Debug workflow | ⬜ Proposed |
| REV-B01 | Independent review | ⬜ Proposed |
| REV-B02 | Verify engine | ⬜ Proposed |
| CTX-B01 | Deep graph and history | ⬜ Proposed |
| CTX-B02 | Fast Context subagent | ⬜ Proposed |
| WIKI-B01 | CodeWiki generation | ⬜ Proposed |
| WIKI-B02 | Citation validator | ⬜ Proposed |
| BRS-B01 | Scripted browser verification | ⬜ Proposed |
| BRS-B02 | Full computer use on Linux | ⬜ Proposed |
| EXE-B01 | Remote worker gateway | ⬜ Proposed |
| EXE-B02 | Environment Blueprints/snapshots | ⬜ Proposed |
| IDE-B01 | Agent Command Center | ⬜ Proposed |
| IDE-B02 | Local-to-remote handoff | ⬜ Proposed |
| EXT-B01 | Rules/Skills/Workflows/MCP | ⬜ Proposed |
| AGT-B02 | Session Insights | ⬜ Proposed |
| QA-B01 | Autonomous benchmark | ⬜ Proposed |
| TNT-01..05 | Provenance taint: tagger, propagation ledger, policy dimension, UI, adversarial suite | 🚧 FND-08/09 seed |
| VAD-01..06 | Verification adequacy: mutation adapters, scoring, property-based, differential, flaky quarantine, verifier diversity | ⬜ Proposed |
| MRS-01..04 | Monorepo scale: sparse checkout, VFS spike, Shard Manager, 10M-file benchmark | ⬜ Proposed |
| LCD-01..04 | Capability degradation contract: matrix, negotiation, disclosure, local contract tests | ⬜ Proposed |

---

## Phase 4 — Release C: Team workflows

PRD §6.3. Docket §5. Includes v5.1 families **LRN** and **CRC**.

| ID | Task | Status |
|---|---|---|
| SRV-C01 | Organization/Team/Space/RBAC | ⬜ Proposed |
| SET-C01 | Settings sync and managed policy | ⬜ Proposed |
| SEC-C01 | SSO/SCIM/service identities | ⬜ Proposed |
| AUT-C01 | GitHub/GitLab events | ⬜ Proposed |
| AUT-C02 | Automation engine | ⬜ Proposed |
| SEC-C02 | Task Secret broker | ⬜ Proposed |
| REV-C01 | Full code-review product | ⬜ Proposed |
| CTX-C01 | Remote/shared indexing | ⬜ Proposed |
| WIKI-C01 | Shared CodeWiki and annotations | ⬜ Proposed |
| OBS-C01 | Usage/budgets/chargeback | ⬜ Proposed |
| EXT-C01 | Registry and marketplace | ⬜ Proposed |
| DEP-C01 | Team server Helm/Terraform | ⬜ Proposed |
| QA-C01 | Multi-tenant qualification | ⬜ Proposed |
| LRN-01..08 | Tiered memory and learning | ⬜ Proposed |
| CRC-01..05 | Concurrent-run coordination | ⬜ Proposed |

---

## Phase 5 — Release D: Differentiation

PRD §6.4. Docket §6. Includes v5.1 families **OBR**, **GAT**, **OEV**, **EIX**.

| ID | Task | Status |
|---|---|---|
| CTX-D01 | Multi-repository impact graph | ⬜ Proposed |
| AGT-D01 | Multi-repository change orchestration | ⬜ Proposed |
| WIKI-D01 | Architecture drift | ⬜ Proposed |
| BRS-D01 | Windows computer use | ⬜ Proposed |
| AGT-D02 | Arena | ⬜ Proposed |
| AGT-D03 | Expert swarm | ⬜ Proposed |
| AUT-D01 | Incident workflow | ⬜ Proposed |
| AUT-D02 | Dependency migration | ⬜ Proposed |
| SEC-D01 | Security Swarm | ⬜ Proposed |
| CTX-D02 | Context SDK/MCP | ⬜ Proposed |
| QA-D01 | Competitive benchmark | ⬜ Proposed |
| OBR-01..04 | Outcome-based routing | ⬜ Proposed |
| GAT-01..05 | Graduated autonomy | ⬜ Proposed |
| OEV-01..05 | Online evaluation | ⬜ Proposed |
| EIX-01..04 | Evidence interoperability (SARIF, git-native) | ⬜ Proposed |

---

## Phase 6 — Release E: Enterprise

PRD §6.5. Docket §7.

| ID | Task | Status |
|---|---|---|
| SEC-E01 | Custom roles and IdP groups | ⬜ Proposed |
| DEP-E01 | HA multi-zone | ⬜ Proposed |
| DEP-E02..04 | AWS / Azure / GCP references | ⬜ Proposed |
| SEC-E02 | Private connectivity / IP lists | ⬜ Proposed |
| SEC-E03 | Customer-managed keys | ⬜ Proposed |
| DEP-E05 | Air-gapped | ⬜ Proposed |
| OBS-E01 | SIEM/compliance export | ⬜ Proposed |
| DEP-E06 | Disaster recovery | ⬜ Proposed |
| IDE-E01 | Managed devices/updates | ⬜ Proposed |
| QA-E01 | Regulated qualification | ⬜ Proposed |

---

## Cross-cutting subtasks

Every capability creates these (docket §8). Track them inside the owning task's acceptance list.

```text
-CAP Capability Registry   -SET Settings      -POL Policy       -API API/events
-DATA Data/retention       -SEC Threat model  -AUD Audit        -OBS Telemetry
-UI Surfaces               -TEST Tests        -DOC Docs         -ROL Rollout/rollback
```

---

## Open decisions (ADR candidates)

From SDD §20. These are ADR candidates, **not** permission to diverge silently.

| # | Decision | Owner | Status |
|---|---|---|---|
| 1 | Native macOS sandbox implementation | Execution | Open |
| 2 | Production vector/search engine beyond initial adapters | Knowledge | Open |
| 3 | Durable workflow engine vs event-sourced orchestrator | Agent Platform | Open |
| 4 | MicroVM technology for high-risk pools | Execution | Open |
| 5 | Full Windows computer-use worker stack | Execution | Open |
| 6 | Mutation-engine adapter set + adequacy-score normalization | Quality Agents | Open |
| 7 | VFS technology for virtual workspaces | Knowledge | Open |
| 8 | Drift-significance statistics for online evaluation | Evaluation | Open |

---

## Notes

- `modbit docs/` is frozen and read-only (R-DOC-06).
- One product decision is recorded as open and unapplied: the scope-tiering pass described in PRD
  Appendix H and `FINAL-VALIDATION-REPORT-v5.1.md` §6. Until it is applied, all v5.0 MUSTs remain
  release-blocking at their stated release.
