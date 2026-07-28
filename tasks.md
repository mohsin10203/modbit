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
| SET-A01 | Settings Registry core — definition schema, TS/Go generation, scope resolver, UI metadata, local files, validation, change effects | ✅ Qualified — every sub-item a–c complete; sync is SET-C01 (Phase 4) |
| CTX-A01 | Local indexing — ignore/classification, watcher, lexical/vector/symbol, branch/worktree, status, citations | 🚧 In Progress — **every sub-item a–i is Qualified**; what remains is six native backends behind ports that already exist and are tested (`c3`–`c5`, `d2`, `e2`, `f2`), each gated on its own ADR |
| MOD-A01 | Model Gateway v1 — canonical IR, hosted adapter, OpenAI-compatible local endpoint, DLP, metadata, streaming, cost | ✅ Qualified — every sub-item a–k complete; see MOD-A01 breakdown below |
| IDE-A03 | Tab completion — FIM, multiline, next edit, latency budget, settings, acceptance telemetry | ⬜ Proposed |
| IDE-A04 | Inline edit — selection/cursor, diff preview, accept/reject/refine, escalation to Code run | ⬜ Proposed |
| AGT-A01 | Local agent — Ask/Plan/Code, typed tools, events, checkpoints, steering, worktree, completion contract | ✅ Qualified — every sub-item a–d complete; see AGT-A01 breakdown below |
| EXE-A01 | Native local sandbox — backend contract, filesystem/network/resource controls, conformance | 🚧 In Progress — contract, suite, portable backend, and macOS confinement Qualified (EXE-A01a/b); Linux and container backends remain |
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

**The pattern generalised.** Every remaining CTX-A01 item took the same shape, and the shape is now
the default for this workstream: define the port, ship a correct in-process implementation, prove
the contract against it, and let the engine decision be its own ADR. That gave `ChangeSource` +
`PollSource`, `LexicalIndex` + BM25, `VectorIndex` + `Embedder` + exhaustive cosine, and
`SymbolExtractor` + a standard-library Go extractor. Four consequences worth keeping:

- `go.mod` still holds **one** direct dependency after six capabilities.
- Every port has a working implementation, so no channel is a stub — the Go extractor indexes this
  repository, and the in-process indexes serve a single repository fine.
- The reference implementations are what an engine gets measured against. Exhaustive cosine has 100%
  recall by construction, which is exactly the baseline RET-10 needs for an approximate index.
- The contracts were provable *before* any engine was chosen, so an adapter arrives with its
  invariants already written down rather than inferred from whatever the engine happens to do.

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
| CTX-A01d3 | Early termination (MaxScore) and top-k selection in the in-process index | CTX-5, RET-1 | ✅ Qualified | `pkg/index/lexical.go`; L9 mutation-verified against an exhaustive reference (5 of 7 mutants caught, 2 documented). 75.5→40.9 ms on the realistic query, 182→119 ms on corpus-wide terms |
| CTX-A01d2 | Native lexical engine behind the port (SQLite FTS5 local / OpenSearch server) | CTX-5 | ⛔ Blocked | Blocked on ADR-0103 acceptance, not on the store question — PRD §40.2 already locks SQLite. After CTX-A01d3 the in-process index is **faster than FTS5 on every measured shape**; the case for an engine is memory alone. Adapter cannot live in `pkg/index` (boundary test forbids `database/sql`) |
| CTX-A01e | Symbol extraction and dependency graph — `SymbolExtractor`/`SymbolIndex` ports, stdlib Go extractor, import edges | CTX-5, CTX-7, CTX-12 | ✅ Qualified | `pkg/index/symbol.go`, 11 tests; G1–G8 mutation-verified |
| CTX-A01e2 | tree-sitter extractor for the remaining languages | CTX-5 | ⬜ Ready | cgo dependency; needs an ADR. Implements `SymbolExtractor` without changing anything above it |
| CTX-A01f | Semantic index — `VectorIndex` port, `Embedder` port, model-scoped partitions, in-process cosine | CTX-5, RET-1 | ✅ Qualified | `pkg/index/vector.go`, 14 tests; V1–V8 and V10 mutation-verified, V9 documented as structural |
| CTX-A01f2 | pgvector/HNSW behind the port | CTX-5 | ⛔ Blocked | Same gate as CTX-A01d2: ADR-0103 acceptance. PRD §40.2 leaves the local vector adapter open ("selected from supported implementations"), so this needs its own ADR on top |
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

**CTX-A01d2 — measured before proposing an engine (ADR-0102, ADR-0103)**

The question was framed as "which engine", but the first thing to establish was whether the shipped
in-process index actually needs replacing, and where — because that decides how much dependency is
worth taking. `BenchmarkLexicalIndexScale` measures scale on a code-shaped synthetic corpus. The
counter is **files**; `Chunk`'s 60-line window makes it two documents per file.

| files | chunks | search (common terms) | heap | bytes/file |
|---|---|---|---|---|
| 1,000 | 2,000 | 1.5 ms | 9.2 MB | 9,663 |
| 10,000 | 20,000 | 19.4 ms | 90 MB | 9,454 |
| 50,000 | 100,000 | 228 ms | 417 MB | 8,746 |

Memory is linear at ~9 KB/file with nothing to gain at scale, and the index is rebuilt from scratch
on every start. Extrapolated to a 100k-file repository: **~880 MB resident**, against a PRD §9.6
target far larger again.

**One query measured this wrong — twice.** `BenchmarkLexicalQueryShape` varies the query at fixed
scale (50k files). After `CTX-A01d3`, with both engines given the **same** query:

| query | in-process | FTS5 (cgo, pre-tokenized) |
|---|---|---|
| four corpus-wide terms | **119 ms** | 323 ms |
| `handle4217` — one rare token, 2 hits | **13.9 µs** | 83 µs |
| `Handle4217Item3` — what a user types | **40.9 ms** | 110 ms |

The in-process index is faster on every shape. Two errors had to be corrected to see that:

1. **Scale was measured with one query**, which hid that cost tracks the query's most common term.
   `splitIdentifier` cuts on case and underscore, so `Handle4217Item3` carries `item3` — in every
   file — and the scoring loop walked every posting of every term. Fixed in `CTX-A01d3`: 75.5→40.9 ms.
   MaxScore cannot do better, because it cannot start skipping until k candidates exist and only two
   documents carry the rare terms; the other eighteen can only come from `item3`. **That is inherent
   to returning k results, not a defect.**
2. **The two engines were answering different queries.** FTS5 stored raw text, where the identifier is
   one token matching 2 documents — reported as 115 µs against 75.5 ms. Given the same three-term
   query and the same k, FTS5 takes **110 ms**. A comparison across two tokenizations is not one.

So latency is settled and is *not* an argument for an engine. What remains is **memory**: ~880 MB
resident at 100k files, rebuilt from scratch at every launch. ADR-0102 now recommends FTS5 for that
alone, and states the price — ~2.7× latency — rather than presenting it as a straight win. Deferring
the engine entirely is recorded as a defensible alternative below ~20k files.

**Tokenization is a compatibility constraint, not just a performance one.** FTS5's `unicode61` splits
`snake_case` on the underscore but **not** `camelCase`, so storing raw source satisfies half of L6 and
silently fails the other half (`porter` and `ascii` likewise; `trigram` has no usable term ranking).
Pre-tokenizing with the existing `tokenize` before insert fixes it completely, acronym runs included,
and loses nothing — `Match` carries path/span/score, and snippets come from the file through `Cite`.

**ADR-0102 was revised the day it was written**, before acceptance, on two counts: it cited PRD §6.1
for the local retrieval stack (that is §40.2; §6.1 is the Release A IDE section), and it recommended
an engine for a latency problem that is not an engine problem. See its revision history.

The benchmarks stay as the gate, and `BenchmarkLexicalQueryShape` must stay a **shape** benchmark —
a single query measured this decision wrong once already.

**ADR-0103 — the store was never the open question**

ADR-0102 treated "is SQLite adopted for local metadata?" as undecided. It is not: **PRD §40.2** fixes
it, under a preamble declaring those defaults *locked unless an ADR proves a compatibility-preserving
correction is required*. Two other passages read as permissive (§24.1 "Embedded or local
PostgreSQL-compatible store"; Appendix A "SQLite **or** embedded PostgreSQL-compatible option"), but
Appendix A disclaims itself as non-mandatory and §24.1 is a packaging inventory. §40.2 governs.

What *is* open is the driver, which the pack does not name. Both were measured:

| | `modernc.org/sqlite` (pure Go) | `mattn/go-sqlite3` (cgo) |
|---|---|---|
| Non-stdlib packages compiled in | **37** (25 are `modernc.org/libc`) | **1** |
| Pulls `net` / `os/exec` | **yes / yes** | no / no |
| Cross-compilation | works everywhere | C toolchain per target |
| Query, four common terms @50k | 1,318 ms | 326–362 ms |

Both results cut against the intuitive reading. The pure-Go driver is 3–4× slower — it is SQLite's C
transpiled over an emulated libc, and the emulation is not free. And it is the option that **expands**
the trusted surface: `modernc.org/libc` emulates sockets and process control, so it drags in `net` and
`os/exec` whether or not SQLite calls them, while the cgo driver adds one package and neither import.
`pkg/index/boundary_test.go` already fails the build on both, and **LCL-4** requires Local Private and
Offline to pass automated zero-egress qualification.

ADR-0103 therefore recommends the cgo driver with pure-Go retained as a build-tagged fallback — the
cost is build infrastructure, which `EXE-A01c` needs anyway, rather than runtime and audit surface in
the exact dimension LCL-4 measures. **Its weakest claim is the one it asserts rather than measures:**
no cross-compilation was attempted, and that is the first thing to verify before acceptance.

Consequence worth noting: the SQLite-backed `LexicalIndex` **cannot live in `pkg/index`**, whose own
boundary test forbids `database/sql`. The port stays; the adapter goes in a sibling package. The
boundary named the constraint before any code was written against it.

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

**CTX-A01e symbol protocol (G1–G8)**

CTX-5's symbol and graph channels. dev-06 places tree-sitter behind it with a per-language grammar
pack, which is a cgo dependency and an ADR. What ships now is the port plus a Go extractor built
entirely on the standard library — a real implementation rather than a placeholder, since this
repository is Go and the channel is useful the day it lands.

| # | Invariant |
|---|---|
| G1 | A symbol indexed for one revision is never returned to a query on another |
| G2 | Only indexable content is parsed |
| G3 | Parsing never executes repository code |
| G4 | A removed path never appears in a later result |
| G5 | Re-indexing a path replaces its symbols and edges |
| G6 | Results are deterministic |
| G7 | Every symbol and edge carries the path and span a citation needs |
| G8 | A file that cannot be parsed degrades visibly and does not abort the batch |

All eight are mutation-verified.

| # | Decision | Rationale |
|---|---|---|
| 115 | Symbol extraction uses `go/parser` and `go/ast`, and **never** `go/types` | CTX-12 forbids indexing from executing repository code, and Go's own tooling makes that easy to violate by accident: `go/build` shells out through `os/exec`, and `go/importer` can invoke a compiler. Declarations are recoverable from the syntax tree alone, so a type checker buys resolution this channel does not promise and costs the guarantee that indexing executes nothing. |
| 116 | G3 is enforced by the dependency guard, not by discipline | `TestSecurityIndexPackageCannotReachTheNetwork` now also fails on `go/build`, `go/importer`, and `plugin`. The guard written for the embedding boundary turned out to be the right mechanism for CTX-12 as well — both are statements about what this package is allowed to reach, and both were previously comments. |
| 117 | A symbol's span covers its **doc comment** | A citation of a function without its doc comment routinely omits the one sentence that answers the question being asked. A grouped declaration prefers the spec's own doc, so one constant in a block cannot claim the whole block's comment. |
| 118 | Only `imports` edges, not calls or implements | dev-06 lists calls, inherits, implements, and references too, but those need scope and binding resolution across files — CTX-B01's deep graph. An import is exact, static, and derivable from one file, so it is the edge this channel can assert rather than estimate. An edge carries its span because CTX-7 wants links attributable, and the line that creates the dependency is what a reviewer needs. |
| 119 | Lookup takes a bare **or** qualified name against one index | `Close` on two types is the case a bare-name index gets wrong and the one a user hits constantly. Filtering one map beats maintaining two that can disagree. |
| 120 | A file that fails to parse is **retracted**, not left stale | A repository mid-edit routinely holds one. Keeping the previous symbols would answer lookups with declarations at spans that no longer point anywhere, which is worse than answering nothing. |

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

| QA-A01 | Foundation qualification — Capability Registry, client/API event conformance, secret tests, performance gates, benchmark smoke | 🚧 In Progress — capability-evidence gate (QA-A01a) and performance gates (QA-A01c) Qualified; event conformance (QA-A01b) covers R-EVT-01, with R-EVT-04/05/06/08 blocked on a durable store |

### SET-A01 breakdown

| ID | Task | Requirements | Status | Evidence |
|---|---|---|---|---|
| SET-A01a | Registry, scope resolver, merge strategies, validation | SET-1..SET-7 | ✅ Qualified | delivered as FND-06/07 |
| SET-A01b | Local settings files — discovery, scope binding, diagnostics | §20A.10, SET-2 | ✅ Qualified | `pkg/settings/files.go`, 9 tests; F1–F8 mutation-verified |
| SET-A01c | UI metadata on definitions — label, group, order, widget | §20A.6 | ✅ Qualified | `pkg/settings/ui.go` + generator; 9 tests; U1–U6 mutation-verified |

**SET-A01b local settings files (F1–F8)**

One authored settings document travels with the repository, and that single fact shapes the whole
design: a committed settings file is content a contributor chose, which makes it untrusted input
(TNT-1) that the product reads and acts on. The resolver already refuses a lower scope weakening a
higher-scope security setting; the loader's job is to make sure a file can never be *presented* as a
scope it did not come from.

| # | Invariant |
|---|---|
| F1 | A file's scope comes from its location, never from its contents |
| F2 | A repository-committed file can never author a policy scope |
| F3 | An unreadable, oversized, or malformed file is a diagnostic, never a silent default |
| F4 | Unknown keys are preserved and reported |
| F5 | Files are read only from declared locations; a symlink out is refused |
| F6 | A file may only author settings whose definition permits that scope |
| F7 | Discovery order and diagnostic order are deterministic |
| F8 | A missing file is an ordinary outcome, not an error |

All eight are mutation-verified. F7 took two rounds: the first test checked *file source* order, which
comes from a static slice and would be stable with no sorting at all, so it could not catch an
unsorted key walk. The added assertion loads a multi-key file twenty times and requires the
diagnostics to be sorted and identical.

| # | Decision | Rationale |
|---|---|---|
| 175 | The scope is checked against a **closed set** before the file is read | Policy scopes are absent from `fileScopes`, and that absence is the control. A repository able to author `product_safety` or `enterprise_policy` would be publishing its own constraint envelope — the inversion the scope hierarchy exists to prevent, and one the resolver alone cannot stop because it trusts the scope the layer declares. |
| 176 | A malformed file contributes nothing and says so **loudly** | Falling back to defaults silently would leave a user believing their configuration is in force when it is not. For a security setting that is the worst available outcome, so the diagnostic is an error rather than a warning. |
| 177 | A symlinked settings file is not followed | A repository can commit a link, and following one would read a file the repository chose from somewhere the layout never declared — the same reasoning as CTX-A01b decision 52 for the indexer. |
| 178 | Layout paths are joined to a resolved root, never taken from a document | No value inside a settings file can redirect the loader at another path. |
| 179 | Discovery order is a slice, not a map | It decides which file wins when two author the same key at one scope, and a map would make that vary per run — the same defect as B-9 in the index ignore files. |

**SET-A01c UI metadata (U1–U6)**

§20A.6 requires a settings surface to render every key without hardcoding a list, because a
hardcoded list is one that silently omits the setting added last week.

**Where the metadata lives was the structural decision.** It goes in `contracts/settings/*.yaml`
rather than a separate presentation contract: two contracts would be two files that can disagree
about which keys exist, which is exactly what the drift gate exists to prevent, and the repository
already treats `contracts/settings/` as the single authority for Go and TypeScript alike.

**Most of it is derived.** A label, group, and widget follow from the key and the type, so a new
setting is renderable the moment it is declared. The alternative — 54 hand-written labels — has some
fraction wrong within a release, and nothing to notice. Only what derivation cannot know is
declared: whether a control belongs behind an "advanced" disclosure is a product judgement, not a
property of its key.

| # | Invariant |
|---|---|
| U1 | Every definition has renderable metadata; there is no unrenderable setting |
| U2 | Derivation is deterministic: one key and type always give one label, group, and widget |
| U3 | A declared value always wins over a derived one |
| U4 | A widget is compatible with the type it renders |
| U5 | Ordering within a group is total and stable |
| U6 | Security class and change effect reach the surface |

| # | Decision | Rationale |
|---|---|---|
| 180 | UI metadata lives in the **settings contract**, not a second document | Two contracts can disagree about which keys exist. One contract with a drift gate cannot. |
| 181 | An incompatible widget is refused at **generation** | A string list rendered as a toggle is not cosmetic: the surface would write a boolean into a setting whose merge is `union`, and the resolver would reject it at the worst possible moment. |
| 182 | Order defaults to **declaration order in the contract file** | That sequence is already reviewed — the author grouped related keys together — so it beats anything derivable from the key and costs nothing to carry. |
| 183 | `Sensitive()` surfaces the security consequence | A `critical` setting rendered as an ordinary toggle tells the user nothing about what they are changing. The registry cannot force a surface to render well, but it can refuse to let one claim it did not know. |
| 184 | The generator **duplicates** the widget and initialism tables, and a test compares them | The non-test generator importing `pkg/settings` would make a clean-tree build circular: producing `definitions_gen.go` would require the package that requires it. A test in the generator's package has no such problem, so that is where the duplication is kept honest. Comparing only the keys in the registry was not enough — an unused initialism can drift for releases before a key needs it, so the guard walks both tables directly. |

### QA-A01 breakdown

| ID | Task | Requirements | Status | Evidence |
|---|---|---|---|---|
| QA-A01a | Capability-evidence gate — every cited test must exist; orphaned security tests reported | R-TST-01, R-TST-05 | ✅ Qualified | `tools/modbitgen/evidence.go`; 193 cited tests verified, 0 orphans |
| QA-A01b | Client/API event conformance | R-EVT-01..08 | 🚧 In Progress | `pkg/event/conformance` — the shared `Sequencer` suite (E1–E9) covering R-EVT-01 and the gap-freedom R-EVT-07 rests on, plus capability `run.event_log` registering 17 previously uncited event tests. R-EVT-04/05/06/08 need a durable store — see below |
| QA-A01c | Performance gates and benchmark smoke | PRD §7, §8A.3 | ✅ Qualified | `pkg/index/perf_test.go` + `make perf-gate`. LCX-2/3/4 measured as p95 per PRD §8A.3, per repository class, each budget marked enforced or known gap. Found and fixed an O(vocabulary)-per-edit defect in `retract` — see below |

**QA-A01b — the sequencer that matters is the one that does not exist yet**

`MemorySequencer` had four tests. It is also not the implementation whose failure would corrupt an
audit log: the authoritative one allocates inside the same transaction as the state write and the
outbox insert. Assertions written against the in-process implementation alone would mean the
implementation that actually needs them is the one that never ran them.

So R-EVT-01 now lives in `pkg/event/conformance` as a suite (E1–E9), the same shape as the inference
adapter and sandbox backend suites, and `MemorySequencer` is its first subject rather than its owner.
E9 (resume is not retrograde) is probed as an optional capability and reported **Skipped** — not
passed — when a sequencer cannot resume, because a capability that was never exercised has not been
shown to work.

**The suite is checked against a deliberately broken sequencer**, because a conformance suite that
cannot fail certifies whatever it is given. The fixture does a read-modify-write without holding the
lock across both halves — a *lost update*, not a data race, deliberately: a real race would be caught
by `-race` before the suite reported anything, and the test would then be measuring the race detector.
It is also the bug a store-backed sequencer actually ships with (SELECT, add one, UPDATE, no
transaction). E6 catches it, stable over 50 race-enabled runs. Five mutants of `MemorySequencer`
were caught: unpersisted allocation, retrograde resume accepted, cancellation ignored, non-run
identifier accepted, and a `Current` that advances.

Registering capability `run.event_log` also brought **17 event tests into the registry that were
cited by nothing** — the package predates QA-A01a's gate, and the gate only reports orphaned
`TestSecurity*` tests, so ordinary uncited tests had stayed invisible.

**What is left needs a durable store, not more test design.** R-EVT-04 (transactional outbox),
R-EVT-05 (idempotency keys), R-EVT-06 (single active transition lease), and R-EVT-08 (artifacts
durable before a step completes) are all properties of persistence. They are blocked behind ADR-0103
with `CTX-A01d2` and `CTX-A01f2`, and writing conformance cases for them now would be writing them
against an imagined API.

**QA-A01c — the gate found an O(vocabulary) defect on its first run**

`test-benchmark-smoke` ran every benchmark and asserted nothing, so PRD §8A.3's budgets were
documented and unmeasured. `make perf-gate` now measures them as **p95** — the form the PRD states
them in, and not what a benchmark's mean reports — per repository class (§8A.3: Small ≤10k files,
Standard ≤100k), with each budget marked `enforced` or `known gap`. A known gap is logged loudly,
does not fail, and **fails if it starts passing**: an unrecorded commitment is how the next
regression goes unnoticed.

Its first run did not report a number, it **hung for twenty minutes**. `partition.retract` scanned
every posting list in the partition to delete one document's entries — invisible at test-corpus size
and, on a Standard repository with millions of distinct terms, seconds per edited file. LCX-3 gives
incremental edits a 500 ms budget. Fixed by recording each document's own posting lists so retraction
touches only those; `retract` went from O(vocabulary) to O(terms in the document).

The representation mattered more than the fix. Storing the terms as strings cost **+400 MB** on a
50k-file corpus — the (document, term) pairing is what `postings` already holds, and a second copy at
a string header apiece nearly doubled the index. Interned ids needed a second map over the same keys.
Storing the posting-list pointer needs no side table at all: **+18% memory** (9.4 → 11.1 KB/file) to
remove the scan.

Measured on an idle M2, Go 1.24:

| | Small (10k files) | Standard (100k files) |
|---|---|---|
| Resident | 106 MB | **994 MB** |
| LCX-2 initial indexing (budget 90 s) | 5.1 s ✅ | **2 m 45 s** ⛔ |
| LCX-4 warm retrieval p95 (budget 50 ms) | 40.4 ms ✅ | **383 ms** ⛔ |
| LCX-3 incremental edit p95 (budget 500 ms) | 8.7 ms ✅ | 7.4 ms ✅ |

994 MB confirms ADR-0102's ~880 MB extrapolation, and the per-shape breakdown confirms its diagnosis:
at Standard scale a rare token answers in **797 µs** while corpus-wide terms take 484 ms. Selectivity,
not scale, decides retrieval cost.

**Two caveats on the numbers.** These are wall-clock budgets and need a quiet machine — an early run
reported LCX-4 at 286 ms where the idle figure was 21 ms, entirely from concurrent benchmark
processes; the gate's promote-me error is what surfaced it. And Small's aggregate sits at 40 ms
against a 50 ms budget, close enough that it will be the first thing to go flaky.

**QA-A01a — the registry could lie about its own evidence**

The Capability Registry already required every capability to cite tests. It did **not** check that
the cited tests exist. A renamed or deleted test left the capability citing evidence that was not
there, and the registry went on reporting the capability as covered — an assertion without evidence
wearing the costume of a control, which is the one failure mode this registry exists to prevent.

The gate parses every `_test.go` with `go/parser` (never `go/build` or `go/importer`, which shell
out — the same CTX-12 reasoning that constrains the symbol extractor) and resolves every
`package:TestName` reference. Non-Go references must match a declared external form, so a typo
cannot pass as an external suite.

**What it found immediately**, all of it real:

- **Two shipped capabilities had no registry entry at all** — `pkg/agent` (AGT-A01, 4 sub-items) and
  `pkg/sandbox` (EXE-A01a). Both are now registered as `agent.run` and `execution.sandbox`.
- **Four `pkg/index` security tests from CTX-A01h were never cited**, including snapshot corruption
  detection and manifest exclusion. Added.
- **Two `pkg/policy` taint tests were uncited.** Added.

Verified in three directions: a renamed test fails, a deleted test fails, and a typo'd external form
fails. Registry now stands at 7 capabilities, 193 cited tests, 0 orphaned security tests.

| # | Decision | Rationale |
|---|---|---|
| 173 | Missing cited evidence is **fatal**; an orphaned security test is **reported** | A capability citing a test that does not exist is claiming coverage it cannot support, and that must break the build. An uncited `TestSecurity...` is a weaker signal — it may belong to a capability not yet registered — and failing the build for it would push authors toward not writing the test, which is the opposite of what the report is for. |
| 174 | External evidence forms are an **allowlist**, not a fallback | Treating "anything without a colon" as an external suite would let `pkg/agnet:TestFoo` pass as one. Only `conformance/` and `security/` are declared, so a typo is caught rather than absorbed. |

### EXE-A01 breakdown

| ID | Task | Requirements | Status | Evidence |
|---|---|---|---|---|
| EXE-A01a | Backend contract, SBX-5 conformance suite, portable process backend | SBX-1..SBX-6, EXE-7, EXE-9 | ✅ Qualified | `pkg/sandbox`, 12 tests; X1–X8 mutation-verified |
| EXE-A01b | Native macOS backend (Seatbelt) | EXE-4, EXE-6 | ✅ Qualified | `pkg/sandbox/seatbelt_darwin.go`, 5 tests; ADR-0101. Enforces filesystem scope and network deny; SBX-5 suite 6 pass / 0 inconclusive |
| EXE-A01c | Native Linux backend (namespaces + seccomp) | EXE-4, EXE-5, EXE-6 | ⬜ Ready | Achievable via `syscall` without a dependency; cgroup v2 for EXE-5 |
| EXE-A01d | Container and microVM backends | SBX-1, SBX-4 | ⬜ Proposed | ADR-0100 open decision 4 (microVM technology) |

**EXE-A01b macOS confinement (ADR-0101)**

`EXE-A01a` left macOS — the platform an IDE actually runs on — with no enforced filesystem scope and
no enforced network deny. ADR-0101 resolves ADR-0100's open decision 1 by adopting `sandbox-exec`.

**Measured before deciding**, on macOS 26.5.1: a write outside the workspace is refused by the kernel
rather than by a shell check, a write inside is permitted once the profile names the symlink-resolved
path, and an outbound connect under a deny-network profile is refused. No cgo, no dependency.

The accepted risk is that Apple deprecated the interface. There is no supported replacement for
per-command confinement of a child process, and the alternative reaches the *same* deprecated
mechanism through cgo. The mitigation is structural: it is a `Backend` behind SBX-1, so replacing it
is one implementation rather than a migration, and `NewSeatbeltBackend` probes for the binary and
refuses rather than degrading silently.

**Three defects the work surfaced, all found by the suite rather than by review:**

| # | Defect | Fix |
|---|---|---|
| B-13 | `Establish` delegated to the process backend **with `Required` intact**, so the inner backend re-ran the requirement check against its own weaker capabilities and refused the very controls this backend exists to add | The inner spec clears `Required` and `MinimumStrength`; the outer check already ran against the stronger capabilities |
| B-14 | The profile allowed writes to `/private/var/folders` for toolchain temp files, which made "filesystem scope enforced" **false** — the suite's escape probe writes to `os.TempDir()` and succeeded | Temp writes are confined to `<workspace>/.modbit-tmp` with `TMPDIR` pointed at it, so the claim and the profile agree |
| B-15 | The suite's `network_deny` probe was Inconclusive, which blocked readiness the moment a backend genuinely claimed the control | A real probe: the suite binds its own loopback listener, verifies it is reachable from outside the sandbox, then requires the confined command to be refused. A public address could not distinguish a denied egress from an unreachable host |

B-15 is the suite's design working exactly as intended. "A declared control the suite cannot
demonstrate is Inconclusive, and Inconclusive blocks readiness" was written to catch an over-claiming
backend; what it actually caught first was a **missing probe**, which is the same statement from the
other side.

| # | Decision | Rationale |
|---|---|---|
| 185 | The workspace path is **symlink-resolved** before the profile is generated | A profile's `(subpath ...)` matches the resolved path, so a workspace under `/var/folders` is not matched by a rule naming `/var/...` — the kernel sees `/private/var/...`. The unresolved path produces a profile that denies everything including the workspace itself: a sandbox that looks configured and breaks the run. |
| 186 | A path containing SBPL syntax is **refused**, not escaped | SBPL is Lisp-like, and a workspace path is attacker-influenced when a run is pointed at a checked-out repository. An unescaped quote or paren would close the string and let the remainder become profile *source* — arbitrary sandbox rules chosen by whoever named the directory. Escaping is a thing to get subtly wrong once; refusal is not, and a directory whose name requires escaping is not one Modbit needs to confine. |
| 187 | Strength stays `StrengthProcess` | `sandbox-exec` confines a process, it does not virtualize one. Claiming `StrengthContainer` would let a profile demanding container isolation select something that is not one (SBX-4). |
| 188 | Reads stay broad; only **writes** are scoped | A build reads toolchains, headers, and libraries from all over the system, and narrowing that is a compatibility project rather than a confinement one. What must not leave is covered by the egress deny and by the classifier deciding what is ever read into an index. |
| 189 | `(deny network*)` is kept although `(deny default)` already covers it | Measured both ways: deny-default with no network line refuses a connect, and allow-default with only the network line also refuses one. The explicit line is what keeps egress denied if the default is ever loosened for a compatibility reason, and it is labelled so the next reader does not delete it as redundant. |
| 190 | `Run` delegates to the process backend rather than re-implementing execution | Working-directory resolution, environment replacement, hook suppression, and cancellation stay in one place. A second copy would drift, and the copy that drifted would be the confined one. |

**EXE-A01a sandbox protocol (X1–X8)**

SBX-1 requires every backend — native, container, microVM — to implement one versioned contract, and
SBX-3 is why the contract looks the way it does: a backend must not report a policy as enforced when
it is advisory, so enforcement level is a declared per-control value rather than a boolean the caller
infers.

| # | Invariant |
|---|---|
| X1 | A backend declares an enforcement level for every control; there is no default |
| X2 | A control a backend cannot enforce is never reported as enforced |
| X3 | A spec requiring a control the backend does not enforce fails closed at establishment |
| X4 | Degraded isolation requires an explicit, recorded permission |
| X5 | Every backend answers one versioned contract |
| X6 | Isolation strength is ordered, so a profile can require a minimum |
| X7 | The conformance suite covers all ten SBX-5 areas |
| X8 | An unexercised conformance claim is not a pass |

All eight are mutation-verified.

**The portable backend's weakness is the deliverable.** Go's standard library offers no portable way
to confine a child's filesystem access, deny its egress, or cap CPU and memory: `syscall.Setrlimit`
applies to the calling process rather than a child, and darwin's `SysProcAttr` carries no namespace,
seccomp, or rlimit fields at all. A backend that set a working directory and called that "filesystem
scope" would be reporting an advisory arrangement as an enforced one — precisely what SBX-3 forbids.
So `ProcessBackend` declares filesystem scope and process confinement **advisory**, CPU, memory,
process, disk, and network **unsupported**, and only wall-clock and hook suppression **enforced**;
the contract then makes that honesty consequential, because a profile requiring confinement cannot
establish against it and one requiring container strength cannot select it.

| # | Decision | Rationale |
|---|---|---|
| 165 | Enforcement is a **per-control declared level**, not a boolean | SBX-3 distinguishes enforced from advisory, and a boolean cannot carry that distinction. `EnforcementUnsupported` is the zero value so a control omitted from a capability map reads as "not enforced" — the only safe reading of no answer, and the third instance of this pattern after `taint.Class`'s zero and `VerifierStatus`'s. |
| 166 | `Enforces()` is a method | `!= unsupported` is the easy thing to write and it silently accepts advisory, which is the exact conflation SBX-3 forbids. One method means one place to get it right. |
| 167 | `Check` is a shared function, not per-backend logic | SBX-1's "same versioned contract" is worth little if each backend decides for itself what "required" means. Fail-closed establishment lives in one place that every backend calls. |
| 168 | Degradation needs `AllowDegraded` **and** a rationale, both recorded on the session | SBX-6 permits degraded isolation only where a documented policy explicitly says so. A boolean on its own is a switch somebody flips during an incident with nothing to show afterwards. |
| 169 | `AllowDegraded` cannot bypass `MinimumStrength` | Strength is what a high-risk profile is choosing, not a control it is trading away. A microVM requirement satisfied by "allow degraded" would make SBX-4 advisory. |
| 170 | A declared-but-undemonstrated control is **Inconclusive**, not Skipped | Skipped would let an over-claiming backend look clean; Pass would be the SBX-3 violation itself. A control honestly declared unsupported is Skipped, because there is no claim to check — so honesty is rewarded and over-claiming is caught. `TestSecurityAnUnexercisedClaimBlocksReadiness` runs the suite against a deliberately over-claiming backend to prove it. |
| 171 | Cleanup removes only what the backend created | Deleting a caller-supplied workspace would destroy a user's checkout. Cleanup is idempotent, and a cleaned-up session refuses to run anything, since its workspace may be gone. |
| 172 | The child's environment is **replaced**, not inherited | EXE-7 disables repository-defined hooks, and the same mechanism closes a wider hole: a credential in the operator's shell must not reach repository code. Git is pointed at an empty `core.hooksPath` via `GIT_CONFIG_*`, which a repository's own config cannot override. |

### AGT-A01 breakdown

| ID | Task | Requirements | Status | Evidence |
|---|---|---|---|---|
| AGT-A01a | Run state machine — phases, modes, halt reasons, bounded loops, checkpoints, resume | RUN-1..RUN-6, COR-5 | ✅ Qualified | `pkg/agent/run.go`, 14 tests; A1–A9 mutation-verified |
| AGT-A01b | Typed tool registry — versioned schemas, policy-gated invocation, taint propagation into results | TLS-1..TLS-7, INV-13 | ✅ Qualified | `pkg/agent/tool.go` + `schema.go`, 14 tests; T1–T9 mutation-verified |
| AGT-A01c | Steering queue — ordered, durable, safe-boundary application, Interrupt Now | STR-1..STR-7 | ✅ Qualified | `pkg/agent/steering.go`, 12 tests; Q1–Q8 mutation-verified |
| AGT-A01d | Completion contract — four verifier states, evidence record, revision-bound verdict | VER-1, VER-2, VER-6 | ✅ Qualified | `pkg/agent/completion.go`, 10 tests; P1–P7 mutation-verified |

**AGT-A01a run protocol (A1–A9)**

PRD §11.1 specifies a durable workflow graph rather than an unbounded chat loop, and that distinction
is the whole design: a chat loop has no phase to checkpoint, no transition to emit, and no bound to
exhaust, so none of RUN-1 through RUN-6 can be stated about it, let alone enforced.

| # | Invariant |
|---|---|
| A1 | Every transition emits exactly one event, written with the state change |
| A2 | A run halts for exactly one reason from RUN-4's closed set, and a halted run cannot transition |
| A3 | A run cannot enter a phase its mode's plan does not contain |
| A4 | Loops are bounded; exhausting the budget halts rather than spinning |
| A5 | Every phase entered produces a checkpoint |
| A6 | Resume is refused when the environment or inputs changed |
| A7 | An illegal transition is refused and emits nothing |
| A8 | A cancelled or superseded run records the phase it interrupted |
| A9 | Ask mode can never reach execute |

All nine are mutation-verified.

| # | Decision | Rationale |
|---|---|---|
| 131 | A mode is a **phase plan**, not a permission flag | §11.1 says not every workflow requires every phase, and the differences *are* the modes' meaning. Making the plan the authority is what turns "Ask is read-only" from a rule somebody remembers into something structural: `execute` is absent from Ask's plan, so there is no transition to refuse. `TestSecurityAskModeCanNeverExecute` checks both the refusal and the plan's contents, because a runtime check standing in for a structural guarantee is the weaker of the two. |
| 132 | `Mode` carries all six values from the settings enum, and three are refused **by name** | `agent.default_mode` is the contract and the authority. A type with only the implemented three would make a valid setting unrepresentable; falling back to an implemented mode would run something the user did not choose. `MODBIT_CAPABILITY_UNAVAILABLE` says "not yet" rather than "unknown". |
| 133 | Exhausting the loop budget **halts** rather than refusing | A run that could not loop and could not stop would sit at a failing phase forever, and RUN-3's bound would be a number nothing enforced. The halt is a real outcome a caller can report. |
| 134 | Only declared backward edges are loops at all | An arbitrary jump backwards would let a run re-enter `authorize` after executing, which is how an approved plan quietly becomes a different one. Forward skips are refused for the same reason: `authorize` is the one phase whose omission changes what the run is allowed to do. |
| 135 | The checkpoint is taken on **entry** to a phase, not exit | A run that dies mid-phase then resumes at the start of that phase rather than at the end of the previous one — the difference between redoing a phase and skipping it. |
| 136 | A checkpoint carries `LoopsUsed`, and resume restores it | Without it, resume is an unbounded-loop primitive: fail, resume, fail, resume, with RUN-3's bound never reached. `TestSecurityResumeCannotResetTheLoopBudget` pins it. |
| 137 | Resume compares an environment **digest**, not a caller's assurance | RUN-5 and RUN-6 need a value to compare. Resuming into a moved tree would apply a plan built for one revision to another and nothing downstream could tell — the run would look like it had simply continued. Revision, worktree, tool surface, and policy snapshot all participate. |
| 138 | A failed emit **rolls back** the phase | R-EVT-04 makes the state write and the event one act. A run that advanced while its event was lost is the exact divergence the rule prevents, so the transition is undone rather than reported as done. |
| 139 | Halt reasons map onto **distinct** canonical events | A consumer filtering the audit log for failures must not also catch deliberate cancellations. Completion, failure, and cancellation keep their own types; the remaining five share `run.halted`, which carries the reason. |
| 140 | `emit` takes no payload map | The canonical envelope carries payloads by reference (`Attributes.PayloadRef`), not inline. A map accepted and discarded reads as though the detail were recorded, which is worse than not offering it — the first draft did exactly that. What a halt records lives in the `Halt` value and the event type. |

**AGT-A01d completion protocol (P1–P7)**

VER-1, VER-2, VER-6. The contract decides whether a run may legitimately halt as `completed`. The
four verifier states exist because two would not be enough: a check that did not run and a check that
ran and passed are the same shape to anything recording booleans, and that conflation is how
unverified work ships as verified.

| # | Invariant |
|---|---|
| P1 | A verifier status is one of VER-6's four; the zero value is `not_run`, never `passed` |
| P2 | `not_run` and `inconclusive` never count as passed |
| P3 | A contract completes only when every required check passed |
| P4 | Evidence records revision, environment, command, timestamps, and exit state |
| P5 | Evidence output is bounded and its digest covers the whole |
| P6 | A required failure halts as failed; a required gap halts as inconclusive |
| P7 | Evidence from another revision does not satisfy a check |

All seven are mutation-verified.

| # | Decision | Rationale |
|---|---|---|
| 158 | `not_run` is the **zero value** of `VerifierStatus` | A status field left unset must mean "nothing happened here". The alternative — an unset field that reads as a pass — is exactly the failure four states exist to prevent, and it is the same trap as `taint.Class`'s zero being `user_trusted` (decision 47). |
| 159 | `Satisfies()` is a method, not a comparison at each call site | `== VerifierPassed` is easy to write and `!= VerifierFailed` is easier — and the second silently accepts both `not_run` and `inconclusive`. One method means one place to get it right. |
| 160 | A failure **outranks** a gap | If anything is known to be broken, that is the finding to report. The two are otherwise distinct outcomes because the recovery differs: a failure needs the work fixed, a gap needs the check run. |
| 161 | Evidence is bound to a revision, checked **before** the status | Evidence gathered before an edit proves nothing about the tree after it, and a *passing* result from another revision is the most convincing-looking way for stale evidence to slip through. Checking the revision after the status switch would have counted it as a pass. |
| 162 | Later evidence for one check supersedes earlier | A re-run after a fix is the answer, not an additional opinion. This is also what makes staleness recoverable rather than terminal. |
| 163 | A contract with no **required** check is refused | VER-1 requires every profile to define a contract, and one that gates on nothing is indistinguishable from no verification while looking like governance — worse than admitting a profile is unverified. |
| 164 | Execution details are required only when the check **ran** | A check that did not run has no environment, command, or timing to give. Demanding them anyway would force callers to invent values, which is how a record stops meaning anything. |

**AGT-A01b tool protocol (T1–T9)**

TLS-1 through TLS-7. This is where the policy engine, the taint lattice, and the side-effect ladder
meet a real caller for the first time — each was built against its own tests, and a tool call is the
first thing that drives all three together.

| # | Invariant |
|---|---|
| T1 | A tool with no declared side-effect class cannot be registered |
| T2 | Input is validated before policy is evaluated |
| T3 | A tool cannot receive a provider credential |
| T4 | Every call produces a record carrying actor, policy decision, timing, and result hash |
| T5 | A tool error is a structured value, never prose |
| T6 | Tool output is untrusted; a result is at least `tool_result` provenance |
| T7 | Oversized output is truncated with a handle, never silently dropped |
| T8 | A denied decision means the tool is never invoked |
| T9 | A schema is versioned, and input is validated against the version being invoked |

All nine are mutation-verified.

| # | Decision | Rationale |
|---|---|---|
| 148 | An undeclared side-effect class is refused at **registration**, not at call time | A tool nobody classified is one nobody decided the risk of. Discovering that mid-run means discovering it after the plan was approved, when the cheapest remaining option is to halt. |
| 149 | Validation runs **before** policy evaluation | TLS-2 states the order, and the reason is that a decision is an audited artifact (INV-7): minting one for a call that was never going to run fills the record with authorizations nothing acted on. The test asserts both that the tool was not reached *and* that no decision was minted. |
| 150 | `additionalProperties: false` is enforced, and undeclared properties are refused | The input comes from a model. A tool that quietly ignores an extra field lets a prompt injection carry an argument the schema author never anticipated — the refusal is a prompt-injection control, not a tidiness one. |
| 151 | The validator **refuses what it cannot check** | Full JSON Schema is a specification, not a function, so `BasicValidator` covers the subset tool schemas use and `Supports` reports anything else. A constraint the author wrote and nothing enforces is worse than no constraint, because it reads as one. Adopting a real validator is a dependency decision under R-GO-09 and stays behind the `SchemaValidator` port. |
| 152 | `Tool.Invoke` takes an input document and nothing else | TLS-7. There is no parameter, field, or context value through which a provider credential could reach a tool. The credential boundary is an explicit argument on adapter methods (MOD-A01 decision 10) precisely so every place one travels is visible, and a tool is not one of those places. |
| 153 | Recorded provenance is **raised**, never lowered | INV-13. A tool declaring its own output `user_trusted` would launder whatever it read — a file, an HTTP response, a subprocess's stdout — into the class the agent acts on without question. A *higher* class is preserved, so a tool that knows its output is a web fetch can say so. |
| 154 | The result hash covers the **whole** output, not the truncated record | TLS-5 truncates for the context budget and the event log; a hash over the truncated part would make the record prove only what happened to fit. A failed artifact store fails the call rather than returning a quietly incomplete result. |
| 155 | The operation hash covers the tool's **versioned identity and its input** | SFX-3/SFX-4 bind an approval to an exact operation. Hashing the name alone would let an approved "run tests" become an approved "run anything" the moment the arguments changed. |
| 156 | Re-registering a name is a conflict, not a replacement | Silent replacement would let a later registration change what an already-approved plan authorized, under the same name. Two schema versions of one tool are therefore separate registrations, not an in-place upgrade. |
| 157 | `MaxOutputBytes` is a constant, not a setting | It protects the run's own context budget and the event log, neither of which is an operator preference — and a configurable limit is one somebody raises to make a symptom go away. |

**AGT-A01c steering protocol (Q1–Q8)**

STR-1 through STR-7. The queue exists because a message arriving mid-run has to land *somewhere*
definite: a design that applied user input wherever the agent happened to be reading would make "was
my correction taken into account" unanswerable, which is what STR-2 exists to prevent.

| # | Invariant |
|---|---|
| Q1 | The queue is ordered, and the order is stable across reads |
| Q2 | A message has exactly one state; pending is the only state that can change |
| Q3 | Queued steering applies only at a safe boundary |
| Q4 | An interrupt is distinct from queued steering and records what it interrupted |
| Q5 | Reordering is optimistically concurrent; a stale version is refused |
| Q6 | A message that invalidates an authorization is surfaced, never silently incorporated |
| Q7 | Message provenance is an explicit argument; automation follow-ups are not user-trusted |
| Q8 | Every state change emits a canonical event |

All eight are mutation-verified. Q2 took two rounds: it is guarded in the callers *and* in `resolve`,
so removing either layer alone changes nothing observable and removing both fails the test. That is
recorded in the code as deliberate layering rather than left to look redundant.

| # | Decision | Rationale |
|---|---|---|
| 141 | `execute`, `authorize`, `package`, and `complete` are **not** safe boundaries | STR-3 puts steering at a safe boundary, and a boundary is safe when new instruction cannot corrupt work already in flight. A message applied halfway through a file write changes the intent of an edit already partly on disk, and nothing downstream could tell which half belonged to which instruction. |
| 142 | An unsafe phase yields nothing rather than erroring | The run calls `ApplyAt` at every phase; refusing at `execute` would push the boundary rule onto every caller, which is how it eventually gets got wrong. What must not happen is quiet incorporation, and the map is what prevents that. |
| 143 | An interrupt is a **distinct operation**, not a flag | STR-6. The two have different consequences and different audit meaning: queued steering waits, an interrupt stops something that was running. It applies at a phase that is deliberately not a safe boundary, which is the whole reason it is separate. An interrupt also leaves queued messages pending — stopping the operation is not the same as discarding instructions the user is still waiting on. |
| 144 | Steering arriving after `authorize` is **surfaced and left pending** | It would change the plan the approval was granted against — the same class of problem the approval fence epoch solves (decision 24), applied to instructions rather than effects. It stays pending rather than being rejected, because a user who re-authorizes should still have it. |
| 145 | Provenance is an explicit positional argument | STR-5 lets automations deliver follow-ups through this same contract, so a message is not necessarily user input, and steering is by design content the agent acts on. `taint.Class`'s zero value is `user_trusted`, so a struct field left unset would launder an integration payload into the most trusted class. A positional argument is what Go will not let a caller omit — the same reasoning as MOD-A01 decision 10 for credentials. The `Valid` check guards a *garbage* class, not an unset one, and the code says so rather than implying more. |
| 146 | Reordering moves only pending messages | Reordering the whole queue would rewrite the record of what was applied and when. The version token is what stops two surfaces silently applying one ordering on top of the other, leaving the loser to discover their arrangement was discarded. |
| 147 | A run that ends rejects its pending messages | Leaving them pending forever tells a user their correction is still coming. |

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
| MOD-A01g | First provider adapter — OpenAI chat-completions protocol, covering hosted and local endpoints | §14.1, ADP-5 | ✅ Qualified | `pkg/inference/openai`, 19 tests; O1–O10 stated, security invariants mutation-verified; **18 pass / 0 fail / 0 inconclusive / 0 skipped** on the shared conformance suite |
| MOD-A01h | Provider credential boundary | INV-2, SDD §10 | ✅ Qualified | `pkg/inference/credential.go`, `TestCredentialResistsAccidentalDisclosure` |
| MOD-A01i | Gateway streaming pipeline: S1–S10 protocol, cancellation, backpressure, stall abandonment | SDD §10 | ✅ Qualified | `pkg/gateway/streaming.go`, 16 protocol tests + `stream_terminal_contract` conformance case |
| MOD-A01j | Canonical event emission, written atomically with the metadata | INV-5, R-EVT-04, OEV-1 | ✅ Qualified | `pkg/gateway/events.go`, 9 assertions |
| MOD-A01k | Provider egress allowlist enforced in-process; no-filesystem-mounts remains deployment-level | SDD §10 | ✅ Qualified | `pkg/gateway/egress.go`, 22 assertions incl. metadata-endpoint and DNS-rebind suites |

**MOD-A01g provider adapter (O1–O10)**

One adapter covers hosted providers speaking the OpenAI chat-completions protocol and the local
endpoints — Ollama, vLLM, LM Studio — that reimplement it. They differ in what they support, not in
how they are addressed, and capability records already carry the difference (§14.2), so a second
adapter would only duplicate the translation.

| # | Invariant |
|---|---|
| O1 | The adapter never builds its own HTTP client; egress control belongs to the caller's transport |
| O2 | A credential reaches the Authorization header and nothing else |
| O3 | Every provider failure maps to a stable Modbit code, carrying no upstream body content |
| O4 | A capability gap is a refusal or a declared Loss, never a silent drop |
| O5 | A stream closes exactly once and carries exactly one terminal event |
| O6 | Cancellation abandons the request rather than draining it |
| O7 | A tool call round-trips: id, name, and arguments survive both translations |
| O8 | Media is never inlined without a resolver; without one the part is refused |
| O9 | A token count says whether it is exact or estimated |
| O10 | The observed model revision comes from the response, never from the request |

**The shared conformance suite earned its keep.** MOD-A01e was built against a fake adapter, which
only proved the suite worked. Run against the first real adapter over real HTTP, it failed
`content_types` immediately — and it was right. See decision 124.

| # | Decision | Rationale |
|---|---|---|
| 121 | The HTTP client is a **required** constructor argument | MOD-A01k puts the egress allowlist in the adapter's own transport. A client the adapter built for itself would carry `http.DefaultTransport` and reach any host the process can: the allowlist would still be configured, still be tested, and no longer be in the path. Requiring it means the guard cannot be dropped by omission — it has to be removed deliberately. |
| 122 | An egress refusal is unwrapped back to its policy denial | `net/http` wraps a `RoundTrip` error in a `*url.Error`, which would read as a transport failure. The gateway fails over on retryable classes, so a misclassified denial costs an attempt against a destination that is blocked by definition. |
| 123 | The credential travels in the Authorization header only | A URL is logged by proxies, servers, and Go's own error strings, so a credential in a query parameter is a credential in somebody's log. The upstream error body is drained and discarded for the same reason: provider errors routinely echo the request, including the prompt and occasionally the rejected key. |
| 124 | An unsupported **modality** is a refusal, not a declared Loss | This shipped as a Loss and the conformance suite rejected it. Omitting an image is not a degraded answer, it is an answer to a different question: a user asking what is wrong in a screenshot gets fluent prose about the accompanying text, and the completion looks entirely successful. The Loss would have been recorded truthfully and read by nobody in time. Routing should never send an image to a model without vision, which is precisely why the adapter must hold the line when it happens. |
| 125 | `MediaResolver` is a collaborator, and its absence is a refusal | The IR carries references and never bytes (decision 2), but the protocol needs the bytes, so somebody must fetch them. Making it an explicit port keeps the fetch visible; refusing without one keeps a prompt from being sent with its image quietly missing. |
| 126 | Streamed tool-call fragments accumulate **by index** | The protocol sends the id and name once and the arguments across many fragments. Anything else hands the harness two half-formed calls whose arguments parse as nothing. |
| 127 | Cached and reasoning tokens are **subtracted** from their totals | The protocol reports them as subsets of `prompt_tokens` and `completion_tokens`; the canonical `Usage` keeps all four separate and sums them. Not subtracting bills a cached call twice for the same tokens. |
| 128 | `stream_options.include_usage` is always requested | Without it most implementations stream deltas and never report token counts, leaving every streamed call unbillable — a budget that silently does not apply to streaming is not a budget. |
| 129 | Terminal delivery is one bounded blocking send, shared by both exit paths | Written first as a non-blocking send with a `default:` arm, which drops the terminal event whenever the consumer is briefly busy and closes the channel with nothing. That is B-7 in the gateway, found there by a drain helper enforcing S4. The same trap is one line away in every adapter that streams, so the `drain` helper came across with it. |
| 130 | A text-only message sends a **string**, not a one-element array | Several local implementations reject the array form. This is the difference between working against Ollama and not, and it is invisible until a local endpoint is the thing under test. |

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
