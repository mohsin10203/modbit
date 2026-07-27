# Modbit Implementation Tracker

> **Authority:** PRD v5.1 (`modbit docs/modbit-platform-prd-v5.1.md`). Every task references a
> locked requirement or docket id (R-DOC-01).
>
> **Update rule:** the change that completes a task updates this file in the same commit
> (R-DOC-02). Never delete a task to defer it — move its milestone (R-DOC-04).
>
> **Status values:** `Proposed` → `Ready` → `In Progress` → `Blocked` → `Review` → `Qualified` →
> `Released`. No task is `Qualified` without Capability Registry and acceptance evidence.

**Last updated:** 2026-07-27

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
| CTX-A01 | Local indexing — ignore/classification, watcher, lexical/vector/symbol, branch/worktree, status, citations | 🚧 In Progress — see breakdown below |
| MOD-A01 | Model Gateway v1 — canonical IR, hosted adapter, OpenAI-compatible local endpoint, DLP, metadata, streaming, cost | 🚧 In Progress — see MOD-A01 breakdown below |
| IDE-A03 | Tab completion — FIM, multiline, next edit, latency budget, settings, acceptance telemetry | ⬜ Proposed |
| IDE-A04 | Inline edit — selection/cursor, diff preview, accept/reject/refine, escalation to Code run | ⬜ Proposed |
| AGT-A01 | Local agent — Ask/Plan/Code, typed tools, events, checkpoints, steering, worktree, completion contract | ⬜ Proposed |
| EXE-A01 | Native local sandbox — backend contract, filesystem/network/resource controls, conformance | ⬜ Proposed |
| IDE-A05 | Diff zones — per hunk/file/group, checkpoint comparison, artifact link | ⬜ Proposed |
| BRS-A01 | Local preview browser — server detection, element selection, console errors, screenshot, origin policy | ⬜ Proposed |
### CTX-A01 breakdown

Capability registry entry: `contracts/capabilities/context.classification.yaml`.

| ID | Task | Requirements | Status | Evidence |
|---|---|---|---|---|
| CTX-A01a | Ignore/classification filter — gitignore-compatible matching, hierarchical sources, protected paths, binary/generated/size classification, provenance assignment | CTX-4, CTX-12, TNT-1 | ✅ Qualified | `pkg/index`, 38 assertions |
| CTX-A01b | Hierarchical ignore discovery over a real tree (walking `.gitignore`/`.modbitignore`/`.modbitindexingignore` per directory) | §20A.10 | ✅ Qualified | `pkg/index/walk.go`, 19 tests incl. 4 security suites |
| CTX-A01c | File watcher and incremental reindex within the freshness SLO | CTX-1, CTX-2 | ⬜ Ready | |
| CTX-A01d | Lexical index (Tantivy-class) | CTX-5 | ⬜ Ready | |
| CTX-A01e | Symbol extraction and dependency graph | CTX-5 | ⬜ Ready | |
| CTX-A01f | Semantic index (pgvector behind adapter) | CTX-5 | ⬜ Ready | |
| CTX-A01g | Branch, revision, and worktree awareness | CTX-3 | ⬜ Ready | |
| CTX-A01h | Immutable index snapshots recording source revision, indexer version, policy version | CTX-8, CTX-9 | ⬜ Ready | |
| CTX-A01i | Citations and context-item provenance | RET-6, RET-9 | ⬜ Ready | |

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
