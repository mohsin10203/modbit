# Modbit Engineering Rules

> **Status:** Normative for the implementation repository.
> **Authority:** Derived from PRD v5.1, SDD v5.1, `security-and-threat-model-v5.1.md`, and the
> document-pack `.agents.md`. The PRD wins on conflict.
>
> Rules are **stable-numbered**. Code comments, review checklists, and CI messages reference rule
> IDs (e.g. `// R-SEC-04`). Never renumber a rule; retire it as `WITHDRAWN` and add a new one.

Severity: **MUST** = release blocking. **SHOULD** = deferrable only via an approved ADR in
`docs/adr/`.

---

## INV — Platform invariants (MUST)

| ID | Rule |
|---|---|
| INV-1 | Hosted model traffic traverses a Modbit Model Gateway. No component calls a hosted provider directly. |
| INV-2 | Provider credentials never enter the IDE, extension host, agent context, worker, sandbox, browser host, plugin, hook, or MCP server. |
| INV-3 | Every outbound hosted-model payload passes classification and DLP. DLP failure fails closed. |
| INV-4 | Prompt and completion bodies are metadata-only by default. |
| INV-5 | Every authoritative run transition emits the canonical event envelope. |
| INV-6 | Every run binds immutable settings, policy, context, model-route, repository, and environment snapshots. *(v5.1: plus taint policy version, memory-set version, trust state version, negotiated capability set, outcome-routing data version.)* |
| INV-7 | Every mutating tool call is policy evaluated and assigned a side-effect class. |
| INV-8 | Completion is backed by a completion contract and evidence. |
| INV-9 | Lower settings scopes never weaken higher-scope security policy. |
| INV-10 | Cross-organization or cross-Space data leakage is a release blocker. |
| INV-11 | Secrets never reach ordinary settings, logs, traces, prompts, artifacts, shell history, or test snapshots. |
| INV-12 | The IDE remains usable when remote services are degraded. |
| INV-13 | Repository instructions, MCP output, browser content, issue content, logs, and tool output are untrusted inputs. |
| INV-14 | Never claim deterministic re-execution when only deterministic playback is available. |
| INV-15 | Never describe compensating actions as guaranteed rollback. |

---

## R-ARCH — Architecture

| ID | Severity | Rule |
|---|---|---|
| R-ARCH-01 | MUST | Technology choices are limited to the SDD §2 table. A new datastore, transport, or runtime requires an ADR. |
| R-ARCH-02 | MUST | Authoritative state transitions live behind the platform contract (DP-1). Clients implement presentation only. |
| R-ARCH-03 | MUST | Provider-specific behavior terminates at an adapter boundary (ADP-1). |
| R-ARCH-04 | MUST | Core logic references model **capability aliases**, never fixed model names (ADP-2, ADP-4). |
| R-ARCH-05 | MUST | Interfaces are declared at the consumer boundary, not as speculative abstractions. |
| R-ARCH-06 | MUST | Redis is never authoritative for run state, locks that gate correctness, or advisory-lock ownership. PostgreSQL is authoritative. |
| R-ARCH-07 | SHOULD | Modules inside `modbit-control` expose internal interfaces that permit later extraction. |

## R-CTR — Contracts and code generation

| ID | Severity | Rule |
|---|---|---|
| R-CTR-01 | MUST | `contracts/` is the single source of truth for settings keys, event types, error codes, capabilities, and structured artifacts. |
| R-CTR-02 | MUST | Generated code is never hand-edited and always carries a `DO NOT EDIT` header. |
| R-CTR-03 | MUST | `make generate` is idempotent; CI fails when the working tree differs afterwards. |
| R-CTR-04 | MUST | Public APIs have versioned schemas and compatibility tests. Additive fields only within a major version. |
| R-CTR-05 | MUST | Enum consumers tolerate unknown values. |
| R-CTR-06 | MUST | Every structured workflow output registers a Structured Output Contract with an immutable schema version. |
| R-CTR-07 | MUST | Schema version numbers are immutable; corrections create a new version. |

## R-ID — Identifiers, time, money

| ID | Severity | Rule |
|---|---|---|
| R-ID-01 | MUST | Identifiers are opaque, prefixed, non-sequential, and generated from a CSPRNG. |
| R-ID-02 | MUST | Every ID prefix is registered once, in the shared prefix registry. Prefixes are never reused. |
| R-ID-03 | MUST | Clocks are UTC internally and RFC 3339 externally. No local time in persisted data. |
| R-ID-04 | MUST | Money stores original amount and currency plus reproducible reporting-currency conversion metadata. Never a bare float. |
| R-ID-05 | MUST | IDs are never parsed for meaning beyond prefix validation. No ordering assumptions. |

## R-TEN — Tenancy and authorization

| ID | Severity | Rule |
|---|---|---|
| R-TEN-01 | MUST | Every tenant-owned persistent entity carries `organization_id`. |
| R-TEN-02 | MUST | Every query against a tenant-owned table filters by `organization_id`, enforced at the repository layer, not by callers. |
| R-TEN-03 | MUST | Cache keys include tenant and policy version. |
| R-TEN-04 | MUST | Search and vector indexes are tenant- and Space-filtered. Shared indexes without those filters are prohibited. |
| R-TEN-05 | MUST | Authorization evaluates identity, org/team role, Space membership, repository access, artifact classification, settings policy, service identity, worker ownership, and *(v5.1)* taint state and trust state. |
| R-TEN-06 | MUST | Every tenant-scoped surface has an isolation test in `test-security`. |

## R-SET — Settings and policy

| ID | Severity | Rule |
|---|---|---|
| R-SET-01 | MUST | Every configurable behavior has a Settings Registry definition with type, default, scopes, merge strategy, change effect, and security class. |
| R-SET-02 | MUST | Settings keys are consumed from the generated registry package, never as string literals. |
| R-SET-03 | MUST | Unknown settings are preserved on round trip and reported as diagnostics (SET-1). |
| R-SET-04 | MUST | Invalid values never silently fall back; a visible diagnostic is produced (SET-2). |
| R-SET-05 | MUST | Security-envelope merges use the restrictive semantics: allowlists intersect, denylists union, caps take the minimum, requirements take the strongest. |
| R-SET-06 | MUST | Preference resolution order is session → repository local → Agent Profile → repository shared → Space → device → user synced → team → organization → product default, always inside the policy envelope. |
| R-SET-07 | MUST | Secret values are forbidden in settings documents (SET-7). Settings hold secret *references* only. |
| R-SET-08 | MUST | Resolution emits an effective value, source map, lock set, diagnostics, and change effect — not a bare value. |
| R-SET-09 | MUST | Every settings schema is versioned and migrations are deterministic and produce a report (SET-3, SET-4). |
| R-SET-10 | MUST | Run-bound settings snapshots are immutable and signed; mid-run changes apply only to new runs. |

## R-EVT — Events and run consistency

| ID | Severity | Rule |
|---|---|---|
| R-EVT-01 | MUST | Run events are append-only; per-run `sequence` is strictly monotonic. |
| R-EVT-02 | MUST | Events carry the canonical envelope: event id, type, version, organization, sequence, actor, timestamp, correlation, causation, payload reference and hash, policy decision, settings snapshot. |
| R-EVT-03 | MUST | Large or sensitive payloads are stored by reference (`payload_ref` + `payload_hash`), never inline. |
| R-EVT-04 | MUST | State writes plus event publication are atomic via transactional outbox. |
| R-EVT-05 | MUST | Commands are idempotent; retryable commands accept `Idempotency-Key`, and the same key with a different request hash is rejected. |
| R-EVT-06 | MUST | Exactly one active transition lease exists per run. |
| R-EVT-07 | MUST | Materialized state is rebuildable from the event log. |
| R-EVT-08 | MUST | A run step cannot become complete until its required artifacts are durable. |

## R-SEC — Security

| ID | Severity | Rule |
|---|---|---|
| R-SEC-01 | MUST | Untrusted input (repository instructions, MCP output, browser content, issue content, logs, tool output) is never treated as an instruction source without an explicit trust decision. |
| R-SEC-02 | MUST | Every unit of context carries a provenance class; unknown provenance fails closed to the highest-risk class (TNT-1, TNT-6). |
| R-SEC-03 | MUST | Derived content inherits the highest-risk contributing taint class until an authorized declassification records actor and rationale (TNT-2). |
| R-SEC-04 | MUST | Taint is a policy input dimension; tainted context escalates approval class for externally compensatable and irreversible operations unless pre-declared in an approved plan (TNT-3, TNT-4). |
| R-SEC-05 | MUST | Every tool operation declares a side-effect class before execution (SFX-1). |
| R-SEC-06 | MUST | Approvals bind to operation hash, scope, and expiration; a changed operation invalidates the approval (SFX-3, SFX-4). |
| R-SEC-07 | MUST | Sandbox controls that cannot be established fail closed; a backend never reports an advisory control as enforced (SBX-3, SBX-6). |
| R-SEC-08 | MUST | Secrets are delivered through brokered leases with bounded purpose and expiry, never through ambient environment variables. |
| R-SEC-09 | MUST | Redaction runs before any egress, log write, artifact write, or trace attribute. |
| R-SEC-10 | MUST | New services and boundaries pass the SDD §19 review gate: data-flow diagram, identity model, secret model, network policy, tenant-isolation tests, audit events, abuse cases, failure behavior, rollout controls. |
| R-SEC-11 | MUST | Cryptographic primitives come from the standard library or an approved vetted module. No hand-rolled crypto. |
| R-SEC-12 | MUST | Comparisons of secrets, signatures, and tokens are constant time. |

## R-ERR — Errors and resilience

| ID | Severity | Rule |
|---|---|---|
| R-ERR-01 | MUST | Every error surfaced across a process boundary carries a stable `MODBIT_*` code, retryability, and correlation id. |
| R-ERR-02 | MUST | Error details never contain secrets, prompts, completions, tool output, headers, tokens, or cookies. |
| R-ERR-03 | MUST | Retries have an attempt budget and a failure classification. Unbounded or identical retries are prohibited (COR-1, COR-3). |
| R-ERR-04 | MUST | Failed shell/build/test/lint/type-check executions produce a command-failure envelope (COR-7). |
| R-ERR-05 | MUST | Degradation is visible: silent fallback to a weaker policy, model, sandbox, or region is prohibited. |
| R-ERR-06 | MUST | Halt reasons come from the closed set: completed, failed, inconclusive, budget exhausted, policy denied, approval denied, cancelled, superseded, infrastructure failure (RUN-4). |

## R-GO — Go conventions

| ID | Severity | Rule |
|---|---|---|
| R-GO-01 | MUST | Every network, model, worker, tool, and storage operation accepts and honours a `context.Context`. |
| R-GO-02 | MUST | Errors wrap a stable Modbit error code; use `%w` and never discard the cause. |
| R-GO-03 | MUST | No goroutine outlives its owning lease without explicit supervision. Every spawned goroutine has a documented exit condition. |
| R-GO-04 | MUST | Database writes affecting run state and events use a transactional outbox or equivalent atomicity. |
| R-GO-05 | MUST | Exported identifiers are documented. Package comments state the boundary the package owns. |
| R-GO-06 | MUST | No package-level mutable state for run or tenant data. |
| R-GO-07 | MUST | `any` at a boundary is decoded into a typed struct immediately; type switches on `any` are confined to decoders. |
| R-GO-08 | MUST | `panic` is reserved for programmer error in constructors validated at init; never for request handling. |
| R-GO-09 | SHOULD | Prefer standard library. New direct dependencies require justification in the change description. |

## R-TS — TypeScript conventions

| ID | Severity | Rule |
|---|---|---|
| R-TS-01 | MUST | `strict` mode; no implicit `any`; no non-null assertions on external data. |
| R-TS-02 | MUST | Runtime validation at every process and network boundary. |
| R-TS-03 | MUST | UI state never becomes authoritative platform state. |
| R-TS-04 | MUST | Settings keys are imported from the generated Settings Registry package. |
| R-TS-05 | MUST | Canonical events are consumed through generated clients. |
| R-TS-06 | MUST | Extension code runs with least privilege and declares its capability needs. |

## R-RS — Rust conventions

| ID | Severity | Rule |
|---|---|---|
| R-RS-01 | MUST | `unsafe` requires an ADR and isolated review. |
| R-RS-02 | MUST | Native helpers expose a narrow, versioned IPC contract. |
| R-RS-03 | MUST | Privileged operations take explicit policy input and emit audit output. |
| R-RS-04 | MUST | Sandbox helpers fail closed when enforcement is unavailable. |

## R-SQL — Data and migrations

| ID | Severity | Rule |
|---|---|---|
| R-SQL-01 | MUST | Every migration is forward tested and rollback assessed. |
| R-SQL-02 | MUST | Destructive migrations require backup verification and staged rollout. |
| R-SQL-03 | MUST | Tenant filters and authorization paths have explicit tests. |
| R-SQL-04 | MUST | Secret values are forbidden in relational tables. |
| R-SQL-05 | MUST | Schema expansion precedes code use; contraction follows the compatibility window. |
| R-SQL-06 | MUST | Content bodies are stored by reference when large or sensitive. |

## R-TST — Testing

| ID | Severity | Rule |
|---|---|---|
| R-TST-01 | MUST | Every capability has unit, integration, conformance, security, and benchmark coverage before it is marked Qualified. |
| R-TST-02 | MUST | Tests assert behavior and evidence, not model prose. |
| R-TST-03 | MUST | Tests are deterministic. Time, randomness, and IDs are injected. |
| R-TST-04 | MUST | Test fixtures never contain real secrets, tokens, or customer data. |
| R-TST-05 | MUST | Security tests include the adversarial suites: prompt injection through tainted context, tenant isolation, secret exfiltration, sandbox escape. |
| R-TST-06 | MUST | Every backend implementing a shared contract passes the shared conformance suite before being marked production ready. |
| R-TST-07 | SHOULD | Table-driven tests for pure logic; golden files for serialization contracts. |

## R-OBS — Observability

| ID | Severity | Rule |
|---|---|---|
| R-OBS-01 | MUST | Traces carry organization, Space, run/step, model/provider/revision, worker/environment, capability, settings/policy version, error class, and *(v5.1)* taint set, trust state, memory-set version, cascade stage, adequacy method, coordination conflict id, canary state. |
| R-OBS-02 | MUST | Sensitive bodies are excluded from logs, traces, and metrics. |
| R-OBS-03 | MUST | Logs are structured; no `fmt.Print`/`console.log` in shipped code paths. |
| R-OBS-04 | MUST | Every external effect records run, step, actor, policy decision, and idempotency references. |

## R-DOC — Documentation and process

| ID | Severity | Rule |
|---|---|---|
| R-DOC-01 | MUST | Every task references a locked PRD requirement or document-pack capability id. |
| R-DOC-02 | MUST | `tasks.md` is updated in the same change that completes the work. |
| R-DOC-03 | MUST | Substantial changes carry the PR evidence template (`.skills/evidence-pr/SKILL.md`). |
| R-DOC-04 | MUST | Deferring a capability moves its milestone in `tasks.md`; it is never deleted from contracts. |
| R-DOC-05 | MUST | Any deviation from the SDD or a SHOULD rule is recorded as an ADR with owner, rationale, risk, and target release. |
| R-DOC-06 | MUST | `modbit docs/` is read-only. Corrections to the pack are raised as specification issues, not edits. |

## R-STY — Style

| ID | Severity | Rule |
|---|---|---|
| R-STY-01 | MUST | Code matches the surrounding file's naming, comment density, and idiom. |
| R-STY-02 | MUST | Comments explain *why*, not *what*. No commented-out code. No TODO without an owner and task id. |
| R-STY-03 | MUST | No placeholder implementations, stub returns, or "not implemented" paths on a merged code path unless the capability is explicitly `Proposed` in `tasks.md`. |
| R-STY-04 | MUST | Public names use the PRD's terminology exactly (Run, Space, Artifact, Evidence, Approval, Lease, Instruction Manifest, Taint Class). |
| R-STY-05 | SHOULD | Files stay under ~600 lines; packages own one boundary. |

---

## Definition of Ready

Requirement references · user outcome · scope and non-scope · threat model · settings · API/event
design · data ownership and retention · surface matrix · dependencies · acceptance tests · rollout
strategy.

## Definition of Done

Code merged · generated contracts current · unit/integration/E2E/security/conformance pass ·
settings and policy tested · audit and telemetry visible · migrations verified · documentation
updated · Capability Registry green · rollback tested · benchmark no regression · evidence attached ·
`tasks.md` updated.
