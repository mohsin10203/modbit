---
name: new-capability
description: Add a Modbit product capability end to end — registry entry, settings, policy, API and events, data ownership, threat model, implementation, surfaces, observability, tests, rollout, docs. Use for any work that introduces or materially changes a user-visible or platform capability.
---

# Add a capability

Implements `.agents.md` §6. Do not skip steps; record any deferral as an ADR.

## 0. Establish authority

- [ ] Locate the governing requirement in `modbit docs/modbit-platform-prd-v5.1.md`. Record its
      section and requirement IDs (e.g. `RUN-4`, `TNT-3`).
- [ ] Locate the workstream/family id in `modbit docs/development-docket-v5.1.md`
      (e.g. `CTX-A01`, `TNT-03`).
- [ ] If no locked requirement covers the work, **stop**. New product scope is rejected from the
      v5.1 backlog (PRD Appendix G).

## 1. Capability Registry

- [ ] Add `contracts/capabilities/<id>.yaml` with `id`, `version`, `owner`, `security_class`,
      `surfaces` (desktop/cli/ts_sdk/python_sdk/web/extension), `events`, `settings`, `tests`.
- [ ] Surface values must match `modbit docs/capability-matrix-v5.1.md`. A required cell cannot be
      red at general release.
- [ ] Visual-only surfaces marked `E` must still produce structured state or artifacts.

## 2. Settings and policy

- [ ] Run the `settings-key` skill for each new control.
- [ ] Decide the policy envelope: which scopes may lock or bound it, and the merge strategy.
- [ ] Confirm no lower scope can weaken a higher-scope security setting (INV-9, R-SET-05).

## 3. API and canonical events

- [ ] Add REST resources/commands to the OpenAPI contract; commands are idempotent.
- [ ] Run the `canonical-event` skill for each new event type.
- [ ] Add stable error codes to `contracts/errors/`.
- [ ] Confirm API/SDK/CLI parity: every authoritative operation in the API and SDK, every
      non-visual operation in the CLI (`api-and-events-v5.1.md` §1).

## 4. Data ownership and retention

- [ ] Name the owning store. Tenant-owned entities carry `organization_id` (R-TEN-01).
- [ ] Declare retention class and whether bodies are stored by reference (R-SQL-06).
- [ ] Write the migration; forward test it and assess rollback (R-SQL-01).

## 5. Threat model

- [ ] Run the `threat-model` skill.
- [ ] Run the `taint-review` skill if the capability consumes context or causes external effects.

## 6. Implement server/domain behavior

- [ ] Follow `go-package` for new packages.
- [ ] Bind immutable snapshots to the run (INV-6).
- [ ] Assign a side-effect class to every mutating operation (SFX-1).

## 7. Implement required surfaces

- [ ] Every `R` cell in the capability matrix has an implementation.
- [ ] Degradation in a restricted operating mode is negotiated and disclosed, never silent
      (LCD-1..LCD-3).

## 8. Audit, usage, observability

- [ ] Audit event for every authoritative and privileged action.
- [ ] Usage/cost attribution where the capability consumes model or compute budget.
- [ ] Trace dimensions per R-OBS-01.

## 9. Tests

- [ ] Unit: pure logic, table driven.
- [ ] Integration: real store, real event bus.
- [ ] Conformance: the capability's row in the surface conformance suite.
- [ ] Security: tenant isolation, secret handling, and the relevant adversarial suite.
- [ ] Benchmark: smoke coverage where a performance budget applies (SDD §18).

## 10. Rollout and rollback

- [ ] Feature flag with a default-off path for the first release.
- [ ] Observable rollout signal and a tested rollback.

## 11. Documentation and tracker

- [ ] User and operator documentation.
- [ ] **Update `tasks.md`**: status, acceptance checkboxes, evidence links.
- [ ] Write the change description with `evidence-pr`.
