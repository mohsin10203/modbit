---
name: canonical-event
description: Add or change a canonical Modbit event type — envelope conformance, catalog entry, versioning, payload-by-reference, ordering, and subscriber compatibility. Use whenever an authoritative state transition needs to be observable.
---

# Add a canonical event

Every authoritative run transition emits the canonical envelope (INV-5, R-EVT-02).

## 1. Catalog entry

Add to `contracts/events/catalog.yaml`:

```yaml
- type: run.step.completed
  version: 1
  family: run
  description: A run step reached a terminal successful state.
  scope: run              # run | space | organization | worker | system
  payload_schema: schemas/events/run.step.completed.v1.json
  emits_artifact: false
  audit: true
  subjects: [runs.events]
```

- [ ] `type` is dotted, past tense, `<domain>.<subject>.<verb-ed>`.
- [ ] `version` starts at 1 and is immutable. Breaking payload changes create `v2`, not an edit.
- [ ] The family matches an existing family in `api-and-events-v5.1.md` §5 or a v5.1 family, or an
      ADR justifies a new one.

## 2. Envelope conformance

The envelope is produced by the shared event constructor, never assembled by hand. Confirm:

- [ ] `organization_id` present for every tenant-scoped event (R-TEN-01).
- [ ] `sequence` is allocated by the run's sequence authority — monotonic per run (R-EVT-01).
- [ ] `actor` is one of `user | service | agent | worker | system` with a real id.
- [ ] `correlation_id` propagates from the originating command; `causation_id` points at the
      triggering event.
- [ ] `policy_decision_id` set for anything policy evaluated (INV-7).
- [ ] `settings_snapshot_id` set for anything run bound (INV-6).

## 3. Payload

- [ ] Payload is stored by reference: `payload_ref` + `payload_hash` (R-EVT-03).
- [ ] Payload contains no secrets, prompts, completions, raw tool output, headers, tokens, or
      cookies (INV-11, R-ERR-02).
- [ ] Payload has a JSON Schema under `contracts/schemas/events/`.

## 4. Atomicity

- [ ] The state write and the event publication happen in one transaction via the outbox
      (R-EVT-04). Never publish first and write second.
- [ ] Emission is idempotent under command retry (R-EVT-05).

## 5. Consumers

- [ ] Unknown event types and unknown enum values are tolerated by subscribers (R-CTR-05).
- [ ] WebSocket reconnect by last sequence still yields a complete stream.
- [ ] Webhook delivery has retry with dead-letter.

## 6. Tests

- [ ] Envelope conformance test (generated from the catalog).
- [ ] Ordering test: monotonic sequence under concurrent emitters.
- [ ] Replay test: materialized state rebuilds from the log (R-EVT-07).
- [ ] Redaction test: no sensitive field reaches the payload.

## 7. Document

- [ ] Reference the event from the owning capability's registry entry.
- [ ] Update `tasks.md`.
