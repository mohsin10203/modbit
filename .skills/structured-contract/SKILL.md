---
name: structured-contract
description: Register a Structured Output Contract so a workflow returns a validated artifact instead of prose — schema, version, owner, retention, classification, renderer, migration, and the validate-repair-persist runtime path. Use when a workflow's result is consumed by another system or shown as evidence.
---

# Register a Structured Output Contract

Prose cannot substitute for a required artifact (`structured-outputs-v5.1.md` §5).

## 1. Contract definition

Add `contracts/schemas/<schema_id>.v<N>.json` and register it in
`contracts/schemas/registry.yaml`:

```yaml
- schema_id: modbit.verification.adequacy
  schema_version: 1
  owner: quality-agents
  workflows: [verify, review]
  retention: standard
  security_classification: internal
  renderer: adequacy-report
  schema: schemas/modbit.verification.adequacy.v1.json
```

- [ ] `schema_id` is a dotted, stable, product-level identifier.
- [ ] `schema_version` is immutable. Corrections create a new version (R-CTR-07).
- [ ] Unknown-field policy is stated: `reject` (default for evidence) or `preserve`.
- [ ] Sensitive fields carry classification and retention.

## 2. Required contracts already locked

Review report · Security finding · Security scan report · Verification report · Deployment
plan/result · Incident report · Migration plan/result · Architecture impact report · Plan ·
Completion report · *(v5.1)* Adequacy report · Taint ledger · Memory record · Trust state change ·
Coordination conflict · Evaluation report · Evidence export manifest · Capability negotiation
record.

- [ ] If the work fits one of these, extend it — do not create a parallel schema.

## 3. Runtime path

Implement exactly this sequence (`structured-outputs-v5.1.md` §4):

1. [ ] Select contract (pinned version from the workflow).
2. [ ] Generate canonical artifact.
3. [ ] Validate against the schema.
4. [ ] Repair within budget if invalid — bounded attempts, classified failures (R-ERR-03).
5. [ ] Persist artifact; validation state is stored, not inferred.
6. [ ] Render the human summary from the artifact, never the reverse.
7. [ ] Emit `output.validated` or `output.validation.failed`.
8. [ ] Reference the artifact from the API response and the completion contract.

- [ ] Completion never succeeds on prose alone (INV-8, prohibited shortcut "success based solely
      on model text").

## 4. Export mappings

- [ ] SARIF is an **export mapping** of Security finding and Review report, not a replacement
      schema. Register the mapping profile alongside the contract and validate it in the export
      qualification suite (EIX-1, EIX-3).

## 5. Renderer

- [ ] The renderer supports formatted view, raw JSON, schema, validation diagnostics, version
      comparison, download/export, and source evidence links.

## 6. Tests

- [ ] Schema round-trip and golden fixtures.
- [ ] Invalid-artifact repair path with a bounded budget.
- [ ] Compatibility test against the previous major version.
- [ ] Redaction test for classified fields.

- [ ] Update `tasks.md`.
