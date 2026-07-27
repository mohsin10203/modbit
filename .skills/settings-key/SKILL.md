---
name: settings-key
description: Add or change a Modbit Settings Registry definition — type, default, scopes, merge strategy, change effect, security class, migration. Use whenever behavior becomes configurable or an existing setting's semantics change.
---

# Add a settings key

Settings are a product API (DP-12). A behavior that is configurable but unregistered is a bug
(R-SET-01).

## 1. Define

Add or edit a definition in `contracts/settings/<namespace>.yaml`:

```yaml
- key: agent.execution.mode
  type: enum
  enum: [manual, allowlist, auto-review, unrestricted]
  default: auto-review
  scopes: [user, device, repository, repository_local, team, organization]
  merge: most_restrictive
  change_effect: next_tool_call
  security_class: high
  description: Controls when agent tool calls require approval.
```

- [ ] `key` is dotted, lowercase, namespaced by domain (`agent.`, `context.`, `model.`, `taint.`,
      `memory.`, `trust.`, `verification.`, `coordination.`, `evaluation.`, `evidence.export.`,
      `workspace.scale.`, `mode.capability.`).
- [ ] `type` ∈ `bool | int | number | string | enum | duration | string_list | object`.
- [ ] `default` is the safe value. Defaults never grant capability.
- [ ] `scopes` lists only the scopes where the setting is meaningful (PRD §20A.4).
- [ ] `merge` ∈ `override | append_unique | union | intersection | union_deny | minimum | maximum |
      most_restrictive | deep_merge | custom`.
- [ ] `change_effect` states when a change takes effect (`immediate`, `next_run`, `next_tool_call`,
      `next_index`, `restart_required`) — the UI shows this (SET / §20A.8).
- [ ] `security_class` ∈ `none | low | medium | high | critical`. `high`/`critical` settings are
      lockable by policy and appear in the audit trail.

## 2. Envelope check (R-SET-05)

Pick the merge strategy from the semantics, not convenience:

| Semantics | Strategy |
|---|---|
| Allowed models, allowed origins, allowed tools | `intersection` |
| Denied tools, denied domains | `union_deny` |
| Cost/budget ceiling | `minimum` |
| Required verification strength, required approvals | `most_restrictive` |
| Additive lists (extra rules paths) | `append_unique` |
| Plain preference (theme, font) | `override` |

- [ ] Confirm a lower scope cannot weaken the value (INV-9). If it could, the strategy is wrong.

## 3. Secrets

- [ ] The value is **not** a secret (SET-7). If a credential is needed, store a reference to a
      Provider Connection, Integration Credential, or Task Secret and record only its id.

## 4. Generate and consume

- [ ] `make generate` → typed constants and accessors in Go and TypeScript.
- [ ] Consume the generated key. String literals for settings keys are prohibited (R-SET-02).

## 5. Migration and diagnostics

- [ ] Renames and type changes require a deterministic migration with a report (SET-4).
- [ ] Invalid values must produce a diagnostic, never a silent fallback (SET-2).
- [ ] Unknown keys are preserved on round trip and reported (SET-1).

## 6. Tests

- [ ] Resolution test: value, source map, locks, diagnostics, change effect.
- [ ] Envelope test: a lower scope attempting to weaken the setting is rejected and diagnosed.
- [ ] Round-trip test for unknown-key preservation.
- [ ] `make settings-schema-check` passes.

## 7. Document

- [ ] Add the key to the settings documentation and, if user visible, its UI category
      (PRD §20A.10).
- [ ] Update `tasks.md`.
