---
name: evidence-pr
description: Write the evidence summary for a Modbit change — capability, requirements, security and policy, settings, data and API, verification, rollout. Use when finishing any substantial change, before requesting review.
---

# Change evidence summary

Merging without release-gated acceptance evidence is a prohibited shortcut. Fill every section; write
`none` explicitly rather than deleting a heading.

```markdown
## Capability
- Registry ID:
- Surfaces:
- Release:

## Requirements
- PRD/SDD sections:
- ADRs:

## Security and policy
- Trust boundaries:
- New permissions:
- Secret handling:
- Tenant isolation:
- Taint effects (v5.1):

## Settings
- New/changed keys:
- Scope and merge:
- Application timing:

## Data/API
- Schema changes:
- Event changes:
- Migration:

## Verification
- Unit:
- Integration:
- E2E:
- Security:
- Conformance:
- Benchmark:

## Rollout
- Feature flag:
- Observability:
- Rollback:
```

## Honesty rules

- [ ] Report what actually ran. If a suite was skipped, say so and why.
- [ ] Never describe compensating actions as guaranteed rollback (INV-15).
- [ ] Never claim deterministic re-execution when only deterministic playback exists (INV-14).
- [ ] A failed runtime validation is `inconclusive` unless evidence proves mitigation.
- [ ] List remaining risks. An empty risk section on a security-relevant change is a review blocker.

## Before requesting review

- [ ] `make check` clean, output pasted or summarized.
- [ ] `make generate` produced no diff.
- [ ] `tasks.md` updated in this same change (R-DOC-02).
