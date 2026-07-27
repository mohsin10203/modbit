# ADR-0100 — `engineering-specifications.md` is a secondary engineering reference

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owner:** Platform
- **Supersedes:** none

> **Numbering:** repository ADRs start at 0100 so they can never be confused with the document
> pack's `ADR-0001-foundational-decisions-v5.1.md`, which carries product decisions 1–42.

## Context

`engineering-specifications.md` ("Agent Harness v2.2 — Engineering Specifications", 7,937 lines)
appeared in the repository root. It is a complete engineering baseline: 200-table PostgreSQL DDL,
planner algorithms, retrieval ranking, memory scoring, routing utility functions, Kubernetes
manifests, and CI definitions.

It is **not** part of the Modbit v5.1 document pack:

- absent from `MANIFEST-v5.1.md`;
- synthesised from two different source PDFs, for a differently named product;
- self-described as "an implementation synthesis… Defaults are starting points and MUST be
  validated against the target repository, language, model, latency, data-residency, and threat
  profile."

PRD v5.1 states the pack "is the sole implementation baseline" and that "product-scope ideas not
represented here are outside Modbit v5.1."

### Where it conflicts with the locked pack

| Area | Harness v2.2 | Modbit v5.1 |
|---|---|---|
| Error namespace | `HARNESS_*` | `MODBIT_*` (`api-and-events-v5.1.md` §6) |
| Effect taxonomy | `read`, `workspace_write`, `external_write`, `credential_use`, `deployment`, `destructive` | five side-effect classes, PRD §12.2, SFX-1 |
| Run states | 14-value `run_state` enum | phase list, PRD §11.1 |
| Sequencing | Waves 0–7 | Releases A–E |
| Schema | `harness` schema, 200 tables | entity model, PRD §33.1 |

### Where it covers less

CodeWiki: 0 mentions. Security Swarm: 0. ACU: 0. Trust Portal: 0. Computer use: 1, in passing.
It describes a narrower product. Adopting it as the baseline would silently delete locked
capabilities, which PRD Appendix G forbids.

### Where it is genuinely stronger

Modbit's PRD is dense on *what* and near-silent on *how*. This document supplies algorithms for
exactly the places the PRD leaves open: retrieval fusion and coverage-constrained packing (§9.3–9.5),
routing utility and contextual-bandit calibration (§11.2–11.3), memory scoring and decay
(§13.3–13.5), the planner portfolio (§8), fenced leases (§14.4), effect reconciliation (§15.3),
benchmark immutability and judge calibration (§16), and Pareto-safe promotion (§17).

## Decision

`engineering-specifications.md` is a **secondary engineering reference**, not a requirements source.

1. It is added to `.agents.md` §3 **below** the Capability Registry, explicitly non-authoritative.
2. Material from it enters the build only through an approved ADR that names the Modbit requirement
   it implements.
3. It **may not** introduce or remove product scope. A capability present there and absent from the
   v5.1 pack stays out; a capability present in the pack and absent there stays in.
4. Where its taxonomy conflicts with a locked Modbit taxonomy, **Modbit wins** without exception.
   This covers error codes, side-effect classes, run phases, and release sequencing.
5. Its DDL is a reference for column conventions, tenancy keys, and fencing patterns. It is not a
   schema to adopt: it models a different entity set.

## Consequences

**Positive.** The algorithmic depth becomes available without reopening the scope lock. SDD §20's
open implementation decisions gain candidate answers with a documented provenance.

**Negative.** Two documents now describe overlapping architecture, so a reader can mistake the
reference for the baseline. Mitigated by the explicit ordering in `.agents.md` §3 and by requiring
an ADR for every adoption.

**Risk.** Gradual drift toward the Harness taxonomy through incremental borrowing. Mitigated by
rule 4 being absolute, and by `capability-check` cross-validating every capability against the
Modbit event and settings catalogs.

## Adopted immediately under this ADR

Three additions that conflict with nothing in the locked pack:

| Item | Source | Modbit requirement it serves |
|---|---|---|
| Taint **sink** matrix and a sticky `known_secret` class | §20.3 | TNT-1 ("minimum classes" permits addition), TNT-3, INV-11 |
| Error codes `MODBIT_SNAPSHOT_DIVERGED`, `MODBIT_EFFECT_RECONCILIATION_REQUIRED`, `MODBIT_CONTEXT_DEGRADED` | §7.5 | RCV-4/RCV-5, SDD §15 ("index failures degrade visibly"), R-ERR-05 |
| Fence tokens in approval binding | §14.4, §20.4 | SFX-3, SFX-4, R-EVT-06 |

Each is additive. None renames a Modbit code, alters the side-effect taxonomy, or changes a run
phase.

## Deferred to later ADRs

Retrieval ranking and packing · routing utility and bandit calibration · memory scoring and decay ·
planner portfolio selection · effect reconciliation protocol · benchmark factory and judge
calibration · Pareto-safe promotion and canary rollback.

Each requires its own ADR naming the Modbit requirement it implements and the evidence that the
algorithm satisfies it.
