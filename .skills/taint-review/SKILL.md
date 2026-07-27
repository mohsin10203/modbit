---
name: taint-review
description: Verify provenance taint handling (PRD v5.1 §12A, TNT-1..TNT-7) on any code path that ingests context, calls a tool, produces derived content, or performs an external effect. Use before merging context, tool, model, or approval code.
---

# Taint and capability confinement review

Delimiters label risk; they do not enforce anything. Provenance is a **policy dimension**.

## 1. Classification at ingestion (TNT-1)

Every unit of content entering a run context carries a provenance class:

```text
user-trusted        direct user input in a trusted surface
repository-untrusted  repository files, repo-authored instructions
web                 search results, fetched pages, browser-extracted content
tool-result         output of a local or platform tool
mcp-result          output of an MCP server
integration         normalized inbound events from an integration
generated           model-produced content
```

- [ ] Every ingestion point assigns a class explicitly.
- [ ] Unknown or unverifiable provenance → highest-risk class. **Fail closed** (TNT-6).
- [ ] The class is attached at the context-pack item, not inferred later.

## 2. Propagation (TNT-2)

- [ ] Derived content (summaries, extractions, generated text incorporating input) inherits the
      **highest-risk contributing class**.
- [ ] Laundering paths are covered: summarize → embed → retrieve → generate still carries taint.
- [ ] Declassification is an explicit, authorized operation that records actor and rationale in the
      declassification ledger. It is never automatic.

## 3. Policy input (TNT-3, TNT-4)

- [ ] The policy call for a mutating operation receives the run's current taint set.
- [ ] Default managed policy is implemented: once `web`, `mcp-result`, or `repository-untrusted`
      content enters a run, **externally compensatable** and **externally irreversible**
      operations escalate one approval class — unless the operation was declared in the approved
      plan *before* the taint entered.
- [ ] Policy may additionally restrict tool availability or require plan-declared operations.
- [ ] Escalation returns `MODBIT_TAINT_ESCALATION_REQUIRED`, not a generic denial.

## 4. Lease restriction

- [ ] Worker leases embed taint-derived tool restrictions and the escalation table (SDD §11).
- [ ] A worker cannot widen its own restriction set.

## 5. Visibility (TNT-5)

- [ ] Taint class is displayed in the composer, context chips, approval cards, and status bar.
- [ ] Entry, escalation, and declassification emit `taint.class.entered`,
      `taint.escalation.applied`, `taint.declassified`.
- [ ] The run's taint ledger is produced as the `modbit.run.taint` structured artifact.

## 6. Budget

- [ ] Taint evaluation adds **< 10 ms p95** to policy decisions (SDD §18). Precompute the run's
      class set; do not re-derive per call.

## 7. Adversarial tests (TNT-7)

- [ ] Seeded injection in a repository file attempting a high-risk tool call.
- [ ] Seeded injection in fetched web content.
- [ ] Seeded injection in an MCP tool result.
- [ ] Laundering attempt through a summarization step.
- [ ] Attempt to reach an irreversible operation without pre-declaration.
- [ ] Attempt to self-declassify from inside model output.

Each test asserts the operation was **escalated or denied**, an event was emitted, and the ledger
recorded the class.
