# ADR-0105 — Code OSS derivation: overlay with a bounded patch series

- **Status:** Proposed
- **Date:** 2026-07-28
- **Owner:** Desktop
- **Supersedes:** none
- **Resolves:** the fork/rebase half of `IDE-A01`, which gates `IDE-A02`–`A05` and `BRS-A01`

> **This ADR is analysis, not measurement.** No TypeScript exists in this repository and Code OSS has
> not been built here. Every other ADR in this directory rests on numbers taken on this machine; this
> one rests on the document pack and on how upstream-derivative maintenance is known to fail. It says
> so plainly, and it names the one measurement that has to happen before it is accepted.

## Context

`IDE-A01` bundles six things — fork/rebase strategy, branding, update service, process isolation,
marketplace, startup/memory telemetry. Five of them are ordinary work. The sixth is not: **the
derivation strategy is the least reversible decision in the project**, because its cost is not paid
at the moment it is made. A hard fork looks identical to every other option on day one and
progressively worse every month after, as upstream moves and the merge cost compounds. By the time
the cost is visible, the decision is expensive to revisit.

So it should be decided first, and on a stated principle rather than on what is fastest to start.

## What the pack has already decided

Three constraints are settled, and they narrow the space considerably:

| Source | Constraint |
|---|---|
| SDD §17 | **"Code OSS rebases are isolated from Modbit product modules."** |
| SDD §6 | The local IDE runtime is *Workbench, Extension Host, Local Agent Host, Settings Cache, Local Context Cache, Browser Host, Local Worker* — the Workbench is **one component among seven** |
| PRD §6, §24.1 | Extensions come from an **Open VSX-compatible** marketplace |
| PRD NG2 | No pixel-for-pixel copying of Cursor, Devin or Augment branding or assets |
| PRD §20 | Usable editor startup **<3 s warm, <6 s cold**, and these are **release gates** |

SDD §17 is the important one, and it is a *requirement*, not a suggestion. It rules out the strategy
most products in this space actually adopt — copying the tree and building the product inside it —
because that makes rebases and product modules the same thing by construction.

SDD §6's decomposition is the same statement viewed from the other side. Six of the seven local
components are not the Workbench, and the Local Agent Host, Settings Cache and Context Cache are
precisely the parts this repository has already built in Go. **The isolation the pack asks for is
the architecture it already describes.**

The Open VSX constraint deserves recording so nobody later "fixes" it: the Microsoft marketplace's
terms restrict its use to Microsoft's own products, so a Code OSS derivative that pointed at it would
have a licensing problem, not a technical one. The PRD resolved this; it is not an open trade-off.

## Options

| Option | How upstream is tracked | Failure mode |
|---|---|---|
| **Hard fork** | Copy once, diverge | Merge cost compounds; security patches lag upstream by however long the merge takes. Contradicts SDD §17 by construction. |
| **Patch series on upstream** | Ordered patches rebased onto each upstream release | Sound, and what VSCodium does. Cost is proportional to how many core files are touched — which nobody measures until it hurts. |
| **Extension-only** | No patches at all | Cheapest to maintain and cannot deliver IDE-1's inline Tab UI or IDE-9's diff zones if the extension API does not reach them. Whether it does is the open question. |
| **Overlay + bounded patch series** | Upstream unmodified; Modbit code in a separate tree; a small, numbered patch series for what genuinely cannot be reached otherwise | The recommendation. Requires the patch budget to be enforced, or it degrades into a hard fork one justified exception at a time. |

## Recommendation

**Overlay, with the patch series treated as a budgeted resource.**

1. **Upstream stays unmodified and vendored by version.** Modbit product code lives in its own tree
   and is composed at build time. This is SDD §17 restated as a build property rather than a hope.
2. **Anything reachable through the extension API goes in an extension**, not a patch. The default is
   "extension", and a core patch requires a reason.
3. **Core patches are a numbered, ordered series**, each naming the `IDE-n` requirement it serves and
   why the extension API cannot reach it. A patch with no requirement is deleted, not carried.
4. **The patch surface is gated.** The count of upstream files touched is the number that predicts
   rebase cost, so it is measured on every build and has a ceiling. Raising the ceiling is an ADR.

Point 4 is the one that makes the difference between this and a hard fork. Every derivative that
ended up unmaintainable got there by accepting individually reasonable patches, and the honest defence
is not discipline — it is a number that has to be argued up. The repository already does this to
itself: `QA-A01c` gates PRD §8A.3's budgets and marks each one enforced or a known gap, and the
startup targets (<3 s warm, <6 s cold) are release gates that belong in the same harness.

## The measurement this needs before acceptance

**Classify IDE-1 through IDE-15 into "extension API suffices" and "core patch required."**

That single classification determines the patch surface, and the patch surface determines the entire
maintenance cost of the strategy. Choosing between the options above without it is choosing on
temperament. The uncertain ones are known in advance:

- **IDE-1** (inline Tab: multi-line, fill-in-the-middle, next-edit, partial-accept) — the inline
  completion API covers some of this; partial-accept and next-edit are where it may not reach.
- **IDE-9** (diff zones with per-hunk accept/reject) — rendering inside the editor, not beside it.
- **IDE-4** (selected editor *and terminal* text into context, automatically and visibly) — terminal
  selection access is the narrower API.
- **IDE-12** (multiple agents in isolated worktrees) — likely a window/workspace-service concern.

A spike answering those four decides it. Until then this ADR is a position, not a finding.

## Consequences

- **Nothing in this repository changes yet.** The Go platform is already on the correct side of the
  boundary: `pkg/settings`, `pkg/index`, `pkg/agent` and `pkg/sandbox` are the Settings Cache, Context
  Cache, Local Agent Host and sandbox of SDD §6, and none of them assume an editor.
- The IDE talks to the platform over a versioned contract, as every other surface does. `contracts/`
  already generates TypeScript, so the boundary has a shape before the client exists.
- **`IDE-A01` should be split.** Fork strategy, branding, update service, process isolation,
  marketplace and startup telemetry are six deliverables with different owners and risks; carrying
  them as one item hides that only the first is architecturally binding.
- A patch-surface gate has to exist from the first patch. Adding it after a hundred is how the number
  gets normalised.

## Not decided here

- **Branding, update service, process isolation, marketplace integration, startup telemetry.** Named
  in `IDE-A01`; none is architecturally binding and each is ordinary work once the derivation model is
  settled.
- **Electron version and upstream cadence.** Which Code OSS releases to track, and how often, is a
  release-engineering decision that depends on the patch surface above.
- **Whether Tauri has any role.** PRD NG9 says only that it is *not required* to replace the primary
  IDE. Nothing here proposes it.
