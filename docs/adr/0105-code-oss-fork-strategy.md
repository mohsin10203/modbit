# ADR-0105 — Code OSS derivation: overlay with a bounded patch series

- **Status:** Proposed
- **Date:** 2026-07-28
- **Owner:** Desktop
- **Supersedes:** none
- **Resolves:** the fork/rebase half of `IDE-A01`, which gates `IDE-A02`–`A05` and `BRS-A01`

> **Was analysis; now partly measured.** This ADR originally rested on the document pack and on how
> upstream-derivative maintenance is known to fail, and it named the one measurement it needed: the
> IDE-1..IDE-15 classification. That measurement was taken on 2026-07-30 against the real API surface
> — `vscode.d.ts` and the 176 proposed `.d.ts` files at `microsoft/vscode@main` — and is recorded
> below. It changed the answer: **one likely core patch, not the handful feared**, because three of
> the four doubtful cases are proposed APIs, which cost a Code OSS derivative nothing at rebase time.
>
> Still not measured: whether IDE-9 genuinely requires a patch, which needs a source-level spike
> rather than a header-level one. No Code OSS checkout exists in this repository.

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
   The measurement below puts the **initial ceiling at 5 touched upstream files**, with IDE-9 the
   only requirement expected to spend against it.
5. **Proposed APIs are preferred over patches, and pinned.** They are the third option the original
   framing missed. A proposed API is upstream-maintained and costs nothing at rebase; it changes
   without deprecation, so the upstream version is pinned and re-checked on every bump. That is a
   version-pinning cost, not a merge cost, and it is the cheaper of the two by a wide margin.

Point 4 is the one that makes the difference between this and a hard fork. Every derivative that
ended up unmaintainable got there by accepting individually reasonable patches, and the honest defence
is not discipline — it is a number that has to be argued up. The repository already does this to
itself: `QA-A01c` gates PRD §8A.3's budgets and marks each one enforced or a known gap, and the
startup targets (<3 s warm, <6 s cold) are release gates that belong in the same harness.

## The measurement (taken 2026-07-30)

**This section was the ADR's stated gap. It is now measured**, against the actual API surface rather
than recollection: `src/vscode-dts/vscode.d.ts` at `microsoft/vscode@main` — 21,235 lines — plus the
176 `vscode.proposed.*.d.ts` files in the same directory. Every claim below cites a symbol that
exists or an absence verified by grep over that file set.

### The finding that changes the answer

The four doubtful cases were framed as "extension API or core patch". That framing was **wrong**,
and the third category is where three of them actually land:

| | Available to a marketplace extension | Available to Modbit |
|---|---|---|
| **Stable API** | yes | yes |
| **Proposed API** | **no** — Microsoft permits proposed APIs only for built-in extensions | **yes** — Modbit ships its own derivative and controls `--enable-proposed-api` |
| **Core patch** | n/a | yes, at rebase cost |

Modbit is not publishing to Microsoft's marketplace (PRD §6, §24.1 — Open VSX), and it builds its own
Workbench. **A proposed API therefore costs nothing at rebase time**: it is an upstream-maintained
`.d.ts`, not a patch to upstream source. It carries a different risk — proposed APIs change without
deprecation — but that is a version-pinning problem, not a merge-conflict problem.

### The four doubtful cases, resolved

| Req | Verdict | Evidence |
|---|---|---|
| **IDE-1** multi-line / FIM | **stable** | `InlineCompletionItemProvider` (`vscode.d.ts:5233`), `registerInlineCompletionItemProvider` (`:14862`), `InlineCompletionList` (`:5255`) |
| **IDE-1** partial-accept (PACC-1/2) | **proposed** | `handleDidPartiallyAcceptCompletionItem(item, info: PartialAcceptInfo)` — `vscode.proposed.inlineCompletionsAdditions.d.ts:123`. Absent from stable, confirmed by grep. |
| **IDE-1** next-edit | **proposed** | same file: `isInlineEdit`, `showRange`, `displayLocation`, `showInlineEditMenu` |
| **IDE-4** terminal selection | **proposed** | `Terminal.selection: string \| undefined` — `vscode.proposed.terminalSelection.d.ts:14`. Absent from stable. |
| **IDE-9** in-editor diff zones | **core patch, probably** | Stable offers `TextEditorDecorationType` and `WorkspaceEdit` (`:3969`), which render *decorations*, not an accept/reject-per-hunk zone. No proposed API provides one; `mappedEditsProvider` is about computing edits, not presenting them. This is the one genuinely likely patch. |
| **IDE-12** isolated worktrees | **no patch needed** | A worktree is a separate folder, so this is one window per `workspaceFolder` plus process isolation Modbit already owns. `pkg/index/worktree.go` (CTX-A01g) is the hard part and it is done. |

### What that means for the patch budget

**One likely core patch, not fifteen.** IDE-9 is the only requirement with no stable and no proposed
route. IDE-2, IDE-3, IDE-5, IDE-6, IDE-7, IDE-8, IDE-10, IDE-11, IDE-13, IDE-14 are ordinary
extension work over stable APIs (`WebviewView`, `ViewColumn`, `scm`/`SourceControl` at `:16580`,
tree views, status bar, commands); IDE-15 (voice) is explicitly optional and not a completion
dependency.

So the overlay recommendation stands, and the number that predicts its cost is now measured rather
than feared. **The initial patch ceiling should be small — 5 touched upstream files — and IDE-9 is
what the first patches are expected to spend it on.**

### What is still not measured

- **Whether IDE-9 truly needs a patch.** No proposed API supplies an in-editor accept/reject zone,
  but Copilot-style inline editing exists upstream, so the mechanism is in the tree even if it is not
  exposed. Confirming that means reading `src/vs/workbench/contrib/` rather than the `.d.ts`, which
  is a deeper spike than this one.
- **Proposed-API churn.** These carry no compatibility promise. The cost is a pinned upstream version
  and a re-check per bump — real, ongoing, and cheaper than a patch.
- **Nothing has been built.** No Code OSS checkout exists in this repository; this is a
  classification of the API surface, not a working overlay.

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
