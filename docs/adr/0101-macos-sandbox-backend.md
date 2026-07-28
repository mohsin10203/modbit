# ADR-0101 — macOS sandbox backend uses `sandbox-exec`

- **Status:** Accepted
- **Date:** 2026-07-28
- **Owner:** Execution
- **Supersedes:** none
- **Resolves:** ADR-0100 open decision 1 ("Native macOS sandbox implementation")

## Context

`EXE-A01a` shipped the backend contract (SBX-1) and a portable process backend that honestly declares
it enforces almost nothing: Go's standard library offers no way to confine a child's filesystem
access or deny its egress, `syscall.Setrlimit` applies to the calling process rather than a child,
and darwin's `SysProcAttr` carries no namespace, seccomp, or rlimit fields.

That leaves macOS — the platform an IDE actually runs on — with no enforced filesystem scope and no
enforced network deny. EXE-4 and EXE-6 are unmet there, and SBX-6 means any profile requiring them
cannot establish. The portable backend is honest, but honesty about having no sandbox is not a
sandbox.

## Options considered

| Option | Verdict |
|---|---|
| `sandbox_init(3)` via cgo | Same deprecated API as `sandbox-exec`, plus cgo. It applies to the *calling* process, and Go cannot safely run arbitrary code between fork and exec, so it needs a helper binary anyway — which is what `sandbox-exec` already is. |
| `/usr/bin/sandbox-exec` | Deprecated by Apple, present and functional on current macOS, no dependency, no cgo. |
| Endpoint Security framework | Requires an entitlement and notarization, and observes rather than confines. Wrong tool. |
| App Sandbox entitlements | Applies to a signed bundle as a whole, not to a child process per run. Wrong granularity. |
| Container runtime | Real isolation, but a different strength tier (`StrengthContainer`) and a much larger dependency. Belongs to `EXE-A01d`, not here. |

## Evidence

Measured on macOS 26.5.1, `/usr/bin/sandbox-exec` present and root-owned:

| Control | Result |
|---|---|
| Write outside the workspace | **denied** by the kernel (`Operation not permitted`), not by a shell check |
| Write inside the workspace | **allowed**, once the profile names the symlink-resolved path |
| Outbound TCP connect under `(deny network*)` | **refused** |

One finding shaped the implementation: a profile's `(subpath ...)` matches the **resolved** path. A
workspace under `/var/folders/...` is not matched by a rule naming `/var/...` because the kernel sees
`/private/var/...`. Writing the unresolved path produces a profile that denies everything including
the workspace itself — a sandbox that looks configured and breaks the run. The backend resolves the
path before generating the profile, and a test pins it.

## Decision

The macOS backend generates an SBPL profile and executes through `/usr/bin/sandbox-exec`.

It declares `filesystem_scope` and `network_deny` as **enforced**, and everything else at the level
the portable backend already declares. Its strength stays `StrengthProcess`: `sandbox-exec` confines
a process, it does not virtualize one, and claiming `StrengthContainer` would let a profile
demanding container isolation select something that is not one (SBX-4).

## Consequences

**Accepted risk: the API is deprecated.** Apple has marked `sandbox-exec` deprecated for several
major versions and has shipped it in every one of them, including the current release. There is no
supported replacement for per-command confinement of a child process; the alternative is the same
deprecated mechanism reached through cgo. The mitigation is structural rather than hopeful: this is a
`Backend` behind the SBX-1 contract, so replacing it is one implementation, not a migration — and
`Establish` probes for the binary and refuses rather than degrading silently if a future macOS
removes it.

**Profile injection is a real risk and is handled by refusal.** A workspace path is attacker-influenced
in the case that matters (a run pointed at a checked-out repository), and SBPL is a Lisp-like syntax
where an unescaped `"` or `)` in a path would close the string and let the rest of the path become
profile source — arbitrary sandbox rules chosen by whoever named the directory. Rather than escape,
the backend **refuses** any workspace path containing a character it cannot represent safely. A
directory name that requires escaping is not a directory Modbit needs to index.

**Linux and Windows are unchanged** and remain `EXE-A01c` and `EXE-A01d`. Linux is achievable with
namespaces and seccomp through `syscall` with no dependency, and is the stronger candidate for
reaching `StrengthContainer`.
