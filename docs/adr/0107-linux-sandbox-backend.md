# ADR-0107 — Linux sandbox: what an unprivileged process can actually enforce

- **Status:** Proposed
- **Date:** 2026-07-30
- **Owner:** Execution
- **Supersedes:** none
- **Resolves:** the capability-map half of `EXE-A01c`. The backend is not built; this fixes what it
  may declare.

> **This ADR is measurement, and the measurement contradicted the design it was going to justify.**
> Every number below was taken on a stock Ubuntu 24.04.4 VM (kernel 6.17, `Standard_D2ns_v6`,
> uksouth), as an ordinary user with a systemd session — not as root, and not in a container. That
> distinction changed the answer in every row.

## Why the environment is the finding

The first version of this work was probed in Docker, because Docker was available and runs a real
Linux kernel. It produced a clean, confident, and **entirely wrong** capability map:

| Control | Docker said | Stock Ubuntu, unprivileged |
|---|---|---|
| `filesystem_scope` | works | **denied** |
| `network_deny` | works | works |
| `process_confinement` | works | works |
| `cpu_limit` / `memory_limit` / `process_limit` | impossible | **all three work** |

Docker ran as **root** with AppArmor absent and `/sys/fs/cgroup` mounted read-only. Both halves of
that are wrong for the target: Modbit's sandbox runs as the developer's own user, on a distro that
confines it, with systemd delegating a cgroup subtree that Docker does not expose.

Had the backend been written against the container evidence, it would have declared three controls
`enforced` that an unprivileged user cannot use, and three `unsupported` that it can. Under SBX-3 the
first of those is a release blocker — and it would have been reached by testing in the wrong
environment, not by writing careless code.

## What Ubuntu's user-namespace restriction actually does

`kernel.apparmor_restrict_unprivileged_userns=1` is the stock default on Ubuntu 24.04. It does **not**
block namespace creation, which is what the name suggests and what this investigation first concluded:

```
unshare --user                  : ok
unshare --user --net            : ok
unshare --user --map-root-user  : FAIL -- write /proc/self/uid_map: Operation not permitted
```

Setting the sysctl to 0 makes the third succeed and restoring it makes it fail again, so the sysctl is
the cause rather than a coincidence.

What it does is strip the namespace of authority. Inside an unprivileged userns:

```
Uid:    65534 65534 65534 65534
CapEff: 0000000000000000
```

**No capabilities at all.** So the rule that predicts every result below is simple: *a namespace that
needs no capability works; one that needs `CAP_SYS_ADMIN` does not.*

## Measured capability map

| Control | Enforcement | Evidence |
|---|---|---|
| `network_deny` | **enforced** | Host reaches 1.1.1.1:443; inside `unshare --user --net` the same connect is refused, `/proc/self/net/dev` lists only `lo`, and DNS resolution fails. Needs no capability — a fresh netns simply has no route. |
| `memory_limit` | **enforced** | `memory.max` written to `104857600` by the user in its own cgroup |
| `cpu_limit` | **enforced** | `cpu.max` written to `50000 100000` |
| `process_limit` | **enforced** | `pids.max` writable, owner is the user, mode 644 |
| `process_confinement` | **enforced**, with a caveat | `unshare --user --pid --fork` yields `pid=1`; descendants share the namespace and die with it. Caveat: `/proc` is not remounted (that needs `CAP_SYS_ADMIN`), so host PIDs remain *visible* even though they cannot be signalled. |
| `filesystem_scope` | **unsupported** | `mount --bind`, `chroot` and even `unshare --mount` all fail with "cannot change root filesystem propagation: Permission denied", and a file outside the workspace stays readable. |

cgroup delegation is what makes four of these work: systemd creates
`/sys/fs/cgroup/user.slice/user-$UID.slice/user@$UID.service` with `cpu memory pids` already in both
`cgroup.controllers` and `cgroup.subtree_control`, owned by the user.

**seccomp is available and bites.** An unprivileged process sets `PR_SET_NO_NEW_PRIVS`, installs a
`SECCOMP_SET_MODE_FILTER` BPF program, and the filtered syscall then returns `EPERM`. This is not one
of the declared controls, but it is how `network_deny` could be tightened to a syscall-level denial
rather than a routing one, and it is the mechanism `EXE-A01d` will need.

## Decision

**Declare five controls enforced and `filesystem_scope` unsupported, and do not pretend otherwise.**

1. `network_deny`, `cpu_limit`, `memory_limit`, `process_limit`, `process_confinement` are enforced,
   each backed by the property test above rather than by the presence of a mechanism.
2. **`filesystem_scope` is unsupported on stock Ubuntu**, and SBX-6 then makes a profile requiring it
   fail closed at establishment. That is the correct outcome and it is worth stating plainly: on this
   axis the macOS backend is *stronger* than the Linux one, which inverts the usual expectation.
3. **Strength stays `StrengthProcess`.** This confines a process; it does not virtualize one.
4. The backend must **measure, not assume, at construction.** `apparmor_restrict_unprivileged_userns`
   is a sysctl an administrator can change, `max_user_watches` is memory-derived, and cgroup
   delegation depends on there being a systemd user session. A backend that hardcoded this table
   would report enforcement it does not have on the first host that differs — which is SBX-3's
   failure mode arrived at by a different route. The capability map is built by probing at
   `NewLinuxBackend`, exactly as `NewSeatbeltBackend` refuses when `sandbox-exec` is absent.

## Consequences

- `EXE-A01c` is a larger deliverable than `EXE-A01b` and a differently shaped one: five enforced
  controls against Seatbelt's two, but missing the one Seatbelt leads with.
- **A container backend becomes more valuable, not less.** `filesystem_scope` is exactly what
  `EXE-A01d` buys on Linux, and this ADR is the argument for it.
- Raising `filesystem_scope` to enforced on Linux requires either a privileged helper, a distro
  where the AppArmor restriction is off, or `EXE-A01d`. None is in `EXE-A01c`'s scope.

## Not measured

- **Any distro other than Ubuntu 24.04.** Debian, Fedora and RHEL configure the userns restriction
  differently, and Fedora ships no AppArmor at all. The construction-time probe is the answer, but
  the *spread* of outcomes is unmeasured.
- **A host with no systemd user session.** Delegation was verified with `loginctl enable-linger`
  active. A daemon-run Modbit under a system unit has a different cgroup path.
- **Whether the PID-namespace `/proc` leak matters to a real policy.** Host processes are visible but
  not signallable; no requirement currently distinguishes those.
- **seccomp as a control.** Proven to work, not yet wired to anything.
