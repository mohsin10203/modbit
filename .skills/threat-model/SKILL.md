---
name: threat-model
description: Threat model a new Modbit service, trust boundary, tool, or external effect — data-flow, identity, secrets, network, isolation tests, audit, abuse cases, failure behavior, rollout. Required by the SDD security review gate before general release.
---

# Threat model a boundary

Implements SDD §19 and `security-and-threat-model-v5.1.md`. Output is a document under
`docs/adr/` or the capability's design note, plus tests.

## 1. Data-flow diagram

- [ ] Name every actor, process, store, and channel.
- [ ] Mark each trust boundary crossing.
- [ ] For each crossing, state the classification of the data and whether DLP/redaction applies.

## 2. Identity model

- [ ] Who calls this? (user, service identity, agent, worker, system)
- [ ] How is the caller authenticated? What proves the organization?
- [ ] What authorization dimensions apply (R-TEN-05), including taint state and trust state?

## 3. Secret model

- [ ] Which credential classes are in play: Provider Credential, Integration Credential, Task
      Secret?
- [ ] Confirm provider credentials stay inside the Model Gateway boundary (INV-2).
- [ ] Secrets are leased with bounded purpose and expiry (R-SEC-08); no ambient environment
      variables.
- [ ] Redaction covers logs, traces, artifacts, prompts, and errors (R-SEC-09).

## 4. Network policy

- [ ] Ingress: who may reach it, from which zone?
- [ ] Egress: explicit allowlist. Default deny.
- [ ] Does this component need outbound internet at all? Prefer no.

## 5. Isolation

- [ ] Tenant isolation test for every read and write path (R-TEN-06).
- [ ] Space isolation where the entity is Space scoped.
- [ ] Cache keys include tenant and policy version (R-TEN-03).

## 6. Abuse cases

Walk each and record the mitigation:

- [ ] **Prompt injection** through repository instructions, MCP output, web content, issue text,
      logs, or tool output (INV-13, TNT-7).
- [ ] **Secret exfiltration** via prompts, artifacts, logs, network egress, or generated code.
- [ ] **Confused deputy**: agent induced to use a privileged tool on behalf of untrusted content.
- [ ] **Tenant escape**: id substitution, cache poisoning, index bleed.
- [ ] **Sandbox escape**: path/symlink/process/network escape (SBX-5).
- [ ] *(v5.1)* **Memory poisoning**: crafted corroboration to activate a hostile memory.
- [ ] *(v5.1)* **Trust farming**: low-risk successes farmed to unlock high-risk autonomy.
- [ ] *(v5.1)* **Taint bypass**: laundering tainted content through summarization or generation.
- [ ] *(v5.1)* **Export leakage**: sensitive content escaping through SARIF or git-native evidence.

## 7. Failure behavior

- [ ] Enumerate each dependency failure and state the behavior. Default is **fail closed** for
      enforcement paths and **visible degradation** for capability paths (R-ERR-05, SBX-6).
- [ ] Confirm no silent fallback to a weaker policy, model, sandbox, or region.

## 8. Audit

- [ ] Every privileged and authoritative action emits an audit event with actor, decision, and
      reason.
- [ ] Denials are audited as loudly as approvals.

## 9. Rollout controls

- [ ] Feature flag, blast-radius limit, observable signal, tested rollback.

## 10. Evidence

- [ ] Security tests written and passing under `make test-security`.
- [ ] Findings recorded with the shared finding schema and lifecycle.
- [ ] Update `tasks.md` and the capability registry entry.
