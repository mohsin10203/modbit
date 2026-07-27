# Modbit Agent Skills

Repeatable procedures for agents working in this repository. Each skill is a directory containing a
`SKILL.md` with YAML frontmatter (`name`, `description`) and a checklist-shaped body.

These skills encode the *process* requirements from PRD v5.1 and `rules.md` so a capability is never
shipped with a missing surface, settings definition, event, threat model, or test.

| Skill | Use when |
|---|---|
| `new-capability` | Adding any product capability. Drives the 11-step sequence from `.agents.md` §6. |
| `settings-key` | Adding or changing a Settings Registry definition. |
| `canonical-event` | Adding or changing a canonical event type. |
| `structured-contract` | A workflow must return a validated artifact instead of prose. |
| `threat-model` | A new service, boundary, tool, or external effect is introduced. |
| `go-package` | Creating a new Go package under `pkg/` or `services/`. |
| `taint-review` | Any code path that consumes context, calls a tool, or performs an external effect. |
| `evidence-pr` | Writing the change description for a substantial change. |

## Conventions

- A skill never weakens a rule in `rules.md`; it operationalizes one.
- Skills reference requirement IDs (`SET-1`, `TNT-4`, `RUN-2`, …) so evidence is traceable.
- If a skill's checklist cannot be satisfied, stop and open an ADR in `docs/adr/`.
