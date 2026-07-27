---
name: go-package
description: Create a Go package under pkg/ or services/ that satisfies Modbit's Go conventions — boundary ownership, context propagation, error codes, goroutine lifetime, tenancy, observability, and tests. Use before writing the first file of a new Go package.
---

# New Go package

## 1. Decide the boundary

- [ ] The package owns exactly one boundary. Name it in the package comment.
- [ ] `pkg/` = shared library used by ≥2 deployable units. `services/<unit>/internal/` = private to
      one unit. Do not put single-consumer code in `pkg/`.
- [ ] Interfaces are declared where they are consumed, not where they are implemented
      (R-ARCH-05).

## 2. File skeleton

```go
// Package taint implements provenance classification and propagation for run context.
//
// Boundary: taint classification and lattice arithmetic only. Policy escalation decisions
// live in pkg/policy; ingestion points live in the context plane.
//
// Requirements: PRD v5.1 §12A (TNT-1..TNT-7).
package taint
```

- [ ] Package comment states: what it owns, what it explicitly does not own, and the requirement
      IDs it implements.
- [ ] Every exported identifier is documented (R-GO-05).

## 3. Conventions checklist

- [ ] Every network/model/worker/tool/storage call takes `ctx context.Context` as its first
      parameter and honours cancellation (R-GO-01).
- [ ] Errors wrap a stable Modbit code: `modberr.Wrap(err, modberr.CodePolicyDenied, "...")`
      (R-ERR-01, R-GO-02).
- [ ] No package-level mutable state for run or tenant data (R-GO-06).
- [ ] Every goroutine has a documented exit condition and is owned by a lease or an
      `errgroup`/supervisor (R-GO-03).
- [ ] Tenant-owned reads and writes filter by `organization_id` at the repository layer
      (R-TEN-02).
- [ ] Time and randomness are injected (`Clock`, `IDSource`) so tests are deterministic
      (R-TST-03).
- [ ] Structured logging only; no `fmt.Print*` in shipped paths (R-OBS-03).
- [ ] `panic` only for constructor-time programmer error (R-GO-08).

## 4. Dependencies

- [ ] Prefer the standard library. A new direct dependency needs justification in the change
      description (R-GO-09).
- [ ] No dependency from `pkg/` on `services/`.
- [ ] No import cycles; run `go list ./... > /dev/null` to confirm.

## 5. Tests

- [ ] `_test.go` in the same package for internal invariants; `_test` package for the public
      contract.
- [ ] Table driven for pure logic (R-TST-07).
- [ ] Golden files for anything serialized into a contract.
- [ ] `go test -race ./...` clean.
- [ ] No real secrets or customer data in fixtures (R-TST-04).

## 6. Wire up

- [ ] `make format lint typecheck test-unit` clean.
- [ ] Update `tasks.md`.
