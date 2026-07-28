# Modbit repository commands.
#
# These target names are the stable CI contract (.agents.md §8). Component-local commands may
# exist, but CI invokes only these.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

GO          ?= go
GOFLAGS     ?=
GO_PKGS     := ./...
GENERATOR   := ./tools/modbitgen

# Directories that generated code is written into. Used by the drift gate.
GENERATED_GLOBS := 'pkg/**/*_gen.go' 'packages/contracts/src/*.ts'

.PHONY: help
help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

# --------------------------------------------------------------------------------------------
# Setup
# --------------------------------------------------------------------------------------------

.PHONY: bootstrap
bootstrap: ## Install toolchain dependencies and verify the environment
	$(GO) version
	$(GO) mod download
	@echo "bootstrap: ok"

# --------------------------------------------------------------------------------------------
# Contracts and code generation (R-CTR-01..03)
# --------------------------------------------------------------------------------------------

.PHONY: generate
generate: ## Regenerate all code from contracts/ (idempotent)
	$(GO) run $(GENERATOR) -contracts ./contracts -root .

.PHONY: generate-check
generate-check: ## Fail when generated code is stale relative to contracts/
	@$(MAKE) --no-print-directory generate
	@if [ -d .git ] && ! git diff --quiet -- $(GENERATED_GLOBS) 2>/dev/null; then \
		echo "ERROR: generated code is stale. Run 'make generate' and commit the result."; \
		git --no-pager diff --stat -- $(GENERATED_GLOBS); \
		exit 1; \
	fi
	@echo "generate-check: ok"

# --------------------------------------------------------------------------------------------
# Static quality
# --------------------------------------------------------------------------------------------

.PHONY: format
format: ## Apply canonical formatting
	$(GO) fmt $(GO_PKGS)

.PHONY: format-check
format-check: ## Fail on unformatted files
	@out="$$(gofmt -l . 2>/dev/null)"; \
	if [ -n "$$out" ]; then echo "ERROR: unformatted files:"; echo "$$out"; exit 1; fi
	@echo "format-check: ok"

.PHONY: lint
lint: ## Run static analysis
	$(GO) vet $(GO_PKGS)

.PHONY: typecheck
typecheck: ## Compile every package without producing binaries
	$(GO) build $(GO_PKGS)

# --------------------------------------------------------------------------------------------
# Tests (R-TST-01)
# --------------------------------------------------------------------------------------------

.PHONY: test-unit
test-unit: ## Unit tests with the race detector
	$(GO) test -race -count=1 $(GO_PKGS)

.PHONY: test-integration
test-integration: ## Integration tests against real stores and buses
	$(GO) test -race -count=1 -tags=integration $(GO_PKGS)

.PHONY: test-e2e
test-e2e: ## End-to-end surface tests
	$(GO) test -count=1 -tags=e2e $(GO_PKGS)

.PHONY: test-security
test-security: ## Adversarial and isolation suites (R-TST-05)
	$(GO) test -race -count=1 -tags=security -run 'Security|Isolation|Injection|Taint|Secret' $(GO_PKGS)

.PHONY: test-conformance
test-conformance: ## Shared contract conformance suites (R-TST-06)
	$(GO) test -race -count=1 ./pkg/inference/conformance/...
	$(GO) test -race -count=1 -tags=conformance -run Conformance $(GO_PKGS)

.PHONY: test-benchmark-smoke
test-benchmark-smoke: ## Benchmark smoke run, one iteration per benchmark
	$(GO) test -run '^$$' -bench . -benchtime 1x $(GO_PKGS)

# Deliberately outside `check` (QA-A01c): building a Standard-class corpus takes minutes, and a gate
# that slows the edit-test loop is one people stop running. CI runs it; `check` stays fast.
#
# Budgets are PRD §8A.3's, measured as p95 rather than as a mean, and each names its requirement.
# A budget carried as a known gap fails if it starts *passing* — an unrecorded commitment is how the
# next regression goes unnoticed.
.PHONY: perf-gate
perf-gate: ## Performance budgets from PRD §8A.3 (LCX-2, LCX-3, LCX-4)
	$(GO) test -tags=perf -count=1 -timeout 30m -run 'TestPerformanceBudget' -v $(GO_PKGS)

# --------------------------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------------------------

.PHONY: db-migrate
db-migrate: ## Apply forward migrations
	@echo "db-migrate: no migrations registered yet (Phase 1 has no persistent store)"

.PHONY: db-rollback-check
db-rollback-check: ## Verify every migration has an assessed rollback (R-SQL-01)
	@echo "db-rollback-check: no migrations registered yet"

# --------------------------------------------------------------------------------------------
# Contract gates
# --------------------------------------------------------------------------------------------

.PHONY: api-breaking-check
api-breaking-check: ## Diff the API contract against the previous release
	@echo "api-breaking-check: no published API surface yet"

.PHONY: errors-freeze
errors-freeze: ## Regenerate the error-contract lock (requires an ADR for any non-additive change)
	$(GO) run $(GENERATOR) -contracts ./contracts -root . -freeze-errors

.PHONY: errors-freeze-check
errors-freeze-check: ## Fail when an error code was removed or its wire semantics changed
	$(GO) run $(GENERATOR) -contracts ./contracts -root . -check errors-freeze

.PHONY: settings-schema-check
settings-schema-check: ## Validate every Settings Registry definition
	$(GO) run $(GENERATOR) -contracts ./contracts -root . -check settings

.PHONY: capability-check
capability-check: ## Validate the Capability Registry against the capability matrix
	$(GO) run $(GENERATOR) -contracts ./contracts -root . -check capabilities

.PHONY: docs-check
docs-check: ## Verify tracker and governance documents are present and consistent
	@test -f tasks.md    || { echo "ERROR: tasks.md missing (R-DOC-02)"; exit 1; }
	@test -f rules.md    || { echo "ERROR: rules.md missing"; exit 1; }
	@test -f .agents.md  || { echo "ERROR: .agents.md missing"; exit 1; }
	@echo "docs-check: ok"

# --------------------------------------------------------------------------------------------
# Aggregate
# --------------------------------------------------------------------------------------------

.PHONY: check
check: generate-check format-check lint typecheck test-unit errors-freeze-check settings-schema-check capability-check docs-check ## Pre-review gate

.PHONY: package
package: ## Build distributable artifacts
	@mkdir -p bin
	$(GO) build -o bin/ $(GENERATOR)
	@echo "package: bin/"
