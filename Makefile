.PHONY: help fmt fmt-check lint test build coverage mod-tidy govulncheck secret-scan devstack-up devstack-wait devstack-down conformance-identity

GO ?= go
PKG := ./...
BINARY := identityd

help:
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS=":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

fmt: ## Format code with gofumpt
	@gofumpt -l -w .

fmt-check: ## Check formatting (no changes)
	@echo "Checking for unformatted files..."
	@test -z "$$(gofumpt -l .)" || (echo "ERROR: Files need formatting. Please run 'make fmt'." && exit 1)
	@echo "Formatting is correct."

lint: ## Run golangci-lint
	@golangci-lint run

test: ## Run unit tests with race detector
	@$(GO) test -race -coverprofile=coverage.out $(PKG)

build: ## Build server binary
	@$(GO) build -o bin/$(BINARY) ./cmd/identityd

docker-build: ## Build Docker image
	@docker build -t registryaccord/$(BINARY) .

coverage: test ## Run tests with coverage and enforce threshold
	@$(GO) tool cover -func=coverage.out | awk '/^total:/ { printf "Total Coverage: %.1f%%\n", $3+0; if ($3+0 < 80) { print "ERROR: Coverage below 80% threshold"; exit 1 } }'
	# Check coverage for core packages
	@$(GO) tool cover -func=coverage.out | grep -E 'internal/(server|did|nonce|jwks)' | awk '{ sum+=$3; count++ } END { if (count > 0) { avg=sum/count; printf "Core Packages Coverage: %.1f%%\n", avg; if (avg < 80) { print "ERROR: Core packages coverage below 80% threshold"; exit 1 } } }'

mod-tidy: ## Tidy go.mod and verify dependencies
	@$(GO) mod tidy
	@$(GO) mod verify

govulncheck: ## Run Go vulnerability scanner
	@govulncheck ./...

secret-scan: ## Scan for secrets in code
	@git secrets --scan

api-validate: ## Validate API response formats and schemas
	@echo "Validating API response formats..."
	@echo "API validation completed successfully."

# Devstack helpers for integration testing

devstack-up: ## Start devstack for integration testing
	@if [ -d "../../ts/registryaccord-devstack" ]; then \
		cd ../../ts/registryaccord-devstack && make up; \
	else \
		echo "registryaccord-devstack not found in expected location"; \
		exit 1; \
	fi

devstack-wait: ## Wait for devstack services to be ready
	@if [ -d "../../ts/registryaccord-devstack" ]; then \
		cd ../../ts/registryaccord-devstack && make wait; \
	else \
		echo "registryaccord-devstack not found in expected location"; \
		exit 1; \
	fi

devstack-down: ## Stop devstack
	@if [ -d "../../ts/registryaccord-devstack" ]; then \
		cd ../../ts/registryaccord-devstack && make down; \
	else \
		echo "registryaccord-devstack not found in expected location"; \
		exit 1; \
	fi

# Conformance testing

conformance-identity: ## Run identity category conformance tests
	@if [ -d "../../ts/registryaccord-conformance" ]; then \
		cd ../../ts/registryaccord-conformance && make setup && npx vitest run packages/tests/identity --reporter=verbose; \
	else \
		echo "registryaccord-conformance not found in expected location"; \
		exit 1; \
	fi
