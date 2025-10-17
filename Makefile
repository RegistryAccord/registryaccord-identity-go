.PHONY: help fmt fmt-check lint test build coverage mod-tidy govulncheck secret-scan

GO ?= go
PKG := ./...
BINARY := identityd

help:
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS=":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

fmt: ## Format code with gofumpt
	@gofumpt -l -w .

fmt-check: ## Check formatting (no changes)
	@gofumpt -l . | tee /tmp/gofumpt-check.log
	@test -s /tmp/gofumpt-check.log && (echo "Files need formatting:" && cat /tmp/gofumpt-check.log && rm /tmp/gofumpt-check.log && exit 1) || (rm -f /tmp/gofumpt-check.log && echo "Formatting is correct" && exit 0)

lint: ## Run golangci-lint
	@golangci-lint run

test: ## Run unit tests with race detector
	@$(GO) test -race -coverprofile=coverage.out $(PKG)

build: ## Build server binary
	@$(GO) build -o bin/$(BINARY) ./cmd/identityd

docker-build: ## Build Docker image
	@docker build -t registryaccord/$(BINARY) .

coverage: test ## Show coverage summary
	@$(GO) tool cover -func=coverage.out | tail -n 1

mod-tidy: ## Tidy go.mod and verify dependencies
	@$(GO) mod tidy
	@$(GO) mod verify

govulncheck: ## Run Go vulnerability scanner
	@govulncheck ./...

secret-scan: ## Scan for secrets in code
	@git secrets --scan

api-validate: ## Optional: validate API naming against upstream conventions
	@echo "No API validator yet; ensure alignment with specs/schemas NSIDs" && exit 0
