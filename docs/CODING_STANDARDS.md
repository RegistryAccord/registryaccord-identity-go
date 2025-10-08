# Go Coding Standards

Normative terms (MUST/SHOULD/MAY) follow RFC 2119/8174 and upstream `TERMINOLOGY.md`.
Sources: `../registryaccord-specs/TERMINOLOGY.md`, `../registryaccord-specs/GOVERNANCE.md`.

## Tooling
- **Formatting (MUST):** `gofumpt`. CI runs format check. Use `make fmt`.
- **Lint (MUST):** `golangci-lint` with `gofumpt, govet, errcheck, staticcheck, revive, gosec`. Run `make lint`.
- **Security (SHOULD):** `gosec` issues addressed or justified.

## Package & Naming
- **Packages (SHOULD):** lower_snake or single word; avoid stutter (e.g., `identity` not `identitypkg`).
- **Exported names (SHOULD):** concise, Go-idiomatic. Keep API types aligned with spec field names where feasible.

## Errors
- **Wrapping (MUST):** wrap with `%w`; define sentinel errors where appropriate.
- **No panics (MUST):** avoid panics in request path; return errors.

## Context
- **Usage (MUST):** public functions that block take `context.Context` first. Propagate; respect cancellation/timeouts.

## Logging
- **Library (MUST):** `log/slog`.
- **Security (MUST):** no secrets or PII in logs; structured fields; avoid logging entire request bodies.

## Tests
- **Table tests (SHOULD):** prefer table-driven.
- **Golden files (MAY):** for stable wire formats.
- **Race/coverage (SHOULD):** `make test` runs `-race` and coverage.

## API Shape & Specs Alignment
- **Naming (SHOULD):** Endpoint/type names mirror Lexicon NSID shapes (schema language only). Cite `schemas/INDEX.md`.
- **Evolution (MUST):** backward-compatible; breaking changes require ADR and new name per upstream `GOVERNANCE.md`.

## Code Review Checklist
- **[fmt/lint]** Clean `make fmt-check` and `make lint`.
- **[errors]** `%w` wrapping and helpful messages.
- **[ctx]** Context passed/honored.
- **[logs]** No secrets; structured slog.
- **[tests]** Cover happy/error paths with table tests.
- **[specs]** Names and fields align with upstream shapes.
