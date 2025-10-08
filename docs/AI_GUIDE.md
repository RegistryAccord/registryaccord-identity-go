# AI Guide for registryaccord-identity-go

This guide is a prompt-ready, one-page reference for AIs and contributors. Normative terms (MUST/SHOULD/MAY) follow RFC 2119/8174 and the upstream `TERMINOLOGY.md` in the specs repo.

Sources: `../registryaccord-specs/TERMINOLOGY.md`, `../registryaccord-specs/GOVERNANCE.md`, `../registryaccord-specs/schemas/INDEX.md`, `../registryaccord-specs/schemas/SPEC-README.md`.

## Scope & Service Type
- **Purpose:** Identity service implementing issuance and DID operations aligned with `com.registryaccord.identity` shapes (schema language only; we don’t embed Lexicon in Go).
- **Runtime:** Go 1.22+.
- **Layout:** `cmd/identityd`, `internal/`, `pkg/`, `api/`.

## Coding Style
- **Formatting:** gofumpt. Run `make fmt`.
- **Lint:** golangci-lint with `gofumpt, govet, errcheck, staticcheck, revive, gosec`. Run `make lint`.
- **Errors:** Return wrapped errors with `%w`. Prefer sentinel errors in package scope. No panics in request path.
- **Context:** All public funcs that may block MUST accept `context.Context` as the first arg; honor cancellation/timeouts.
- **Logging:** Use `log/slog`. No secrets or PII in logs. Use structured fields.

## Error Handling & Input Validation
- **Validation:** Validate all external inputs (HTTP, config). Reject unknown fields in JSON if feasible. Use clear 4xx vs 5xx separation.
- **Security:** Run `gosec` via `make lint` (in CI). Never log secrets. Environment variables MAY be used for secrets but MUST NOT be committed.

## Tests
- **Layout:** Table-driven tests, use golden files for stable outputs. Run `make test`.
- **Coverage:** `make coverage` prints summary.

## API & Spec Alignment
- **Naming:** Endpoint and type names SHOULD mirror Lexicon NSID shapes (schema language only). Cite `schemas/INDEX.md` and examples for field names.
- **Evolution:** Backward-compatible changes only; breaking changes require ADR and new versioned name per upstream `GOVERNANCE.md` policy.

## Local Dev
- **Format check:** `make fmt-check`
- **Lint:** `make lint`
- **Test:** `make test`
- **Build:** `make build` (outputs `bin/identityd`)

## Proposing Changes (Minimal Diffs)
- Keep PRs small and focused. Update docs and ADRs when changing public behavior.
- If API-affecting, tag CODEOWNERS `@RegistryAccord/spec-editors`.
- Link upstream issues/ADRs where relevant. Include rationale.

## Docs & Examples Sync
- If API structs or naming change, update `docs/ARCHITECTURE.md` and ADRs; ensure alignment with `registryaccord-specs` shapes and examples cited in `schemas/INDEX.md`.
