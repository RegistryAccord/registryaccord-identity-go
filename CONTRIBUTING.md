# Contributing to registryaccord-identity-go

This repository implements the RegistryAccord Identity service in Go. For specification context and normative processes, see the upstream specs repo:
- `../registryaccord-specs/README.md`
- `../registryaccord-specs/GOVERNANCE.md`
- `../registryaccord-specs/TERMINOLOGY.md`
- `../registryaccord-specs/schemas/INDEX.md` and `schemas/SPEC-README.md`

Normative keywords (MUST/SHOULD/MAY) follow RFC 2119/8174 and the upstream TERMINOLOGY.

## Local Workflow
- Go 1.22+.
- Install tools once: `go install mvdan.cc/gofumpt@latest` and golangci-lint per CI script.
- Format: `make fmt` (MUST be clean via `make fmt-check`).
- Lint: `make lint` (MUST pass).
- Test: `make test` (race + coverage).
- Build: `make build` → `bin/identityd`.

## Proposing Changes
- Keep PRs minimal and focused; include rationale. If public/API behavior changes, you MUST:
  - Update `docs/ARCHITECTURE.md` and add/modify ADRs under `docs/DECISIONS/`.
  - Align naming/data shapes with `com.registryaccord.identity` in the specs (schema language only) and reference examples.
  - Tag `@RegistryAccord/spec-editors` for API-affecting changes (CODEOWNERS enforced).
- Link any related upstream spec issue/PR as per `GOVERNANCE.md`.

## Security
- No secrets in repo or logs. See `docs/SECURITY.md` for reporting.

## Developer Certificate of Origin
- Sign commits with `-s`.

## CI locally
- Run `make fmt-check lint test` before pushing.
- Optional schema/API naming check: `make api-validate`.
