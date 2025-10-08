# registryaccord-identity-go
registryaccord identity go

License

“This project is licensed under the GNU Affero General Public License v3.0 (AGPL‑3.0). For organizations unable to comply with AGPL obligations (including network use), commercial licenses are available. Contact legal@registryaccord.org.”

## Purpose
Identity service for the RegistryAccord protocol, focused on identity issuance and DID operations. API naming and data shapes SHOULD align with `com.registryaccord.identity` definitions in the upstream specs (schema language only).

References (upstream specs):
- `../registryaccord-specs/README.md`
- `../registryaccord-specs/schemas/INDEX.md`
- `../registryaccord-specs/schemas/SPEC-README.md`
- `../registryaccord-specs/GOVERNANCE.md`
- `../registryaccord-specs/TERMINOLOGY.md`

Normative terms (MUST/SHOULD/MAY) are as defined by RFC 2119/8174 and the upstream TERMINOLOGY.

## Quick start
- Requirements: Go 1.22+
- Install tools (once):
  - `go install mvdan.cc/gofumpt@latest`
  - Install golangci-lint per CI script if not present
- Commands:
  - Format: `make fmt` (check: `make fmt-check`)
  - Lint: `make lint`
  - Test: `make test`
  - Build: `make build` → `bin/identityd`

## Contributing
- See `CONTRIBUTING.md` for local workflow and CI steps.
- Security policy: `docs/SECURITY.md`.
- Architectural docs and ADRs: `docs/ARCHITECTURE.md`, `docs/DECISIONS/`.

## License
- SPDX: AGPL-3.0-only (see `LICENSE`).
- Commercial license available — contact `legal@registryaccord.org`.
