# Security Policy

Normative terms (MUST/SHOULD/MAY) follow RFC 2119/8174 and the upstream specs `TERMINOLOGY.md`.

## Scope
- This policy applies to the `registryaccord-identity-go` server and related tooling within this repository.
- No secrets MUST be committed to the repository. `.env.local` and similar files are ignored by default.

## Reporting a Vulnerability
- Responsible disclosures are welcome.
- Please email security@registryaccord.org with details. Include steps to reproduce, impact, and version/commit.
- Do not open public issues for sensitive findings.

## Handling
- We will acknowledge receipt within 3 business days and work on a fix or mitigation plan.
- If the issue affects upstream specifications, we will coordinate with spec maintainers per `GOVERNANCE.md`.

## Logging & Privacy
- Logs MUST NOT contain secrets, tokens, or full request bodies with sensitive data.
- Use structured logging via `log/slog` and scrub sensitive fields.

## Dependencies
- Keep dependencies minimal and up to date. CI runs `gosec` via `golangci-lint`.
