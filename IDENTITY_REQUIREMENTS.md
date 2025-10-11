This document defines Phase 1 requirements for the identity service, including APIs, security controls, key lifecycle, observability, CI gates, and acceptance criteria required to interoperate with the protocol and downstream services.​

Scope
Provide DID creation and resolution, short‑lived JWT session issuance, and a documented key lifecycle runbook to serve as the protocol’s identity foundation in Phase 1.​

Expose simple, developer‑ready endpoints for local stacks and demos, with clear compatibility and governance notes that align with the protocol‑first, modular architecture.​

APIs
POST /v1/identity: Create a new DID with requested keySpec and optional recovery configuration, returning did, verification methods, and createdAt fields.​

GET /.well-known/did.json and GET /v1/identity/:did: Resolve a DID Document including verification methods and optional service endpoints with stable caching semantics.​

POST /v1/session: Perform nonce challenge and return a short‑lived JWT where sub is the DID and aud is the target service, with explicit exp and minimal claims.​

POST /v1/key/rotate: Rotate verification keys under the DID with signed rotation proof, updating the DID Document reference and appending to the operation log.​

POST /v1/identity/recover: Admin‑guarded recovery with policy‑bound proofs to restore control in compromised or lost‑key scenarios, producing a new authoritative DID Document.​

Data and models
Default key algorithm Ed25519 with pluggable key backends and a DID Document containing verification methods and services appropriate to Phase 1 needs.​

Maintain an append‑only operation log to reconcile DID state and enable auditing and recovery, with optional Postgres storage and in‑memory cache for local stacks.​

Security
JWT sessions must include aud, sub=did, exp, and a signed nonce challenge to prevent replay, with short expirations and strict validation on every service consuming the token.​

Publish and follow a Key Lifecycle Runbook detailing rotation cadence, backup and recovery procedures, device linking, and revocation, with operational guardrails for production.​

Enforce TLS, signed commits, CODEOWNERS reviews, and secrets scanning in CI while keeping AGPL‑3.0 licensing for Go code consistent with org policy.​

Governance and compatibility
Align API naming and data shapes with com.registryaccord.identity definitions and specs status labels, documenting any draft or stable indicators in release notes.​

Track changes via a repo CHANGELOG and tag releases only after governance checklist and CI gates pass, mirroring the cross‑repo governance discipline.​

Non‑functional requirements
Latency: p95 ≤ 150 ms for DID resolve and ≤ 250 ms for session issuance under nominal dev/demo load to keep local end‑to‑end flows snappy.​

Availability: Align to Phase 1 demo targets with CI‑verified readiness probes and graceful degradation for resolves, prioritizing reliability for repeatable demos.​

Observability
Accept and emit a correlation ID on all requests and include it in logs and error envelopes to enable cross‑service debugging during local and CI runs.​

Structured JSON logs with levels, correlationId, did where authorized, and event types for create, resolve, rotate, and recover operations.​

Errors and envelopes
Return success as { data, meta? } and errors as { error: { code, message, details?, correlationId } } using the common taxonomy and deterministic messages across endpoints.​

Map validation to 422, auth to 401/403, conflicts to 409, rate limits to 429, and transient issues to 503 with clear retry guidance in the error class.​

Configuration
Environment variables for key backend selection, JWT signing keys, database DSN, and cache settings, with secure defaults and explicit dev overrides for local stacks.​

Feature flags for recovery endpoints, DID Document service fields, and rotation policies to allow progressive hardening without breaking API contracts.​

Build, test, and CI
Toolchain: Go 1.22+, gofumpt, and golangci‑lint with Makefile targets fmt, lint, test, and build producing bin/identityd for local runs.​

CI must run lint, unit, and integration tests, secrets scanning, and dependency updates, with protected main and required status checks per repo policy.​

Testing and conformance
Unit tests: DID creation, resolution, JWT signing/verification, and operation log integrity, including invalid nonce, expired JWT, and rotation precondition cases.​

Integration tests: Local end‑to‑end flow where CLI/SDK creates identity, issues session, then calls CDV using the JWT to validate cross‑service auth interoperability.​

Documentation
Provide ARCHITECTURE overview and DECISIONS records specific to identity, linking to the Key Lifecycle Runbook and recovery procedures maintained in docs.​

Include API references aligned to the shared conventions and keep examples synchronized with demo flows to reduce onboarding time for SDK and CLI users.​

Release checklist
CI green on lint, unit, integration, and security scans with CHANGELOG updated and governance checklist attached to the PR proposing the tag.​

Verify session tokens interoperate with CDV and gateway in the local stack and that recovery and rotation policies are documented and approved.​

Local developer experience
Make dev up commands or a script to boot identity with sensible defaults and seed data for smoke tests alongside CLI and SDK for a one‑command demo loop.​

Provide example curl snippets and SDK snippets for create, resolve, and session flows in README to streamline verification by contributors and reviewers.​

License and compliance
Keep AGPL‑3.0 licensing with a note about commercial licensing availability, and ensure third‑party dependencies pass license and vulnerability checks in CI.​

No storage or processing of unnecessary personal data, respecting selective disclosure and privacy‑first principles across identity interactions.​

Acceptance criteria
End‑to‑end: CLI can identity:create and session:login, and the issued JWT authorizes CDV write in a local stack without manual token editing.​

Stability: ≥80% unit coverage on core identity and session paths with deterministic error envelopes and reproducible local demos as defined by the plan.​

This requirements file should be placed at the repository root as IDENTITY_REQUIREMENTS.md and used alongside CONTRIBUTING and SECURITY policies to guide implementation, reviews, and releases for Phase 1.