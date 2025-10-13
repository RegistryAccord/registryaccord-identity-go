# IDENTITY_REQUIREMENTS.md

Purpose
- Define Phase 1 requirements for the Identity service: DID lifecycle (create/resolve), short‑lived JWT session issuance via nonce challenge, key rotation/recovery, JWKS exposure, security, observability, configuration, CI, and acceptance criteria. 
- Ensure compatibility with protocol specs (API conventions, error taxonomy, time, pagination) and downstream services (CDV, gateway) for deterministic interop and conformance. 

Scope
- Provide DID:plc creation and resolution, JWT sessions for service authorization, key lifecycle management (rotation, recovery), and a minimal operation log for audit and replay. 
- Expose a JWKS endpoint so services (e.g., CDV) can verify JWTs; publish issuer metadata and enforce strict audience and algorithm checks. 

APIs (Phase 1)
- POST /v1/identity
  - Request: { keySpec?: "ed25519", recovery?: { method?: "email" | "none" } }
  - Behavior: Generate DID:plc with Ed25519 verification method, persist operation log entry, and return DID, verification methods, createdAt (RFC 3339 UTC).
  - Response: { data: { did: string, verificationMethods: Array<{ id, type, publicKey }>, createdAt: string } }
- GET /.well-known/did.json and GET /v1/identity/:did
  - Behavior: Resolve DID Document with verification methods and optional service endpoints; include ETag and Cache-Control for safe short caching; return RFC 3339 timestamps where applicable.
  - Response: DID Document (JSON) or { data: { didDocument } } where a uniform envelope is desired.
- GET /v1/jwks (alias: /.well-known/jwks.json)
  - Behavior: Publish current signing public keys with kid and alg metadata; support key rotation with overlapping validity windows.
  - Response: JWKS JSON.
- GET /v1/session/nonce
  - Behavior: Issue a short‑lived nonce (e.g., 60s) bound to the request DID (query or header); store nonce with expiry and correlationId.
  - Response: { data: { nonce: string, expiresAt: string } }
- POST /v1/session
  - Request: { did: string, nonce: string, signature: string, aud: string }
  - Behavior: Verify signature of nonce with the DID’s current key; validate aud against configured allowlist; issue short‑lived JWT (EdDSA/Ed25519) with sub=did, aud, exp, iat, jti; log issuance in op log.
  - Response: { data: { jwt: string, exp: string, aud: string, sub: string } }
- POST /v1/key/rotate
  - Request: { did: string, rotationProof: object }
  - Behavior: Verify rotation proof, update DID Document verification method, publish updated state, and append op log entry; maintain overlapping key validity for safe rollout.
  - Response: { data: { did: string, rotatedAt: string, newKid: string } }
- POST /v1/identity/recover (feature‑flagged)
  - Request: { did: string, recoveryProof: object }
  - Behavior: Admin‑guarded; validate recovery policy, publish new authoritative DID Document, append op log entry.
  - Response: { data: { did: string, recoveredAt: string } }

JWT issuance and validation (normative)
- Algorithm: EdDSA with Ed25519 keys; include kid header matching JWKS entry.
- Claims: sub (DID), aud (target service, e.g., “cdv”), iat, exp (short‑lived, e.g., ≤15m), jti (random).
- Audiences: configurable allowlist (e.g., cdv, gateway), validated strictly by consumers; tokens with unknown aud MUST be rejected.
- JWKS: expose /.well-known/jwks.json; rotate with overlap; cache TTL configurable (e.g., 5–10 minutes).
- Nonce: single‑use, short‑lived; bind to DID; reject replay; deterministic errors on expired/used nonce.

Error taxonomy and envelopes
- Success: { data, meta? }
- Errors: { error: { code, message, details?, correlationId } }
- Codes:
  - 400: IDENTITY_VALIDATION, IDENTITY_BAD_REQUEST
  - 401/403: IDENTITY_AUTHZ (invalid signature, issuer, aud, or expired token/nonce)
  - 404: IDENTITY_NOT_FOUND
  - 409: IDENTITY_CONFLICT
  - 429: IDENTITY_RATE_LIMIT
  - 500: IDENTITY_INTERNAL
  - 503: IDENTITY_UNAVAILABLE

DID method and document
- DID method: plc (Phase 1 default); DID Document includes Ed25519 verification method and optional service endpoints for internal discovery.
- Operation log: append‑only entries for create, rotate, recover, and session issuance metadata (non‑PII), enabling audit and replay.

Security
- TLS 1.3; deny‑all CORS by default (devstack may permit localhost origins explicitly).
- Key lifecycle: rotation cadence documented; backup/recovery procedures defined; revoke and replace compromised keys promptly.
- JWKS and issuer metadata hardened; reject unknown algs/kids; fail closed on invalid issuer or key mismatch.
- No secrets or tokens in logs; redact sensitive fields consistently.

Observability
- Structured JSON logs with level, correlationId, did (when authorized), route, latency.
- Metrics: request latency histograms, request/error counters by route and code, JWKS cache refreshes, nonce issuance/validation counters.
- Tracing: OpenTelemetry spans for HTTP handlers and storage operations with environment‑appropriate sampling defaults.

Configuration
- Required env:
  - ID_ISSUER_URL, ID_JWT_SIGNING_KEY or ID_KMS_KEY_URI
  - ID_ALLOWED_AUDIENCES (CSV or JSON), ID_DID_METHOD=plc
  - ID_DB_DSN (for op log; optional memory mode in dev)
  - PORT, ID_ENV
- Precedence: process env is authoritative; .env is for local dev only; fail fast on missing/invalid required keys.

Storage
- Minimal Postgres schema (or memory backend in dev):
  - op_log(seq pk, did, type, payload jsonb, occurred_at)
  - nonces(nonce pk, did, expires_at, used boolean, correlation_id)
  - keys(kid pk, alg, public_key, created_at, rotated_at?)
- Indexes for nonce lookups and op log queries; retention policies documented.

Compatibility with CDV
- Aud claim MUST match CDV’s configured audience (e.g., “cdv”); token TTL MUST be short; Ed25519 keys MUST be discoverable via JWKS.
- JWKS cache behavior documented (TTL, backoff on fetch errors) so CDV verification remains reliable under rotation.
- Deterministic envelopes and error codes to match shared API conventions.

Devstack integration
- Service name: identity
- Default port: 8081 (example; coordinate with devstack)
- Health: /healthz (liveness), /readyz (readiness)
- Seed: optional helper to generate a deterministic test DID for local demos

Testing and conformance
- Unit: DID create/resolve, nonce issuance/replay protection, signature verification, JWT issuance (claims, TTL, kid), JWKS rotation overlap.
- Integration: issue session and call a protected CDV stub in the devstack to verify audience/issuer alignment.
- Negative cases: expired nonce, wrong aud, unknown kid/issuer, expired token.
- Coverage: ≥80% on core paths; deterministic error bodies and timestamps.

CI/CD
- Actions: fmt, golangci‑lint, unit (race+coverage), integration (devstack), govulncheck/secrets scan, container build+push with SBOM and provenance.
- Protected main: required checks, CODEOWNERS review, signed commits; semver‑tagged releases with image digests and published JWKS snapshot.

Docs
- README: quickstart, curl examples (create DID, nonce, session), JWT claims, and JWKS usage.
- ARCHITECTURE: DID method rationale (plc), key lifecycle, JWKS rotation.
- SECURITY: threat outline (key compromise, replay, issuer spoofing) and mitigations.
- DECISIONS (ADRs): DID method choice, JWT claims and alg policy, JWKS rotation design.

Acceptance criteria (Phase 1)
- End‑to‑end: identity:create → session:nonce → session:issue, then CDV accepts the JWT (aud=subset configured), and protected flows succeed in devstack.
- Reliability: JWKS rotation with overlap does not break CDV verification; nonce replay is rejected with deterministic errors.
- Quality: ≥80% core coverage; green CI; logs/metrics/traces present; health endpoints stable; signed image and SBOM published on release.
