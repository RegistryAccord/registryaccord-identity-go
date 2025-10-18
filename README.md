# registryaccord-identity-go

Identity service for the RegistryAccord protocol, focused on identity issuance and DID operations. API naming and data shapes align with `com.registryaccord.identity` definitions in the upstream specs.

## Features

- **DID Creation**: Create `did:plc` identities with Ed25519 keys
- **DID Resolution**: Resolve identities at `/v1/identity/{did}` and `/.well-known/did.json`
- **Key Rotation**: Rotate identity keys via `/v1/key/rotate`
- **Identity Recovery**: Recover identities via `/v1/identity/recover` (feature flag)
- **Session Management**: Issue JWT sessions via nonce exchange
- **JWKS Endpoint**: Expose public keys at `/v1/jwks` and `/.well-known/jwks.json` for JWT verification
- **Storage**: In-memory and PostgreSQL backends with connection pooling
- **Observability**: Structured JSON logging, Prometheus metrics, and health/readiness probes
- **Production Ready**: Graceful shutdown, request timeouts, background jobs, and cloud-native deployment

## CI/CD Gates

This repository enforces the following Phase-1 CI/CD gates:

1. **Lint**: Code formatting and static analysis checks
2. **Unit Tests**: Minimum 80% coverage on core packages (`internal/{server,did,nonce,jwks}`)
3. **Integration Tests**: Smoke test with devstack (nonce→session flow + JWKS validation)
4. **Conformance Tests**: ≥95% pass rate on identity category tests
5. **API Validation**: Response format validation against RegistryAccord specifications

All checks must pass for PRs to be merged.

## Quick Start

### Requirements
- Go 1.25+
- PostgreSQL (optional, for persistent storage)

### Build
```bash
make build
# Output: bin/identityd
```

### Environment Variables

The service can be configured using the following environment variables. See `.env.example` for a complete list.

Required environment variables:
- `ID_JWT_SIGNING_KEY`: Base64-encoded Ed25519 private key for JWT signing
- `ID_ISSUER_URL`: Service issuer URL (e.g., http://localhost:8080)
- `ID_ALLOWED_AUDIENCES`: Comma-separated list of allowed audiences (e.g., cdv,gateway)

Optional environment variables:
- `ID_DB_DSN`: PostgreSQL connection string for persistent storage
- `ID_FEATURE_RECOVERY`: Enable identity recovery feature (default: false)
- `ID_DID_METHOD`: DID method (must be "plc" for Phase 1, default: plc)
- `PORT`: Server port (default: 8080)

For local development, you can:
1. Copy `local.env.example` to `.env.local` (gitignored)
2. Modify the values as needed
3. The service will automatically load `.env.local` at startup

### Run
```bash
# In-memory storage
ID_JWT_SIGNING_KEY=$(openssl rand -base64 32) \
ID_ISSUER_URL=http://localhost:8080 \
ID_ALLOWED_AUDIENCES=cdv,gateway \
./bin/identityd

# PostgreSQL storage
ID_DB_DSN="postgres://user:pass@localhost/db" \
ID_JWT_SIGNING_KEY=$(openssl rand -base64 32) \
ID_ISSUER_URL=http://localhost:8080 \
ID_ALLOWED_AUDIENCES=cdv,gateway \
./bin/identityd
```

### Run with Docker

The service can be configured in multiple ways with Docker Compose:
1. **Default values** (hardcoded in docker-compose.yml)
2. **Environment files** (`.env` or `.env.local`)
3. **OS environment variables** (highest precedence)

#### Using environment files:
```bash
# Create .env file from example
cp .env.example .env
# Edit .env to set your values (especially ID_JWT_SIGNING_KEY)

# Or create .env.local for local overrides (gitignored)
cp local.env.example .env.local
# Edit .env.local with your local settings

# Run with docker-compose (uses in-memory storage by default)
docker-compose up
```

#### Using OS environment variables:
```bash
# Set required variables
export ID_JWT_SIGNING_KEY=$(openssl rand -base64 32)
export ID_ISSUER_URL=http://localhost:8080
export ID_ALLOWED_AUDIENCES=cdv,gateway

# Run with docker-compose (overrides defaults)
docker-compose up
```

#### Using external Postgres database:
```bash
# Set database connection
export ID_DB_DSN="postgres://user:pass@host:5432/dbname?sslmode=disable"
export ID_KEY_BACKEND="postgres"

# Run with docker-compose
docker-compose up
```

#### Run with direct Docker (without docker-compose):
```bash
# Generate signing key
export ID_JWT_SIGNING_KEY=$(openssl rand -base64 32)
export ID_ISSUER_URL=http://localhost:8080
export ID_ALLOWED_AUDIENCES=cdv,gateway

# Run with in-memory storage
docker run -p 8080:8080 \
  -e ID_JWT_SIGNING_KEY="$ID_JWT_SIGNING_KEY" \
  -e ID_ISSUER_URL="$ID_ISSUER_URL" \
  -e ID_ALLOWED_AUDIENCES="$ID_ALLOWED_AUDIENCES" \
  registryaccord/identityd
```

### Test
```bash
make test
```

## Running Integration Tests Locally

To run integration tests locally using the devstack:

1. Ensure you have the `registryaccord-devstack` repository checked out as a sibling directory
2. Start the devstack:
   ```bash
   make devstack-up
   ```
3. Wait for services to be ready:
   ```bash
   make devstack-wait
   ```
4. Run the smoke test:
   ```bash
   ./scripts/smoke_identity.sh
   ```
5. Clean up:
   ```bash
   make devstack-down
   ```

## Running Conformance Tests Locally

To run conformance tests locally:

1. Ensure you have the `registryaccord-conformance` repository checked out as a sibling directory
2. Run identity conformance tests:
   ```bash
   make conformance-identity
   ```

## API Examples

### Create Identity
```bash
curl -X POST http://localhost:8080/v1/identity \
  -H "Content-Type: application/json" \
  -d '{"keySpec": "ed25519"}'
```

### Resolve Identity
```bash
curl http://localhost:8080/v1/identity/did:plc:abc123
```

### Get Session Nonce
```bash
curl "http://localhost:8080/v1/session/nonce?did=did:plc:abc123&aud=cdv"
```

### Issue Session
```bash
curl -X POST http://localhost:8080/v1/session \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:plc:abc123",
    "aud": "cdv",
    "nonce": "...",
    "signature": "..."
  }'
```

### Rotate Key
```bash
curl -X POST http://localhost:8080/v1/key/rotate \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:plc:abc123",
    "signature": "..."
  }'
```

### Get JWKS
```bash
curl http://localhost:8080/v1/jwks
# or
curl http://localhost:8080/.well-known/jwks.json
```

## Release Process

Releases are automatically built, signed, and published when tags are pushed:

1. **Build Container Image**: Images are built and pushed to GHCR as `ghcr.io/registryaccord/identityd:${tag}` and `:latest`
2. **Sign with Cosign**: Images are signed using cosign with keyless signing
3. **Generate SBOM**: Software Bill of Materials is generated with syft and attached to the image
4. **Emit SLSA Provenance**: Build provenance is generated and attached
5. **Create GitHub Release**: Release is created with SBOM as an asset

To create a new release:

1. Create and push a new tag:
   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```
2. The release workflow will automatically run and create the release

## Contributing

- See `CONTRIBUTING.md` for local workflow and CI steps.
- Security policy: `docs/SECURITY.md`.
- Architectural docs and ADRs: `docs/ARCHITECTURE.md`, `docs/DECISIONS/`.

## License

- SPDX: AGPL-3.0-only (see `LICENSE`).
- Commercial license available — contact `legal@registryaccord.org`.
