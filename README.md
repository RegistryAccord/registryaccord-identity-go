# registryaccord-identity-go

Identity service for the RegistryAccord protocol, focused on identity issuance and DID operations. API naming and data shapes align with `com.registryaccord.identity` definitions in the upstream specs.

## Features

- **DID Creation**: Create `did:plc` identities with Ed25519 keys
- **DID Resolution**: Resolve identities at `/v1/identity/{did}` and `/.well-known/did.json`
- **Key Rotation**: Rotate identity keys via `/v1/key/rotate`
- **Identity Recovery**: Recover identities via `/v1/identity/recover` (feature flag)
- **Session Management**: Issue JWT sessions via nonce exchange
- **Storage**: In-memory and PostgreSQL backends with connection pooling
- **Observability**: Structured JSON logging, Prometheus metrics, and health/readiness probes
- **Production Ready**: Graceful shutdown, request timeouts, background jobs, and cloud-native deployment

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

- `ID_JWT_SIGNING_KEY` (required): Base64-encoded Ed25519 private key for JWT signing
- `ID_DB_DSN` (optional): PostgreSQL connection string for persistent storage
- `ID_FEATURE_RECOVERY`: Enable identity recovery feature (default: false)

For local development, you can:
1. Copy `local.env.example` to `.env.local` (gitignored)
2. Modify the values as needed
3. The service will automatically load `.env.local` at startup

### Run
```bash
# In-memory storage
ID_JWT_SIGNING_KEY=$(openssl rand -base64 32) ./bin/identityd

# PostgreSQL storage
ID_DB_DSN="postgres://user:pass@localhost/db" \
ID_JWT_SIGNING_KEY=$(openssl rand -base64 32) \
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

# Run with in-memory storage
docker run -p 8080:8080 \
  -e ID_JWT_SIGNING_KEY="$ID_JWT_SIGNING_KEY" \
  registryaccord/identityd
```

### Test
```bash
make test
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
curl "http://localhost:8080/v1/session/nonce?did=did:plc:abc123&aud=example.com"
```

### Issue Session
```bash
curl -X POST http://localhost:8080/v1/session \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:plc:abc123",
    "aud": "example.com",
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

## Contributing

- See `CONTRIBUTING.md` for local workflow and CI steps.
- Security policy: `docs/SECURITY.md`.
- Architectural docs and ADRs: `docs/ARCHITECTURE.md`, `docs/DECISIONS/`.

## License

- SPDX: AGPL-3.0-only (see `LICENSE`).
- Commercial license available — contact `legal@registryaccord.org`.
