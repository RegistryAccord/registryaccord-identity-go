// Package storage contains PostgreSQL schema migrations for the identity service.
// These migrations create and maintain the database schema required for all storage operations.
package storage

import (
	"context"
	"database/sql"
	"fmt"
)

// MigratePostgres applies schema migrations to the PostgreSQL database.
// Creates all necessary tables and indexes for the identity service storage.
// Uses IF NOT EXISTS clauses to make migrations idempotent.
// 
// Tables created:
// - identities: Stores DID documents and associated metadata
// - operation_log: Maintains an append-only log of identity operations
// - nonces: Manages single-use challenges for session authentication
// - idempotency_cache: Caches responses for idempotent operation handling
// - recovery_tokens: Manages single-use tokens for identity recovery
func MigratePostgres(ctx context.Context, db *sql.DB) error {
	// List of migrations to apply in order
	// Each migration is idempotent (uses IF NOT EXISTS)
	migrations := []string{
		// Identities table stores DID documents and cryptographic keys
		// JSONB columns provide flexible storage for complex data structures
		`CREATE TABLE IF NOT EXISTS identities (
            did TEXT PRIMARY KEY,           -- Decentralized Identifier
            document JSONB NOT NULL,        -- DID Document as JSON
            keys JSONB NOT NULL,            -- Cryptographic keys as JSON array
            created_at_utc TEXT NOT NULL,   -- Creation timestamp (RFC3339)
            updated_at_utc TEXT NOT NULL,   -- Last update timestamp (RFC3339)
            recovery_state JSONB NOT NULL   -- Recovery policy as JSON
        )`,
		// Operation log table maintains an append-only history of identity operations
		// Used for audit trails and potential conflict resolution
		`CREATE TABLE IF NOT EXISTS operation_log (
            id SERIAL PRIMARY KEY,          -- Auto-incrementing log entry ID
            did TEXT NOT NULL,              -- DID this operation applies to
            operation TEXT NOT NULL,        -- Type of operation (create, rotate, recover)
            performed_at TEXT NOT NULL,     -- Timestamp when operation occurred (RFC3339)
            actor TEXT NOT NULL,            -- Entity that performed the operation
            correlation_id TEXT NOT NULL,   -- Request correlation identifier
            payload JSONB NOT NULL          -- Operation-specific data as JSON
        )`,
		// Index on DID for efficient log queries
		`CREATE INDEX IF NOT EXISTS idx_operation_log_did ON operation_log (did)`,
		// Nonces table manages single-use challenges for secure authentication
		// Nonces are consumed during session issuance to prove key possession
		`CREATE TABLE IF NOT EXISTS nonces (
            value TEXT PRIMARY KEY,         -- Cryptographically secure nonce value
            did TEXT NOT NULL,              -- DID that requested this nonce
            audience TEXT NOT NULL,         -- Intended audience for the session
            expires_at TIMESTAMPTZ NOT NULL,-- Expiration timestamp with timezone
            used BOOLEAN NOT NULL DEFAULT FALSE -- Whether this nonce has been consumed
        )`,
		// Index on expiration time for efficient cleanup of expired nonces
		`CREATE INDEX IF NOT EXISTS idx_nonces_expires_at ON nonces (expires_at)`,
		// Idempotency cache stores responses to make operations idempotent
		// Prevents duplicate processing of requests like identity creation
		`CREATE TABLE IF NOT EXISTS idempotency_cache (
            key TEXT PRIMARY KEY,           -- Idempotency key (typically from HTTP header)
            status_code INTEGER NOT NULL,   -- HTTP status code of cached response
            body BYTEA NOT NULL,            -- Response body as binary data
            headers JSONB NOT NULL,         -- Response headers as JSON
            expires_at TIMESTAMPTZ NOT NULL -- Expiration timestamp with timezone
        )`,
		// Index on expiration time for efficient cleanup of expired cache entries
		`CREATE INDEX IF NOT EXISTS idx_idempotency_cache_expires_at ON idempotency_cache (expires_at)`,
		// Recovery tokens table manages single-use tokens for identity recovery
		// Recovery tokens are used to verify identity during recovery operations
		`CREATE TABLE IF NOT EXISTS recovery_tokens (
            token TEXT PRIMARY KEY,         -- Cryptographically secure token value
            did TEXT NOT NULL,              -- DID this token is for
            email TEXT NOT NULL,            -- Email address associated with this token
            expires_at TIMESTAMPTZ NOT NULL,-- Expiration timestamp with timezone
            used BOOLEAN NOT NULL DEFAULT FALSE -- Whether this token has been used
        )`,
		// Index on DID for efficient token lookup
		`CREATE INDEX IF NOT EXISTS idx_recovery_tokens_did ON recovery_tokens (did)`,
		// Index on expiration time for efficient cleanup of expired tokens
		`CREATE INDEX IF NOT EXISTS idx_recovery_tokens_expires_at ON recovery_tokens (expires_at)`,
		// JWT signing keys table manages server-side keys for JWT signing
		// Supports key rotation with overlapping validity windows
		`CREATE TABLE IF NOT EXISTS jwt_signing_keys (
            id TEXT PRIMARY KEY,            -- Unique key identifier
            private_key BYTEA NOT NULL,     -- Private key bytes (NEVER exposed in APIs)
            public_key BYTEA NOT NULL,      -- Public key bytes (exposed in JWKS)
            created_at TIMESTAMPTZ NOT NULL,-- When the key was created
            activated_at TIMESTAMPTZ NOT NULL,-- When the key became active
            retired_at TIMESTAMPTZ,         -- When the key was retired (NULL if still active)
            expires_at TIMESTAMPTZ NOT NULL -- When the key expires and should be removed
        )`,
		// Index on activation time for efficient key lookup
		`CREATE INDEX IF NOT EXISTS idx_jwt_signing_keys_activated_at ON jwt_signing_keys (activated_at)`,
		// Index on expiration time for efficient cleanup of expired keys
		`CREATE INDEX IF NOT EXISTS idx_jwt_signing_keys_expires_at ON jwt_signing_keys (expires_at)`,
	}

	// Apply each migration in sequence
	for i, migration := range migrations {
		if _, err := db.ExecContext(ctx, migration); err != nil {
			return fmt.Errorf("migration %d failed: %w", i, err)
		}
	}
	return nil
}
