// Package storage contains PostgreSQL implementation of the Store interface.
// Provides persistent storage for identity data, nonces, operation logs, and idempotency records.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
)

// postgres implements the ExtendedStore interface using PostgreSQL as the backend.
// Uses connection pooling and JSON serialization for complex data structures.
type postgres struct {
	db *sql.DB // Database connection pool
}

// NewPostgres creates a Store backed by PostgreSQL with connection pooling.
// Configures connection pool settings for optimal performance and resource usage.
// Tests the database connection before returning the store.
// 
// Connection pool configuration:
// - Max 25 open connections to prevent overwhelming the database
// - Max 5 idle connections to maintain a warm pool
// - 5-minute lifetime and idle time to prevent stale connections
func NewPostgres(dsn string) (ExtendedStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)                 // Maximum number of open connections
	db.SetMaxIdleConns(5)                  // Maximum number of idle connections
	db.SetConnMaxLifetime(5 * time.Minute) // Maximum lifetime of a connection
	db.SetConnMaxIdleTime(5 * time.Minute) // Maximum idle time of a connection

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	return &postgres{db: db}, nil
}

// DB returns the underlying *sql.DB connection pool.
// This method is primarily used by migration functions that need direct database access.
func (p *postgres) DB() *sql.DB {
	return p.db
}

// CreateIdentity stores a new identity record in PostgreSQL.
// Serializes complex data structures (DIDDocument, Keys, RecoveryState) as JSON.
// Returns an error if an identity with the same DID already exists (violates unique constraint).
func (p *postgres) CreateIdentity(ctx context.Context, identity model.Identity) error {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Insert identity with all associated data serialized as JSON
	const q = `INSERT INTO identities (did, document, keys, created_at_utc, updated_at_utc, recovery_state) VALUES ($1, $2, $3, $4, $5, $6)`
	// Serialize DIDDocument as JSON for storage
	docBytes, err := json.Marshal(identity.Document)
	if err != nil {
		return fmt.Errorf("marshal document: %w", err)
	}
	// Serialize Keys array as JSON for storage
	keysBytes, err := json.Marshal(identity.Keys)
	if err != nil {
		return fmt.Errorf("marshal keys: %w", err)
	}
	// Serialize RecoveryState as JSON for storage
	recoveryBytes, err := json.Marshal(identity.RecoveryState)
	if err != nil {
		return fmt.Errorf("marshal recovery: %w", err)
	}
	// Execute insert with all serialized data
	_, err = p.db.ExecContext(ctx, q, identity.DID, docBytes, keysBytes, identity.CreatedAtUTC, identity.UpdatedAtUTC, recoveryBytes)
	if err != nil {
		return fmt.Errorf("insert identity: %w", err)
	}
	return nil
}

// GetIdentity retrieves an identity by its DID identifier from PostgreSQL.
// Deserializes JSON data back into Go structures.
// Returns ErrNotFound if no identity exists with the specified DID.
func (p *postgres) GetIdentity(ctx context.Context, did string) (model.Identity, error) {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Select all identity data by DID
	const q = `SELECT did, document, keys, created_at_utc, updated_at_utc, recovery_state FROM identities WHERE did = $1`
	var identity model.Identity
	// Byte slices to hold serialized JSON data
	var docBytes, keysBytes, recoveryBytes []byte
	// Execute query and scan results
	err := p.db.QueryRowContext(ctx, q, did).Scan(&identity.DID, &docBytes, &keysBytes, &identity.CreatedAtUTC, &identity.UpdatedAtUTC, &recoveryBytes)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Identity{}, ErrNotFound
		}
		return model.Identity{}, fmt.Errorf("query identity: %w", err)
	}
	// Deserialize DIDDocument from JSON
	if err := json.Unmarshal(docBytes, &identity.Document); err != nil {
		return model.Identity{}, fmt.Errorf("unmarshal document: %w", err)
	}
	// Deserialize Keys array from JSON
	if err := json.Unmarshal(keysBytes, &identity.Keys); err != nil {
		return model.Identity{}, fmt.Errorf("unmarshal keys: %w", err)
	}
	// Deserialize RecoveryState from JSON
	if err := json.Unmarshal(recoveryBytes, &identity.RecoveryState); err != nil {
		return model.Identity{}, fmt.Errorf("unmarshal recovery: %w", err)
	}
	return identity, nil
}

// UpdateIdentity updates an existing identity record in PostgreSQL.
// Serializes complex data structures as JSON for storage.
// Returns ErrNotFound if no identity exists with the specified DID.
func (p *postgres) UpdateIdentity(ctx context.Context, identity model.Identity) error {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Update identity with new data, serialized as JSON
	const q = `UPDATE identities SET document = $1, keys = $2, updated_at_utc = $3, recovery_state = $4 WHERE did = $5`
	// Serialize DIDDocument as JSON for storage
	docBytes, err := json.Marshal(identity.Document)
	if err != nil {
		return fmt.Errorf("marshal document: %w", err)
	}
	// Serialize Keys array as JSON for storage
	keysBytes, err := json.Marshal(identity.Keys)
	if err != nil {
		return fmt.Errorf("marshal keys: %w", err)
	}
	// Serialize RecoveryState as JSON for storage
	recoveryBytes, err := json.Marshal(identity.RecoveryState)
	if err != nil {
		return fmt.Errorf("marshal recovery: %w", err)
	}
	// Execute update with all serialized data
	res, err := p.db.ExecContext(ctx, q, docBytes, keysBytes, identity.UpdatedAtUTC, recoveryBytes, identity.DID)
	if err != nil {
		return fmt.Errorf("update identity: %w", err)
	}
	// Check if any rows were affected (identity exists)
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// AppendOperation adds a new entry to the operation log for a DID in PostgreSQL.
// Maintains an append-only log by inserting new entries.
// Serializes the payload as JSON for flexible operation data storage.
func (p *postgres) AppendOperation(ctx context.Context, entry model.OperationLogEntry) error {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Insert new operation log entry with serialized payload
	const q = `INSERT INTO operation_log (did, operation, performed_at, actor, correlation_id, payload) VALUES ($1, $2, $3, $4, $5, $6)`
	// Serialize operation payload as JSON for flexible storage
	payloadBytes, err := json.Marshal(entry.Payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	// Execute insert with all operation data
	_, err = p.db.ExecContext(ctx, q, entry.DID, entry.Operation, entry.PerformedAt, entry.Actor, entry.CorrelationID, payloadBytes)
	if err != nil {
		return fmt.Errorf("insert operation: %w", err)
	}
	return nil
}

// ListOperations retrieves all log entries for a specific DID from PostgreSQL.
// Returns entries in chronological order (oldest first).
// Deserializes JSON payload data back into Go structures.
func (p *postgres) ListOperations(ctx context.Context, did string) ([]model.OperationLogEntry, error) {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Select all operation log entries for the DID, ordered chronologically
	const q = `SELECT did, operation, performed_at, actor, correlation_id, payload FROM operation_log WHERE did = $1 ORDER BY performed_at ASC`
	// Execute query
	rows, err := p.db.QueryContext(ctx, q, did)
	if err != nil {
		return nil, fmt.Errorf("query operations: %w", err)
	}
	defer rows.Close()
	var entries []model.OperationLogEntry
	// Process each row
	for rows.Next() {
		var entry model.OperationLogEntry
		// Byte slice to hold serialized JSON payload
		var payloadBytes []byte
		// Scan row data into entry fields
		err := rows.Scan(&entry.DID, &entry.Operation, &entry.PerformedAt, &entry.Actor, &entry.CorrelationID, &payloadBytes)
		if err != nil {
			return nil, fmt.Errorf("scan operation: %w", err)
		}
		// Deserialize payload from JSON
		if err := json.Unmarshal(payloadBytes, &entry.Payload); err != nil {
			return nil, fmt.Errorf("unmarshal payload: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// PutNonce stores a new nonce for later validation in PostgreSQL.
// Nonces are stored with their associated DID, audience, expiration time, and used status.
func (p *postgres) PutNonce(ctx context.Context, nonce model.Nonce) error {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Insert nonce with all associated data
	const q = `INSERT INTO nonces (value, did, audience, expires_at, used) VALUES ($1, $2, $3, $4, $5)`
	// Execute insert with nonce data
	_, err := p.db.ExecContext(ctx, q, nonce.Value, nonce.DID, nonce.Audience, nonce.ExpiresAt, nonce.Used)
	if err != nil {
		return fmt.Errorf("insert nonce: %w", err)
	}
	return nil
}

// ConsumeNonce retrieves and invalidates a nonce (single-use) from PostgreSQL.
// Uses atomic UPDATE with RETURNING to ensure single-use semantics.
// Returns ErrNotFound if the nonce doesn't exist, has expired, or has already been used.
func (p *postgres) ConsumeNonce(ctx context.Context, value string) (model.Nonce, error) {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Atomically update and return the nonce if it exists, hasn't expired, and hasn't been used
	const q = `UPDATE nonces SET used = true WHERE value = $1 AND expires_at > $2 AND used = false RETURNING did, audience, expires_at`
	var nonce model.Nonce
	// Execute update and scan returned data
	err := p.db.QueryRowContext(ctx, q, value, time.Now().UTC()).Scan(&nonce.DID, &nonce.Audience, &nonce.ExpiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Nonce{}, ErrNotFound
		}
		return model.Nonce{}, fmt.Errorf("consume nonce: %w", err)
	}
	// Set the nonce value (not returned by the query) and mark as used
	nonce.Value = value
	nonce.Used = true
	return nonce, nil
}

// CleanupExpired removes expired nonces from PostgreSQL storage.
// This periodic cleanup prevents database bloat from expired nonces.
// Also removes used nonces that have expired to free up space.
func (p *postgres) CleanupExpired(ctx context.Context, now time.Time) error {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Delete all expired nonces and used nonces that have expired in a single operation
	const q = `DELETE FROM nonces WHERE expires_at <= $1`
	// Execute delete with current time
	_, err := p.db.ExecContext(ctx, q, now)
	if err != nil {
		return fmt.Errorf("cleanup nonces: %w", err)
	}
	return nil
}

// Remember stores a response for later retrieval to support idempotent operations in PostgreSQL.
// Serializes HTTP response data for caching.
// The response is cached with an expiration time to prevent indefinite growth.
func (p *postgres) Remember(ctx context.Context, key string, response StoredResponse) error {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Insert cached response with all associated data
	const q = `INSERT INTO idempotency_cache (key, status_code, body, headers, expires_at) VALUES ($1, $2, $3, $4, $5)`
	// Serialize headers map as JSON for storage
	headersBytes, err := json.Marshal(response.Headers)
	if err != nil {
		return fmt.Errorf("marshal headers: %w", err)
	}
	// Execute insert with all response data
	_, err = p.db.ExecContext(ctx, q, key, response.StatusCode, response.Body, headersBytes, response.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert cache: %w", err)
	}
	return nil
}

// Recall retrieves a previously stored response if it exists and hasn't expired from PostgreSQL.
// Deserializes JSON headers data back into Go structures.
// Returns false if the cached response doesn't exist or has expired.
func (p *postgres) Recall(ctx context.Context, key string) (StoredResponse, bool) {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Select cached response by key if it hasn't expired
	const q = `SELECT status_code, body, headers, expires_at FROM idempotency_cache WHERE key = $1 AND expires_at > $2`
	var response StoredResponse
	// Byte slice to hold serialized JSON headers
	var headersBytes []byte
	// Execute query and scan results
	err := p.db.QueryRowContext(ctx, q, key, time.Now().UTC()).Scan(&response.StatusCode, &response.Body, &headersBytes, &response.ExpiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return StoredResponse{}, false
		}
		return StoredResponse{}, false
	}
	// Deserialize headers from JSON
	if err := json.Unmarshal(headersBytes, &response.Headers); err != nil {
		return StoredResponse{}, false
	}
	return response, true
}

// StoreRecoveryToken stores a new recovery token for later validation in PostgreSQL.
// Recovery tokens are stored with their associated DID, email, and expiration time.
func (p *postgres) StoreRecoveryToken(ctx context.Context, token RecoveryToken) error {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Insert recovery token with all associated data
	const q = `INSERT INTO recovery_tokens (token, did, email, expires_at, used) VALUES ($1, $2, $3, $4, $5)`
	// Execute insert with recovery token data
	_, err := p.db.ExecContext(ctx, q, token.Token, token.DID, token.Email, token.ExpiresAt, token.Used)
	if err != nil {
		return fmt.Errorf("insert recovery token: %w", err)
	}
	return nil
}

// ValidateRecoveryToken validates a recovery token and marks it as used in PostgreSQL.
// Uses atomic UPDATE with RETURNING to ensure single-use semantics.
// Returns true if the token is valid and hasn't been used or expired.
func (p *postgres) ValidateRecoveryToken(ctx context.Context, did, email, token string) (bool, error) {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Atomically update and return the token if it exists, matches DID/email, and hasn't expired or been used
	const q = `UPDATE recovery_tokens SET used = true WHERE token = $1 AND did = $2 AND email = $3 AND expires_at > $4 AND used = false RETURNING token`
	var validatedToken string
	// Execute update and scan returned data
	err := p.db.QueryRowContext(ctx, q, token, did, email, time.Now().UTC()).Scan(&validatedToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("validate recovery token: %w", err)
	}
	// If we got here, the token was valid and has been marked as used
	return true, nil
}

// CleanupExpiredRecoveryTokens removes expired recovery tokens from PostgreSQL storage.
// This periodic cleanup prevents database bloat from expired tokens.
func (p *postgres) CleanupExpiredRecoveryTokens(ctx context.Context, now time.Time) error {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Delete all expired recovery tokens in a single operation
	const q = `DELETE FROM recovery_tokens WHERE expires_at <= $1`
	// Execute delete with current time
	_, err := p.db.ExecContext(ctx, q, now)
	if err != nil {
		return fmt.Errorf("cleanup recovery tokens: %w", err)
	}
	return nil
}
