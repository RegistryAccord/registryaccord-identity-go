// Package storage contains PostgreSQL implementation of the Store interface.
// This file provides JWT signing key storage for key rotation support.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
)

// GetCurrentSigningKey returns the currently active signing key from PostgreSQL.
func (p *postgres) GetCurrentSigningKey(ctx context.Context) (model.JWTSigningKey, error) {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Query for the key with the latest activation time that is not retired
	const q = `SELECT id, private_key, public_key, created_at, activated_at, retired_at, expires_at 
			  FROM jwt_signing_keys 
			  WHERE (retired_at IS NULL OR retired_at > $1) 
				AND activated_at <= $1 
			  ORDER BY activated_at DESC 
			  LIMIT 1`
	
	var key model.JWTSigningKey
	var retiredAt *time.Time
	var privateKey []byte
	
	// Execute query and scan results
	row := p.db.QueryRowContext(ctx, q, time.Now().UTC())
	err := row.Scan(&key.ID, &privateKey, &key.PublicKey, &key.CreatedAt, &key.ActivatedAt, &retiredAt, &key.ExpiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.JWTSigningKey{}, ErrNotFound
		}
		return model.JWTSigningKey{}, fmt.Errorf("get current signing key: %w", err)
	}
	
	// Set retired time if it exists
	if retiredAt != nil {
		key.RetiredAt = *retiredAt
	}
	
	// Set private key (never serialized but needed for signing)
	key.PrivateKey = privateKey
	
	return key, nil
}

// GetSigningKeyByID retrieves a specific signing key by its ID from PostgreSQL.
func (p *postgres) GetSigningKeyByID(ctx context.Context, keyID string) (model.JWTSigningKey, error) {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Query for the specific key by ID
	const q = `SELECT id, private_key, public_key, created_at, activated_at, retired_at, expires_at FROM jwt_signing_keys WHERE id = $1`
	
	var key model.JWTSigningKey
	var retiredAt *time.Time
	var privateKey []byte
	
	// Execute query and scan results
	row := p.db.QueryRowContext(ctx, q, keyID)
	err := row.Scan(&key.ID, &privateKey, &key.PublicKey, &key.CreatedAt, &key.ActivatedAt, &retiredAt, &key.ExpiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.JWTSigningKey{}, ErrNotFound
		}
		return model.JWTSigningKey{}, fmt.Errorf("get signing key by ID: %w", err)
	}
	
	// Set retired time if it exists
	if retiredAt != nil {
		key.RetiredAt = *retiredAt
	}
	
	// Set private key (never serialized but needed for signing)
	key.PrivateKey = privateKey
	
	return key, nil
}

// ListActiveSigningKeys returns all currently active signing keys from PostgreSQL.
// (including those in the overlap window)
func (p *postgres) ListActiveSigningKeys(ctx context.Context) ([]model.JWTSigningKey, error) {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Query for all active keys (not expired and activated)
	const q = `SELECT id, private_key, public_key, created_at, activated_at, retired_at, expires_at 
			  FROM jwt_signing_keys 
			  WHERE (expires_at IS NULL OR expires_at > $1) 
				AND activated_at <= $1 
			  ORDER BY activated_at DESC`
	
	// Execute query
	rows, err := p.db.QueryContext(ctx, q, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("list active signing keys: %w", err)
	}
	defer rows.Close()
	
	var keys []model.JWTSigningKey
	
	// Process each row
	for rows.Next() {
		var key model.JWTSigningKey
		var retiredAt *time.Time
		var privateKey []byte
		
		err := rows.Scan(&key.ID, &privateKey, &key.PublicKey, &key.CreatedAt, &key.ActivatedAt, &retiredAt, &key.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("scan signing key: %w", err)
		}
		
		// Set retired time if it exists
		if retiredAt != nil {
			key.RetiredAt = *retiredAt
		}
		
		// Set private key (never serialized but needed for signing)
		key.PrivateKey = privateKey
		
		keys = append(keys, key)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate signing keys: %w", err)
	}
	
	return keys, nil
}

// AddSigningKey adds a new signing key to PostgreSQL storage.
func (p *postgres) AddSigningKey(ctx context.Context, key model.JWTSigningKey) error {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Insert the new signing key
	const q = `INSERT INTO jwt_signing_keys (id, private_key, public_key, created_at, activated_at, retired_at, expires_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7)`
	
	var retiredAt *time.Time
	if !key.RetiredAt.IsZero() {
		retiredAt = &key.RetiredAt
	}
	
	// Execute insert
	_, err := p.db.ExecContext(ctx, q, key.ID, key.PrivateKey, key.PublicKey, key.CreatedAt, key.ActivatedAt, retiredAt, key.ExpiresAt)
	if err != nil {
		return fmt.Errorf("add signing key: %w", err)
	}
	
	return nil
}

// RetireSigningKey marks a signing key as retired in PostgreSQL storage.
// It will remain in the store until its expiration time.
func (p *postgres) RetireSigningKey(ctx context.Context, keyID string, retiredAt time.Time) error {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Update the key to mark it as retired
	const q = `UPDATE jwt_signing_keys SET retired_at = $1 WHERE id = $2`
	
	// Execute update
	_, err := p.db.ExecContext(ctx, q, retiredAt, keyID)
	if err != nil {
		return fmt.Errorf("retire signing key: %w", err)
	}
	
	return nil
}

// CleanupExpiredSigningKeys removes expired signing keys from PostgreSQL storage.
func (p *postgres) CleanupExpiredSigningKeys(ctx context.Context, now time.Time) error {
	// Set a reasonable timeout for database operations
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Delete all expired signing keys in a single operation
	const q = `DELETE FROM jwt_signing_keys WHERE expires_at <= $1`
	
	// Execute delete with current time
	_, err := p.db.ExecContext(ctx, q, now)
	if err != nil {
		return fmt.Errorf("cleanup signing keys: %w", err)
	}
	
	return nil
}
