// Package storage provides interfaces and implementations for persistent storage
// of identity data, nonces, operation logs, and idempotency records.
package storage

import (
	"context"
	"errors"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
)

// Standard error values used across storage implementations
var (
	// ErrNotFound indicates the requested resource does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict indicates the resource already exists or the operation would violate invariants.
	ErrConflict = errors.New("conflict")
)

// IdentityStore persists DID documents and related metadata.
// Provides CRUD operations for identity records in the storage backend.
type IdentityStore interface {
	// CreateIdentity stores a new identity record
	CreateIdentity(ctx context.Context, identity model.Identity) error
	// GetIdentity retrieves an identity by its DID identifier
	GetIdentity(ctx context.Context, did string) (model.Identity, error)
	// UpdateIdentity updates an existing identity record
	UpdateIdentity(ctx context.Context, identity model.Identity) error
}

// OperationLogStore captures the append-only mutation history for a DID.
// Maintains an immutable log of all operations performed on an identity.
type OperationLogStore interface {
	// AppendOperation adds a new entry to the operation log
	AppendOperation(ctx context.Context, entry model.OperationLogEntry) error
	// ListOperations retrieves all log entries for a specific DID
	ListOperations(ctx context.Context, did string) ([]model.OperationLogEntry, error)
}

// SessionNonceStore manages nonce lifecycle for session issuance.
// Implements a single-use challenge mechanism for secure authentication.
type SessionNonceStore interface {
	// PutNonce stores a new nonce for later validation
	PutNonce(ctx context.Context, nonce model.Nonce) error
	// ConsumeNonce retrieves and invalidates a nonce (single-use)
	ConsumeNonce(ctx context.Context, nonce string) (model.Nonce, error)
	// CleanupExpired removes expired nonces from storage
	CleanupExpired(ctx context.Context, now time.Time) error
}

// IdempotencyStore stores deterministic responses for a limited period.
// Enables idempotent handling of otherwise non-idempotent operations.
type IdempotencyStore interface {
	// Remember stores a response for later retrieval
	Remember(ctx context.Context, key string, response StoredResponse) error
	// Recall retrieves a previously stored response if it exists and hasn't expired
	Recall(ctx context.Context, key string) (StoredResponse, bool)
}

// RecoveryTokenStore manages recovery tokens for identity recovery.
type RecoveryTokenStore interface {
	// StoreRecoveryToken stores a new recovery token for later validation
	StoreRecoveryToken(ctx context.Context, token RecoveryToken) error
	
	// ValidateRecoveryToken validates a recovery token and marks it as used
	ValidateRecoveryToken(ctx context.Context, did, email, token string) (bool, error)
	
	// CleanupExpiredRecoveryTokens removes expired recovery tokens
	CleanupExpiredRecoveryTokens(ctx context.Context, now time.Time) error
}

// Store aggregates all persistence capabilities required by the service.
// Provides a unified interface for all storage operations needed by the identity service.
type Store interface {
	IdentityStore
	OperationLogStore
	SessionNonceStore
	IdempotencyStore
}

// ExtendedStore extends the base Store interface with recovery token support.
type ExtendedStore interface {
	Store
	RecoveryTokenStore
}

// StoredResponse captures the HTTP response data persisted for idempotent replays.
type StoredResponse struct {
	StatusCode int               // HTTP status code of the original response
	Body       []byte            // Response body content
	Headers    map[string]string // Response headers
	ExpiresAt  time.Time         // Expiration timestamp for this cached response
}
