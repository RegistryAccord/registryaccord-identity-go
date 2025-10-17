// Package storage contains persistence abstractions and implementations
// for identity records used by the service.
// This file provides an in-memory implementation suitable for development and testing.
package storage

import (
	"context"
	"sync"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
)

// NewMemory returns a concurrency-safe in-memory implementation of Store.
// Suitable for local development, tests, and as a fallback cache when
// Postgres is unavailable.
// 
// The implementation uses fine-grained mutexes for better concurrency:
// - Separate mutexes for identities, operations, nonces, and idempotency records
// - Read-write mutexes to allow concurrent reads
func NewMemory() ExtendedStore {
	return &memory{
		identities:     make(map[string]model.Identity),  // DID -> Identity mapping
		operations:     make(map[string][]model.OperationLogEntry), // DID -> Operation log entries
		nonces:         make(map[string]model.Nonce),      // Nonce value -> Nonce mapping
		idempotency:    make(map[string]StoredResponse),   // Key -> Cached response mapping
		recoveryTokens: make(map[string]RecoveryToken),   // Token value -> RecoveryToken mapping
		jwtSigningKeys: make(map[string]model.JWTSigningKey), // Key ID -> JWTSigningKey mapping
	}
}

// memory implements the ExtendedStore interface using in-memory data structures.
// Uses separate read-write mutexes for each data collection to improve concurrency.
type memory struct {
	muIdentity sync.RWMutex                    // Mutex for identity operations
	identities map[string]model.Identity       // DID -> Identity mapping

	muOps      sync.RWMutex                    // Mutex for operation log operations
	operations map[string][]model.OperationLogEntry // DID -> Operation log entries

	muNonce sync.RWMutex                       // Mutex for nonce operations
	nonces  map[string]model.Nonce             // Nonce value -> Nonce mapping

	muIdempotency sync.RWMutex                 // Mutex for idempotency operations
	idempotency   map[string]StoredResponse    // Key -> Cached response mapping

	muRecovery sync.RWMutex                    // Mutex for recovery token operations
	recoveryTokens map[string]RecoveryToken    // Token value -> RecoveryToken mapping

	muJWTKeys sync.RWMutex                     // Mutex for JWT signing key operations
	jwtSigningKeys map[string]model.JWTSigningKey // Key ID -> JWTSigningKey mapping
}

// CreateIdentity stores a new identity record in memory.
// Returns ErrConflict if an identity with the same DID already exists.
// Uses a write lock to ensure exclusive access during creation.
func (m *memory) CreateIdentity(ctx context.Context, identity model.Identity) error {
	m.muIdentity.Lock()
	defer m.muIdentity.Unlock()
	if _, exists := m.identities[identity.DID]; exists {
		return ErrConflict
	}
	m.identities[identity.DID] = cloneIdentity(identity)
	return nil
}

// GetIdentity retrieves an identity by its DID identifier from memory.
// Returns ErrNotFound if no identity exists with the specified DID.
// Uses a read lock to allow concurrent reads.
func (m *memory) GetIdentity(ctx context.Context, did string) (model.Identity, error) {
	m.muIdentity.RLock()
	defer m.muIdentity.RUnlock()
	identity, ok := m.identities[did]
	if !ok {
		return model.Identity{}, ErrNotFound
	}
	return cloneIdentity(identity), nil
}

// UpdateIdentity updates an existing identity record in memory.
// Returns ErrNotFound if no identity exists with the specified DID.
// Uses a write lock to ensure exclusive access during update.
func (m *memory) UpdateIdentity(ctx context.Context, identity model.Identity) error {
	m.muIdentity.Lock()
	defer m.muIdentity.Unlock()
	if _, ok := m.identities[identity.DID]; !ok {
		return ErrNotFound
	}
	m.identities[identity.DID] = cloneIdentity(identity)
	return nil
}

// AppendOperation adds a new entry to the operation log for a DID.
// Maintains an append-only log by adding entries to the end of the slice.
// Uses a write lock to ensure exclusive access during append.
func (m *memory) AppendOperation(ctx context.Context, entry model.OperationLogEntry) error {
	m.muOps.Lock()
	defer m.muOps.Unlock()
	// Create a new slice with just the entry to avoid copying
	ops := append([]model.OperationLogEntry{}, entry)
	// Append to existing operations for this DID
	m.operations[entry.DID] = append(m.operations[entry.DID], ops...)
	return nil
}

// ListOperations retrieves all log entries for a specific DID.
// Returns a copy of the operation log to prevent external modification.
// Uses a read lock to allow concurrent reads.
func (m *memory) ListOperations(ctx context.Context, did string) ([]model.OperationLogEntry, error) {
	m.muOps.RLock()
	defer m.muOps.RUnlock()
	ops := m.operations[did]
	// Create a copy to prevent external modification of internal data
	out := make([]model.OperationLogEntry, len(ops))
	copy(out, ops)
	return out, nil
}

// PutNonce stores a new nonce for later validation.
// Nonces are stored by their value for efficient lookup during validation.
// Uses a write lock to ensure exclusive access during storage.
func (m *memory) PutNonce(ctx context.Context, nonce model.Nonce) error {
	m.muNonce.Lock()
	defer m.muNonce.Unlock()
	m.nonces[nonce.Value] = nonce
	return nil
}

// ConsumeNonce retrieves and invalidates a nonce (single-use).
// Returns ErrNotFound if the nonce doesn't exist, has expired, or has already been used.
// The nonce is marked as used in storage to ensure single-use.
// Uses a write lock since it modifies the nonce collection.
func (m *memory) ConsumeNonce(ctx context.Context, value string) (model.Nonce, error) {
	m.muNonce.Lock()
	defer m.muNonce.Unlock()
	nonce, ok := m.nonces[value]
	if !ok {
		return model.Nonce{}, ErrNotFound
	}
	// Check if the nonce has already been used
	if nonce.Used {
		return model.Nonce{}, ErrNotFound
	}
	// Check if the nonce has expired
	if time.Now().UTC().After(nonce.ExpiresAt) {
		// Delete expired nonces
		delete(m.nonces, value)
		return model.Nonce{}, ErrNotFound
	}
	// Mark the nonce as used
	nonce.Used = true
	m.nonces[value] = nonce
	return nonce, nil
}

// CleanupExpired removes expired nonces from storage.
// This periodic cleanup prevents memory bloat from expired nonces.
// Uses a write lock since it modifies the nonce collection.
func (m *memory) CleanupExpired(ctx context.Context, now time.Time) error {
	m.muNonce.Lock()
	defer m.muNonce.Unlock()
	for value, nonce := range m.nonces {
		// Remove expired nonces
		if now.After(nonce.ExpiresAt) {
			delete(m.nonces, value)
		}
	}
	return nil
}

// Remember stores a response for later retrieval to support idempotent operations.
// The response is cached with an expiration time to prevent indefinite growth.
// Uses a write lock to ensure exclusive access during storage.
func (m *memory) Remember(ctx context.Context, key string, response StoredResponse) error {
	m.muIdempotency.Lock()
	defer m.muIdempotency.Unlock()
	m.idempotency[key] = response
	return nil
}

// Recall retrieves a previously stored response if it exists and hasn't expired.
// Returns a clone of the stored response to prevent external modification.
// Uses a read lock to allow concurrent reads.
func (m *memory) Recall(ctx context.Context, key string) (StoredResponse, bool) {
	m.muIdempotency.RLock()
	defer m.muIdempotency.RUnlock()
	resp, ok := m.idempotency[key]
	if !ok {
		return StoredResponse{}, false
	}
	// Check if the cached response has expired
	if time.Now().UTC().After(resp.ExpiresAt) {
		return StoredResponse{}, false
	}
	// Create a deep copy to prevent external modification of internal data
	clone := StoredResponse{
		StatusCode: resp.StatusCode,
		Body:       append([]byte(nil), resp.Body...), // Copy body bytes
		Headers:    make(map[string]string, len(resp.Headers)), // New header map
		ExpiresAt:  resp.ExpiresAt,
	}
	// Copy all headers
	for k, v := range resp.Headers {
		clone.Headers[k] = v
	}
	return clone, true
}

// StoreRecoveryToken stores a new recovery token for later validation.
// Recovery tokens are stored by their value for efficient lookup during validation.
// Uses a write lock to ensure exclusive access during storage.
func (m *memory) StoreRecoveryToken(ctx context.Context, token RecoveryToken) error {
	m.muRecovery.Lock()
	defer m.muRecovery.Unlock()
	m.recoveryTokens[token.Token] = token
	return nil
}

// ValidateRecoveryToken validates a recovery token and marks it as used.
// Returns true if the token is valid and hasn't been used or expired.
// The token is marked as used upon successful validation.
// Uses a write lock since it modifies the recovery token collection.
func (m *memory) ValidateRecoveryToken(ctx context.Context, did, email, token string) (bool, error) {
	m.muRecovery.Lock()
	defer m.muRecovery.Unlock()
	recoveryToken, ok := m.recoveryTokens[token]
	if !ok {
		return false, nil
	}
	// Check if the token has expired
	if time.Now().UTC().After(recoveryToken.ExpiresAt) {
		delete(m.recoveryTokens, token)
		return false, nil
	}
	// Check if the token has already been used
	if recoveryToken.Used {
		return false, nil
	}
	// Check if the token matches the DID and email
	if recoveryToken.DID != did || recoveryToken.Email != email {
		return false, nil
	}
	// Mark the token as used
	recoveryToken.Used = true
	m.recoveryTokens[token] = recoveryToken
	return true, nil
}

// CleanupExpiredRecoveryTokens removes expired recovery tokens from storage.
// This periodic cleanup prevents memory bloat from expired tokens.
// Uses a write lock since it modifies the recovery token collection.
func (m *memory) CleanupExpiredRecoveryTokens(ctx context.Context, now time.Time) error {
	m.muRecovery.Lock()
	defer m.muRecovery.Unlock()
	for value, token := range m.recoveryTokens {
		// Remove expired tokens
		if now.After(token.ExpiresAt) {
			delete(m.recoveryTokens, value)
		}
	}
	return nil
}

// cloneIdentity creates a deep copy of an Identity to prevent external modification
// of internal data structures. This is important for maintaining data integrity.
func cloneIdentity(in model.Identity) model.Identity {
	out := in
	out.Document = cloneDoc(in.Document)
	return out
}

// cloneDoc creates a deep copy of a DIDDocument to prevent external modification
// of internal data structures. This is important for maintaining data integrity.
func cloneDoc(doc model.DIDDocument) model.DIDDocument {
	out := doc
	// Deep copy slices to prevent external modification
	if doc.Context != nil {
		out.Context = append([]string(nil), doc.Context...)
	}
	if doc.VerificationMethod != nil {
		out.VerificationMethod = append([]model.VerificationMethod(nil), doc.VerificationMethod...)
	}
	if doc.Authentication != nil {
		out.Authentication = append([]string(nil), doc.Authentication...)
	}
	if doc.AssertionMethod != nil {
		out.AssertionMethod = append([]string(nil), doc.AssertionMethod...)
	}
	// Deep copy service slice
	if doc.Service != nil {
		services := make([]model.DIDService, len(doc.Service))
		copy(services, doc.Service)
		out.Service = services
	}
	return out
}
