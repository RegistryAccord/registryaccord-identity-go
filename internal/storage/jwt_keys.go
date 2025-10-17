// Package storage contains persistence abstractions and implementations
// for identity records used by the service.
// This file provides JWT signing key storage for key rotation support.
package storage

import (
	"context"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
)

// GetCurrentSigningKey returns the currently active signing key
func (m *memory) GetCurrentSigningKey(ctx context.Context) (model.JWTSigningKey, error) {
	m.muJWTKeys.RLock()
	defer m.muJWTKeys.RUnlock()
	
	// Find the key with the latest activation time that is not retired
	var currentKey model.JWTSigningKey
	var found bool
	var latestActivation time.Time
	
	for _, key := range m.jwtSigningKeys {
		// Skip retired keys
		if !key.RetiredAt.IsZero() && key.RetiredAt.Before(time.Now().UTC()) {
			continue
		}
		// Skip keys that haven't been activated yet
		if key.ActivatedAt.After(time.Now().UTC()) {
			continue
		}
		// Find the most recently activated key
		if !found || key.ActivatedAt.After(latestActivation) {
			currentKey = cloneJWTSigningKey(key)
			latestActivation = key.ActivatedAt
			found = true
		}
	}
	
	if !found {
		return model.JWTSigningKey{}, ErrNotFound
	}
	
	return currentKey, nil
}

// GetSigningKeyByID retrieves a specific signing key by its ID
func (m *memory) GetSigningKeyByID(ctx context.Context, keyID string) (model.JWTSigningKey, error) {
	m.muJWTKeys.RLock()
	defer m.muJWTKeys.RUnlock()
	
	key, ok := m.jwtSigningKeys[keyID]
	if !ok {
		return model.JWTSigningKey{}, ErrNotFound
	}
	
	return cloneJWTSigningKey(key), nil
}

// ListActiveSigningKeys returns all currently active signing keys
// (including those in the overlap window)
func (m *memory) ListActiveSigningKeys(ctx context.Context) ([]model.JWTSigningKey, error) {
	m.muJWTKeys.RLock()
	defer m.muJWTKeys.RUnlock()
	
	var activeKeys []model.JWTSigningKey
	
	for _, key := range m.jwtSigningKeys {
		// Skip expired keys
		if !key.ExpiresAt.IsZero() && key.ExpiresAt.Before(time.Now().UTC()) {
			continue
		}
		// Skip keys that haven't been activated yet
		if key.ActivatedAt.After(time.Now().UTC()) {
			continue
		}
		// Include active keys and those in overlap window (retired but not expired)
		activeKeys = append(activeKeys, cloneJWTSigningKey(key))
	}
	
	return activeKeys, nil
}

// AddSigningKey adds a new signing key to the store
func (m *memory) AddSigningKey(ctx context.Context, key model.JWTSigningKey) error {
	m.muJWTKeys.Lock()
	defer m.muJWTKeys.Unlock()
	
	m.jwtSigningKeys[key.ID] = key
	return nil
}

// RetireSigningKey marks a signing key as retired
// It will remain in the store until its expiration time
func (m *memory) RetireSigningKey(ctx context.Context, keyID string, retiredAt time.Time) error {
	m.muJWTKeys.Lock()
	defer m.muJWTKeys.Unlock()
	
	key, ok := m.jwtSigningKeys[keyID]
	if !ok {
		return ErrNotFound
	}
	
	key.RetiredAt = retiredAt
	m.jwtSigningKeys[keyID] = key
	return nil
}

// CleanupExpiredSigningKeys removes expired signing keys from storage
func (m *memory) CleanupExpiredSigningKeys(ctx context.Context, now time.Time) error {
	m.muJWTKeys.Lock()
	defer m.muJWTKeys.Unlock()
	
	for keyID, key := range m.jwtSigningKeys {
		if !key.ExpiresAt.IsZero() && key.ExpiresAt.Before(now) {
			delete(m.jwtSigningKeys, keyID)
		}
	}
	return nil
}

// cloneJWTSigningKey creates a deep copy of a JWTSigningKey to prevent external modification
func cloneJWTSigningKey(in model.JWTSigningKey) model.JWTSigningKey {
	out := in
	if in.PrivateKey != nil {
		out.PrivateKey = append([]byte(nil), in.PrivateKey...)
	}
	if in.PublicKey != nil {
		out.PublicKey = append([]byte(nil), in.PublicKey...)
	}
	return out
}
