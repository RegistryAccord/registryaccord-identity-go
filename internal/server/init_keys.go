// Package server contains HTTP handlers for the identity service.
// This file handles initialization of JWT signing keys.
package server

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/config"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/storage"
)

// initializeSigningKey ensures that at least one signing key exists in storage.
// If no keys exist, it creates and stores the initial signing key from config.
func initializeSigningKey(ctx context.Context, store storage.ExtendedStore, cfg config.Config) error {
	// Check if any keys already exist
	keys, err := store.ListActiveSigningKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to list signing keys: %w", err)
	}
	
	// If keys already exist, we're done
	if len(keys) > 0 {
		return nil
	}
	
	// No keys exist, create the initial key from config
	// Validate the configured key
	if len(cfg.JWTPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid JWT signing key size: %d bytes, expected %d", len(cfg.JWTPrivateKey), ed25519.PrivateKeySize)
	}
	
	privateKey := ed25519.PrivateKey(cfg.JWTPrivateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	
	// Create a key ID based on the public key
	keyID := fmt.Sprintf("key-%x", publicKey[:4])
	
	// Create the signing key model
	now := time.Now().UTC()
	key := model.JWTSigningKey{
		ID:         keyID,
		PrivateKey: []byte(privateKey),
		PublicKey:  []byte(publicKey),
		CreatedAt:  now,
		ActivatedAt: now,
		ExpiresAt:  now.Add(365 * 24 * time.Hour), // 1 year expiration
	}
	
	// Store the key
	if err := store.AddSigningKey(ctx, key); err != nil {
		return fmt.Errorf("failed to store initial signing key: %w", err)
	}
	
	return nil
}
