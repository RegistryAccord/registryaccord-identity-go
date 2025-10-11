// Package storage contains tests for the in-memory storage implementation.
// This file tests the basic CRUD operations for identities.
package storage

import (
	"context"
	"testing"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
)

// TestMemoryStore_CreateGetIdentity tests the basic identity creation and retrieval flow.
// Verifies that an identity can be successfully stored and retrieved from memory storage.
func TestMemoryStore_CreateGetIdentity(t *testing.T) {
	// Create a new in-memory store
	store := NewMemory()
	// Create a background context for the test
	ctx := context.Background()

	// Create a test identity with minimal data
	identity := model.Identity{
		DID: "did:plc:abc123", // Test DID
		Document: model.DIDDocument{
			ID: "did:plc:abc123", // Matching document ID
		},
		Keys: []model.KeyMaterial{{
			ID: "key1", // Test key material
		}},
		CreatedAtUTC: "2024-01-01T00:00:00Z", // Creation timestamp
		UpdatedAtUTC: "2024-01-01T00:00:00Z", // Update timestamp
	}
	// Test identity creation
	if err := store.CreateIdentity(ctx, identity); err != nil {
		t.Fatalf("CreateIdentity failed: %v", err)
	}

	// Test identity retrieval
	got, err := store.GetIdentity(ctx, identity.DID)
	if err != nil {
		t.Fatalf("GetIdentity failed: %v", err)
	}
	// Verify the retrieved identity matches the created one
	if got.DID != identity.DID {
		t.Errorf("DID mismatch: got %q want %q", got.DID, identity.DID)
	}
}

// TestMemoryStore_GetIdentityNotFound tests that retrieving a non-existent identity
// returns the appropriate ErrNotFound error.
func TestMemoryStore_GetIdentityNotFound(t *testing.T) {
	// Create a new in-memory store
	store := NewMemory()
	// Attempt to retrieve an identity that doesn't exist
	_, err := store.GetIdentity(context.Background(), "did:plc:missing")
	// Verify that an error was returned
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	// Verify that the error is specifically ErrNotFound
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
