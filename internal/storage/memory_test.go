// internal/storage/memory_test.go
package storage

import (
	"context"
	"testing"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
)

func TestMemoryStore_PutGet(t *testing.T) {
	store := NewMemory()
	ctx := context.Background()

	rec := model.IdentityRecord{
		DID:       "did:ra:ed25519:abc",
		PublicKey: []byte{1, 2, 3},
		CreatedAt: "2024-01-01T00:00:00Z",
	}
	if err := store.Put(ctx, rec); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got, err := store.Get(ctx, rec.DID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.DID != rec.DID {
		t.Errorf("DID mismatch: got %q want %q", got.DID, rec.DID)
	}
	if string(got.PublicKey) != string(rec.PublicKey) {
		t.Errorf("PublicKey mismatch: got %v want %v", got.PublicKey, rec.PublicKey)
	}
	if got.CreatedAt != rec.CreatedAt {
		t.Errorf("CreatedAt mismatch: got %q want %q", got.CreatedAt, rec.CreatedAt)
	}
}

func TestMemoryStore_GetNotFound(t *testing.T) {
	store := NewMemory()
	_, err := store.Get(context.Background(), "did:ra:ed25519:missing")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
