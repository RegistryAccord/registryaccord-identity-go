// Package storage contains persistence abstractions and in-memory
// implementations for identity records used by the service.
package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
)

// ErrNotFound is returned when a requested record does not exist in the store.
var ErrNotFound = errors.New("not found")

// Store abstracts persistence operations for identity records. Implementations
// must be safe for concurrent use.
type Store interface {
	Put(ctx context.Context, rec model.IdentityRecord) error
	Get(ctx context.Context, did string) (model.IdentityRecord, error)
}

type memory struct {
	mu   sync.RWMutex
	data map[string]model.IdentityRecord
}

// NewMemory returns a concurrency-safe in-memory implementation of Store.
// Useful for tests, demos, or as a default ephemeral backend.
func NewMemory() Store {
	return &memory{data: make(map[string]model.IdentityRecord)}
}

// Put stores or overwrites the record keyed by its DID.
func (m *memory) Put(ctx context.Context, rec model.IdentityRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[rec.DID] = rec
	return nil
}

// Get retrieves a record by DID. Returns ErrNotFound when no record exists.
func (m *memory) Get(ctx context.Context, did string) (model.IdentityRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.data[did]
	if !ok {
		return model.IdentityRecord{}, ErrNotFound
	}
	return rec, nil
}
