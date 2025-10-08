// Package server contains HTTP routing and handlers for the identity service.
// It exposes a small XRPC-style API for creating and retrieving identity
// records and a basic health endpoint.
package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/storage"
	"github.com/mr-tron/base58"
)

type Mux struct {
    mux   *http.ServeMux
    store storage.Store
}

// NewMux constructs an *http.ServeMux wired with health and XRPC endpoints.
// The provided Store is used by handlers to persist and fetch identity records.
func NewMux(store storage.Store) *http.ServeMux {
    m := &Mux{
        mux:   http.NewServeMux(),
        store: store,
    }

	// Health
	m.mux.HandleFunc("/health", m.handleHealth)

	// XRPC-style endpoints per com.registryaccord.identity
	m.mux.HandleFunc("/xrpc/com.registryaccord.identity.create", m.method("POST", m.handleIdentityCreate))
	m.mux.HandleFunc("/xrpc/com.registryaccord.identity.get", m.method("GET", m.handleIdentityGet))

    return m.mux
}

// method returns a handler that enforces the given HTTP verb, returning 405
// when the request method does not match.
func (m *Mux) method(method string, h http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != method {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        h(w, r)
    }
}

// handleHealth indicates process liveness. Extend to check dependencies if
// needed (e.g., databases, caches).
func (m *Mux) handleHealth(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("ok"))
}

type createInput struct {
	PublicKey string `json:"publicKey"` // base64
}
type createOutput struct {
	DID string `json:"did"`
}

// handleIdentityCreate implements POST /xrpc/com.registryaccord.identity.create
// It accepts a JSON body with a base64-encoded publicKey, derives a PoC DID of
// the form did:ra:ed25519:<base58(pubKey)>, persists the record, and returns
// the DID.
func (m *Mux) handleIdentityCreate(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var in createInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if in.PublicKey == "" {
		http.Error(w, "publicKey is required", http.StatusBadRequest)
		return
	}
	pk, err := base64.StdEncoding.DecodeString(in.PublicKey)
	if err != nil || len(pk) == 0 {
		http.Error(w, "publicKey must be base64 bytes", http.StatusBadRequest)
		return
	}

	// PoC DID: did:ra:ed25519:<base58(pubKey)>
	did := "did:ra:ed25519:" + base58.Encode(pk)

	rec := model.IdentityRecord{
		DID:       did,
		PublicKey: pk,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := m.store.Put(r.Context(), rec); err != nil {
		slog.Error("persist identity failed", "error", err)
		http.Error(w, "failed to persist identity", http.StatusInternalServerError)
		return
	}

	out := createOutput{DID: did}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleIdentityGet implements
// GET /xrpc/com.registryaccord.identity.get?did=<id>.
// Returns 400 if DID is missing, 404 if not found, and 500 on other errors.
func (m *Mux) handleIdentityGet(w http.ResponseWriter, r *http.Request) {
	did := r.URL.Query().Get("did")
	if did == "" {
		http.Error(w, "did is required", http.StatusBadRequest)
		return
	}
	rec, err := m.store.Get(r.Context(), did)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	dto := model.IdentityRecordDTO{
		DID:       rec.DID,
		PublicKey: base64.StdEncoding.EncodeToString(rec.PublicKey),
		CreatedAt: rec.CreatedAt,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dto)
}
