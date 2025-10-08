// cmd/identityd/main_test.go
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/server"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/storage"
)

// This is an integration-style test that wires the same components main() uses
// (in-memory store + server mux) but runs them under httptest.Server.
func TestIdentityd_Integration(t *testing.T) {
	store := storage.NewMemory()
	mux := server.NewMux(store)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Health
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("health request error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Create identity
	pk := []byte{9, 8, 7}
	in := map[string]string{"publicKey": base64.StdEncoding.EncodeToString(pk)}
	body, _ := json.Marshal(in)
	resp, err = http.Post(ts.URL+"/xrpc/com.registryaccord.identity.create", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create status = %d body=%s", resp.StatusCode, string(b))
	}
	var created struct{ DID string `json:"did"` }
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		resp.Body.Close()
		t.Fatalf("decode create: %v", err)
	}
	resp.Body.Close()

	// Get identity
	resp, err = http.Get(ts.URL + "/xrpc/com.registryaccord.identity.get?did=" + created.DID)
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get status = %d body=%s", resp.StatusCode, string(b))
	}
	var dto model.IdentityRecordDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		resp.Body.Close()
		t.Fatalf("decode get: %v", err)
	}
	resp.Body.Close()
	if dto.DID != created.DID {
		t.Fatalf("DID mismatch: got %s want %s", dto.DID, created.DID)
	}
	if dto.PublicKey != base64.StdEncoding.EncodeToString(pk) {
		t.Fatalf("publicKey mismatch: got %s", dto.PublicKey)
	}
}
