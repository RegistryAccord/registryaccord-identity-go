// cmd/identityd/main_test.go
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/config"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/server"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/storage"
	"log/slog"
)

// This is an integration-style test that wires the same components main() uses
// (in-memory store + server mux) but runs them under httptest.Server.
func TestIdentityd_Integration(t *testing.T) {
	cfg := config.Config{
		Address:       ":8080",
		JWTPrivateKey: make([]byte, 64),
		JWTAudience:   "test",
		JWTIssuer:     "test",
		SessionTTL:    10 * time.Minute,
		NonceTTL:      5 * time.Minute,
	}
	store := storage.NewMemory()
	h, _ := server.New(cfg, store, slog.Default())
	ts := httptest.NewServer(h.Router())
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
	in := map[string]string{"keySpec": "ed25519"}
	body, _ := json.Marshal(in)
	resp, err = http.Post(ts.URL+"/v1/identity", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create error: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create status = %d body=%s", resp.StatusCode, string(b))
	}
	var env struct {
		Data struct {
			DID                 string                     `json:"did"`
			VerificationMethods []model.VerificationMethod `json:"verificationMethods"`
			CreatedAt           string                     `json:"createdAt"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		resp.Body.Close()
		t.Fatalf("decode create: %v", err)
	}
	resp.Body.Close()

	// Get identity
	resp, err = http.Get(ts.URL + "/v1/identity/" + env.Data.DID)
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get status = %d body=%s", resp.StatusCode, string(b))
	}
	var doc model.DIDDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		resp.Body.Close()
		t.Fatalf("decode get: %v", err)
	}
	resp.Body.Close()
	if doc.ID != env.Data.DID {
		t.Fatalf("DID mismatch: got %s want %s", doc.ID, env.Data.DID)
	}
}
