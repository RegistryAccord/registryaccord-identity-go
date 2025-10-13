// Package server contains tests for the HTTP handlers of the identity service.
// This file tests the main mux router and core endpoints.
package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/config"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/storage"
)

// newTestServer creates a test HTTP server with in-memory storage for testing endpoints.
// Returns both the test server and the underlying store for direct manipulation in tests.
// Uses minimal configuration suitable for testing purposes.
func newTestServer() (*httptest.Server, storage.Store) {
	cfg := config.Config{
		Address:       ":8080",           // Test server address
		JWTPrivateKey: make([]byte, 64),  // Mock JWT signing key
		JWTAudience:   "test",            // Test JWT audience
		JWTIssuer:     "test",            // Test JWT issuer
		SessionTTL:    10 * time.Minute,  // Test session duration
		NonceTTL:      5 * time.Minute,   // Test nonce duration
	}
	// Use in-memory storage for test isolation
	store := storage.NewMemory()
	// Create handler with test configuration
	h, _ := New(cfg, store, slog.Default())
	// Create test server with the handler's router
	return httptest.NewServer(h.Router()), store
}

// TestHealth verifies that the health check endpoint returns 200 OK with body "ok".
// This is a basic liveness check that the server is running and responding to requests.
func TestHealth(t *testing.T) {
	// Create test server
	ts, _ := newTestServer()
	// Ensure server is closed after test
	defer ts.Close()

	// Make GET request to /health endpoint
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health error: %v", err)
	}
	// Ensure response body is closed
	defer resp.Body.Close()
	// Verify status code is 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d want %d", resp.StatusCode, http.StatusOK)
	}
	// Read response body
	b, _ := io.ReadAll(resp.Body)
	// Verify response body is "ok"
	if string(b) != "ok" {
		t.Fatalf("body = %q want %q", string(b), "ok")
	}
}

// TestIdentityCreateAndGet_Success tests the full identity lifecycle:
// 1. Creating a new identity via POST /v1/identity
// 2. Retrieving the created identity via GET /v1/identity/{did}
// Verifies that the created identity can be successfully retrieved
// and that the DID is in the expected format.
func TestIdentityCreateAndGet_Success(t *testing.T) {
	// Create test server
	ts, _ := newTestServer()
	// Ensure server is closed after test
	defer ts.Close()

	// Prepare test data
	in := map[string]string{"keySpec": "ed25519"}
	buf, _ := json.Marshal(in)

	// Test identity creation
	resp, err := http.Post(ts.URL+"/v1/identity", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST create error: %v", err)
	}
	// Ensure response body is closed
	defer resp.Body.Close()
	// Verify creation was successful
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status = %d body=%s", resp.StatusCode, string(b))
	}
	// Parse the response to get the created DID
	var env struct {
		Data struct {
			DID                 string                     `json:"did"`
			VerificationMethods []model.VerificationMethod `json:"verificationMethods"`
			CreatedAt           string                     `json:"createdAt"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	// Verify DID is in expected format
	if !strings.HasPrefix(env.Data.DID, "did:plc:") {
		t.Fatalf("unexpected DID: %s", env.Data.DID)
	}

	// Test identity retrieval
	getResp, err := http.Get(ts.URL + "/v1/identity/" + env.Data.DID)
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	// Ensure response body is closed
	defer getResp.Body.Close()
	// Verify retrieval was successful
	if getResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(getResp.Body)
		t.Fatalf("get status = %d body=%s", getResp.StatusCode, string(b))
	}
	// Parse the response to verify the retrieved identity
	var doc model.DIDDocument
	if err := json.NewDecoder(getResp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	// Verify the retrieved DID matches the created DID
	if doc.ID != env.Data.DID {
		t.Fatalf("DID mismatch: got %s want %s", doc.ID, env.Data.DID)
	}
}

// TestIdentityCreate_MethodNotAllowed verifies that sending a GET request
// to the identity creation endpoint returns Method Not Allowed (405).
// The /v1/identity endpoint only accepts POST requests for creation.
func TestIdentityCreate_MethodNotAllowed(t *testing.T) {
	// Create test server
	ts, _ := newTestServer()
	// Ensure server is closed after test
	defer ts.Close()

	// Create a GET request to the identity creation endpoint
	// (which only accepts POST requests)
	req, _ := http.NewRequest("GET", ts.URL+"/v1/identity", nil)
	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	// Ensure response body is closed
	defer resp.Body.Close()
	// Verify that GET is not allowed (should return 405 Method Not Allowed)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestIdentityCreate_ValidationErrors tests various validation error cases
// for the identity creation endpoint:
// 1. Invalid JSON syntax
// 2. Unsupported key specification
// 3. Malformed JSON
// Verifies that appropriate error responses are returned for each case.
func TestIdentityCreate_ValidationErrors(t *testing.T) {
	// Create test server
	ts, _ := newTestServer()
	// Ensure server is closed after test
	defer ts.Close()

	// Test 1: Invalid JSON syntax (missing closing brace)
	resp, err := http.Post(ts.URL+"/v1/identity", "application/json", strings.NewReader("{"))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	// Verify that invalid JSON returns 400 Bad Request
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid json status = %d want %d", resp.StatusCode, http.StatusBadRequest)
	}
	resp.Body.Close()

	// Test 2: Unsupported key specification (only ed25519 is supported)
	resp, err = http.Post(ts.URL+"/v1/identity", "application/json", strings.NewReader(`{"keySpec":"rsa"}`))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	// Verify that unsupported keySpec returns 422 Unprocessable Entity
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unsupported keySpec status = %d want %d", resp.StatusCode, http.StatusUnprocessableEntity)
	}
	resp.Body.Close()

	// Test 3: Malformed JSON (missing closing quote and brace)
	resp, err = http.Post(ts.URL+"/v1/identity", "application/json", strings.NewReader(`{"keySpec":"***"`))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	// Verify that malformed JSON returns 400 Bad Request
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid base64 status = %d want %d", resp.StatusCode, http.StatusBadRequest)
	}
	resp.Body.Close()
}

// TestIdentityGet_Errors tests error cases for the identity retrieval endpoint:
// 1. Missing DID in the path
// 2. Request for a non-existent DID
// Verifies that appropriate error responses are returned for each case.
func TestIdentityGet_Errors(t *testing.T) {
	// Create test server
	ts, _ := newTestServer()
	// Ensure server is closed after test
	defer ts.Close()

	// Test 1: Missing DID in path (trailing slash with no DID)
	resp, err := http.Get(ts.URL + "/v1/identity/")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	// Verify that missing DID returns 400 Bad Request
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing did status = %d want %d", resp.StatusCode, http.StatusBadRequest)
	}
	resp.Body.Close()

	// Test 2: Request for a non-existent DID
	resp, err = http.Get(ts.URL + "/v1/identity/did:plc:notfound")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	// Verify that non-existent DID returns 404 Not Found
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("not found status = %d want %d", resp.StatusCode, http.StatusNotFound)
	}
	resp.Body.Close()
}
