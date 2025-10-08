// internal/server/mux_test.go
package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/storage"
)

func newTestServer() (*httptest.Server, storage.Store) {
	store := storage.NewMemory()
	mux := NewMux(store)
	return httptest.NewServer(mux), store
}

func TestHealth(t *testing.T) {
	ts, _ := newTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d want %d", resp.StatusCode, http.StatusOK)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "ok" {
		t.Fatalf("body = %q want %q", string(b), "ok")
	}
}

func TestIdentityCreateAndGet_Success(t *testing.T) {
	ts, _ := newTestServer()
	defer ts.Close()

	pk := []byte{1, 2, 3, 4, 5}
	in := map[string]string{"publicKey": base64.StdEncoding.EncodeToString(pk)}
	buf, _ := json.Marshal(in)

	resp, err := http.Post(ts.URL+"/xrpc/com.registryaccord.identity.create", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST create error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status = %d body=%s", resp.StatusCode, string(b))
	}
	var out struct{ DID string `json:"did"` }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if !strings.HasPrefix(out.DID, "did:ra:ed25519:") {
		t.Fatalf("unexpected DID: %s", out.DID)
	}

	// GET should return the record and base64 public key
	getResp, err := http.Get(ts.URL + "/xrpc/com.registryaccord.identity.get?did=" + out.DID)
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(getResp.Body)
		t.Fatalf("get status = %d body=%s", getResp.StatusCode, string(b))
	}
	var dto model.IdentityRecordDTO
	if err := json.NewDecoder(getResp.Body).Decode(&dto); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if dto.DID != out.DID {
		t.Fatalf("DID mismatch: got %s want %s", dto.DID, out.DID)
	}
	if dto.PublicKey != base64.StdEncoding.EncodeToString(pk) {
		t.Fatalf("publicKey mismatch: got %s", dto.PublicKey)
	}
}

func TestIdentityCreate_MethodNotAllowed(t *testing.T) {
	ts, _ := newTestServer()
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/xrpc/com.registryaccord.identity.create", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestIdentityCreate_ValidationErrors(t *testing.T) {
	ts, _ := newTestServer()
	defer ts.Close()

	// invalid JSON
	resp, err := http.Post(ts.URL+"/xrpc/com.registryaccord.identity.create", "application/json", strings.NewReader("{"))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid json status = %d want %d", resp.StatusCode, http.StatusBadRequest)
	}
	resp.Body.Close()

	// missing publicKey
	resp, err = http.Post(ts.URL+"/xrpc/com.registryaccord.identity.create", "application/json", strings.NewReader(`{"publicKey":""}`))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing publicKey status = %d want %d", resp.StatusCode, http.StatusBadRequest)
	}
	resp.Body.Close()

	// invalid base64
	resp, err = http.Post(ts.URL+"/xrpc/com.registryaccord.identity.create", "application/json", strings.NewReader(`{"publicKey":"***"}`))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid base64 status = %d want %d", resp.StatusCode, http.StatusBadRequest)
	}
	resp.Body.Close()
}

func TestIdentityGet_Errors(t *testing.T) {
	ts, _ := newTestServer()
	defer ts.Close()

	// missing did
	resp, err := http.Get(ts.URL + "/xrpc/com.registryaccord.identity.get")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing did status = %d want %d", resp.StatusCode, http.StatusBadRequest)
	}
	resp.Body.Close()

	// not found
	resp, err = http.Get(ts.URL + "/xrpc/com.registryaccord.identity.get?did=did:ra:ed25519:notfound")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("not found status = %d want %d", resp.StatusCode, http.StatusNotFound)
	}
	resp.Body.Close()
}
