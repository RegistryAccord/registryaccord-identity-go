package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/config"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/did"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/storage"
)

type contextKey string

const (
	contextKeyCorrelationID contextKey = "correlationId"
	contextKeyDID           contextKey = "did"

	headerContentType    = "Content-Type"
	headerCorrelationID  = "X-Correlation-Id"
	headerIdempotencyKey = "Idempotency-Key"
	headerCacheControl   = "Cache-Control"
	headerETag           = "ETag"

	contentTypeJSON     = "application/json"
	cacheControlResolve = "public, max-age=60"
)

// Handler wires HTTP endpoints using net/http.
type Handler struct {
	cfg    config.Config
	store  storage.Store
	logger *slog.Logger
	signer ed25519.PrivateKey
	clock  func() time.Time
	router *http.ServeMux
}

// New creates a Handler using the supplied dependencies.
func New(cfg config.Config, store storage.Store, logger *slog.Logger) (*Handler, error) {
	if len(cfg.JWTPrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("jwt signing key must be %d bytes", ed25519.PrivateKeySize)
	}
	if logger == nil {
		logger = slog.Default()
	}
	h := &Handler{
		cfg:    cfg,
		store:  store,
		logger: logger,
		signer: ed25519.PrivateKey(cfg.JWTPrivateKey),
		clock:  time.Now().UTC,
		router: http.NewServeMux(),
	}
	h.registerRoutes()
	return h, nil
}

// Router returns an *http.ServeMux with all Phase 1 routes registered.
func (h *Handler) Router() *http.ServeMux {
	return h.router
}

func (h *Handler) registerRoutes() {
	h.router.Handle("/health", h.loggingMiddleware(h.timeoutMiddleware(http.HandlerFunc(h.health))))
	h.router.Handle("/ready", h.loggingMiddleware(h.timeoutMiddleware(http.HandlerFunc(h.readyHandler))))
	h.router.Handle("/metrics", h.loggingMiddleware(h.timeoutMiddleware(http.HandlerFunc(h.metricsHandler))))

	h.router.Handle("/v1/identity", h.loggingMiddleware(h.timeoutMiddleware(h.wrap(h.handleIdentityCreate))))
	h.router.Handle("/v1/identity/", h.loggingMiddleware(h.timeoutMiddleware(h.wrap(h.handleIdentityResolve))))
	h.router.Handle("/.well-known/did.json", h.loggingMiddleware(h.timeoutMiddleware(h.wrap(h.wellKnownHandler))))

	// Session authentication endpoints (challenge-response flow)
	// GET /v1/session/nonce - Generate a single-use nonce for authentication
	// POST /v1/session - Validate signed nonce and issue JWT session token
	h.router.Handle("/v1/session/nonce", h.loggingMiddleware(h.timeoutMiddleware(h.wrap(h.handleSessionNonce))))
	h.router.Handle("/v1/session", h.loggingMiddleware(h.timeoutMiddleware(h.wrap(h.handleSessionIssue))))

	h.router.Handle("/v1/key/rotate", h.loggingMiddleware(h.timeoutMiddleware(h.wrap(h.keyRotateHandler))))
	h.router.Handle("/v1/identity/recover", h.loggingMiddleware(h.timeoutMiddleware(h.wrap(h.identityRecoverHandler))))
}

type responseEnvelope struct {
	Data  any            `json:"data,omitempty"`
	Meta  any            `json:"meta,omitempty"`
	Error *errorEnvelope `json:"error,omitempty"`
}

type errorEnvelope struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	Details       any    `json:"details,omitempty"`
	CorrelationID string `json:"correlationId"`
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (h *Handler) ready(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func (h *Handler) wrap(next func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationID := h.ensureCorrelationID(w, r)
		ctx := context.WithValue(r.Context(), contextKeyCorrelationID, correlationID)
		r = r.WithContext(ctx)
		w.Header().Set(headerContentType, contentTypeJSON)

		if h.tryReplay(w, r) {
			return
		}

		defer func() {
			if rec := recover(); rec != nil {
				h.logger.Error("panic recovered", "panic", rec, "correlationId", correlationID)
				h.writeError(w, http.StatusInternalServerError, "IDENTITY_INTERNAL", "internal server error", correlationID, nil)
			}
		}()

		next(w, r)
	})
}

func (h *Handler) ensureCorrelationID(w http.ResponseWriter, r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get(headerCorrelationID))
	if id == "" {
		id = uuid.NewString()
	}
	w.Header().Set(headerCorrelationID, id)
	return id
}

func (h *Handler) tryReplay(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return false
	}
	key := strings.TrimSpace(r.Header.Get(headerIdempotencyKey))
	if key == "" {
		return false
	}
	cached, ok := h.store.Recall(r.Context(), key)
	if !ok {
		return false
	}
	for k, v := range cached.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(cached.StatusCode)
	_, _ = w.Write(cached.Body)
	return true
}

func (h *Handler) remember(r *http.Request, w http.ResponseWriter, status int, payload []byte) {
	if r.Method == http.MethodGet {
		return
	}
	key := strings.TrimSpace(r.Header.Get(headerIdempotencyKey))
	if key == "" {
		return
	}
	headers := make(map[string]string, len(w.Header()))
	for k := range w.Header() {
		headers[k] = w.Header().Get(k)
	}
	_ = h.store.Remember(r.Context(), key, storage.StoredResponse{
		StatusCode: status,
		Body:       append([]byte(nil), payload...),
		Headers:    headers,
		ExpiresAt:  h.clock().Add(24 * time.Hour),
	})
}

func (h *Handler) handleIdentityCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorWithRequest(w, r, http.StatusMethodNotAllowed, "IDENTITY_VALIDATION", "method not allowed", nil)
		return
	}

	var input struct {
		KeySpec  string `json:"keySpec"`
		Recovery struct {
			Method string `json:"method"`
		} `json:"recovery"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.writeErrorWithRequest(w, r, http.StatusBadRequest, "IDENTITY_VALIDATION", "invalid JSON body", nil)
		return
	}

	keySpec := strings.TrimSpace(input.KeySpec)
	if keySpec == "" {
		keySpec = "ed25519"
	}
	if keySpec != "ed25519" {
		h.writeErrorWithRequest(w, r, http.StatusUnprocessableEntity, "IDENTITY_VALIDATION", "unsupported keySpec", map[string]any{"supported": []string{"ed25519"}})
		return
	}

	didID, err := did.GeneratePLC()
	if err != nil {
		h.writeErrorWithRequest(w, r, http.StatusInternalServerError, "IDENTITY_INTERNAL", "failed to allocate did", nil)
		return
	}

	createdAt := h.clock().Format(time.RFC3339)
	vmID := fmt.Sprintf("%s#keys-1", didID)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.writeErrorWithRequest(w, r, http.StatusInternalServerError, "IDENTITY_INTERNAL", "failed to generate key", nil)
		return
	}

	doc := model.DIDDocument{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      didID,
		VerificationMethod: []model.VerificationMethod{{
			ID:                 vmID,
			Type:               "Ed25519VerificationKey2020",
			Controller:         didID,
			PublicKeyMultibase: "z" + base58.Encode(pubKey),
		}},
		Authentication: []string{vmID},
		Created:        createdAt,
		Updated:        createdAt,
		VersionID:      "1",
	}

	identity := model.Identity{
		DID:      didID,
		Document: doc,
		Keys: []model.KeyMaterial{{
			ID:         vmID,
			Spec:       keySpec,
			PublicKey:  append([]byte(nil), pubKey...),
			PrivateKey: append([]byte(nil), privKey...),
			CreatedAt:  createdAt,
		}},
		CreatedAtUTC: createdAt,
		UpdatedAtUTC: createdAt,
		RecoveryState: model.RecoveryPolicy{
			Method: strings.TrimSpace(input.Recovery.Method),
		},
	}

	if err := h.store.CreateIdentity(r.Context(), identity); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			h.writeErrorWithRequest(w, r, http.StatusConflict, "IDENTITY_CONFLICT", "identity already exists", nil)
			return
		}
		h.writeErrorWithRequest(w, r, http.StatusInternalServerError, "IDENTITY_INTERNAL", "failed to persist identity", nil)
		return
	}

	if err := h.store.AppendOperation(r.Context(), model.OperationLogEntry{
		DID:           didID,
		Operation:     model.OperationCreate,
		PerformedAt:   createdAt,
		Actor:         didID,
		CorrelationID: correlationIDFrom(r.Context()),
		Payload: map[string]any{
			"keySpec": keySpec,
		},
	}); err != nil {
		h.logger.Warn("append operation log failed", "error", err, "did", didID)
	}

	data := map[string]any{
		"did":                 didID,
		"verificationMethods": doc.VerificationMethod,
		"createdAt":           createdAt,
	}

	payload := h.writeSuccess(w, http.StatusCreated, data, nil, r)
	h.remember(r, w, http.StatusCreated, payload)
	h.logger.Info("identity created", "did", didID, "correlationId", correlationIDFrom(r.Context()))
}

func (h *Handler) handleIdentityResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErrorWithRequest(w, r, http.StatusMethodNotAllowed, "IDENTITY_VALIDATION", "method not allowed", nil)
		return
	}
	didID := strings.TrimPrefix(r.URL.Path, "/v1/identity/")
	if didID == "" {
		h.writeErrorWithRequest(w, r, http.StatusBadRequest, "IDENTITY_VALIDATION", "did is required", nil)
		return
	}
	identity, err := h.store.GetIdentity(r.Context(), didID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			h.writeErrorWithRequest(w, r, http.StatusNotFound, "IDENTITY_NOT_FOUND", "identity not found", nil)
			return
		}
		h.writeErrorWithRequest(w, r, http.StatusInternalServerError, "IDENTITY_INTERNAL", "lookup failed", nil)
		return
	}
	ctx := context.WithValue(r.Context(), contextKeyDID, identity.DID)
	r = r.WithContext(ctx)

	body := h.writeSuccess(w, http.StatusOK, map[string]any{"document": identity.Document}, nil, r)
	w.Header().Set(headerCacheControl, cacheControlResolve)
	w.Header().Set(headerETag, generateETag(body))
	h.logger.Info("identity resolved", "did", identity.DID, "correlationId", correlationIDFrom(r.Context()))
}

func (h *Handler) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	h.writeErrorWithRequest(w, r, http.StatusNotImplemented, "IDENTITY_INTERNAL", "well-known not configured", nil)
}

// handleSessionNonce generates and stores a single-use nonce for session authentication
// This is the first step in the challenge-response authentication flow
func (h *Handler) handleSessionNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErrorWithRequest(w, r, http.StatusMethodNotAllowed, "IDENTITY_VALIDATION", "method not allowed", nil)
		return
	}
	// Extract required parameters from query string
	didID := strings.TrimSpace(r.URL.Query().Get("did"))
	audience := strings.TrimSpace(r.URL.Query().Get("aud"))
	if didID == "" || audience == "" {
		h.writeErrorWithRequest(w, r, http.StatusBadRequest, "IDENTITY_VALIDATION", "did and aud are required", nil)
		return
	}
	// Verify the DID exists before issuing a nonce for it
	if _, err := h.store.GetIdentity(r.Context(), didID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			h.writeErrorWithRequest(w, r, http.StatusNotFound, "IDENTITY_NOT_FOUND", "identity not found", nil)
			return
		}
		h.writeErrorWithRequest(w, r, http.StatusInternalServerError, "IDENTITY_INTERNAL", "identity lookup failed", nil)
		return
	}

	// Generate a cryptographically secure random nonce
	nonceValue := generateNonce()
	// Set expiration time based on configured TTL
	expires := h.clock().Add(h.cfg.NonceTTL)

	// Create and store the nonce with its associated DID and audience
	nonce := model.Nonce{
		Value:     nonceValue,
		DID:       didID,
		Audience:  audience,
		ExpiresAt: expires,
	}
	if err := h.store.PutNonce(r.Context(), nonce); err != nil {
		h.writeErrorWithRequest(w, r, http.StatusInternalServerError, "IDENTITY_INTERNAL", "failed to persist nonce", nil)
		return
	}

	h.writeSuccess(w, http.StatusOK, map[string]any{
		"nonce":     nonceValue,
		"expiresAt": expires.Format(time.RFC3339),
	}, nil, r)
	h.logger.Info("session nonce issued", "did", didID, "aud", audience, "correlationId", correlationIDFrom(r.Context()))
}

// handleSessionIssue validates a signed nonce and issues a JWT session token
// This is the second step in the challenge-response authentication flow
func (h *Handler) handleSessionIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorWithRequest(w, r, http.StatusMethodNotAllowed, "IDENTITY_VALIDATION", "method not allowed", nil)
		return
	}
	// Parse the authentication request payload
	var input struct {
		Nonce     string `json:"nonce"`     // The nonce value to validate
		Signature string `json:"signature"` // Client's signature of the nonce
		Audience  string `json:"audience"`  // Intended audience for the session
		DID       string `json:"did"`       // DID claiming ownership of the nonce
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.writeErrorWithRequest(w, r, http.StatusBadRequest, "IDENTITY_VALIDATION", "invalid JSON body", nil)
		return
	}

	// Retrieve and consume the nonce (single-use)
	nonce, err := h.store.ConsumeNonce(r.Context(), input.Nonce)
	if err != nil {
		h.writeErrorWithRequest(w, r, http.StatusUnauthorized, "IDENTITY_AUTHZ", "nonce invalid or expired", nil)
		return
	}
	// Verify the nonce is bound to the correct DID and audience
	if input.DID != nonce.DID || input.Audience != nonce.Audience {
		h.writeErrorWithRequest(w, r, http.StatusUnauthorized, "IDENTITY_AUTHZ", "nonce binding mismatch", nil)
		return
	}

	// Retrieve the identity to get the public key for signature verification
	identity, err := h.store.GetIdentity(r.Context(), nonce.DID)
	if err != nil {
		h.writeErrorWithRequest(w, r, http.StatusUnauthorized, "IDENTITY_AUTHZ", "identity lookup failed", nil)
		return
	}
	if len(identity.Document.VerificationMethod) == 0 {
		h.writeErrorWithRequest(w, r, http.StatusInternalServerError, "IDENTITY_INTERNAL", "no verification methods", nil)
		return
	}
	vm := identity.Document.VerificationMethod[0]
	pubKeyBytes, err := decodeMultibase(vm.PublicKeyMultibase)
	if err != nil {
		h.writeErrorWithRequest(w, r, http.StatusInternalServerError, "IDENTITY_INTERNAL", "invalid stored key", nil)
		return
	}

	// Decode the client's signature from base64
	sig, err := base64.StdEncoding.DecodeString(input.Signature)
	if err != nil {
		h.writeErrorWithRequest(w, r, http.StatusBadRequest, "IDENTITY_VALIDATION", "signature must be base64", nil)
		return
	}

	// Verify the signature against the expected message format
	message := []byte(input.Nonce + "|" + input.Audience + "|" + input.DID)
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), message, sig) {
		h.writeErrorWithRequest(w, r, http.StatusUnauthorized, "IDENTITY_AUTHZ", "signature verification failed", nil)
		return
	}

	// Generate a JWT session token with appropriate claims
	issuedAt := time.Now()
	expires := issuedAt.Add(h.cfg.SessionTTL)
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodEdDSA, jwtlib.MapClaims{
		"sub": nonce.DID,      // Subject is the authenticated DID
		"aud": nonce.Audience, // Audience as specified in the request
		"iss": h.cfg.JWTIssuer, // Issuer identifier from config
		"iat": issuedAt.Unix(), // Issued at timestamp
		"exp": expires.Unix(),  // Expiration timestamp
	})

	// Sign the JWT with the server's private key
	signedToken, err := token.SignedString(h.signer)
	if err != nil {
		h.writeErrorWithRequest(w, r, http.StatusInternalServerError, "IDENTITY_INTERNAL", "failed to sign jwt", nil)
		return
	}

	// Add the DID to the request context for logging/middleware
	ctx := context.WithValue(r.Context(), contextKeyDID, nonce.DID)
	r = r.WithContext(ctx)

	h.writeSuccess(w, http.StatusOK, map[string]any{
		"jwt": signedToken,
		"exp": expires.Format(time.RFC3339),
		"aud": nonce.Audience,
		"sub": nonce.DID,
	}, nil, r)
	h.logger.Info("session issued", "did", nonce.DID, "aud", nonce.Audience, "correlationId", correlationIDFrom(r.Context()))
}

func (h *Handler) handleKeyRotate(w http.ResponseWriter, r *http.Request) {
	h.writeErrorWithRequest(w, r, http.StatusNotImplemented, "IDENTITY_INTERNAL", "key rotation not yet implemented", nil)
}

func (h *Handler) handleIdentityRecover(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.FeatureRecovery {
		h.writeErrorWithRequest(w, r, http.StatusForbidden, "IDENTITY_AUTHZ", "recovery disabled", nil)
		return
	}
	h.writeErrorWithRequest(w, r, http.StatusNotImplemented, "IDENTITY_INTERNAL", "recovery not yet implemented", nil)
}

func (h *Handler) writeSuccess(w http.ResponseWriter, status int, data any, meta any, r *http.Request) []byte {
	env := responseEnvelope{Data: data, Meta: meta}
	payload := mustJSON(env)
	w.WriteHeader(status)
	if _, err := w.Write(payload); err != nil {
		h.logger.Warn("write success failed", "error", err, "correlationId", correlationIDFrom(r.Context()))
	}
	return payload
}

func (h *Handler) writeErrorWithRequest(w http.ResponseWriter, r *http.Request, status int, code, message string, details any) {
	h.writeError(w, status, code, message, correlationIDFrom(r.Context()), details)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, message, correlationID string, details any) {
	env := responseEnvelope{Error: &errorEnvelope{Code: code, Message: message, Details: details, CorrelationID: correlationID}}
	payload := mustJSON(env)
	w.WriteHeader(status)
	if _, err := w.Write(payload); err != nil {
		h.logger.Warn("write error failed", "error", err, "correlationId", correlationID)
	}
}

func mustJSON(v any) []byte {
	payload, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return payload
}

func decodeMultibase(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "z") {
		return nil, fmt.Errorf("unsupported multibase prefix")
	}
	return base58.Decode(value[1:])
}

// generateNonce creates a cryptographically secure random nonce value
// Uses 32 bytes of randomness and encodes it as base64 for safe transport
func generateNonce() string {
	buf := make([]byte, 32) // 256 bits of entropy
	if _, err := rand.Read(buf); err != nil {
		panic(err) // Critical failure if we can't generate randomness
	}
	// Encode as base64 URL-safe string (no padding) for compatibility
	return base64.RawURLEncoding.EncodeToString(buf)
}

func generateETag(body []byte) string {
	return fmt.Sprintf("W/\"%x\"", len(body))
}

func correlationIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(contextKeyCorrelationID).(string); ok {
		return v
	}
	return ""
}
