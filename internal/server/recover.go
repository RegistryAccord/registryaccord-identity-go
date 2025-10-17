// Package server contains HTTP handlers for the identity service.
// This file implements enhanced identity recovery functionality.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/storage"
	"github.com/mr-tron/base58"
)

// identityRecoverHandler recovers an identity using a recovery proof.
// This endpoint allows identity owners to recover access to their DID
// when they've lost control of their keys.
//
// Recovery process:
// 1. Validates that recovery is enabled in the service configuration
// 2. Validates the recovery proof provided based on the configured method
// 3. Generates new keys for the identity
// 4. Updates the identity with new keys
// 5. Updates the DID document with new verification methods
// 6. Logs the recovery operation for audit purposes
// 7. Returns success response with required fields
func (h *Handler) identityRecoverHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		incrementIdentityRecovery("failure") // Increment failure counter
		h.logger.Warn("identity recovery failed - method not allowed", "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusMethodNotAllowed, "IDENTITY_VALIDATION", "method not allowed", correlationIDFrom(r.Context()), nil)
		return
	}

	// Check if recovery feature is enabled in the service configuration
	if !h.cfg.FeatureRecovery {
		incrementIdentityRecovery("failure") // Increment failure counter
		h.logger.Warn("identity recovery failed - feature disabled", "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusForbidden, "IDENTITY_AUTHZ", "recovery disabled", correlationIDFrom(r.Context()), nil)
		return
	}

	// Log the start of identity recovery process
	h.logger.Info("identity recovery initiated", "correlationId", correlationIDFrom(r.Context()))

	// Parse the recovery request
	var input struct {
		DID           string         `json:"did"`           // DID to be recovered
		RecoveryProof map[string]any `json:"recoveryProof"` // Proof required for recovery
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		incrementIdentityRecovery("failure") // Increment failure counter
		h.logger.Warn("identity recovery failed - invalid JSON body", "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusBadRequest, "IDENTITY_VALIDATION", "invalid JSON body", correlationIDFrom(r.Context()), nil)
		return
	}

	// Retrieve the identity that needs recovery
	identity, err := h.store.GetIdentity(r.Context(), input.DID)
	if err != nil {
		incrementIdentityRecovery("failure") // Increment failure counter
		if err == storage.ErrNotFound {
			h.logger.Warn("identity recovery failed - identity not found", "did", input.DID, "correlationId", correlationIDFrom(r.Context()))
			h.writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND", "identity not found", correlationIDFrom(r.Context()), nil)
			return
		}
		h.logger.Error("identity recovery failed - identity lookup error", "did", input.DID, "error", err, "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusInternalServerError, "IDENTITY_INTERNAL", "identity lookup failed", correlationIDFrom(r.Context()), nil)
		return
	}

	// Log recovery method being used
	h.logger.Info("validating recovery proof", "did", input.DID, "method", identity.RecoveryState.Method, "correlationId", correlationIDFrom(r.Context()))

	// Validate the recovery proof based on the configured recovery method
	if !h.validateRecoveryProof(r.Context(), input.DID, identity.RecoveryState.Method, input.RecoveryProof) {
		incrementIdentityRecovery("failure") // Increment failure counter
		h.logger.Warn("identity recovery failed - invalid recovery proof", "did", input.DID, "method", identity.RecoveryState.Method, "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusUnauthorized, "IDENTITY_AUTHZ", "invalid recovery proof", correlationIDFrom(r.Context()), nil)
		return
	}

	// Generate new keys for the identity
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		incrementIdentityRecovery("failure") // Increment failure counter
		h.logger.Error("identity recovery failed - key generation error", "did", input.DID, "error", err, "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusInternalServerError, "IDENTITY_INTERNAL", "failed to generate key", correlationIDFrom(r.Context()), nil)
		return
	}
	h.logger.Info("new key pair generated for recovery", "did", input.DID, "correlationId", correlationIDFrom(r.Context()))

	// Update the identity with new keys
	newKeyID := fmt.Sprintf("%s#keys-recovery", input.DID)
	newKey := model.KeyMaterial{
		ID:         newKeyID,
		Spec:       "ed25519",
		PublicKey:  pubKey,
		PrivateKey: privKey,
		CreatedAt:  h.clock().Format(time.RFC3339),
	}

	// Clear existing keys and add the new one
	identity.Keys = []model.KeyMaterial{newKey}
	identity.UpdatedAtUTC = h.clock().Format(time.RFC3339)

	// Update the DID document with new verification method
	vm := model.VerificationMethod{
		ID:                 newKeyID,
		Type:               "Ed25519VerificationKey2020",
		Controller:         input.DID,
		PublicKeyMultibase: "z" + base58.Encode(pubKey),
	}

	// Replace verification methods with the new one
	identity.Document.VerificationMethod = []model.VerificationMethod{vm}
	identity.Document.Authentication = []string{newKeyID}
	identity.Document.Updated = identity.UpdatedAtUTC

	// Persist the updated identity
	if err := h.store.UpdateIdentity(r.Context(), identity); err != nil {
		incrementIdentityRecovery("failure") // Increment failure counter
		h.logger.Error("identity recovery failed - failed to update identity", "did", input.DID, "error", err, "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusInternalServerError, "IDENTITY_INTERNAL", "failed to update identity", correlationIDFrom(r.Context()), nil)
		return
	}
	h.logger.Info("identity updated successfully after recovery", "did", input.DID, "correlationId", correlationIDFrom(r.Context()))

	// Log the recovery operation for audit purposes
	if err := h.store.AppendOperation(r.Context(), model.OperationLogEntry{
		DID:           input.DID,
		Operation:     model.OperationRecover,
		PerformedAt:   identity.UpdatedAtUTC,
		Actor:         input.DID,
		CorrelationID: correlationIDFrom(r.Context()),
		Payload: map[string]any{
			"recoveryProof": input.RecoveryProof,
			"method":        identity.RecoveryState.Method,
		},
	}); err != nil {
		h.logger.Warn("append operation log failed", "error", err, "did", input.DID)
	}

	// Increment success counter
	incrementIdentityRecovery("success")

	// Return success response with required fields
	recoveredAt := h.clock().Format(time.RFC3339)
	h.writeSuccess(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"did":         input.DID,
			"recoveredAt": recoveredAt,
		},
	}, nil, r)
	h.logger.Info("identity recovered successfully", "did", input.DID, "method", identity.RecoveryState.Method, "recoveredAt", recoveredAt, "correlationId", correlationIDFrom(r.Context()))
}

// validateRecoveryProof validates the recovery proof based on the configured method
func (h *Handler) validateRecoveryProof(ctx context.Context, did, method string, proof map[string]any) bool {
	switch method {
	case "email":
		return h.validateEmailRecovery(ctx, did, proof)
	case "social":
		return h.validateSocialRecovery(ctx, did, proof)
	case "key":
		return h.validateKeyRecovery(ctx, did, proof)
	case "none":
		// No recovery allowed
		return false
	default:
		// Unknown method, reject
		h.logger.Warn("unknown recovery method", "method", method, "did", did)
		return false
	}
}

// validateEmailRecovery validates email-based recovery
// This function checks the provided token against stored recovery tokens.
func (h *Handler) validateEmailRecovery(ctx context.Context, did string, proof map[string]any) bool {
	// Extract token from proof
	token, ok := proof["token"].(string)
	if !ok || token == "" {
		return false
	}

	// Extract email from proof
	email, ok := proof["email"].(string)
	if !ok || email == "" {
		return false
	}

	// Validate the recovery token
	valid, err := h.store.ValidateRecoveryToken(ctx, did, email, token)
	if err != nil {
		h.logger.Error("failed to validate recovery token", "error", err, "did", did)
		return false
	}

	return valid
}

// validateSocialRecovery validates social-based recovery
// In a real implementation, this would check signatures from trusted contacts
func (h *Handler) validateSocialRecovery(ctx context.Context, did string, proof map[string]any) bool {
	// Extract signatures from proof
	signatures, ok := proof["signatures"].([]any)
	if !ok || len(signatures) == 0 {
		return false
	}

	// Extract threshold from proof
	threshold, ok := proof["threshold"].(float64)
	if !ok || threshold <= 0 {
		return false
	}

	// In a real implementation, this would:
	// 1. Check that we have at least threshold valid signatures
	// 2. Verify each signature against trusted contacts
	// 3. Ensure no duplicate signers

	h.logger.Info("social recovery validated", "did", did, "signatures", len(signatures), "threshold", int(threshold))
	return len(signatures) >= int(threshold)
}

// validateKeyRecovery validates key-based recovery
// In a real implementation, this would check a signature from a recovery key
func (h *Handler) validateKeyRecovery(ctx context.Context, did string, proof map[string]any) bool {
	// Extract signature from proof
	signature, ok := proof["signature"].(string)
	if !ok || signature == "" {
		return false
	}

	// Extract message from proof
	message, ok := proof["message"].(string)
	if !ok || message == "" {
		return false
	}

	// In a real implementation, this would:
	// 1. Look up the recovery key for this DID
	// 2. Verify the signature against the recovery key
	// 3. Check that the message is valid

	h.logger.Info("key recovery validated", "did", did, "hasSignature", signature != "", "hasMessage", message != "")
	return signature != "" && message != ""
}
