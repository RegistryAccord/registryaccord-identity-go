// Package server contains HTTP handlers for the identity service.
// This file implements key rotation functionality for identities.
package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/model"
	"github.com/mr-tron/base58"
)

// keyRotateHandler rotates the identity's key material.
// This endpoint allows an identity owner to generate new cryptographic keys
// for their DID, maintaining security through regular key rotation.
// 
// The process:
// 1. Validates the request and verifies ownership via signature
// 2. Generates a new Ed25519 key pair
// 3. Updates both the internal identity record and public DID document
// 4. Logs the operation for audit purposes
func (h *Handler) keyRotateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "IDENTITY_VALIDATION", "method not allowed", correlationIDFrom(r.Context()), nil)
		return
	}

	// Parse the key rotation request
	var input struct {
		DID       string `json:"did"`       // DID requesting key rotation
		Signature string `json:"signature"` // Signature proving ownership
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.writeError(w, http.StatusBadRequest, "IDENTITY_VALIDATION", "invalid JSON body", correlationIDFrom(r.Context()), nil)
		return
	}
	
	// Log the start of key rotation process
	h.logger.Info("key rotation initiated", "did", input.DID, "correlationId", correlationIDFrom(r.Context()))

	// Retrieve the identity to be updated
	identity, err := h.store.GetIdentity(r.Context(), input.DID)
	if err != nil {
		h.logger.Warn("key rotation failed - identity not found", "did", input.DID, "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND", "identity not found", correlationIDFrom(r.Context()), nil)
		return
	}

	// Verify the request is authorized by checking the signature
	// Uses the current key to sign a challenge message
	if len(identity.Keys) == 0 {
		h.logger.Error("key rotation failed - no keys found", "did", input.DID, "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusInternalServerError, "IDENTITY_INTERNAL", "no keys found", correlationIDFrom(r.Context()), nil)
		return
	}
	currentKey := identity.Keys[0]
	// Decode the provided signature from base64
	sig, err := base64.StdEncoding.DecodeString(input.Signature)
	if err != nil {
		h.logger.Warn("key rotation failed - invalid signature format", "did", input.DID, "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusBadRequest, "IDENTITY_VALIDATION", "signature must be base64", correlationIDFrom(r.Context()), nil)
		return
	}
	// Create a challenge message that includes the DID and timestamp
	// This prevents replay attacks
	message := []byte(fmt.Sprintf("rotate-key:%s:%d", input.DID, time.Now().Unix()))
	// Verify the signature using the current key
	if !ed25519.Verify(currentKey.PublicKey, message, sig) {
		h.logger.Warn("key rotation failed - signature verification failed", "did", input.DID, "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusUnauthorized, "IDENTITY_AUTHZ", "signature verification failed", correlationIDFrom(r.Context()), nil)
		return
	}

	// Generate a new Ed25519 key pair for the identity
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.logger.Error("key rotation failed - key generation error", "did", input.DID, "error", err, "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusInternalServerError, "IDENTITY_INTERNAL", "failed to generate key", correlationIDFrom(r.Context()), nil)
		return
	}
	h.logger.Info("new key pair generated for rotation", "did", input.DID, "correlationId", correlationIDFrom(r.Context()))

	// Update the identity record with the new key material
	newKey := model.KeyMaterial{
		ID:         fmt.Sprintf("%s#keys-%d", input.DID, len(identity.Keys)+1), // Sequential key ID
		Spec:       "ed25519",                                                     // Key specification
		PublicKey:  pubKey,                                                      // Public key for verification
		PrivateKey: privKey,                                                     // Private key for signing (stored securely)
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),                       // Creation timestamp
	}
	// Append the new key to the identity's key collection
	identity.Keys = append(identity.Keys, newKey)
	// Update the last modification timestamp
	identity.UpdatedAtUTC = time.Now().UTC().Format(time.RFC3339)

	// Update the public DID document with the new verification method
	vm := model.VerificationMethod{
		ID:                 newKey.ID,                                    // Reference ID for the verification method
		Type:               "Ed25519VerificationKey2020",                // Cryptographic suite identifier
		Controller:         input.DID,                                    // DID that controls this method
		PublicKeyMultibase: "z" + base58.Encode(pubKey),                 // Public key in multibase format
	}
	// Add the new verification method to the document
	identity.Document.VerificationMethod = append(identity.Document.VerificationMethod, vm)
	// Add the new key to the authentication methods
	identity.Document.Authentication = append(identity.Document.Authentication, newKey.ID)
	// Update the document's last modification timestamp
	identity.Document.Updated = identity.UpdatedAtUTC

	// Persist the updated identity
	if err := h.store.UpdateIdentity(r.Context(), identity); err != nil {
		h.logger.Error("key rotation failed - failed to update identity", "did", input.DID, "error", err, "correlationId", correlationIDFrom(r.Context()))
		h.writeError(w, http.StatusInternalServerError, "IDENTITY_INTERNAL", "failed to update identity", correlationIDFrom(r.Context()), nil)
		return
	}
	h.logger.Info("identity updated successfully after key rotation", "did", input.DID, "newKeyId", newKey.ID, "correlationId", correlationIDFrom(r.Context()))

	// Log the key rotation operation for audit purposes
	if err := h.store.AppendOperation(r.Context(), model.OperationLogEntry{
		DID:           input.DID,                           // DID that was modified
		Operation:     model.OperationRotate,               // Type of operation
		PerformedAt:   identity.UpdatedAtUTC,              // When it occurred
		Actor:         input.DID,                           // Who performed it
		CorrelationID: correlationIDFrom(r.Context()),     // Request tracing ID
		Payload: map[string]any{
			"newKeyId": newKey.ID,                        // Details about the change
		},
	}); err != nil {
		h.logger.Warn("append operation log failed", "error", err, "did", input.DID)
	}

	// Return success response with details about the new key
	rotatedAt := time.Now().UTC().Format(time.RFC3339)
	h.writeSuccess(w, http.StatusOK, map[string]any{
		"did":      input.DID,           // DID that was rotated
		"rotatedAt": rotatedAt,          // When the rotation occurred
		"newKid":    newKey.ID,          // ID of the newly created key
	}, nil, r)
	h.logger.Info("key rotation completed successfully", "did", input.DID, "newKeyId", newKey.ID, "rotatedAt", rotatedAt, "correlationId", correlationIDFrom(r.Context()))
}
