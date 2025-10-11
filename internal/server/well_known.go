// Package server contains HTTP handlers for the identity service.
// This file implements the well-known DID document endpoint.
package server

import (
	"net/http"
)

// wellKnownHandler serves the DID document at .well-known/did.json.
// This endpoint provides a standardized way to discover the DID document
// for the service's canonical DID.
// 
// For Phase 1, this implementation returns the latest created identity.
// In a production implementation, this would likely be configurable to
// return a specific canonical DID document.
func (h *Handler) wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "IDENTITY_VALIDATION", "method not allowed", correlationIDFrom(r.Context()), nil)
		return
	}

	// Get the latest identity (simplified for Phase 1)
	// In a real implementation, this would likely query for a specific
	// canonical DID rather than just returning the latest created identity
	identities, err := h.store.ListOperations(r.Context(), "")
	if err != nil || len(identities) == 0 {
		h.writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND", "no identities found", correlationIDFrom(r.Context()), nil)
		return
	}

	// Use the DID from the first operation (latest created in this simplified implementation)
	latestDID := identities[0].DID
	// Retrieve the full identity record
	identity, err := h.store.GetIdentity(r.Context(), latestDID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "IDENTITY_INTERNAL", "failed to get identity", correlationIDFrom(r.Context()), nil)
		return
	}

	// Return the DID document in the response
	h.writeSuccess(w, http.StatusOK, map[string]any{
		"document": identity.Document, // The DID Document for the canonical identity
	}, nil, r)
}
