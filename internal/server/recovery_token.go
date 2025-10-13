// Package server contains HTTP handlers for the identity service.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/storage"
)

// generateRecoveryToken creates a cryptographically secure random token for identity recovery.
func generateRecoveryToken() string {
	// Generate 32 random bytes (256 bits of entropy)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(err) // This should never happen
	}
	// Encode as hex string for easy storage and transmission
	return hex.EncodeToString(bytes)
}

// requestEmailRecovery generates and stores a recovery token for email-based recovery.
// In a real implementation, this would also send an email to the user with the token.
func (h *Handler) requestEmailRecovery(ctx context.Context, did, email string) error {
	// Generate a recovery token
	token := generateRecoveryToken()
	
	// Set expiration time (e.g., 1 hour)
	expires := h.clock().Add(1 * time.Hour)
	
	// Create and store the recovery token
	recoveryToken := storage.RecoveryToken{
		DID:       did,
		Token:     token,
		Email:     email,
		ExpiresAt: expires,
		Used:      false,
	}
	
	// Store the recovery token
	if err := h.store.StoreRecoveryToken(ctx, recoveryToken); err != nil {
		return fmt.Errorf("failed to store recovery token: %w", err)
	}
	
	// In a real implementation, we would send an email to the user with the token
	// For now, we'll just log it
	h.logger.Info("recovery token generated", "did", did, "email", email, "token", token)
	
	return nil
}

