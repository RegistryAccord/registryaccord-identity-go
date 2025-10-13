// Package storage provides interfaces and implementations for recovery token storage.
package storage

import (
	"time"
)

// RecoveryToken represents a single-use token for identity recovery.
type RecoveryToken struct {
	DID       string    // DID this token is for
	Token     string    // Cryptographically secure random token
	Email     string    // Email address associated with this token
	ExpiresAt time.Time // Expiration timestamp for this token
	Used      bool      // Whether this token has been used
}
