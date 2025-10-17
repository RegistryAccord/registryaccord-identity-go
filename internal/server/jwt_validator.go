// Package server contains HTTP handlers for the identity service.
// This file provides JWT validation functionality.
package server

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/storage"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

// JWTValidator provides methods to validate JWT tokens against the service's JWKS
type JWTValidator struct {
	store storage.ExtendedStore
}

// NewJWTValidator creates a new JWTValidator instance
func NewJWTValidator(store storage.ExtendedStore) *JWTValidator {
	return &JWTValidator{store: store}
}

// ValidateToken validates a JWT token with fail-closed semantics
// It checks iss, aud, alg, and kid claims and verifies the signature
func (v *JWTValidator) ValidateToken(ctx context.Context, tokenString string, expectedAudience string) (*jwtlib.Token, error) {
	// Parse the token, but don't validate claims yet
	token, err := jwtlib.Parse(tokenString, func(token *jwtlib.Token) (interface{}, error) {
		// Check algorithm
		if token.Method != jwtlib.SigningMethodEdDSA {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid header")
		}

		// Look up the key in storage
		key, err := v.store.GetSigningKeyByID(ctx, kid)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve key with kid %s: %w", kid, err)
		}

		// Check if key is retired
		if !key.RetiredAt.IsZero() && key.RetiredAt.Before(time.Now().UTC()) {
			return nil, fmt.Errorf("key with kid %s is retired", kid)
		}

		// Check if key is expired
		if !key.ExpiresAt.IsZero() && key.ExpiresAt.Before(time.Now().UTC()) {
			return nil, fmt.Errorf("key with kid %s is expired", kid)
		}

		// Check if key is activated
		if key.ActivatedAt.After(time.Now().UTC()) {
			return nil, fmt.Errorf("key with kid %s is not yet active", kid)
		}

		// Return the public key for verification
		return ed25519.PublicKey(key.PublicKey), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Validate claims
	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse claims")
	}

	// Validate issuer
	if iss, ok := claims["iss"].(string); !ok || iss == "" {
		return nil, fmt.Errorf("missing or invalid iss claim")
	}

	// Validate audience
	aud, ok := claims["aud"].(string)
	if !ok || aud == "" {
		return nil, fmt.Errorf("missing or invalid aud claim")
	}
	if aud != expectedAudience {
		return nil, fmt.Errorf("aud claim mismatch: expected %s, got %s", expectedAudience, aud)
	}

	// Validate subject
	if sub, ok := claims["sub"].(string); !ok || sub == "" {
		return nil, fmt.Errorf("missing or invalid sub claim")
	}

	// Validate issued at
	if iat, ok := claims["iat"].(float64); !ok || iat == 0 {
		return nil, fmt.Errorf("missing or invalid iat claim")
	} else if time.Unix(int64(iat), 0).After(time.Now().Add(5 * time.Minute)) {
		return nil, fmt.Errorf("token issued in the future")
	}

	// Validate expiration
	if exp, ok := claims["exp"].(float64); !ok || exp == 0 {
		return nil, fmt.Errorf("missing or invalid exp claim")
	} else if time.Unix(int64(exp), 0).Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	// Validate JWT ID
	if jti, ok := claims["jti"].(string); !ok || jti == "" {
		return nil, fmt.Errorf("missing or invalid jti claim")
	}

	return token, nil
}
