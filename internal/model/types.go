// Package model defines internal and external data shapes for the identity
// service. Internal types are used by storage and handlers, while DTOs are
// serialized on the wire.
package model

import "time"

// Identity contains the authoritative DID Document along with metadata used for
// persistence. The DID Document MUST always be a valid did:plc document for
// Phase 1.
type Identity struct {
	DID           string         // The DID identifier for this identity
	Document      DIDDocument    // The DID Document conforming to W3C DID Core specification
	Keys          []KeyMaterial  // Cryptographic keys associated with this identity
	CreatedAtUTC  string         // Creation timestamp in RFC3339 format
	UpdatedAtUTC  string         // Last update timestamp in RFC3339 format
	RecoveryState RecoveryPolicy // Recovery configuration for this identity
}

// DIDDocument models the JSON-LD DID representation returned from resolve
// handlers. It intentionally maps to flattened Go structs to simplify
// marshaling.
type DIDDocument struct {
	Context            []string             `json:"@context"`            // JSON-LD context for the document
	ID                 string               `json:"id"`                  // The DID identifier
	AlsoKnownAs        []string             `json:"alsoKnownAs,omitempty"` // Alternative identifiers for the DID subject
	VerificationMethod []VerificationMethod `json:"verificationMethod"`  // Public keys available for cryptographic operations
	Authentication     []string             `json:"authentication"`      // References to verification methods for authentication
	AssertionMethod    []string             `json:"assertionMethod,omitempty"` // References to verification methods for assertions
	Service            []DIDService         `json:"service,omitempty"`   // Service endpoints associated with the DID
	Created            string               `json:"created"`             // Creation timestamp in RFC3339 format
	Updated            string               `json:"updated"`             // Last update timestamp in RFC3339 format
	VersionID          string               `json:"versionId"`           // Version identifier for the document
}

// VerificationMethod defines a signing or key agreement capability attached to
// the DID. Phase 1 only requires Ed25519 verification keys.
type VerificationMethod struct {
	ID                 string `json:"id"`                  // Unique identifier for this verification method
	Type               string `json:"type"`                // Cryptographic suite type (e.g., Ed25519VerificationKey2020)
	Controller         string `json:"controller"`          // DID that controls this verification method
	PublicKeyMultibase string `json:"publicKeyMultibase"`  // Public key encoded using multibase format
}

// DIDService represents optional service endpoints embedded in the DID
// document. Phase 1 exposes none by default, but the structure enables future
// expansion without breaking consumers.
type DIDService struct {
	ID              string            `json:"id"`               // Unique identifier for this service
	Type            string            `json:"type"`             // Service type identifier
	ServiceEndpoint map[string]string `json:"serviceEndpoint"`  // Service endpoint details as key-value pairs
}

// RecoveryPolicy captures recovery configuration applied to the DID.
type RecoveryPolicy struct {
	Method string `json:"method"`  // Recovery method identifier (e.g., "social", "key")
}

// OperationType distinguishes log entry variants.
type OperationType string

// Supported operation types for the identity mutation log
const (
	OperationCreate  OperationType = "create"  // Initial identity creation
	OperationRotate  OperationType = "rotate"  // Key rotation operation
	OperationRecover OperationType = "recover" // Identity recovery operation
)

// OperationLogEntry is the append-only mutation log for a DID. Entries MUST be
// appended in strictly increasing CreatedAt order.
type OperationLogEntry struct {
	DID           string         `json:"did"`           // The DID this operation applies to
	Operation     OperationType  `json:"operation"`     // Type of operation performed
	PerformedAt   string         `json:"performedAt"`   // Timestamp when operation was performed (RFC3339)
	Actor         string         `json:"actor"`         // Entity that performed the operation
	CorrelationID string         `json:"correlationId"` // Request correlation identifier for tracing
	Payload       map[string]any `json:"payload"`       // Operation-specific data
}

// KeyMaterial represents a verification key associated with the DID.
type KeyMaterial struct {
	ID         string // Identifier matching the verification method ID
	Spec       string // Key specification (e.g., "ed25519")
	PublicKey  []byte // Public key bytes for verification
	PrivateKey []byte // Private key bytes for signing (stored securely)
	CreatedAt  string // Creation timestamp in RFC3339 format
}

// Nonce represents a single use challenge for session issuance.
type Nonce struct {
	Value     string    // Cryptographically secure random value
	DID       string    // DID that requested this nonce
	Audience  string    // Intended audience for the session
	ExpiresAt time.Time // Expiration timestamp for this nonce
}

// SessionToken details returned after successful nonce validation.
type SessionToken struct {
	Token    string    // JWT token string for authenticated sessions
	Subject  string    // Authenticated DID (from validated nonce)
	Audience string    // Intended audience for the token
	Expires  time.Time // Expiration timestamp for the token
}

// JSONWebKey represents a key in JWKS format
type JSONWebKey struct {
	Kty string `json:"kty"` // Key type (e.g., "OKP" for Ed25519)
	Kid string `json:"kid"` // Key ID
	Alg string `json:"alg"` // Algorithm (e.g., "EdDSA")
	Use string `json:"use"` // Public key use (e.g., "sig")
	Crv string `json:"crv"` // Curve name (e.g., "Ed25519")
	X   string `json:"x"`   // Base64URL-encoded public key
}

// JSONWebKeySet represents a JWKS response
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}
