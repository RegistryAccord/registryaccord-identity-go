// Package model defines internal and external data shapes for the identity
// service. Internal types are used by storage and handlers, while DTOs are
// serialized on the wire.
package model

// IdentityRecord is the internal storage model aligned to
// com.registryaccord.identity#record. It stores the raw public key bytes and a
// creation timestamp in RFC3339.
type IdentityRecord struct {
	DID       string
	PublicKey []byte
	CreatedAt string // RFC3339
}

// IdentityRecordDTO is the public response DTO returned by HTTP handlers.
// PublicKey is encoded as base64 to be JSON-friendly.
type IdentityRecordDTO struct {
	DID       string `json:"did"`
	PublicKey string `json:"publicKey"` // base64
	CreatedAt string `json:"createdAt"`
}
