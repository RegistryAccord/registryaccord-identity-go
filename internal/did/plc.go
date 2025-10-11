// Package did provides utilities for working with Decentralized Identifiers (DIDs).
// Currently focused on generating did:plc identifiers for the RegistryAccord identity service.
package did

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// Base32 encoding scheme used for PLC identifiers
// Uses lowercase alphabet and no padding for compact representation
var (
	encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
)

// GeneratePLC produces a new did:plc identifier composed of 24 lowercase base32 characters.
// PLC (Peer Linking Context) DIDs are used as permanent, cryptographically-generated identifiers
// for identities in the RegistryAccord system.
// 
// The function generates 16 random bytes and encodes them as 24-character base32 string.
// Returns a complete DID identifier in the format "did:plc:{24-character-id}"
func GeneratePLC() (string, error) {
	const rawLength = 16 // 128 bits of entropy for the identifier
	buf := make([]byte, rawLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err // Critical failure if we can't generate randomness
	}
	// Encode as base32 and convert to lowercase for consistency
	id := strings.ToLower(encoding.EncodeToString(buf))
	// Ensure exactly 24 characters for consistent identifier length
	if len(id) > 24 {
		id = id[:24]
	}
	return "did:plc:" + id, nil // Return full DID identifier
}
