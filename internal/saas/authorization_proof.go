package saas

import (
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/oauth2"
)

// Raw proofs are transient protocol values, not persisted request fields or
// API response DTOs. Their delivery/storage at the browser boundary is separate.
type authorizationProof struct {
	state    string
	verifier string
}

func (authorizationProof) String() string   { return "[redacted authorization proof]" }
func (authorizationProof) GoString() string { return "[redacted authorization proof]" }

func newAuthorizationProof() authorizationProof {
	// GenerateVerifier already implements RFC 7636's 32-octet random value.
	return authorizationProof{state: oauth2.GenerateVerifier(), verifier: oauth2.GenerateVerifier()}
}

func authorizationDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
