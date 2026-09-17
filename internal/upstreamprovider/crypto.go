package upstreamprovider

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

const (
	stateLen        = 32
	nonceLen        = 32
	pkceVerifierLen = 32
)

// cryptoProvider holds the entropy source for cryptographic operations.
type cryptoProvider struct {
	rand io.Reader
}

// newCryptoProvider creates a provider with the given entropy source.
// Production callers should pass crypto/rand.Reader.
func newCryptoProvider(r io.Reader) *cryptoProvider {
	return &cryptoProvider{rand: r}
}

func (p *cryptoProvider) randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(p.rand, b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateState returns a cryptographically random state parameter.
func (p *cryptoProvider) GenerateState() (string, error) {
	b, err := p.randomBytes(stateLen)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateNonce returns a cryptographically random nonce.
func (p *cryptoProvider) GenerateNonce() (string, error) {
	b, err := p.randomBytes(nonceLen)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GeneratePKCEVerifier returns a PKCE code_verifier and its S256 code_challenge.
func (p *cryptoProvider) GeneratePKCEVerifier() (verifier, challenge string, err error) {
	b, err := p.randomBytes(pkceVerifierLen)
	if err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	digest := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(digest[:])
	return verifier, challenge, nil
}

// DigestSHA256 returns the base64url-encoded SHA-256 digest of s.
func DigestSHA256(s string) string {
	d := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(d[:])
}

// DefaultCryptoProvider returns a provider backed by crypto/rand.
func DefaultCryptoProvider() *cryptoProvider {
	return newCryptoProvider(rand.Reader)
}
