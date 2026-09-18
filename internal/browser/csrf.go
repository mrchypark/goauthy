package browser

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const csrfDomain = "goauthy/browser/csrf/v1"

var ErrInvalidCSRFToken = errors.New("invalid browser CSRF token")

// DeriveCSRFToken deterministically binds a CSRF token to a raw browser
// session token. The raw session token is already a 256-bit secret; it is
// never persisted or returned by validation.
func DeriveCSRFToken(sessionToken string) (string, error) {
	raw, err := canonicalSessionToken(sessionToken)
	if err != nil {
		return "", ErrInvalidCSRFToken
	}
	mac := hmac.New(sha256.New, raw)
	_, _ = mac.Write([]byte(csrfDomain))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// ValidateCSRFToken checks the canonical encoding and compares the derived
// value in constant time. It intentionally returns one error for every
// malformed, missing, or mismatched token.
func ValidateCSRFToken(sessionToken, csrfToken string) error {
	if len(csrfToken) > base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return ErrInvalidCSRFToken
	}
	expected, err := DeriveCSRFToken(sessionToken)
	if err != nil {
		return ErrInvalidCSRFToken
	}
	decoded, err := base64.RawURLEncoding.DecodeString(csrfToken)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != csrfToken {
		return ErrInvalidCSRFToken
	}
	expectedBytes, err := base64.RawURLEncoding.DecodeString(expected)
	if err != nil || !hmac.Equal(expectedBytes, decoded) {
		return ErrInvalidCSRFToken
	}
	return nil
}

func canonicalSessionToken(token string) ([]byte, error) {
	if len(token) > base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return nil, ErrInvalidCSRFToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != sha256.Size || base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, ErrInvalidCSRFToken
	}
	return raw, nil
}
