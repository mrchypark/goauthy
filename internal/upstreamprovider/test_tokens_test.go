package upstreamprovider

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/mrchypark/goauthy/internal/browser"
)

// testSessionToken returns a valid 32-byte base64url browser token suitable
// for test fixtures. DigestSHA256 must NOT be used for session tokens; use
// browser.CanonicalTokenDigest instead.
func testSessionToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// testCanonicalSessionDigest returns the persisted browser-canonical digest of
// a raw session token for use in test hook fixtures.
func testCanonicalSessionDigest(t *testing.T, rawToken string) string {
	t.Helper()
	d, err := browser.CanonicalTokenDigest(rawToken)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
