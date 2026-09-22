package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDPoPTokenMalformedProofError(t *testing.T) {
	t.Parallel()
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	for _, tc := range []struct {
		name   string
		proofs []string
	}{
		{"empty", []string{""}},
		{"malformed", []string{"not-a-proof"}},
		{"duplicate", []string{"first", "second"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.SetBasicAuth(testClientID, testClientSecret)
			r.Header["Dpop"] = tc.proofs
			w := httptest.NewRecorder()
			server.TokenHandler().ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || tokenError(t, w) != "invalid_dpop_proof" {
				t.Fatalf("status=%d error=%q", w.Code, tokenError(t, w))
			}
			if w.Header().Get("DPoP-Nonce") != "" || strings.Contains(w.Body.String(), "not-a-proof") {
				t.Fatal("invalid proof response exposed proof material or issued nonce")
			}
		})
	}
}
