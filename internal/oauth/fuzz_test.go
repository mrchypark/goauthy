package oauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzUserInfoBodyBoundary(f *testing.F) {
	for _, seed := range []struct {
		contentType string
		body        []byte
	}{
		{"application/x-www-form-urlencoded", nil},
		{"application/x-www-form-urlencoded", []byte("access_token=x")},
		{"application/json", []byte("{}")},
		{"application/x-www-form-urlencoded", make([]byte, oauthFormLimit+1)},
	} {
		f.Add(seed.contentType, seed.body)
	}
	f.Fuzz(func(t *testing.T, contentType string, body []byte) {
		if len(contentType) > 1024 || len(body) > oauthFormLimit+1 {
			return
		}
		request := httptest.NewRequest(http.MethodPost, "/oidc/userinfo", bytes.NewReader(body))
		request.Header.Set("Content-Type", contentType)
		response := httptest.NewRecorder()
		(&Server{}).UserInfoHandler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || response.Body.Len() > 1024 {
			t.Fatalf("userinfo boundary status=%d response_bytes=%d", response.Code, response.Body.Len())
		}
	})
}
