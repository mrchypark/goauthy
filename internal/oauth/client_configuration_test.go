package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/claims"
	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestClientConfigurationHandler(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	allowed := []string{"custom.read"}
	defaults := []string{"goauthy.read"}
	policyReads := 0
	server, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{"https://resource.example.test"}, OIDCConfig{
		Issuer: oidcTestIssuer, DefaultAudiences: map[string]string{testClientID: "https://resource.example.test"},
		LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		BootstrapClientScopes: func(_ context.Context, id string) (claims.ClientScopes, error) {
			policyReads++
			return claims.ClientScopes{ClientID: id, Allowed: allowed, Default: defaults}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := server.ClientConfigurationHandler()
	request := func(id, secret string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, clientConfigurationPath, nil)
		if id != "" {
			r.SetBasicAuth(id, secret)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct{ name, id, secret string }{
		{"missing credentials", "", ""},
		{"wrong secret", testClientID, "wrong-secret-value"},
		{"other client", "another-client", testClientSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := request(tc.id, tc.secret); got.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", got.Code, got.Body.String())
			}
		})
	}
	policyReads = 0
	if got := request(testClientID, testClientSecret); got.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", got.Code, got.Body.String())
	} else {
		if policyReads != 1 {
			t.Fatalf("bootstrap scope policy read %d times for one response", policyReads)
		}
		var body map[string]any
		if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["version"] != "goauthy.client-configuration.v1" || body["issuer"] != oidcTestIssuer || body["client_id"] != testClientID || body["client_kind"] != "bootstrap" || body["enabled"] != true || body["confidential"] != true || !reflect.DeepEqual(body["default_aud"], []any{"https://resource.example.test"}) {
			t.Fatalf("unexpected metadata: %#v", body)
		}
		for _, field := range []string{"redirect_uris", "grant_types", "scopes", "default_scopes", "audience", "default_aud"} {
			if body[field] == nil {
				t.Fatalf("%s must be an array: %#v", field, body[field])
			}
		}
		if !reflect.DeepEqual(body["default_scopes"], []any{"goauthy.read"}) {
			t.Fatalf("effective default scopes missing: %#v", body["default_scopes"])
		}
		if strings.Contains(got.Body.String(), testClientSecret) || strings.Contains(got.Body.String(), "secret_hash") || got.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unsafe response headers/body: headers=%v body=%s", got.Header(), got.Body.String())
		}
		digest := sha256.Sum256(got.Body.Bytes())
		if want := `"sha256:` + hex.EncodeToString(digest[:]) + `"`; got.Header().Get("ETag") != want {
			t.Fatalf("ETag=%q want %q", got.Header().Get("ETag"), want)
		}
		if got.Header().Get("ETag") != request(testClientID, testClientSecret).Header().Get("ETag") {
			t.Fatal("ETag changed for unchanged configuration")
		}
	}
	changed := request(testClientID, testClientSecret)
	oldETag := changed.Header().Get("ETag")
	allowed = []string{"custom.read", "custom.write"}
	changed = request(testClientID, testClientSecret)
	if changed.Code != http.StatusOK || changed.Header().Get("ETag") == oldETag {
		t.Fatalf("configuration change did not change ETag: status=%d etag=%q", changed.Code, changed.Header().Get("ETag"))
	}
	server.defaultAudiences[testClientID] = ""
	withoutDefault := request(testClientID, testClientSecret)
	var noDefault map[string]any
	if withoutDefault.Code != http.StatusOK || json.Unmarshal(withoutDefault.Body.Bytes(), &noDefault) != nil || !reflect.DeepEqual(noDefault["default_aud"], []any{}) {
		t.Fatalf("unset default audience was not an empty array: status=%d body=%s", withoutDefault.Code, withoutDefault.Body.String())
	}
	for _, tc := range []struct {
		method, body string
		want         int
	}{
		{http.MethodPost, "", http.StatusMethodNotAllowed},
		{http.MethodGet, "unexpected", http.StatusBadRequest},
		{http.MethodGet, "", http.StatusBadRequest},
	} {
		r := httptest.NewRequest(tc.method, clientConfigurationPath, strings.NewReader(tc.body))
		if tc.method == http.MethodGet && tc.body == "" && tc.want == http.StatusBadRequest {
			r.URL.RawQuery = "unexpected=1"
		}
		r.SetBasicAuth(testClientID, testClientSecret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s body %q: status=%d want=%d", tc.method, tc.body, w.Code, tc.want)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s response missing no-store: %v", tc.method, w.Header())
		}
	}
	duplicate := httptest.NewRequest(http.MethodGet, clientConfigurationPath, nil)
	duplicate.SetBasicAuth(testClientID, testClientSecret)
	duplicate.Header.Add("Authorization", "Basic another-credential")
	denied := httptest.NewRecorder()
	h.ServeHTTP(denied, duplicate)
	if denied.Code != http.StatusUnauthorized || denied.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("duplicate Authorization accepted or cacheable: status=%d headers=%v", denied.Code, denied.Header())
	}
	for _, authorization := range []string{"Bearer fixture-token", "Basic invalid"} {
		r := httptest.NewRequest(http.MethodGet, clientConfigurationPath, nil)
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("non-Basic or malformed authentication accepted or cacheable")
		}
	}
}
