package browser

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

const providerBearerResource = "https://goauthy.providers.local.test"

func TestProviderBearerLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_PROVIDER_BEARER") != "1" {
		t.Skip("set GOAUTHY_E2E_PROVIDER_BEARER=1 to run provider bearer E2E")
	}
	primary, secondary, adminName, adminPassword, _ := browserE2EConfig(t)
	dcr := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	if dcr == "" {
		t.Fatal("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN is required")
	}
	rp := registerOAuth2ConsumerRPFor(t, primary, dcr, providerBearerResource+"/oauth2/callback", "provider")

	admin := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, adminCookie := loginForAuthorizationURL(t, admin, oidcAuthorizationURLForClient(t, primary, "goauthy-dev", defaultRedirectURI, pkceChallenge(verifier), "provider-bearer-admin", "provider-bearer-admin-nonce", "openid"), primary, secondary, adminName, adminPassword, "provider-bearer-admin")
	csrf, err := browsersession.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal("derive admin CSRF token")
	}
	adminHeaders := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	catalogResponse := do(t, admin, http.MethodGet, primary+"/auth/v1/scopes", nil, nil)
	var catalog []struct {
		Scope  string   `json:"scope"`
		Access []string `json:"attr_include_access"`
		ID     []string `json:"attr_include_id"`
	}
	err = json.NewDecoder(io.LimitReader(catalogResponse.Body, 64<<10)).Decode(&catalog)
	catalogResponse.Body.Close()
	if err != nil || catalogResponse.StatusCode != http.StatusOK {
		t.Fatal("read scope catalog failed")
	}
	for _, scope := range []string{"goauthy.providers.read", "goauthy.providers.write"} {
		found := false
		for _, existing := range catalog {
			if existing.Scope == scope {
				if len(existing.Access) != 0 || len(existing.ID) != 0 {
					t.Fatal("provider scope is not permission-only")
				}
				found = true
			}
		}
		if found {
			continue
		}
		body := `{"scope":"` + scope + `","attr_include_id":[],"attr_include_access":[]}`
		r := do(t, admin, http.MethodPost, primary+"/auth/v1/scopes", strings.NewReader(body), adminHeaders)
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("create provider permission scope status=%d", r.StatusCode)
		}
	}

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal("generate provider bearer fixture identifier")
	}
	issue := func(state, email, password, scope, resource string) string {
		client := newBrowserClient(t)
		v := pkceVerifier(t)
		raw := oidcAuthorizationURLForClient(t, primary, rp.ClientID, rp.RedirectURIs[0], pkceChallenge(v), state, state+"-nonce", scope)
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal("build provider bearer authorization URL")
		}
		q := u.Query()
		q.Set("resource", resource)
		u.RawQuery = q.Encode()
		code, _ := loginForAuthorizationURL(t, client, u.String(), primary, secondary, email, password, state)
		tok := exchangeCodeForClient(t, client, primary, rp.ClientID, rp.ClientSecret, rp.RedirectURIs[0], code, v)
		if tok.AccessToken == "" {
			t.Fatal("provider bearer authorization returned no access token")
		}
		return tok.AccessToken
	}

	adminToken := issue("provider-bearer-positive", adminName, adminPassword, "openid email profile goauthy.providers.read goauthy.providers.write", providerBearerResource)
	noCookie := &http.Client{}
	providerURL := primary + "/auth/v1/saas/providers"
	providerID := "provider-bearer-" + hex.EncodeToString(suffix[:])
	providerBody := `{"id":"` + providerID + `","name":"Provider Bearer E2E","kind":"api_key","enabled":true,"connector":{"id":"` + providerID + `","header":"Authorization","prefix":"Bearer ","operations":[{"id":"account","url":"https://api.example.test/account","response_fields":{"id":"string"}}]}}`
	bearer := func(method, endpoint string, body io.Reader, headers map[string]string) *http.Response {
		if headers == nil {
			headers = map[string]string{}
		}
		headers["Authorization"] = "Bearer " + adminToken
		return do(t, noCookie, method, endpoint, body, headers)
	}
	read := bearer(http.MethodGet, providerURL, nil, nil)
	read.Body.Close()
	if read.StatusCode != http.StatusOK {
		t.Fatalf("provider bearer GET status=%d", read.StatusCode)
	}
	created := bearer(http.MethodPost, providerURL, strings.NewReader(providerBody), map[string]string{"Content-Type": "application/json"})
	var provider struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(io.LimitReader(created.Body, 16<<10)).Decode(&provider)
	created.Body.Close()
	if created.StatusCode != http.StatusCreated || provider.ID == "" {
		t.Fatalf("provider bearer POST status=%d", created.StatusCode)
	}
	detail := bearer(http.MethodGet, providerURL+"/"+url.PathEscape(provider.ID), nil, nil)
	etag := detail.Header.Get("ETag")
	detail.Body.Close()
	if detail.StatusCode != http.StatusOK || etag == "" {
		t.Fatalf("provider bearer detail status=%d", detail.StatusCode)
	}
	updateBody := strings.Replace(providerBody, `"id":"`+providerID+`",`, "", 1)
	updated := bearer(http.MethodPut, providerURL+"/"+url.PathEscape(provider.ID), strings.NewReader(updateBody), map[string]string{"Content-Type": "application/json", "If-Match": etag})
	updated.Body.Close()
	if updated.StatusCode != http.StatusOK {
		t.Fatalf("provider bearer PUT status=%d", updated.StatusCode)
	}
	deleted := bearer(http.MethodDelete, providerURL+"/"+url.PathEscape(provider.ID), nil, map[string]string{"If-Match": `"2"`})
	deleted.Body.Close()
	if deleted.StatusCode != http.StatusNoContent {
		t.Fatalf("provider bearer DELETE status=%d", deleted.StatusCode)
	}

	wrongAudience := issue("provider-bearer-wrong-aud", adminName, adminPassword, "openid email profile goauthy.providers.read goauthy.providers.write", "https://other-consumer.local.test")
	missingScope := issue("provider-bearer-missing-scope", adminName, adminPassword, "openid email profile", providerBearerResource)
	assertProviderBearerUnauthorized(t, noCookie, http.MethodGet, providerURL, wrongAudience)
	assertProviderBearerUnauthorized(t, noCookie, http.MethodGet, providerURL, missingScope)

	memberEmail := "provider-bearer-member-" + hex.EncodeToString(suffix[:]) + "@goauthy.e2e"
	memberPassword := "Provider-Bearer-Member-Password-1A"
	createCatalogSessionUser(t, admin, primary, adminHeaders, memberEmail, memberPassword)
	memberToken := issue("provider-bearer-member", memberEmail, memberPassword, "openid email profile goauthy.providers.read goauthy.providers.write", providerBearerResource)
	assertProviderBearerUnauthorized(t, noCookie, http.MethodGet, providerURL, memberToken)

	revoked := issue("provider-bearer-revoked", adminName, adminPassword, "openid email profile goauthy.providers.read goauthy.providers.write", providerBearerResource)
	// Public revocation requires client authentication; use the RP credentials without logging them.
	revoke := do(t, noCookie, http.MethodPost, primary+"/oidc/revoke", strings.NewReader(url.Values{"token": {revoked}, "token_type_hint": {"access_token"}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + basicAuth(rp.ClientID, rp.ClientSecret)})
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusOK {
		t.Fatal("provider bearer revoke failed")
	}
	assertProviderBearerUnauthorized(t, noCookie, http.MethodGet, providerURL, revoked)

	cookieBearer := do(t, admin, http.MethodGet, providerURL, nil, map[string]string{"Authorization": "Bearer " + adminToken})
	cookieBearer.Body.Close()
	if cookieBearer.StatusCode != http.StatusUnauthorized {
		t.Fatalf("provider bearer cookie fallback status=%d", cookieBearer.StatusCode)
	}
}

func assertProviderBearerUnauthorized(t *testing.T, client *http.Client, method, endpoint, token string) {
	t.Helper()
	r := do(t, client, method, endpoint, nil, map[string]string{"Authorization": "Bearer " + token})
	r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("provider bearer unauthorized status=%d", r.StatusCode)
	}
}

func basicAuth(clientID, secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(clientID + ":" + secret))
}
