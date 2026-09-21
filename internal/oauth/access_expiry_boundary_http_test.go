package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestAccessTokenExpiryBoundaryOverRealHTTP(t *testing.T) {
	t.Parallel()
	const verifier = "expiry-boundary-verifier-012345678901234567890123"
	var clock atomic.Int64
	key := oidcTestKey(t)
	db := oauthTestDB(t)
	seedOAuthUser(t, db, "user-1")
	identities, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil },
		ValidateSubject: identities.ValidateSubject,
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionID := oidcTestSessionID(42)
	ensureOIDCTestBrowserSession(t, server, sessionID)
	clockNow := func() time.Time {
		if frozen := clock.Load(); frozen != 0 {
			return time.Unix(0, frozen).UTC()
		}
		// Fosite owns issuance time; freeze only after its token is issued.
		return time.Now().UTC()
	}
	server.store.now = clockNow
	strategy := server.accessTokens.(*signedAccessTokenStrategy)
	strategy.now = clockNow
	code := issueOIDCCode(t, server, verifier, "expiry-boundary", clockNow(), sessionID)

	mux := http.NewServeMux()
	mux.Handle("/oidc/token", server.TokenHandler())
	mux.Handle("/oidc/introspect", server.IntrospectionHandler())
	mux.Handle("/oidc/userinfo", server.UserInfoHandler())
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)

	tokenResponse := postRealOAuthForm(t, httpServer.Client(), httpServer.URL+"/oidc/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}, testClientID, testClientSecret)
	if tokenResponse.StatusCode != http.StatusOK {
		t.Fatalf("token status=%d", tokenResponse.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(tokenResponse.Body), &token); err != nil || token.AccessToken == "" {
		t.Fatalf("token response invalid: err=%v", err)
	}
	claims, err := strategy.verify(context.Background(), token.AccessToken)
	if err != nil || claims.Issuer != oidcTestIssuer || claims.AuthorizedParty != testClientID || len(claims.Audience) != 1 || claims.Audience[0] != testClientID || claims.Subject != "user-1" {
		t.Fatalf("access claims=%#v err=%v", claims, err)
	}

	// Fosite's issuance helpers still use wall time. Advance only the existing
	// consumption clocks to the actual signed expiry; never sleep for expiry.
	clock.Store(claims.ExpiresAt.Add(-time.Nanosecond).UnixNano())
	active := postRealOAuthForm(t, httpServer.Client(), httpServer.URL+"/oidc/introspect", url.Values{"token": {token.AccessToken}}, testClientID, testClientSecret)
	if active.StatusCode != http.StatusOK || !strings.Contains(active.Body, `"active":true`) {
		t.Fatalf("before-expiry introspection status=%d body=%s", active.StatusCode, active.Body)
	}
	userinfo := getRealUserInfo(t, httpServer.Client(), httpServer.URL+"/oidc/userinfo", token.AccessToken)
	if userinfo.StatusCode != http.StatusOK || !strings.Contains(userinfo.Body, `"sub":"user-1"`) {
		t.Fatalf("before-expiry userinfo status=%d body=%s", userinfo.StatusCode, userinfo.Body)
	}

	clock.Store(claims.ExpiresAt.UnixNano())
	expired := postRealOAuthForm(t, httpServer.Client(), httpServer.URL+"/oidc/introspect", url.Values{"token": {token.AccessToken}}, testClientID, testClientSecret)
	if expired.StatusCode != http.StatusOK || expired.Body != `{"active":false}`+"\n" {
		t.Fatalf("at-expiry introspection status=%d body=%s", expired.StatusCode, expired.Body)
	}
	userinfo = getRealUserInfo(t, httpServer.Client(), httpServer.URL+"/oidc/userinfo", token.AccessToken)
	if userinfo.StatusCode != http.StatusUnauthorized {
		t.Fatalf("at-expiry userinfo status=%d body=%s", userinfo.StatusCode, userinfo.Body)
	}
}

type realHTTPResponse struct {
	StatusCode int
	Body       string
}

func postRealOAuthForm(t *testing.T, client *http.Client, endpoint string, values url.Values, clientID, clientSecret string) realHTTPResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<10))
	if err != nil {
		t.Fatal(err)
	}
	return realHTTPResponse{StatusCode: res.StatusCode, Body: string(body)}
}

func getRealUserInfo(t *testing.T, client *http.Client, endpoint, token string) realHTTPResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<10))
	if err != nil {
		t.Fatal(err)
	}
	return realHTTPResponse{StatusCode: res.StatusCode, Body: string(body)}
}
