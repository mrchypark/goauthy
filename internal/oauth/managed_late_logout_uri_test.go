package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

func TestManagedOIDCCodeLoginUsesUpdatedLogoutURIOnSIDRevocation(t *testing.T) {
	db := oauthTestDB(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) {
		return oidcTestKey(t), nil
	})
	managed := clients.NewStore(db, &oidc.Keyring{})
	server.store.managedClients = managed
	guard := func() (string, []any) { return "1", nil }
	client, err := managed.CreateWithGuard(t.Context(), clients.NewRequest{
		ID: "managed-late-uri", RedirectURIs: []string{testRedirectURI},
		Scopes:        []string{"openid", "goauthy.read", "offline_access"},
		DefaultScopes: []string{"openid", "goauthy.read", "offline_access"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
	}, guard)
	if err != nil {
		t.Fatal(err)
	}

	seedOAuthUser(t, db, "user-1")
	sid := oidcTestSessionID(52)
	ensureOIDCTestBrowserSession(t, server, sid)
	verifier := strings.Repeat("m", 43)
	values := url.Values{
		"response_type":         {"code"},
		"client_id":             {client.ID},
		"redirect_uri":          {testRedirectURI},
		"scope":                 {"openid goauthy.read offline_access"},
		"state":                 {strings.Repeat("s", 32)},
		"nonce":                 {"managed-late-uri"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"openid", "goauthy.read", "offline_access"}, oidcTestAuthTime, sid, oidcAuthMethodPwd)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("managed authorization status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}

	post := func(form url.Values) *httptest.ResponseRecorder {
		form.Set("client_id", client.ID)
		request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		result := httptest.NewRecorder()
		server.TokenHandler().ServeHTTP(result, request)
		return result
	}
	decodeOIDCToken(t, post(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {location.Query().Get("code")},
		"redirect_uri":  {testRedirectURI},
		"code_verifier": {verifier},
	}))

	association, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL:  `SELECT logout_uri FROM oidc_session_clients WHERE sid=? AND client_id=?`,
		Args: []any{sid, client.ID}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(association.Rows) != 1 || association.Rows[0][0] != "" {
		t.Fatalf("initial managed logout URI=%#v err=%v", association.Rows, err)
	}

	logoutURI := "https://managed.example.test/logout"
	client, err = managed.UpdateWithGuard(t.Context(), client.ID, client.Revision, clients.UpdateRequest{
		BackchannelLogoutURI: &logoutURI,
		Confidential:         client.Confidential,
		RedirectURIs:         client.RedirectURIs,
		Enabled:              true,
		Scopes:               client.Scopes,
		DefaultScopes:        client.DefaultScopes,
		GrantTypes:           client.GrantTypes,
		Audiences:            client.Audiences,
		DefaultAudiences:     client.DefaultAudiences,
	}, guard)
	if err != nil {
		t.Fatal(err)
	}

	if err := server.RevokeOIDCSession(t.Context(), sid); err != nil {
		t.Fatal(err)
	}
	delivery, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL:  `SELECT client_id,logout_uri FROM oidc_backchannel_deliveries WHERE sid=?`,
		Args: []any{sid}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(delivery.Rows) != 1 || delivery.Rows[0][0] != client.ID || delivery.Rows[0][1] != logoutURI {
		t.Fatalf("managed revoked-session delivery=%#v err=%v", delivery.Rows, err)
	}
}
