package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

func TestManagedClientResourceAudienceUseRefreshAndRemoval(t *testing.T) {
	db := oauthTestDB(t)
	s := resourceAuthorizationServer(t, db, randomSecret(t))
	store := clients.NewStore(db, &oidc.Keyring{})
	s.store.managedClients = store
	guard := func() (string, []any) { return "1", nil }
	c, err := store.CreateWithGuard(t.Context(), clients.NewRequest{
		ID: "managed-resource", RedirectURIs: []string{testRedirectURI},
		Audiences: []string{resourceAuthorizationAudience},
		Scopes:    []string{"goauthy.connections.use", "offline_access"}, DefaultScopes: []string{"goauthy.connections.use"},
		GrantTypes: []string{"authorization_code", "refresh_token"},
	}, guard)
	if err != nil {
		t.Fatal(err)
	}
	seedOAuthUser(t, db, "managed-resource-user")
	verifier := strings.Repeat("m", 43)
	form := url.Values{"response_type": {"code"}, "client_id": {c.ID}, "redirect_uri": {testRedirectURI}, "state": {strings.Repeat("s", 32)}, "code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"}, "scope": {"goauthy.connections.use offline_access"}, "resource": {resourceAuthorizationAudience}}
	authorize := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+form.Encode(), nil)
	}
	// Globally allowed is insufficient: this resource is not registered for c.
	form.Set("resource", wrongResourceAuthorizationAudience)
	if _, err := s.ValidateAuthorizationRequest(authorize()); err == nil {
		t.Fatal("unregistered client resource accepted")
	}
	form.Set("resource", resourceAuthorizationAudience)
	w := httptest.NewRecorder()
	s.WriteAuthorization(w, authorize(), "managed-resource-user", []string{"goauthy.connections.use", "offline_access"})
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization status=%d", w.Code)
	}
	post := func(values url.Values) *httptest.ResponseRecorder {
		values.Set("client_id", c.ID)
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.TokenHandler().ServeHTTP(w, r)
		return w
	}
	token := decodeToken(t, post(url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
	refreshed := decodeToken(t, post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token.RefreshToken}}))
	r := httptest.NewRequest(http.MethodPost, "/use", nil)
	r.Header.Set("Authorization", "Bearer "+refreshed.AccessToken)
	owner, consumer, authority, err := s.AuthorizeConnectionUse(r, resourceAuthorizationAudience)
	if err != nil || owner != "managed-resource-user" || consumer != c.ID || authority == nil {
		t.Fatalf("managed use owner=%q consumer=%q err=%v", owner, consumer, err)
	}
	check := func(want int) {
		t.Helper()
		g, a := authority()
		q, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + g, Args: a, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(q.Rows) != want {
			t.Fatalf("use guard rows=%v err=%v", q.Rows, err)
		}
	}
	check(1)
	_, err = store.UpdateWithGuard(t.Context(), c.ID, c.Revision, clients.UpdateRequest{
		Enabled: true, RedirectURIs: c.RedirectURIs, Scopes: c.Scopes, DefaultScopes: c.DefaultScopes,
		GrantTypes: c.GrantTypes, Audiences: []string{},
	}, guard)
	if err != nil {
		t.Fatal(err)
	}
	check(0)
	if _, _, _, err := s.AuthorizeConnectionUse(r, resourceAuthorizationAudience); err == nil {
		t.Fatal("old audience token survived removal")
	}
	if post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed.RefreshToken}}).Code == http.StatusOK {
		t.Fatal("old refresh token survived audience removal")
	}
	if _, err := s.ValidateAuthorizationRequest(authorize()); err == nil {
		t.Fatal("removed audience still authorized")
	}
}
