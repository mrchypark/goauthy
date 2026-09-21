package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestManagedClientHTTPCodeRefreshSurviveMetadataChange(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	s := oauthTestServer(t, db, randomSecret(t))
	store := clients.NewStore(db, &oidc.Keyring{}) // public clients need no secret envelope
	s.store.managedClients = store
	authority := func() (string, []any) { return "1", nil }
	c, err := store.CreateWithGuard(t.Context(), clients.NewRequest{ID: "managed-public", RedirectURIs: []string{testRedirectURI}}, authority)
	if err != nil {
		t.Fatal(err)
	}
	logoutURI := "https://managed.example.test/logout"
	s.store.backChannelLogoutURI = "https://bootstrap.example.test/logout"
	policy := clients.UpdateRequest{BackchannelLogoutURI: &logoutURI, Enabled: true, RedirectURIs: c.RedirectURIs, Scopes: []string{"profile", "offline_access"}, DefaultScopes: []string{"profile", "offline_access"}, GrantTypes: []string{"authorization_code", "refresh_token"}}
	c, err = store.UpdateWithGuard(t.Context(), c.ID, c.Revision, policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	seedOAuthUser(t, db, "managed-user")
	verifier := strings.Repeat("m", 43)
	digest := sha256.Sum256([]byte(verifier))
	values := url.Values{"response_type": {"code"}, "client_id": {c.ID}, "redirect_uri": {testRedirectURI}, "state": {strings.Repeat("s", 32)}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	s.WriteAuthorization(w, httptest.NewRequest("GET", "/oidc/authorize?"+values.Encode(), nil), "managed-user", policy.Scopes)
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorize status=%d error=%s", w.Code, location.Query().Get("error"))
	}
	code := location.Query().Get("code")
	name := "Renamed before redemption"
	policy.Name = &name
	c, err = store.UpdateWithGuard(t.Context(), c.ID, c.Revision, policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	post := func(form url.Values) *httptest.ResponseRecorder {
		form.Set("client_id", c.ID)
		r := httptest.NewRequest("POST", "/oidc/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.TokenHandler().ServeHTTP(w, r)
		return w
	}
	token := decodeToken(t, post(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
	if token.RefreshToken == "" {
		t.Fatal("refresh token missing")
	}
	association, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT client_id,logout_uri FROM oidc_user_clients WHERE subject='managed-user'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(association.Rows) != 1 || association.Rows[0][0] != c.ID || association.Rows[0][1] != logoutURI {
		t.Fatalf("managed code endpoint: %+v %v", association, err)
	}
	name = "Renamed before refresh"
	c, err = store.UpdateWithGuard(t.Context(), c.ID, c.Revision, policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	refreshed := decodeToken(t, post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token.RefreshToken}}))
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Fatal("refresh failed")
	}
	// The per-request snapshot is stable even if a management update commits
	// between client authentication and a later grant load.
	ctx := context.WithValue(t.Context(), managedClientSnapshotsKey{}, make(map[string]fosite.Client))
	first, err := s.store.GetClient(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	policy.Enabled = false
	c, err = store.UpdateWithGuard(t.Context(), c.ID, c.Revision, policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.store.GetClient(ctx, c.ID)
	if err != nil || first != again {
		t.Fatal("authentication snapshot replaced")
	}
	policy.Enabled = true
	c, err = store.UpdateWithGuard(t.Context(), c.ID, c.Revision, policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	if post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed.RefreshToken}}).Code == http.StatusOK {
		t.Fatal("disabled generation revived")
	}
}

func TestManagedGroupPolicyAuthorizationAdmissionAndRaces(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"allowed", "denied", "membership race", "policy race"} {
		t.Run(mode, func(t *testing.T) {
			principal := PrincipalClaims{Groups: []string{"team/blue"}, Revision: 1}
			s := clientGroupPolicyServer(t, &principal)
			store := clients.NewStore(s.store.db, &oidc.Keyring{})
			s.store.managedClients = store
			guard := func() (string, []any) { return "1", nil }
			prefix := "team/"
			c, err := store.CreateWithGuard(t.Context(), clients.NewRequest{ID: "managed-policy", RestrictGroupPrefix: &prefix, RedirectURIs: []string{testRedirectURI}, Scopes: []string{"profile"}, DefaultScopes: []string{"profile"}}, guard)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "denied" {
				principal.Groups = []string{"other/blue"}
			}
			changed := false
			if strings.HasSuffix(mode, "race") {
				s.beforeAuthorizationIssue = func() {
					changed = true
					if mode == "membership race" {
						_, err = storage.Execute(t.Context(), s.store.db, rhiza.ExecuteRequest{RequestID: "managed-policy-membership-race", SQL: `UPDATE rbac_principal_versions SET revision=revision+1 WHERE subject='user-1'`})
					} else {
						nextPrefix := "other/"
						_, err = store.UpdateWithGuard(t.Context(), c.ID, c.Revision, clients.UpdateRequest{RestrictGroupPrefix: &nextPrefix, Enabled: true, RedirectURIs: c.RedirectURIs, Scopes: c.Scopes, DefaultScopes: c.DefaultScopes, GrantTypes: c.GrantTypes}, guard)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			digest := sha256.Sum256([]byte(strings.Repeat("p", 43)))
			values := url.Values{"response_type": {"code"}, "client_id": {c.ID}, "redirect_uri": {testRedirectURI}, "scope": {"profile"}, "state": {strings.Repeat("s", 32)}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
			w := httptest.NewRecorder()
			s.CompleteAuthorization(w, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"profile"})
			location, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "allowed" {
				if location.Query().Get("code") == "" {
					t.Fatalf("matching group denied: status=%d error=%s", w.Code, location.Query().Get("error"))
				}
			} else {
				if location.Query().Get("code") != "" {
					t.Fatal("denied authorization issued code")
				}
				assertNoAuthorizationState(t, s.store.db)
				if strings.HasSuffix(mode, "race") && !changed {
					t.Fatal("race hook not reached")
				}
			}
		})
	}
}
