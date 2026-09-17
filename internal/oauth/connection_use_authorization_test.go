package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestAuthorizeConnectionUseBindsTokenConsumerAndCurrentAuthority(t *testing.T) {
	db := oauthTestDB(t)
	s := resourceAuthorizationServer(t, db, randomSecret(t))
	token := issueResourceToken(t, s, "goauthy.connections.use")
	r := httptest.NewRequest(http.MethodPost, "/use?client_id=other-consumer", strings.NewReader(`{"client_id":"other-consumer","owner":"other-user"}`))
	r.Header.Set("Authorization", "Bearer "+token.AccessToken)
	if _, _, err := s.AuthorizeUserResource(r, "goauthy.connections.use", resourceAuthorizationAudience); err == nil {
		t.Fatal("generic metadata authorizer accepted the dedicated use scope")
	}
	owner, consumer, authority, err := s.AuthorizeConnectionUse(r, resourceAuthorizationAudience)
	if err != nil || owner != "resource-user" || consumer != testClientID || authority == nil {
		t.Fatalf("owner=%q consumer=%q authority=%v err=%v", owner, consumer, authority != nil, err)
	}
	assertGuard := func(want int) {
		t.Helper()
		g, a := authority()
		q, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + g, Args: a, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(q.Rows) != want {
			t.Fatalf("guard rows=%v want=%d err=%v", q.Rows, want, err)
		}
	}
	assertGuard(1)
	clock := s.store.now
	s.store.now = func() time.Time { return clock().Add(24 * time.Hour) }
	assertGuard(0)
	s.store.now = clock
	if err := s.store.DeleteAccessTokenSession(t.Context(), s.accessTokens.AccessTokenSignature(t.Context(), token.AccessToken)); err != nil {
		t.Fatal(err)
	}
	assertGuard(0)
	owner, consumer, authority, err = s.AuthorizeConnectionUse(r, resourceAuthorizationAudience)
	if err == nil || owner != "" || consumer != "" || authority != nil {
		t.Fatal("revoked token returned a usable consumer authority")
	}
}

func TestAuthorizeConnectionUseRejectsNonUseAndAmbiguousCredentials(t *testing.T) {
	db := oauthTestDB(t)
	s := resourceAuthorizationServer(t, db, randomSecret(t))
	use := issueResourceToken(t, s, "goauthy.connections.use")
	read := issueResourceToken(t, s, "goauthy.connections.read")
	admin := issueResourceToken(t, s, "goauthy.providers.write")
	wrongAudience := issueResourceTokenForAudience(t, s, "goauthy.connections.use", wrongResourceAuthorizationAudience)
	s.store.client.(*fosite.DefaultClient).Scopes = append(s.store.client.(*fosite.DefaultClient).Scopes, "goauthy.connections.use")
	machine := decodeToken(t, postToken(s, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.connections.use"}, "resource": {resourceAuthorizationAudience}}))
	for _, tc := range []struct {
		name, token, audience string
		mutate                func(*http.Request)
	}{
		{"metadata read", read.AccessToken, resourceAuthorizationAudience, nil},
		{"provider admin", admin.AccessToken, resourceAuthorizationAudience, nil},
		{"wrong audience", wrongAudience.AccessToken, resourceAuthorizationAudience, nil},
		{"unconfigured audience", use.AccessToken, "", nil},
		{"machine", machine.AccessToken, resourceAuthorizationAudience, nil},
		{"cookie", use.AccessToken, resourceAuthorizationAudience, func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "session", Value: "fixture"}) }},
		{"empty cookie header", use.AccessToken, resourceAuthorizationAudience, func(r *http.Request) { r.Header["Cookie"] = []string{""} }},
		{"multiple cookie headers", use.AccessToken, resourceAuthorizationAudience, func(r *http.Request) { r.Header["Cookie"] = []string{"", "session=fixture"} }},
		{"duplicate authorization", use.AccessToken, resourceAuthorizationAudience, func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }},
		{"anonymous", "", resourceAuthorizationAudience, func(r *http.Request) { r.Header.Del("Authorization") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/use", nil)
			r.Header.Set("Authorization", "Bearer "+tc.token)
			if tc.mutate != nil {
				tc.mutate(r)
			}
			owner, consumer, authority, err := s.AuthorizeConnectionUse(r, tc.audience)
			if err == nil || owner != "" || consumer != "" || authority != nil {
				t.Fatal("invalid credential returned a usable consumer authority")
			}
		})
	}
	if owner, consumer, authority, err := s.AuthorizeConnectionUse(nil, resourceAuthorizationAudience); err == nil || owner != "" || consumer != "" || authority != nil {
		t.Fatal("nil request returned authority")
	}
	var unavailable *Server
	if owner, consumer, authority, err := unavailable.AuthorizeConnectionUse(httptest.NewRequest(http.MethodPost, "/use", nil), resourceAuthorizationAudience); err == nil || owner != "" || consumer != "" || authority != nil {
		t.Fatal("unavailable server returned authority")
	}
}
