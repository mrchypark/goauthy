package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestAuthorizeConnectionHandoffReturnsOwnerRequesterAndCurrentGuard(t *testing.T) {
	db := oauthTestDB(t)
	s := resourceAuthorizationServer(t, db, randomSecret(t))
	token := issueResourceToken(t, s, "goauthy.connections.write")
	r := httptest.NewRequest(http.MethodPost, "/handoff", nil)
	r.Header.Set("Authorization", "Bearer "+token.AccessToken)

	owner, requester, authority, err := s.AuthorizeConnectionHandoff(r, resourceAuthorizationAudience)
	if err != nil || owner != "resource-user" || requester != testClientID || authority == nil {
		t.Fatalf("owner=%q requester=%q authority=%v err=%v", owner, requester, authority != nil, err)
	}
	guard, args := authority()
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("guard rows=%v err=%v", rows.Rows, err)
	}
}

func TestAuthorizeConnectionHandoffRejectsInvalidCredentials(t *testing.T) {
	s := resourceAuthorizationServer(t, oauthTestDB(t), randomSecret(t))
	write := issueResourceToken(t, s, "goauthy.connections.write")
	read := issueResourceToken(t, s, "goauthy.connections.read")
	wrongAudience := issueResourceTokenForAudience(t, s, "goauthy.connections.write", wrongResourceAuthorizationAudience)
	s.store.client.(*fosite.DefaultClient).Scopes = append(s.store.client.(*fosite.DefaultClient).Scopes, "goauthy.connections.write")
	machine := decodeToken(t, postToken(s, url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"goauthy.connections.write"},
		"resource":   {resourceAuthorizationAudience},
	}))
	for _, tc := range []struct {
		name, token, audience string
		cookie                string
	}{
		{"wrong scope", read.AccessToken, resourceAuthorizationAudience, ""},
		{"wrong audience", wrongAudience.AccessToken, resourceAuthorizationAudience, ""},
		{"missing audience", write.AccessToken, "", ""},
		{"machine", machine.AccessToken, resourceAuthorizationAudience, ""},
		{"cookie", write.AccessToken, resourceAuthorizationAudience, "session=fixture"},
		{"empty cookie header", write.AccessToken, resourceAuthorizationAudience, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/handoff", nil)
			r.Header.Set("Authorization", "Bearer "+tc.token)
			if tc.name == "empty cookie header" {
				r.Header["Cookie"] = []string{""}
			} else if tc.cookie != "" {
				r.Header.Set("Cookie", tc.cookie)
			}
			owner, requester, authority, err := s.AuthorizeConnectionHandoff(r, tc.audience)
			if err == nil || owner != "" || requester != "" || authority != nil {
				t.Fatal("invalid credential returned a usable handoff authority")
			}
		})
	}
}
