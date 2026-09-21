package oauth

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

func TestNonOIDCAuthorizationCodeRecordsSessionClientForLogout(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil })
	const endpoint = "https://rp.example.test/logout"
	server.store.backChannelLogoutURI = endpoint
	sid := oidcTestSessionID(11)
	verifier := strings.Repeat("o", 43)

	code := issueNonOIDCCode(t, server, verifier)
	issued := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))
	if issued.AccessToken == "" {
		t.Fatal("plain OAuth exchange returned no access token")
	}

	association, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT client_id,logout_uri FROM oidc_session_clients WHERE sid=?`, Args: []any{sid}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(association.Rows) != 1 || len(association.Rows[0]) != 2 || association.Rows[0][0] != testClientID || association.Rows[0][1] != endpoint {
		t.Fatalf("plain OAuth session association=%#v err=%v", association.Rows, err)
	}

	if err := server.RevokeOIDCSession(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	delivery, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT logout_uri FROM oidc_backchannel_deliveries WHERE sid=?`, Args: []any{sid}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(delivery.Rows) != 1 || len(delivery.Rows[0]) != 1 || delivery.Rows[0][0] != endpoint {
		t.Fatalf("plain OAuth logout delivery=%#v err=%v", delivery.Rows, err)
	}
}
