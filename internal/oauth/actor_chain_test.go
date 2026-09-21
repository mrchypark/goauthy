package oauth

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestTokenExchangePreservesNestedActorInJWTAndIntrospection(t *testing.T) {
	t.Parallel()
	server := exchangeTestServer(t)
	owner := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "user-1", "goauthy.read")},
		"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)},
	}))
	actor := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor-2", "goauthy.read")},
		"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)},
	}))
	ancestor := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor-3", "goauthy.read")},
		"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)},
	}))

	delegatedActor := decodeToken(t, postToken(server, exchangeActorForm(actor.AccessToken, ancestor.AccessToken)))
	target := decodeToken(t, postToken(server, exchangeActorForm(owner.AccessToken, delegatedActor.AccessToken)))

	claims, err := server.accessTokens.(*signedAccessTokenStrategy).verify(context.Background(), target.AccessToken)
	if err != nil || claims.Actor == nil || claims.Actor.Subject != "actor-2" || claims.Actor.Actor == nil || claims.Actor.Actor.Subject != "actor-3" || claims.Actor.Actor.Actor != nil {
		t.Fatalf("claims actor=%#v err=%v", claims.Actor, err)
	}
	signature := server.accessTokens.AccessTokenSignature(context.Background(), target.AccessToken)
	request, err := server.store.GetAccessTokenSession(context.Background(), signature, nil)
	if err != nil {
		t.Fatal(err)
	}
	session := request.GetSession().(*fosite.DefaultSession)
	if actor, err := accessSessionActor(session.Extra); err != nil || actor == nil || actor.Subject != "actor-2" || actor.Actor == nil || actor.Actor.Subject != "actor-3" || actor.Actor.Actor != nil {
		t.Fatalf("persisted actor=%#v err=%v", actor, err)
	}
	legacy := claims
	legacy.Actor = nil
	if server.accessTokens.(*signedAccessTokenStrategy).matchesRequest(request, legacy) {
		t.Fatal("accepted legacy JWT that omits the persisted actor claim")
	}
	legacy = claims
	legacy.Actor = &oidc.ActorClaims{Subject: "other"}
	if server.accessTokens.(*signedAccessTokenStrategy).matchesRequest(request, legacy) {
		t.Fatal("accepted JWT with an actor different from the persisted actor claim")
	}
	response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {target.AccessToken}}, testClientID, testClientSecret)
	var payload struct {
		Active bool           `json:"active"`
		Actor  map[string]any `json:"act"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || !payload.Active {
		t.Fatalf("introspection status=%d payload=%s err=%v", response.Code, response.Body.String(), err)
	}
	if actor, err := oidc.ParseActorClaims(payload.Actor); err != nil || actor.Subject != "actor-2" || actor.Actor == nil || actor.Actor.Subject != "actor-3" || actor.Actor.Actor != nil {
		t.Fatalf("introspection actor=%#v err=%v", payload.Actor, err)
	}
}

func TestNestedActorAncestorDeadlineCapsAndExpiryInactivatesTarget(t *testing.T) {
	t.Parallel()
	server := exchangeTestServer(t)
	owner, actor, ancestor := nestedActorInputs(t, server)
	deadline := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second)
	shortenAccountExpiryAt(t, server.store.db, "actor-3", deadline)
	delegatedActor := decodeToken(t, postToken(server, exchangeActorForm(actor.AccessToken, ancestor.AccessToken)))
	target := decodeToken(t, postToken(server, exchangeActorForm(owner.AccessToken, delegatedActor.AccessToken)))
	claims, err := server.accessTokens.(*signedAccessTokenStrategy).verify(context.Background(), target.AccessToken)
	if err != nil || claims.ExpiresAt.After(deadline) {
		t.Fatalf("claims expiry=%s deadline=%s err=%v", claims.ExpiresAt, deadline, err)
	}
	setConsumerExpiryClock(server)
	setActorDeadline(t, server, "expire-nested-actor-3", consumerExpiryNow)
	assertInactive(t, postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {target.AccessToken}}, testClientID, testClientSecret))
}

func TestNestedActorAncestorChangePreventsTargetIssue(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, server *Server)
	}{
		{name: "disabled", mutate: func(t *testing.T, server *Server) {
			t.Helper()
			if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "disable-nested-actor-3-before-exchange", SQL: `UPDATE identity_users SET disabled=1 WHERE subject=?`, Args: []any{"actor-3"}}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "deadline changed", mutate: func(t *testing.T, server *Server) {
			t.Helper()
			setActorDeadline(t, server, "shorten-nested-actor-3-before-exchange", time.Now().UTC().Add(2*time.Minute))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := exchangeTestServer(t)
			owner, actor, ancestor := nestedActorInputs(t, server)
			delegatedActor := decodeToken(t, postToken(server, exchangeActorForm(actor.AccessToken, ancestor.AccessToken)))
			before := tokenExchangeAccessCount(t, server)
			requestsBefore := tokenExchangeRequestCount(t, server)
			server.beforeTokenIssue = func() {
				server.beforeTokenIssue = nil
				test.mutate(t, server)
			}
			response := postToken(server, exchangeActorForm(owner.AccessToken, delegatedActor.AccessToken))
			if response.Code != 400 || oauthErrorCode(t, response) != "invalid_grant" {
				t.Fatalf("nested actor change status=%d error=%q", response.Code, oauthErrorCode(t, response))
			}
			if after := tokenExchangeAccessCount(t, server); after != before {
				t.Fatalf("failed nested actor exchange created access row: before=%d after=%d", before, after)
			}
			if after := tokenExchangeRequestCount(t, server); after != requestsBefore {
				t.Fatalf("failed nested actor exchange created request row: before=%d after=%d", requestsBefore, after)
			}
		})
	}
}

func setActorDeadline(t *testing.T, server *Server, requestID string, deadline time.Time) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{deadline.UnixMilli(), "actor-3"}}); err != nil {
		t.Fatal(err)
	}
}

func tokenExchangeRequestCount(t *testing.T, server *Server) int64 {
	t.Helper()
	result, err := server.store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_token_requests`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("token request count rows=%#v err=%v", result.Rows, err)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("token request count=%#v", result.Rows[0][0])
	}
	return count
}

func nestedActorInputs(t *testing.T, server *Server) (tokenResponse, tokenResponse, tokenResponse) {
	t.Helper()
	owner := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "user-1", "goauthy.read")},
		"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)},
	}))
	actor := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor-2", "goauthy.read")},
		"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)},
	}))
	ancestor := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor-3", "goauthy.read")},
		"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)},
	}))
	return owner, actor, ancestor
}

func exchangeActorForm(subject, actor string) url.Values {
	return url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {subject}, "subject_token_type": {accessTokenType},
		"actor_token": {actor}, "actor_token_type": {accessTokenType}, "scope": {"goauthy.read"}, "resource": {exchangeResource},
	}
}
