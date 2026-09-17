package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
)

// TestTokenExchangeMachineSubjectMapping keeps client-credentials exchanges
// machine-only: mapping exposes a client ID without synthesizing an end-user
// principal.
func TestTokenExchangeMachineSubjectMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mapSub bool
		want   string
	}{
		{name: "default empty subject"},
		{name: "mapped subject", mapSub: true, want: testClientID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := exchangeTestServer(t)
			server.oidc.ClientCredentialsMapSub = tc.mapSub
			source := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}))
			response := postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "scope": {"goauthy.read"}})
			if response.Code != http.StatusOK {
				t.Fatalf("machine exchange status=%d error=%q", response.Code, oauthErrorCode(t, response))
			}
			actorResponse := postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "actor_token": {source.AccessToken}, "actor_token_type": {accessTokenType}})
			if tc.mapSub {
				if actorResponse.Code != http.StatusOK {
					t.Fatalf("mapped machine actor status=%d", actorResponse.Code)
				}
				actorIssued := decodeToken(t, actorResponse)
				actorClaims, err := server.accessTokens.(*signedAccessTokenStrategy).verify(t.Context(), actorIssued.AccessToken)
				if err != nil || actorClaims.Actor == nil || actorClaims.Actor.Subject != testClientID {
					t.Fatal("mapped machine actor claims invalid")
				}
			} else if actorResponse.Code != http.StatusBadRequest {
				t.Fatalf("no-sub machine actor status=%d", actorResponse.Code)
			}
			issued := decodeToken(t, response)
			introspection := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret)
			var active map[string]any
			if err := json.Unmarshal(introspection.Body.Bytes(), &active); err != nil || active["active"] != true {
				t.Fatal("machine introspection inactive")
			}
			if active[machineSubjectExtra] != nil || active[actorMachineExtra] != nil {
				t.Fatal("internal machine markers leaked")
			}
			if tc.mapSub && active["sub"] != testClientID {
				t.Fatal("mapped introspection subject missing")
			}
			// Changing global configuration must not invalidate already issued tokens.
			server.oidc.ClientCredentialsMapSub = !tc.mapSub
			chained := postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {issued.AccessToken}, "subject_token_type": {accessTokenType}})
			if chained.Code != http.StatusOK {
				t.Fatalf("chained exchange status=%d", chained.Code)
			}
			chainedClaims, err := server.accessTokens.(*signedAccessTokenStrategy).verify(t.Context(), decodeToken(t, chained).AccessToken)
			wantChained := ""
			if !tc.mapSub {
				wantChained = testClientID
			}
			if err != nil || chainedClaims.Subject != wantChained {
				t.Fatal("chained machine mapping invalid")
			}

			claims, err := server.accessTokens.(*signedAccessTokenStrategy).verify(t.Context(), issued.AccessToken)
			if err != nil || claims.Subject != tc.want || claims.Actor != nil || len(claims.Roles) != 0 || len(claims.Groups) != 0 {
				t.Fatalf("machine claims valid=%t subject_matches=%t actor_set=%t roles=%d groups=%d", err == nil, claims.Subject == tc.want, claims.Actor != nil, len(claims.Roles), len(claims.Groups))
			}
		})
	}
}

func TestMachineExchangeRetainsCollidingUserAncestorGuard(t *testing.T) {
	server := exchangeTestServer(t)
	server.oidc.ClientCredentialsMapSub = true
	machine := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}))
	user := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, testClientID, "goauthy.read")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	// Both actors have the same public sub; only the positional mask distinguishes
	// the real account ancestor from the machine immediately above it.
	delegated := decodeToken(t, postToken(server, exchangeActorForm(machine.AccessToken, user.AccessToken)))
	form := exchangeActorForm(machine.AccessToken, delegated.AccessToken)
	target := decodeToken(t, postToken(server, form))
	signature := server.accessTokens.AccessTokenSignature(t.Context(), target.AccessToken)
	request, err := server.store.GetAccessTokenSession(t.Context(), signature, nil)
	if err != nil {
		t.Fatal(err)
	}
	subjects, err := tokenAccountSubjects(request)
	if err != nil || len(subjects) != 1 || subjects[0] != testClientID {
		t.Fatal("machine actor hid its colliding user ancestor")
	}
	before := tokenExchangeAccessCount(t, server)
	requestsBefore := tokenExchangeRequestCount(t, server)
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		shortenAccountExpiryAt(t, server.store.db, testClientID, time.Now().UTC().Add(-time.Hour))
	}
	response := postToken(server, form)
	if response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "invalid_grant" || tokenExchangeAccessCount(t, server) != before || tokenExchangeRequestCount(t, server) != requestsBefore {
		t.Fatal("machine exchange bypassed ancestor commit guard")
	}
	assertInactive(t, postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {target.AccessToken}}, testClientID, testClientSecret))
	machineRequest, err := server.store.GetAccessTokenSession(t.Context(), server.accessTokens.AccessTokenSignature(t.Context(), machine.AccessToken), &fosite.DefaultSession{})
	if err != nil || server.store.validateTokenAccounts(context.Background(), machineRequest) != nil {
		t.Fatal("unrelated machine token became bound to expired colliding account")
	}
}

func TestMachineAccountMarkersFailClosed(t *testing.T) {
	for _, extra := range []map[string]any{
		{},
		{machineSubjectExtra: true},
		{machineSubjectExtra: "other-client"},
		{machineSubjectExtra: "", actorMachineExtra: []bool{true}},
		{machineSubjectExtra: "", "act": map[string]any{"sub": "user"}, actorMachineExtra: []bool{}},
		{machineSubjectExtra: "", "act": map[string]any{"sub": "user"}, actorMachineExtra: []any{"true"}},
	} {
		request := fosite.NewRequest()
		request.Client = &fosite.DefaultClient{ID: testClientID}
		request.Form = url.Values{"grant_type": {TokenExchangeGrantType}}
		request.Session = &fosite.DefaultSession{Extra: extra}
		if _, err := tokenAccountSubjects(request); err == nil {
			t.Fatal("accepted malformed machine origin or actor mask")
		}
	}
}
