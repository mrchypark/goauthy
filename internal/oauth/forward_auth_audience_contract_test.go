package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// TestForwardAuthAudienceContractAdmitsTokensForUnrelatedResources is the
// recorded GA-DESIGN-003 contract, not an oversight: forward_auth is an
// authentication gate for a reverse proxy. It admits a request when the bearer
// is a live user access token with the openid scope, a live client, a valid
// subject and a passing client-group policy. It intentionally does not compare
// the token audience with the protected resource, so two tokens minted for two
// different resources are both admitted for either protected host. Isolation
// between protected resources is the proxy's job and is expressed by which
// client and group policy the proxy requires. See "Audience contract" in
// docs/security.md; do not add an audience comparison here without changing
// that documented contract.
func TestForwardAuthAudienceContractAdmitsTokensForUnrelatedResources(t *testing.T) {
	const (
		reportResource  = "https://reports.example.test/v1"
		billingResource = "https://billing.example.test/v1"
	)
	server := forwardAuthAudienceServer(t, oauthTestDB(t), nil, nil, reportResource, billingResource)
	tokens := map[string]struct {
		token    string
		resource string
	}{}
	for name, issued := range map[string]struct {
		seed     byte
		verifier string
		resource string
	}{
		"report token":  {seed: 21, verifier: "y", resource: reportResource},
		"billing token": {seed: 22, verifier: "z", resource: billingResource},
	} {
		token := issueForwardAuthResourceToken(t, server, issued.seed, issued.verifier, issued.resource)
		assertResourceAudience(t, server, token, issued.resource)
		tokens[name] = struct {
			token    string
			resource string
		}{token: token, resource: issued.resource}
	}
	for name, issued := range tokens {
		for _, host := range []string{"reports.internal.example.test", "billing.internal.example.test"} {
			t.Run(name+" for "+host, func(t *testing.T) {
				request := forwardAuthRequest(http.MethodGet, issued.token, nil)
				request.Host = host
				if response := forwardAuthResponse(server, request); response.Code != http.StatusOK || response.Body.Len() != 0 {
					t.Fatalf("resource-bound token for %s denied on %s: status=%d headers=%v body=%q", issued.resource, host, response.Code, response.Header(), response.Body.String())
				}
			})
		}
	}
}

// TestForwardAuthAudienceContractRejectsTokenFailingClientGroupPolicy pins the
// other half of the audience contract: the same resource-bound token is
// admitted while the client group policy matches the caller's current groups
// and rejected once it does not. The client plus its group policy, not the
// token audience, is how a proxy isolates protected resources.
func TestForwardAuthAudienceContractRejectsTokenFailingClientGroupPolicy(t *testing.T) {
	state := PrincipalClaims{Roles: []string{"viewer"}, Groups: []string{"team/a"}, Revision: 1}
	server := forwardAuthAudienceServer(t, oauthTestDB(t), &state, &ClientGroupPolicy{Managed: true, Prefix: "team", Revision: 1}, "https://reports.example.test/v1")
	token := issueForwardAuthResourceToken(t, server, 23, "w", "https://reports.example.test/v1")
	assertResourceAudience(t, server, token, "https://reports.example.test/v1")
	if response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, token, nil)); response.Code != http.StatusOK {
		t.Fatalf("matching group policy status=%d headers=%v", response.Code, response.Header())
	}
	state.Groups, state.Revision = []string{"other"}, 2
	assertForwardAuthUnauthorized(t, server, forwardAuthRequest(http.MethodGet, token, nil))
}

// TestForwardAuthAudienceContractRejectsDPoPBoundToken pins the third recorded
// point: a DPoP-bound token is rejected regardless of its audience, because
// forward_auth only admits plain bearer user access tokens.
func TestForwardAuthAudienceContractRejectsDPoPBoundToken(t *testing.T) {
	db := oauthTestDB(t)
	server := forwardAuthAudienceServer(t, db, nil, nil, "https://reports.example.test/v1")
	token := issueForwardAuthResourceToken(t, server, 24, "v", "https://reports.example.test/v1")
	bindForwardAuthTokenDPoP(t, db, server, token)
	assertForwardAuthUnauthorized(t, server, forwardAuthRequest(http.MethodGet, token, nil))
}

// forwardAuthAudienceServer builds an OIDC-enabled server that can mint
// access tokens bound to the given resource audiences. state and policy are
// optional: a nil policy leaves client-group admission unrestricted.
func forwardAuthAudienceServer(t *testing.T, db *rhiza.DB, state *PrincipalClaims, policy *ClientGroupPolicy, resources ...string) *Server {
	t.Helper()
	seedOAuthUser(t, db, "user-1")
	config := OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		ValidateSubject: func(context.Context, string) error { return nil },
	}
	if state != nil {
		config.ResolvePrincipal = func(context.Context, string) (PrincipalClaims, error) { return *state, nil }
	}
	if policy != nil {
		resolved := *policy
		config.ClientGroupPolicy = func(context.Context, string) (ClientGroupPolicy, error) { return resolved, nil }
		// Issuance and admission both fence the current bootstrap restriction
		// revision, so the matching row has to exist.
		var prefix any
		if resolved.Prefix != "" {
			prefix = resolved.Prefix
		}
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "forward-auth-audience-policy", SQL: `INSERT INTO bootstrap_client_login_restrictions (client_id,restrict_group_prefix,revision,updated_at_unix_ms) VALUES (?,?,?,0)`, Args: []any{testClientID, prefix, resolved.Revision}}); err != nil {
			t.Fatal(err)
		}
	}
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, append([]string(nil), resources...), config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

// issueForwardAuthResourceToken mints an openid user access token whose
// audience is the given resource, using the same authorization-code path the
// standalone E2E harness drives.
func issueForwardAuthResourceToken(t *testing.T, server *Server, seed byte, verifierByte, resource string) string {
	t.Helper()
	verifier := strings.Repeat(verifierByte, 43)
	values := oidcAuthorizationValues(verifier, "nonce")
	values.Set("resource", resource)
	sid := oidcTestSessionID(seed)
	ensureOIDCTestBrowserSession(t, server, sid)
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"openid", "goauthy.read", "offline_access"}, oidcTestAuthTime, sid, oidcAuthMethodPwd)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("error") != "" || location.Query().Get("code") == "" {
		t.Fatalf("authorization status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	return decodeOIDCToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	})).AccessToken
}
