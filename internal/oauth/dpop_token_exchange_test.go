package oauth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/ory/fosite"
)

func TestDPoPTokenExchangeBindsBearerInputsAndOutput(t *testing.T) {
	t.Parallel()
	server := exchangeTestServer(t)
	source := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueExchangeCode(t, server)},
		"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)},
	}))
	form := url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken},
		"subject_token_type": {accessTokenType}, "scope": {"goauthy.read"}, "resource": {exchangeResource},
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if response := postDPoPToken(t, server, form, "not-a-proof"); response.Code != http.StatusBadRequest || tokenError(t, response) != "invalid_dpop_proof" {
		t.Fatalf("malformed exchange status=%d error=%q", response.Code, tokenError(t, response))
	}
	challenge := postDPoPToken(t, server, form, dpopTestProof(t, private, http.MethodPost, "/oidc/token", "exchange-challenge", "", ""))
	if challenge.Code != http.StatusBadRequest || tokenError(t, challenge) != "use_dpop_nonce" || challenge.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("exchange challenge status=%d error=%q nonce=%t", challenge.Code, tokenError(t, challenge), challenge.Header().Get("DPoP-Nonce") != "")
	}
	proof := dpopTestProof(t, private, http.MethodPost, "/oidc/token", "exchange-issued-one", challenge.Header().Get("DPoP-Nonce"), "")
	issuedResponse := postDPoPToken(t, server, form, proof)
	issued := decodeToken(t, issuedResponse)
	var output struct {
		CNF map[string]string `json:"cnf"`
	}
	if err := json.Unmarshal(issuedResponse.Body.Bytes(), &output); err != nil || issued.TokenType != "DPoP" || issued.RefreshToken != "" || output.CNF[dpopJKTClaim] == "" {
		t.Fatalf("DPoP exchange status=%d type=%q refresh=%t cnf=%t err=%v", issuedResponse.Code, issued.TokenType, issued.RefreshToken != "", output.CNF[dpopJKTClaim] != "", err)
	}
	public := jose.JSONWebKey{Key: private.Public()}
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	wantJKT := base64.RawURLEncoding.EncodeToString(thumbprint)
	if output.CNF[dpopJKTClaim] != wantJKT {
		t.Fatalf("output JKT does not match proof key")
	}
	claims, err := oidc.VerifyAccessToken(issued.AccessToken, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{oidcTestKey(t).PublicJWK}}, oidcTestIssuer, time.Now().UTC())
	if err != nil || claims.Type != "DPoP" || claims.ConfirmationJKT != wantJKT || claims.AuthorizedParty != testClientID || !sameAccessStrings(claims.Audience, []string{testClientID, exchangeResource}) || !sameAccessStrings(claims.Scope, []string{"goauthy.read"}) {
		t.Fatalf("signed exchange claims valid=%t type=%q jkt=%t azp=%t audience=%t scope=%t", err == nil, claims.Type, claims.ConfirmationJKT == wantJKT, claims.AuthorizedParty == testClientID, sameAccessStrings(claims.Audience, []string{testClientID, exchangeResource}), sameAccessStrings(claims.Scope, []string{"goauthy.read"}))
	}
	stored, err := server.store.GetAccessTokenSession(t.Context(), server.accessTokens.AccessTokenSignature(t.Context(), issued.AccessToken), &fosite.DefaultSession{})
	if err != nil {
		t.Fatalf("stored output unavailable: %v", err)
	}
	if sessionDPoPJKT(stored.GetSession()) != wantJKT {
		t.Fatal("stored output JKT does not match proof key")
	}

	resource := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	resource.Header.Set("Authorization", "DPoP "+issued.AccessToken)
	resource.Header.Set("DPoP", dpopTestProof(t, private, http.MethodGet, "/oidc/userinfo", "exchange-resource-ath-invalid", "", "another-token"))
	if err := server.verifyDPoPResourceRequest(t.Context(), resource, stored, issued.AccessToken); !errors.Is(err, fosite.ErrInvalidRequest) {
		t.Fatalf("wrong ath resource proof err=%v", err)
	}
	resource.Header.Set("DPoP", dpopTestProof(t, private, http.MethodGet, "/oidc/userinfo", "exchange-resource-challenge", "", issued.AccessToken))
	err = server.verifyDPoPResourceRequest(t.Context(), resource, stored, issued.AccessToken)
	var nonceErr *dpopNonceError
	if !errors.As(err, &nonceErr) || nonceErr.nonce == "" {
		t.Fatalf("resource nonce err=%v", err)
	}
	resource.Header.Set("DPoP", dpopTestProof(t, private, http.MethodGet, "/oidc/userinfo", "exchange-resource-ok", nonceErr.nonce, issued.AccessToken))
	if err := server.verifyDPoPResourceRequest(t.Context(), resource, stored, issued.AccessToken); err != nil {
		t.Fatalf("matching DPoP resource proof err=%v", err)
	}

	if replay := postDPoPToken(t, server, form, proof); replay.Code != http.StatusBadRequest || tokenError(t, replay) != "use_dpop_nonce" || replay.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("exchange replay status=%d error=%q nonce=%t", replay.Code, tokenError(t, replay), replay.Header().Get("DPoP-Nonce") != "")
	}
	bearerResponse := postToken(server, form)
	bearer := decodeToken(t, bearerResponse)
	var bearerOutput struct {
		CNF map[string]string `json:"cnf"`
	}
	if err := json.Unmarshal(bearerResponse.Body.Bytes(), &bearerOutput); err != nil || bearer.TokenType != "bearer" || bearer.RefreshToken != "" || len(bearerOutput.CNF) != 0 {
		t.Fatalf("bearer exchange status=%d type=%q refresh=%t cnf=%t err=%v", bearerResponse.Code, bearer.TokenType, bearer.RefreshToken != "", len(bearerOutput.CNF) != 0, err)
	}
}

func TestDPoPTokenExchangeRejectsBoundInputs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		actor bool
	}{
		{name: "subject"},
		{name: "actor", actor: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := exchangeTestServer(t)
			subject := decodeToken(t, postToken(server, url.Values{
				"grant_type": {"authorization_code"}, "code": {issueExchangeCode(t, server)},
				"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)},
			}))
			form := url.Values{
				"grant_type": {TokenExchangeGrantType}, "subject_token": {subject.AccessToken},
				"subject_token_type": {accessTokenType}, "scope": {"goauthy.read"}, "resource": {exchangeResource},
			}
			bound := subject.AccessToken
			if tc.actor {
				actor := decodeToken(t, postToken(server, url.Values{
					"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor", "goauthy.read")},
					"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)},
				}))
				form.Set("actor_token", actor.AccessToken)
				form.Set("actor_token_type", accessTokenType)
				bound = actor.AccessToken
			}
			bindForwardAuthTokenDPoP(t, server.store.db, server, bound)
			response := postToken(server, form)
			if response.Code != http.StatusBadRequest || tokenError(t, response) != "invalid_grant" {
				t.Fatalf("bound %s input status=%d error=%q", tc.name, response.Code, tokenError(t, response))
			}
		})
	}
}
