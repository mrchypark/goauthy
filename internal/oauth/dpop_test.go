package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/ory/fosite"
)

func TestDPoPAuthorizationCodeRefreshAndUserInfo(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	seedOAuthUser(t, db, "user-1")
	server := userInfoTestServer(t, db, nil)
	verifier := strings.Repeat("d", 43)
	code := issueOIDCCode(t, server, verifier, "nonce", oidcTestAuthTime, oidcTestSessionID(0))
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}

	firstProof := dpopTestProof(t, private, http.MethodPost, "/oidc/token", "token-one-abcdefghijkl", "", "")
	challenge := postDPoPToken(t, server, form, firstProof)
	if challenge.Code != http.StatusBadRequest || tokenError(t, challenge) != "use_dpop_nonce" || challenge.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("challenge status=%d headers=%v body=%s", challenge.Code, challenge.Header(), challenge.Body.String())
	}
	nonce := challenge.Header().Get("DPoP-Nonce")
	issueProof := dpopTestProof(t, private, http.MethodPost, "/oidc/token", "token-two-abcdefghijkl", nonce, "")
	issuedResponse := postDPoPToken(t, server, form, issueProof)
	issued := decodeToken(t, issuedResponse)
	var responseCNF struct {
		CNF map[string]string `json:"cnf"`
	}
	if err := json.Unmarshal(issuedResponse.Body.Bytes(), &responseCNF); err != nil || issued.TokenType != "DPoP" || responseCNF.CNF["jkt"] == "" {
		t.Fatalf("DPoP response=%s type=%q cnf=%v err=%v", issuedResponse.Body.String(), issued.TokenType, responseCNF, err)
	}
	jkt := responseCNF.CNF["jkt"]
	access := jwtPayload(t, issued.AccessToken)
	if access["typ"] != "DPoP" || access["cnf"].(map[string]any)["jkt"] != jkt {
		t.Fatalf("signed DPoP access claims=%#v", access)
	}

	accessRequest, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), issued.AccessToken), &fosite.DefaultSession{})
	if err != nil || sessionDPoPJKT(accessRequest.GetSession()) != jkt {
		t.Fatalf("stored DPoP cnf=%q session=%#v err=%v", sessionDPoPJKT(accessRequest.GetSession()), accessRequest.GetSession(), err)
	}
	if encoded, err := encodeRequest(accessRequest); err != nil || strings.Contains(encoded, issueProof) || strings.Contains(encoded, nonce) {
		t.Fatalf("DPoP proof material persisted encoded=%q err=%v", encoded, err)
	}
	if noProof := postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}); noProof.Code == http.StatusOK {
		t.Fatal("bound refresh accepted without DPoP proof")
	}
	wrongRefreshKey := postDPoPToken(t, server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}, dpopTestProof(t, otherPrivate, http.MethodPost, "/oidc/token", "refresh-wrong-abcdef", "", ""))
	if wrongRefreshKey.Code != http.StatusBadRequest || tokenError(t, wrongRefreshKey) != "invalid_dpop_proof" {
		t.Fatal("bound refresh did not reject a different DPoP key with invalid_dpop_proof")
	}
	// A rejected key binding is checked before Fosite rotates the refresh token.
	refreshChallenge := postDPoPToken(t, server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}, dpopTestProof(t, private, http.MethodPost, "/oidc/token", "refresh-one-abcdefgh", "", ""))
	if refreshChallenge.Code != http.StatusBadRequest || refreshChallenge.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("refresh challenge status=%d headers=%v", refreshChallenge.Code, refreshChallenge.Header())
	}
	refreshed := decodeToken(t, postDPoPToken(t, server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}, dpopTestProof(t, private, http.MethodPost, "/oidc/token", "refresh-two-abcdefgh", refreshChallenge.Header().Get("DPoP-Nonce"), "")))
	if refreshed.TokenType != "DPoP" {
		t.Fatalf("refresh token type=%q", refreshed.TokenType)
	}

	missingProof := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	missingProof.Header.Set("Authorization", "DPoP "+refreshed.AccessToken)
	assertDPoPUnauthorized(t, server, missingProof, "DPoP")
	resourceChallenge := userInfoDPoP(t, server, refreshed.AccessToken, dpopTestProof(t, private, http.MethodGet, "/oidc/userinfo", "resource-one-abcdef", "", refreshed.AccessToken))
	if resourceChallenge.Code != http.StatusUnauthorized || resourceChallenge.Header().Get("WWW-Authenticate") != `DPoP error="use_dpop_nonce"` || resourceChallenge.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("resource challenge status=%d headers=%v", resourceChallenge.Code, resourceChallenge.Header())
	}
	resourceNonce := resourceChallenge.Header().Get("DPoP-Nonce")
	valid := userInfoDPoP(t, server, refreshed.AccessToken, dpopTestProof(t, private, http.MethodGet, "/oidc/userinfo", "resource-two-abcdef", resourceNonce, refreshed.AccessToken))
	if valid.Code != http.StatusOK {
		t.Fatalf("userinfo status=%d headers=%v body=%s", valid.Code, valid.Header(), valid.Body.String())
	}
	// A consumed nonce first yields a replacement. Reusing the same JTI with
	// that replacement reaches replay detection and must yield another nonce,
	// after which a fresh JTI succeeds.
	consumedNonce := userInfoDPoP(t, server, refreshed.AccessToken, dpopTestProof(t, private, http.MethodGet, "/oidc/userinfo", "resource-two-abcdef", resourceNonce, refreshed.AccessToken))
	if consumedNonce.Code != http.StatusUnauthorized || consumedNonce.Header().Get("WWW-Authenticate") != `DPoP error="use_dpop_nonce"` || consumedNonce.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("consumed nonce status=%d headers=%v", consumedNonce.Code, consumedNonce.Header())
	}
	replayNonce := userInfoDPoP(t, server, refreshed.AccessToken, dpopTestProof(t, private, http.MethodGet, "/oidc/userinfo", "resource-two-abcdef", consumedNonce.Header().Get("DPoP-Nonce"), refreshed.AccessToken))
	if replayNonce.Code != http.StatusUnauthorized || replayNonce.Header().Get("WWW-Authenticate") != `DPoP error="use_dpop_nonce"` || replayNonce.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("replay status=%d headers=%v", replayNonce.Code, replayNonce.Header())
	}
	if retried := userInfoDPoP(t, server, refreshed.AccessToken, dpopTestProof(t, private, http.MethodGet, "/oidc/userinfo", "resource-three-abcdef", replayNonce.Header().Get("DPoP-Nonce"), refreshed.AccessToken)); retried.Code != http.StatusOK {
		t.Fatalf("replay retry status=%d headers=%v body=%s", retried.Code, retried.Header(), retried.Body.String())
	}
	wrongKey := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	wrongKey.Header.Set("Authorization", "Bearer "+refreshed.AccessToken)
	assertDPoPUnauthorized(t, server, wrongKey, "DPoP")
	wrongProof := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	wrongProof.Header.Set("Authorization", "DPoP "+refreshed.AccessToken)
	wrongProof.Header.Set("DPoP", dpopTestProof(t, otherPrivate, http.MethodGet, "/oidc/userinfo", "resource-wrong-abcdef", "", refreshed.AccessToken))
	assertDPoPUnauthorized(t, server, wrongProof, "DPoP")
}

func TestDPoPHeaderRejectsDuplicateAndOversizedValues(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", nil)
	request.Header.Add("DPoP", "one")
	request.Header.Add("DPoP", "two")
	if _, present, valid := dpopHeader(request); !present || valid {
		t.Fatalf("duplicate DPoP accepted present=%v valid=%v", present, valid)
	}
	request.Header.Del("DPoP")
	request.Header.Set("DPoP", strings.Repeat("x", 8<<10+1))
	if _, present, valid := dpopHeader(request); !present || valid {
		t.Fatalf("oversized DPoP accepted present=%v valid=%v", present, valid)
	}
}

func TestDPoPClientCredentials(t *testing.T) {
	t.Parallel()
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}
	firstProof := dpopTestProof(t, private, http.MethodPost, "/oidc/token", "client-one-abcdefgh", "", "")
	challenge := postDPoPToken(t, server, form, firstProof)
	if challenge.Code != http.StatusBadRequest || tokenError(t, challenge) != "use_dpop_nonce" || challenge.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("challenge status=%d headers=%v body=%s", challenge.Code, challenge.Header(), challenge.Body.String())
	}
	issuedResponse := postDPoPToken(t, server, form, dpopTestProof(t, private, http.MethodPost, "/oidc/token", "client-two-abcdefgh", challenge.Header().Get("DPoP-Nonce"), ""))
	issued := decodeToken(t, issuedResponse)
	var responseCNF struct {
		CNF map[string]string `json:"cnf"`
	}
	if err := json.Unmarshal(issuedResponse.Body.Bytes(), &responseCNF); err != nil || issued.TokenType != "DPoP" || responseCNF.CNF[dpopJKTClaim] == "" {
		t.Fatalf("client credentials DPoP response=%s type=%q cnf=%v err=%v", issuedResponse.Body.String(), issued.TokenType, responseCNF, err)
	}
	stored, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), issued.AccessToken), &fosite.DefaultSession{})
	if err != nil || sessionDPoPJKT(stored.GetSession()) != responseCNF.CNF[dpopJKTClaim] {
		t.Fatalf("stored client DPoP cnf=%q err=%v", sessionDPoPJKT(stored.GetSession()), err)
	}
	// A consumed nonce proof must not issue a token; a retry receives a new
	// nonce instead of silently falling back to a bearer response.
	replay := postDPoPToken(t, server, form, dpopTestProof(t, private, http.MethodPost, "/oidc/token", "client-two-abcdefgh", challenge.Header().Get("DPoP-Nonce"), ""))
	if replay.Code != http.StatusBadRequest || tokenError(t, replay) != "use_dpop_nonce" || replay.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("client replay status=%d headers=%v body=%s", replay.Code, replay.Header(), replay.Body.String())
	}
}

func TestDecodeRequestPreservesOnlyVerifiedDPoPCNF(t *testing.T) {
	t.Parallel()
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	source := fosite.NewRequest()
	source.ID = "request-id"
	source.Client = server.store.client
	source.RequestedAt = oidcTestAuthTime
	source.Session = &fosite.DefaultSession{Subject: "user", Extra: map[string]any{"stored": "value"}}
	encoded, err := encodeRequest(source)
	if err != nil {
		t.Fatal(err)
	}
	jkt := strings.Repeat("A", 43)
	target := &fosite.DefaultSession{Extra: map[string]any{
		dpopCNFExtra: map[string]string{dpopJKTClaim: jkt},
		"transient":  map[string]string{"must": "not persist"},
	}}
	decoded, err := server.store.decodeRequest(context.Background(), encoded, target)
	if err != nil || sessionDPoPJKT(decoded.GetSession()) != jkt {
		t.Fatalf("decoded=%#v jkt=%q err=%v", decoded, sessionDPoPJKT(target), err)
	}
	if _, exists := target.Extra["transient"]; exists || target.Extra["stored"] != "value" {
		t.Fatalf("unexpected restored extra=%#v", target.Extra)
	}
}

func postDPoPToken(t *testing.T, server *Server, values url.Values, proof string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("DPoP", proof)
	request.SetBasicAuth(testClientID, testClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	return response
}

func userInfoDPoP(t *testing.T, server *Server, token, proof string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	request.Header.Set("Authorization", "DPoP "+token)
	request.Header.Set("DPoP", proof)
	response := httptest.NewRecorder()
	server.UserInfoHandler().ServeHTTP(response, request)
	return response
}

func assertDPoPUnauthorized(t *testing.T, server *Server, request *http.Request, want string) {
	t.Helper()
	response := httptest.NewRecorder()
	server.UserInfoHandler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != want {
		t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
}

func tokenError(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Error
}

func dpopTestProof(t *testing.T, private ed25519.PrivateKey, method, path, jti, nonce, accessToken string) string {
	t.Helper()
	key := jose.JSONWebKey{Key: private.Public()}
	claims := map[string]any{"jti": jti, "htm": method, "htu": oidcTestIssuer + path, "iat": time.Now().UTC().Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: private}, (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader(jose.HeaderKey("jwk"), key))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
