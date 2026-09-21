package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type consentTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

func exchangeToken(t *testing.T, server *Server, values url.Values) consentTokenResponse {
	t.Helper()
	response := postToken(server, values)
	var token consentTokenResponse
	if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil || response.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s err=%v", response.Code, response.Body.String(), err)
	}
	return token
}

func consentCode(t *testing.T, server *Server, verifier, requested string, approved []string, sessionID string) string {
	t.Helper()
	ensureOIDCTestBrowserSession(t, server, sessionID)
	values := oidcAuthorizationValues(verifier, "consent-nonce")
	values.Set("scope", requested)
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", approved, oidcTestAuthTime, sessionID, oidcAuthMethodPwd)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	return location.Query().Get("code")
}

// GA-OAUTH-004: consent may approve less than the client requested. Issuance
// and the later refresh grant must carry the durable approval instead of
// restoring every requested scope.
func TestTokenIssuanceKeepsScopesWithheldAtConsent(t *testing.T) {
	t.Parallel()
	accessValue := json.RawMessage(`"access-v1"`)
	server := customClaimsServer(t, false, &accessValue)
	requested := "openid employee goauthy.read offline_access"
	approved := []string{"openid", "goauthy.read", "offline_access"}
	want := "openid goauthy.read offline_access"

	verifier := strings.Repeat("q", 43)
	code := consentCode(t, server, verifier, requested, approved, oidcTestSessionID(7))
	issued := exchangeToken(t, server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}})
	if issued.Scope != want {
		t.Fatalf("code exchange scope=%q want=%q", issued.Scope, want)
	}
	if issued.RefreshToken == "" {
		t.Fatal("approved offline_access did not issue a refresh token")
	}
	for surface, token := range map[string]string{"access": issued.AccessToken, "ID": issued.IDToken} {
		if claims := jwtPayload(t, token); claims["custom"] != nil {
			t.Fatalf("%s token carries withheld custom claims: %#v", surface, claims)
		}
	}

	refreshed := exchangeToken(t, server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}})
	if refreshed.Scope != want {
		t.Fatalf("refresh scope=%q want=%q", refreshed.Scope, want)
	}
	if claims := jwtPayload(t, refreshed.AccessToken); claims["custom"] != nil {
		t.Fatalf("refreshed access token carries withheld custom claims: %#v", claims)
	}

	// A withheld refresh scope must not become refresh eligibility either.
	verifier = strings.Repeat("r", 43)
	code = consentCode(t, server, verifier, requested, []string{"openid", "goauthy.read"}, oidcTestSessionID(8))
	withoutRefresh := exchangeToken(t, server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}})
	if withoutRefresh.Scope != "openid goauthy.read" || withoutRefresh.RefreshToken != "" {
		t.Fatalf("withheld offline_access issued scope=%q refresh=%t", withoutRefresh.Scope, withoutRefresh.RefreshToken != "")
	}
}
