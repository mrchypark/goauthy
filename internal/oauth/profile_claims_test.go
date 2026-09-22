package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestProfileClaimsCodeRefreshUserInfoAndScopeIsolation(t *testing.T) {
	t.Parallel()
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	key := oidcTestKey(t)
	name, email, locale, phone := "Before", "member@example.test", "de", "+49123456789"
	verified := false
	calls := 0
	server.oidc.ResolveProfile = func(_ context.Context, subject string) (oidc.ProfileClaims, error) {
		if subject != "user-1" {
			t.Fatalf("resolved machine/wrong subject %q", subject)
		}
		calls++
		return oidc.ProfileClaims{GivenName: &name, Email: &email, EmailVerified: &verified,
			Locale: &locale, PhoneNumber: &phone, PhoneNumberVerified: &verified,
			Address: map[string]string{"street_address": name}}, nil
	}
	issue := func(scopes string) oidcTokenResponse {
		t.Helper()
		verifier := strings.Repeat("p", 43)
		values := oidcAuthorizationValues(verifier, "profile-nonce")
		values.Set("scope", scopes)
		ensureOIDCTestBrowserSession(t, server, oidcTestSessionID(0))
		response := httptest.NewRecorder()
		server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", strings.Fields(scopes), oidcTestAuthTime, oidcTestSessionID(0), oidcAuthMethodPwd)
		location, err := url.Parse(response.Header().Get("Location"))
		if err != nil || location.Query().Get("code") == "" {
			t.Fatalf("profile authorize failed: %d %s", response.Code, response.Header().Get("Location"))
		}
		return decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
	}
	userinfo := func(token string) map[string]any {
		t.Helper()
		response := httptest.NewRecorder()
		server.UserInfoHandler().ServeHTTP(response, userInfoRequest(http.MethodGet, token, nil))
		var out map[string]any
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &out) != nil {
			t.Fatalf("userinfo status=%d body=%s", response.Code, response.Body.String())
		}
		return out
	}
	issued := issue("openid profile email address phone offline_access")
	before := verifyOIDCTestToken(t, issued.IDToken, key, time.Now().UTC())
	if before.Profile.GivenName == nil || *before.Profile.GivenName != "Before" {
		t.Fatal("code exchange lost current profile")
	}
	name = "After"
	if got := userinfo(issued.AccessToken); got["given_name"] != "After" {
		t.Fatal("UserInfo returned issuance-time profile")
	}
	refreshed := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}))
	after := verifyOIDCTestToken(t, refreshed.IDToken, key, time.Now().UTC())
	if after.Profile.GivenName == nil || *after.Profile.GivenName != "After" || after.Profile.Address["street_address"] != "After" {
		t.Fatal("refresh returned stale profile")
	}
	for _, scope := range []string{"", "profile", "email", "address", "phone"} {
		t.Run("scope_"+scope, func(t *testing.T) {
			token := issue(strings.TrimSpace("openid " + scope))
			p := verifyOIDCTestToken(t, token.IDToken, key, time.Now().UTC()).Profile
			if (p.GivenName != nil) != (scope == "profile") || (p.Locale != nil) != (scope == "profile") || (p.Email != nil) != (scope == "email") || (p.EmailVerified != nil) != (scope == "email") || (p.Address != nil) != (scope == "address") || (p.PhoneNumber != nil) != (scope == "phone") || (p.PhoneNumberVerified != nil) != (scope == "phone") {
				t.Fatalf("ID token scope leak: %#v", p)
			}
			got := userinfo(token.AccessToken)
			for claim, required := range map[string]string{"given_name": "profile", "locale": "profile", "email": "email", "email_verified": "email", "address": "address", "phone_number": "phone", "phone_number_verified": "phone"} {
				if _, exists := got[claim]; exists != (scope == required) {
					t.Fatalf("userinfo claim %s scope %q: %v", claim, scope, got)
				}
			}
		})
	}
	beforeCalls := calls
	machine := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}))
	if machine.IDToken != "" || calls != beforeCalls {
		t.Fatal("machine grant resolved user profile")
	}
	assertUserInfoUnauthorized(t, server, userInfoRequest(http.MethodGet, machine.AccessToken, nil))
}
