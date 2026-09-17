package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/rbac"
)

// TestProfileClaimsLive exercises the deployed authorization, token and
// UserInfo projection. It is opt-in because it creates a real account.
func TestProfileClaimsLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_PROFILE_CLAIMS") != "1" {
		t.Skip("set GOAUTHY_E2E_PROFILE_CLAIMS=1 to run profile claims E2E")
	}
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	client := newBrowserClient(t)
	_, adminCookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "profile-claims-admin")
	csrf, err := browsersession.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	adminHeaders := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	email := "profile-claims-user@goauthy.e2e"
	created := do(t, client, http.MethodPost, primary+"/auth/v1/users", bytes.NewBufferString(`{"email":"`+email+`","language":"en","roles":[]}`), adminHeaders)
	var user rbac.UserResponse
	err = json.NewDecoder(io.LimitReader(created.Body, 16<<10)).Decode(&user)
	created.Body.Close()
	if created.StatusCode != http.StatusOK || err != nil || user.ID == "" {
		t.Fatalf("create status=%d err=%v", created.StatusCode, err)
	}
	profile := map[string]any{"email": email, "given_name": "Ada", "family_name": "Lovelace", "roles": []string{}, "enabled": true, "email_verified": true, "password": "Profile-Claims-Password-1A", "user_values": map[string]any{"street": "1 Analytical Engine Way", "zip": "12345", "city": "London", "country": "GB", "phone": "+441234567890"}}
	body, _ := json.Marshal(profile)
	updated := do(t, client, http.MethodPut, primary+"/auth/v1/users/"+user.ID, bytes.NewReader(body), adminHeaders)
	updated.Body.Close()
	if updated.StatusCode != http.StatusOK {
		t.Fatalf("activate status=%d", updated.StatusCode)
	}
	delete(profile, "password")
	userClient := newBrowserClient(t)
	verifier := pkceVerifier(t)
	scope := "openid profile email address phone offline_access"
	authURL := oidcAuthorizationURLForClient(t, primary, "goauthy-dev", defaultRedirectURI, pkceChallenge(verifier), "profile-claims", "profile-claims-nonce", scope)
	code, _ := loginForAuthorizationURL(t, userClient, authURL, primary, secondary, email, "Profile-Claims-Password-1A", "profile-claims")
	tokens := exchangeCode(t, userClient, primary, clientSecret, defaultRedirectURI, code, verifier)
	claims := verifyPublicIDToken(t, tokens.IDToken, publicJWKS(t, userClient, primary), primary)
	assertProfileClaimValues(t, claims.Profile, "Ada", "Lovelace", "1 Analytical Engine Way", "12345", "London", "GB", "+441234567890")
	for _, node := range adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL")) {
		assertUserInfoProfile(t, userClient, node, tokens.AccessToken, "Ada", "Lovelace", "1 Analytical Engine Way")
	}

	// Updating the profile must be visible on a refresh while preserving the
	// fields not changed by the administrator.
	profile["given_name"], profile["family_name"] = "Grace", "Hopper"
	profile["user_values"] = map[string]any{"street": "2 Compiler Lane", "zip": "12345", "city": "London", "country": "GB", "phone": "+441234567890"}
	body, _ = json.Marshal(profile)
	updated = do(t, client, http.MethodPut, primary+"/auth/v1/users/"+user.ID, bytes.NewReader(body), adminHeaders)
	updated.Body.Close()
	if updated.StatusCode != http.StatusOK {
		t.Fatalf("profile update status=%d", updated.StatusCode)
	}
	refreshed := refresh(t, userClient, primary, clientSecret, tokens.RefreshToken)
	refreshedClaims := verifyPublicIDToken(t, refreshed.IDToken, publicJWKS(t, userClient, secondary), primary)
	assertProfileClaimValues(t, refreshedClaims.Profile, "Grace", "Hopper", "2 Compiler Lane", "12345", "London", "GB", "+441234567890")
	for _, node := range adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL")) {
		assertUserInfoProfile(t, userClient, node, refreshed.AccessToken, "Grace", "Hopper", "2 Compiler Lane")
	}

	// OpenID-only must not leak profile claims.
	openidClient := newBrowserClient(t)
	openidVerifier := pkceVerifier(t)
	openidURL := oidcAuthorizationURLForClient(t, primary, "goauthy-dev", defaultRedirectURI, pkceChallenge(openidVerifier), "profile-claims-openid", "profile-claims-openid-nonce", "openid")
	openidCode, _ := loginForAuthorizationURL(t, openidClient, openidURL, primary, secondary, email, "Profile-Claims-Password-1A", "profile-claims-openid")
	openidTokens := exchangeCode(t, openidClient, primary, clientSecret, defaultRedirectURI, openidCode, openidVerifier)
	openidClaims := verifyPublicIDToken(t, openidTokens.IDToken, publicJWKS(t, openidClient, primary), primary)
	if openidClaims.Profile.Email != nil || openidClaims.Profile.GivenName != nil || openidClaims.Profile.Address != nil {
		t.Fatalf("openid-only token leaked profile claims: %#v", openidClaims.Profile)
	}
	openidInfo := do(t, openidClient, http.MethodGet, primary+"/oidc/userinfo", nil, map[string]string{"Authorization": "Bearer " + openidTokens.AccessToken})
	defer openidInfo.Body.Close()
	var openidBody map[string]any
	if err := json.NewDecoder(io.LimitReader(openidInfo.Body, 32<<10)).Decode(&openidBody); err != nil {
		t.Fatal(err)
	}
	if openidInfo.StatusCode != http.StatusOK || openidBody["email"] != nil || openidBody["given_name"] != nil || openidBody["address"] != nil {
		t.Fatalf("openid-only UserInfo leaked profile: status=%d body=%#v", openidInfo.StatusCode, openidBody)
	}

	// Profile without the email scope follows the deployed username fallback policy.
	profileClient := newBrowserClient(t)
	profileVerifier := pkceVerifier(t)
	profileURL := oidcAuthorizationURLForClient(t, primary, "goauthy-dev", defaultRedirectURI, pkceChallenge(profileVerifier), "profile-claims-profile", "profile-claims-profile-nonce", "openid profile")
	profileCode, _ := loginForAuthorizationURL(t, profileClient, profileURL, primary, secondary, email, "Profile-Claims-Password-1A", "profile-claims-profile")
	profileTokens := exchangeCode(t, profileClient, primary, clientSecret, defaultRedirectURI, profileCode, profileVerifier)
	profileClaims := verifyPublicIDToken(t, profileTokens.IDToken, publicJWKS(t, profileClient, primary), primary)
	wantFallback := os.Getenv("GOAUTHY_E2E_EXPECT_EMAIL_FALLBACK") != "false"
	for _, value := range []*string{claims.Profile.PreferredUsername, refreshedClaims.Profile.PreferredUsername, profileClaims.Profile.PreferredUsername} {
		if wantFallback && (value == nil || *value != email) || !wantFallback && value != nil {
			t.Fatalf("preferred_username fallback enabled=%v value=%v", wantFallback, value)
		}
	}
	for _, node := range adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL")) {
		response := do(t, profileClient, http.MethodGet, node+"/oidc/userinfo", nil, map[string]string{"Authorization": "Bearer " + profileTokens.AccessToken})
		var info map[string]any
		err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&info)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || info["email"] != nil {
			t.Fatalf("profile-only UserInfo status=%d decode=%v", response.StatusCode, err)
		}
		if wantFallback && info["preferred_username"] != email || !wantFallback && info["preferred_username"] != nil {
			t.Fatalf("UserInfo preferred_username fallback enabled=%v value=%v", wantFallback, info["preferred_username"])
		}
	}
	if os.Getenv("GOAUTHY_E2E_TOKEN_EVENTS") == "1" {
		want := 3 // full, openid-only and profile-only authorization-code exchanges.
		if os.Getenv("GOAUTHY_E2E_EXPECT_TOKEN_EVENTS") == "false" {
			want = 0
		}
		for _, node := range adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL")) {
			count := 0
			for _, event := range queryLifecycleEvents(t, client, node) {
				if event.Type != eventlog.TokenIssued || event.Text == nil {
					continue
				}
				if *event.Text == "goauthy-dev (refresh_token) "+email {
					t.Fatal("refresh issued an event")
				}
				if *event.Text == "goauthy-dev (authorization_code) "+email {
					count++
					if event.IP != nil || event.Data != nil || event.Level != expectedTokenEventLevel(t) {
						t.Fatal("invalid user token event")
					}
				}
			}
			if count != want {
				t.Fatalf("user token events=%d want=%d", count, want)
			}
		}
	}

}

func assertProfileClaimValues(t *testing.T, p oidc.ProfileClaims, given, family, street, zip, city, country, phone string) {
	t.Helper()
	if p.Email == nil || *p.Email == "" || p.EmailVerified == nil || !*p.EmailVerified || p.GivenName == nil || *p.GivenName != given || p.FamilyName == nil || *p.FamilyName != family || p.PhoneNumber == nil || *p.PhoneNumber != phone || p.PhoneNumberVerified == nil || *p.PhoneNumberVerified || p.Address["street_address"] != street || p.Address["postal_code"] != zip || p.Address["locality"] != city || p.Address["country"] != country {
		t.Fatalf("unexpected profile claims: %#v", p)
	}
}

func assertUserInfoProfile(t *testing.T, client *http.Client, base, access, given, family, street string) {
	t.Helper()
	r := do(t, client, http.MethodGet, base+"/oidc/userinfo", nil, map[string]string{"Authorization": "Bearer " + access})
	defer r.Body.Close()
	var body map[string]any
	err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&body)
	address, _ := body["address"].(map[string]any)
	if r.StatusCode != http.StatusOK || err != nil || body["given_name"] != given || body["family_name"] != family || address["street_address"] != street {
		t.Fatalf("userinfo status=%d err=%v body=%#v", r.StatusCode, err, body)
	}
}
