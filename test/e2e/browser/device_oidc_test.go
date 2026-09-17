package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestDeviceOIDCLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_DEVICE_OIDC") != "1" {
		t.Skip("set GOAUTHY_E2E_DEVICE_OIDC=1 to run device OIDC E2E")
	}
	if os.Getenv("GOAUTHY_E2E_DEVICE_OIDC_UI") == "1" {
		t.Run("complete_uri", func(t *testing.T) { runDeviceOIDCLive(t, false) })
		t.Run("manual_code", func(t *testing.T) { runDeviceOIDCLive(t, true) })
		return
	}
	runDeviceOIDCLive(t, false)
}

func runDeviceOIDCLive(t *testing.T, manual bool) {
	t.Helper()
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	res := do(t, admin, http.MethodPatch, primary+"/auth/v1/users/bootstrap-admin", strings.NewReader(`{"put":[],"del":[]}`), rbacMutationHeaders(csrf))
	var original rbacMembership
	err := json.NewDecoder(io.LimitReader(res.Body, 8<<10)).Decode(&original)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("read fixture membership status=%d decode=%v", res.StatusCode, err)
	}
	group := rbacCreate(t, admin, primary, "groups", "device-oidc-"+pkceVerifier(t)[:12], nil, csrf)
	t.Cleanup(func() {
		rbacPatchMembership(t, admin, primary, csrf, original)
		response := do(t, admin, http.MethodDelete, primary+"/auth/v1/groups/"+url.PathEscape(group.ID), nil, rbacMutationHeaders(csrf))
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Errorf("delete fixture group status=%d", response.StatusCode)
		}
	})
	groupsWithFixture := append(slices.Clone(original.Groups), group.Name)
	slices.Sort(groupsWithFixture)
	rbacPatchMembership(t, admin, primary, csrf, rbacMembership{Roles: original.Roles, Groups: groupsWithFixture})
	client := newBrowserClient(t)
	grant := startDeviceOIDC(t, client, primary, clientSecret)
	if os.Getenv("GOAUTHY_E2E_DEVICE_OIDC_UI") == "1" {
		loginAndApproveDeviceUI(t, grant, primary, username, password, manual)
	} else {
		loginAndApproveDevice(t, newBrowserClient(t), grant, primary, tertiary, username, password)
	}
	tokens := deviceToken(t, client, secondary, clientSecret, grant.DeviceCode)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken == "" {
		t.Fatal("device OIDC token response is incomplete")
	}
	keys := publicJWKS(t, client, secondary)
	claims := verifyDeviceIDToken(t, tokens.IDToken, keys, primary, tokens.AccessToken)
	if claims.Subject == "" || !slices.Equal(claims.Audience, []string{"goauthy-dev"}) || claims.AuthorizedParty != "goauthy-dev" {
		t.Fatalf("unexpected device ID-token identity claims=%#v", claims)
	}
	if !claims.AuthTime.IsZero() || claims.SessionID != "" || claims.Nonce != "" || len(claims.AuthenticationMethods) != 0 {
		t.Fatalf("device ID token contains browser claims=%#v", claims)
	}
	groups := deviceUserInfoGroups(t, client, secondary, tokens.AccessToken, claims.Subject)
	if !slices.Contains(claims.Groups, group.Name) || !slices.Equal(claims.Groups, groups) {
		t.Fatalf("device ID-token groups=%v userinfo=%v", claims.Groups, groups)
	}

	assertDeviceTokenError(t, client, tertiary, clientSecret, grant.DeviceCode, "expired_token")
	oldGroupName := group.Name
	group = rbacRename(t, admin, primary, "groups", group.ID, group.Name+"-renamed", nil, csrf)
	refreshed := refresh(t, client, tertiary, clientSecret, tokens.RefreshToken)
	if refreshed.IDToken == "" || refreshed.IDToken == tokens.IDToken {
		t.Fatal("device refresh did not issue a new ID token")
	}
	refreshedClaims := verifyDeviceIDToken(t, refreshed.IDToken, publicJWKS(t, client, tertiary), primary, refreshed.AccessToken)
	if refreshedClaims.Subject != claims.Subject || !slices.Equal(refreshedClaims.Audience, []string{"goauthy-dev"}) || refreshedClaims.AccessTokenHash != oidc.AccessTokenHash(refreshed.AccessToken) {
		t.Fatalf("unexpected refreshed device ID-token claims=%#v", refreshedClaims)
	}
	refreshedGroups := deviceUserInfoGroups(t, client, tertiary, refreshed.AccessToken, claims.Subject)
	if !slices.Contains(refreshedClaims.Groups, group.Name) || slices.Contains(refreshedClaims.Groups, oldGroupName) || !slices.Equal(refreshedClaims.Groups, refreshedGroups) {
		t.Fatalf("refreshed device groups=%v userinfo=%v", refreshedClaims.Groups, refreshedGroups)
	}

	revokeAccessToken(t, client, secondary, clientSecret, refreshed.AccessToken)
	assertUserInfoRejected(t, client, secondary, http.MethodGet, "Bearer "+refreshed.AccessToken, "")
	revokeAccessToken(t, client, secondary, clientSecret, refreshed.RefreshToken)
	assertDeviceRefreshRejected(t, client, tertiary, clientSecret, refreshed.RefreshToken)
}

func startDeviceOIDC(t *testing.T, c *http.Client, base, secret string) deviceLoginGrant {
	t.Helper()
	form := url.Values{"client_id": {"goauthy-dev"}, "scope": {"openid groups offline_access"}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/oidc/device", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Bootstrap clients use client_secret_basic in the deployed configuration.
	req.SetBasicAuth("goauthy-dev", secret)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var grant deviceLoginGrant
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 16<<10)).Decode(&grant) != nil || grant.DeviceCode == "" || grant.UserCode == "" || grant.VerificationURIComplete == "" {
		t.Fatalf("device authorization status=%d", res.StatusCode)
	}
	grant.Scope = "openid groups offline_access"
	return grant
}

func verifyDeviceIDToken(t *testing.T, token string, keys jose.JSONWebKeySet, issuer, accessToken string) oidc.IDTokenClaims {
	t.Helper()
	claims, err := oidc.VerifyIDToken(token, keys, issuer, "goauthy-dev", time.Now().UTC())
	if err != nil {
		t.Fatalf("verify device ID token: %v", err)
	}
	if claims.AccessTokenHash != oidc.AccessTokenHash(accessToken) {
		t.Fatalf("device ID token at_hash mismatch")
	}
	return claims
}

func deviceUserInfoGroups(t *testing.T, c *http.Client, base, token, subject string) []string {
	t.Helper()
	res := userInfoResponse(t, c, http.MethodGet, base, "Bearer "+token, "")
	defer res.Body.Close()
	var info struct {
		Subject string   `json:"sub"`
		Groups  []string `json:"groups"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 16<<10)).Decode(&info) != nil || info.Subject != subject {
		t.Fatalf("device UserInfo status=%d subject=%q", res.StatusCode, info.Subject)
	}
	return info.Groups
}
