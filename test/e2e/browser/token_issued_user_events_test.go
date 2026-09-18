package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/oidc"
)

// TestTokenIssuedUserEvents qualifies user token issuance against the deployed
// event sink. It is separate from the machine-flow qualification because the
// managed client must be provisioned with a browser callback and user scopes.
func TestTokenIssuedUserEvents(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_TOKEN_EVENTS") != "1" {
		t.Skip("set GOAUTHY_E2E_TOKEN_EVENTS=1 to run user token event E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	username = "token-event-" + randomManagedUIID(t) + "@goauthy.e2e"
	password = "Token-Event-User-Password-1A"
	subject := createCatalogSessionUser(t, admin, primary, headers, username, password)
	t.Cleanup(func() {
		response := do(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(subject), nil, headers)
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Errorf("token event user cleanup status=%d", response.StatusCode)
		}
	})
	client := createCrossClientExchanger(t, admin, primary, headers, "password", "refresh_token")
	t.Cleanup(func() { deleteCrossClientExchanger(t, admin, primary, headers, client) })
	configureUserTokenEventClient(t, admin, primary, headers, client, redirectURI)

	nodes := adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL"))
	want := 1
	if os.Getenv("GOAUTHY_E2E_EXPECT_TOKEN_EVENTS") == "false" {
		want = 0
	}
	expected := map[string]int{
		"authorization_code": want,
		"password":           0,
		"refresh_token":      0,
	}
	ids := map[string]string{}

	userClient := newBrowserClient(t)
	verifier := pkceVerifier(t)
	state := "token-issued-user-" + randomManagedUIID(t)
	authorizeURL := oidcAuthorizationURLForClient(t, primary, client.ID, redirectURI, pkceChallenge(verifier), state, state+"-nonce", "openid email goauthy.read offline_access")
	code, _ := loginForAuthorizationURL(t, userClient, authorizeURL, primary, secondary, username, password, state)
	tokens := exchangeCodeForClient(t, userClient, primary, client.ID, client.Secret, redirectURI, code, verifier)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("authorization-code user token response is incomplete")
	}
	claims, err := oidc.VerifyIDToken(tokens.IDToken, publicJWKS(t, userClient, primary), primary, client.ID, time.Now().UTC())
	if err != nil {
		t.Fatalf("verify user event ID token: %v", err)
	}
	if claims.Profile.Email == nil || *claims.Profile.Email == "" {
		t.Fatal("verified authorization-code ID token omitted email")
	}
	email := *claims.Profile.Email
	assertUserTokenIssuedEvents(t, nodes, admin, client.ID, email, expected, ids)

	refreshed := tokenRequestForClient(t, newBrowserClient(t), secondary, client.ID, client.Secret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
	})
	if refreshed.AccessToken == "" {
		t.Fatal("refresh user token response is incomplete")
	}
	assertUserTokenIssuedEvents(t, nodes, admin, client.ID, email, expected, ids)

	replay := tokenResponseForClient(t, newBrowserClient(t), secondary, client.ID, client.Secret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	if replay.StatusCode != http.StatusBadRequest {
		replay.Body.Close()
		t.Fatalf("replayed authorization code status=%d, want %d", replay.StatusCode, http.StatusBadRequest)
	}
	replay.Body.Close()
	assertUserTokenIssuedEvents(t, nodes, admin, client.ID, email, expected, ids)

	passwordTokens := tokenRequestForClient(t, newBrowserClient(t), primary, client.ID, client.Secret, url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid goauthy.read"},
	})
	if passwordTokens.AccessToken == "" {
		t.Fatal("password user token response is incomplete")
	}
	expected["password"] = want
	assertUserTokenIssuedEvents(t, nodes, admin, client.ID, email, expected, ids)

	invalid := tokenResponseForClient(t, newBrowserClient(t), secondary, client.ID, client.Secret, url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {"incorrect-token-event-password"},
	})
	var rejected struct {
		Error string `json:"error"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(invalid.Body, 8<<10)).Decode(&rejected)
	invalid.Body.Close()
	if invalid.StatusCode != http.StatusBadRequest || decodeErr != nil || rejected.Error != "invalid_grant" {
		t.Fatalf("invalid password status=%d error=%q decode=%v", invalid.StatusCode, rejected.Error, decodeErr)
	}
	assertUserTokenIssuedEvents(t, nodes, admin, client.ID, email, expected, ids)
	waitTokenEventNotifications(t, ids)
}

func configureUserTokenEventClient(t *testing.T, admin *http.Client, primary string, headers map[string]string, client *crossClientExchanger, redirectURI string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"name":           "Cross-client exchange E2E",
		"confidential":   true,
		"enabled":        true,
		"redirect_uris":  []string{redirectURI},
		"audience":       []string{defaultResourceIndicator},
		"default_aud":    []string{crossClientDefaultAudienceA, crossClientDefaultAudienceB},
		"scopes":         []string{"openid", "email", "goauthy.read", "offline_access"},
		"default_scopes": []string{"goauthy.read"},
		"enabled_flows":  []string{"authorization_code", "password", "refresh_token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, admin, http.MethodPut, primary+"/auth/v1/clients/"+url.PathEscape(client.ID), bytes.NewReader(body), sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(client.Revision, 10))))
	var updated struct {
		Revision int64 `json:"revision"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&updated)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || updated.Revision <= client.Revision {
		t.Fatalf("user token event client update status=%d revision=%d prior=%d decode=%v", response.StatusCode, updated.Revision, client.Revision, err)
	}
	client.Revision = updated.Revision
}

func assertUserTokenIssuedEvents(t *testing.T, nodes []string, admin *http.Client, clientID, email string, expected map[string]int, ids map[string]string) {
	t.Helper()
	for _, node := range nodes {
		counts := map[string]int{}
		for _, event := range queryLifecycleEvents(t, admin, node) {
			if event.Type != eventlog.TokenIssued || event.Text == nil {
				continue
			}
			text := *event.Text
			if !strings.HasPrefix(text, clientID+" (") {
				continue
			}
			flow := ""
			for candidate := range expected {
				if text == clientID+" ("+candidate+") "+email {
					flow = candidate
					break
				}
			}
			if flow == "" {
				t.Fatalf("unexpected user token event text node=%s", node)
			}
			counts[flow]++
			if event.Level != expectedTokenEventLevel(t) || event.IP != nil || event.Data != nil || event.Timestamp <= 0 {
				t.Fatalf("invalid user token event node=%s flow=%s", node, flow)
			}
			if prior := ids[flow]; prior != "" && prior != event.ID {
				t.Fatalf("user token event ID differs across nodes flow=%s node=%s", flow, node)
			}
			ids[flow] = event.ID
		}
		for flow, want := range expected {
			if counts[flow] != want {
				t.Fatalf("user token event flow=%s node=%s events=%d want=%d", flow, node, counts[flow], want)
			}
		}
	}
}
