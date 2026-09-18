package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
)

const clientCredentialsClaim = "e2e_client_credentials_claim"

// TestBootstrapClientCredentialsClaimsAcrossPods treats successful reads from
// independently routed pods as the replication barrier. It has no time-based
// assertion.
func TestBootstrapClientCredentialsClaimsAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_CLIENT_CREDENTIALS_CLAIMS") != "1" {
		t.Skip("set GOAUTHY_E2E_CLIENT_CREDENTIALS_CLAIMS=1 to run bootstrap client-credentials claims E2E")
	}
	primary, secondary, tertiary, username, password, secret := rolesGroupsConfig(t)
	clientID := os.Getenv("GOAUTHY_E2E_CLIENT_CREDENTIALS_CLAIMS_CLIENT_ID")
	if clientID == "" {
		clientID = "browser-client"
	}
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)

	initial := clientCredentialsClaimsGet(t, admin, primary, clientID)
	t.Cleanup(func() { clientCredentialsClaimsRestore(t, admin, primary, clientID, initial, csrf) })

	nested := clientCredentialsClaims{Claims: json.RawMessage(`{"` + clientCredentialsClaim + `":"nested"}`), ClaimsAtRoot: false, Revision: initial.Revision}
	clientCredentialsClaimsPut(t, admin, primary, clientID, nested, csrf)
	nested = clientCredentialsClaimsGet(t, admin, secondary, clientID)
	clientCredentialsClaimsEqual(t, nested, false, json.RawMessage(`{"`+clientCredentialsClaim+`":"nested"}`))
	clientCredentialsClaimsAssertToken(t, newBrowserClient(t), primary, secondary, tertiary, clientID, secret, false, "nested")

	root := clientCredentialsClaims{Claims: json.RawMessage(`{"` + clientCredentialsClaim + `":"root"}`), ClaimsAtRoot: true, Revision: nested.Revision}
	clientCredentialsClaimsPut(t, admin, tertiary, clientID, root, csrf)
	root = clientCredentialsClaimsGet(t, admin, primary, clientID)
	clientCredentialsClaimsEqual(t, root, true, json.RawMessage(`{"`+clientCredentialsClaim+`":"root"}`))
	clientCredentialsClaimsAssertToken(t, newBrowserClient(t), primary, primary, secondary, clientID, secret, true, "root")

	cleared := clientCredentialsClaims{Claims: nil, ClaimsAtRoot: false, Revision: root.Revision}
	clientCredentialsClaimsPut(t, admin, secondary, clientID, cleared, csrf)
	cleared = clientCredentialsClaimsGet(t, admin, tertiary, clientID)
	clientCredentialsClaimsEqual(t, cleared, false, nil)
	clientCredentialsClaimsAssertNoTokenClaim(t, newBrowserClient(t), primary, tertiary, primary, clientID, secret)

	reserved := clientCredentialsClaims{Claims: json.RawMessage(`{"sub":"collision"}`), ClaimsAtRoot: true, Revision: cleared.Revision}
	clientCredentialsClaimsPut(t, admin, primary, clientID, reserved, csrf)
	reserved = clientCredentialsClaimsGet(t, admin, secondary, clientID)
	clientCredentialsClaimsEqual(t, reserved, true, json.RawMessage(`{"sub":"collision"}`))
	clientCredentialsClaimsAssertIssuanceRejected(t, newBrowserClient(t), secondary, clientID, secret)
	clientCredentialsClaimsRestore(t, admin, tertiary, clientID, initial, csrf)
}

type clientCredentialsClaims struct {
	Claims       json.RawMessage `json:"claims"`
	ClaimsAtRoot bool            `json:"claims_at_root"`
	Revision     int64           `json:"revision"`
}

func clientCredentialsClaimsGet(t *testing.T, client *http.Client, base, clientID string) clientCredentialsClaims {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(clientID)+"/claims", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var value clientCredentialsClaims
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&value)
	if bytes.Equal(value.Claims, []byte("null")) {
		value.Claims = nil
	}
	if response.StatusCode != http.StatusOK || err != nil || value.Revision < 0 || (len(value.Claims) != 0 && !json.Valid(value.Claims)) {
		t.Fatalf("get bootstrap client credentials claims status=%d value=%+v decode=%v", response.StatusCode, value, err)
	}
	return value
}

func clientCredentialsClaimsRestore(t *testing.T, client *http.Client, base, clientID string, value clientCredentialsClaims, csrf string) {
	t.Helper()
	value.Revision = clientCredentialsClaimsGet(t, client, base, clientID).Revision
	clientCredentialsClaimsPut(t, client, base, clientID, value, csrf)
}

func clientCredentialsClaimsPut(t *testing.T, client *http.Client, base, clientID string, value clientCredentialsClaims, csrf string) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, client, http.MethodPut, base+"/auth/v1/clients/"+url.PathEscape(clientID)+"/claims", bytes.NewReader(body), rbacMutationHeaders(csrf))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		t.Fatalf("put bootstrap client credentials claims status=%d body=%s", response.StatusCode, body)
	}
}

func clientCredentialsClaimsEqual(t *testing.T, got clientCredentialsClaims, root bool, want json.RawMessage) {
	t.Helper()
	if got.ClaimsAtRoot != root || !reflect.DeepEqual(got.Claims, want) {
		t.Fatalf("bootstrap client credentials claims=%s root=%t want=%s root=%t", got.Claims, got.ClaimsAtRoot, want, root)
	}
}

func clientCredentialsClaimsAssertToken(t *testing.T, client *http.Client, issuerBase, issueBase, jwksBase, clientID, secret string, atRoot bool, want string) {
	t.Helper()
	tokens := tokenRequestForClient(t, client, issueBase, clientID, secret, url.Values{"grant_type": {"client_credentials"}})
	claims := verifyPublicAccessToken(t, tokens.AccessToken, publicJWKS(t, client, jwksBase), issuerBase, clientID, "", "")
	raw := rbacTokenClaims(t, tokens.AccessToken)
	if atRoot {
		if !reflect.DeepEqual(raw[clientCredentialsClaim], json.RawMessage(`"`+want+`"`)) || !claims.CustomClaims.AtRoot || len(claims.CustomClaims.Nested) != 0 || len(claims.CustomClaims.Root) != 0 || !reflect.DeepEqual(claims.CustomClaims.Values[clientCredentialsClaim], json.RawMessage(`"`+want+`"`)) {
			t.Fatalf("root client credentials claim claims=%#v raw=%v want=%q", claims, raw, want)
		}
		return
	}
	if _, exists := raw[clientCredentialsClaim]; exists || claims.CustomClaims.AtRoot || len(claims.CustomClaims.Nested) != 0 || len(claims.CustomClaims.Root) != 0 || !reflect.DeepEqual(claims.CustomClaims.Values[clientCredentialsClaim], json.RawMessage(`"`+want+`"`)) {
		t.Fatalf("nested client credentials claim claims=%#v raw=%v want=%q", claims, raw, want)
	}
}

func clientCredentialsClaimsAssertNoTokenClaim(t *testing.T, client *http.Client, issuerBase, issueBase, jwksBase, clientID, secret string) {
	t.Helper()
	tokens := tokenRequestForClient(t, client, issueBase, clientID, secret, url.Values{"grant_type": {"client_credentials"}})
	claims := verifyPublicAccessToken(t, tokens.AccessToken, publicJWKS(t, client, jwksBase), issuerBase, clientID, "", "")
	raw := rbacTokenClaims(t, tokens.AccessToken)
	if _, root := raw[clientCredentialsClaim]; root || claims.CustomClaims.AtRoot || len(claims.CustomClaims.Nested) != 0 || len(claims.CustomClaims.Root) != 0 || len(claims.CustomClaims.Values) != 0 {
		t.Fatalf("cleared client credentials claim claims=%#v raw=%v", claims, raw)
	}
}

func clientCredentialsClaimsAssertIssuanceRejected(t *testing.T, client *http.Client, base, clientID, secret string) {
	t.Helper()
	response := tokenResponseForClient(t, client, base, clientID, secret, url.Values{"grant_type": {"client_credentials"}})
	defer response.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&token)
	if response.StatusCode == http.StatusOK || token.AccessToken != "" || (err != nil && !strings.Contains(response.Header.Get("Content-Type"), "application/json")) {
		t.Fatalf("reserved root-claim issuance status=%d token=%+v decode=%v", response.StatusCode, token, err)
	}
}
