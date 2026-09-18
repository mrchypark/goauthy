package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

const (
	adminAPIKeyName      = "e2e-api-key"
	adminAPIKeyRole      = "e2e-api-key-role"
	adminAPIKeyAttribute = "e2e-api-key-attr"
	adminAPIKeyScope     = "e2e-api-key-scope"
	adminAPIKeyOtherName = "e2e-api-key-other"
)

func TestAdminAPIKeysAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ADMIN_API_KEYS") != "1" {
		t.Skip("set GOAUTHY_E2E_ADMIN_API_KEYS=1 to run API-key E2E")
	}
	primary, secondary, tertiary, username, password, _ := rolesGroupsConfig(t)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	access := []apiKeyAccess{
		{Group: "ApiKeys", AccessRights: []string{"read", "update", "delete"}},
		{Group: "Roles", AccessRights: []string{"read", "create"}},
		{Group: "Scopes", AccessRights: []string{"read", "create"}},
		{Group: "UserAttributes", AccessRights: []string{"create"}},
	}
	secret := createAdminAPIKey(t, admin, primary, csrf, adminAPIKeyName, access)
	listAdminAPIKeysWithoutSecret(t, admin, secondary, secret)

	keyClient := newBrowserClient(t)
	keyHeader := map[string]string{"Authorization": "API-Key " + secret}
	apiKeyStatus(t, keyClient, http.MethodGet, secondary+"/auth/v1/roles", nil, keyHeader, http.StatusOK, "roles read")
	apiKeyCreateRole(t, keyClient, tertiary, secret)
	apiKeyStatus(t, admin, http.MethodGet, primary+"/auth/v1/roles", nil, map[string]string{"Authorization": "Bearer wrong"}, http.StatusUnauthorized, "wrong scheme does not fall back to cookie")
	apiKeyStatus(t, admin, http.MethodGet, primary+"/auth/v1/roles", nil, map[string]string{"Authorization": "API-Key malformed"}, http.StatusUnauthorized, "malformed key does not fall back to cookie")

	apiKeyCreateAttribute(t, keyClient, primary, secret)
	apiKeyCreateScope(t, keyClient, secondary, secret)
	apiKeyStatus(t, keyClient, http.MethodGet, tertiary+"/auth/v1/scopes", nil, keyHeader, http.StatusOK, "claims scope read")
	reducedAccess := []apiKeyAccess{
		{Group: "ApiKeys", AccessRights: []string{"read", "update", "delete"}},
		{Group: "Roles", AccessRights: []string{"read", "create"}},
	}
	updateAdminAPIKeyAccess(t, admin, tertiary, csrf, reducedAccess)
	apiKeyStatus(t, keyClient, http.MethodGet, primary+"/auth/v1/groups", nil, keyHeader, http.StatusForbidden, "groups denied")
	apiKeyStatus(t, keyClient, http.MethodGet, primary+"/auth/v1/scopes", nil, keyHeader, http.StatusForbidden, "claims denied after access reduction")

	rotated := rotateAdminAPIKey(t, keyClient, tertiary, secret)
	apiKeyStatus(t, keyClient, http.MethodGet, primary+"/auth/v1/roles", nil, keyHeader, http.StatusUnauthorized, "old key revoked after rotate")
	rotatedHeader := map[string]string{"Authorization": "API-Key " + rotated}
	apiKeyStatus(t, keyClient, http.MethodGet, secondary+"/auth/v1/roles", nil, rotatedHeader, http.StatusOK, "rotated key works")
	apiKeyStatus(t, keyClient, http.MethodGet, primary+"/auth/v1/api_keys/"+adminAPIKeyName+"/test", nil, rotatedHeader, http.StatusOK, "key self test")
	apiKeyStatus(t, keyClient, http.MethodGet, primary+"/auth/v1/api_keys/"+adminAPIKeyOtherName+"/test", nil, rotatedHeader, http.StatusForbidden, "key other test")

	apiKeyStatus(t, keyClient, http.MethodDelete, tertiary+"/auth/v1/api_keys/"+adminAPIKeyName, nil, rotatedHeader, http.StatusOK, "key delete")
	apiKeyStatus(t, keyClient, http.MethodGet, secondary+"/auth/v1/roles", nil, rotatedHeader, http.StatusUnauthorized, "deleted key rejected across pod")
}

type apiKeyAccess struct {
	Group        string   `json:"group"`
	AccessRights []string `json:"access_rights"`
}

func createAdminAPIKey(t *testing.T, client *http.Client, base, csrf, name string, access []apiKeyAccess) string {
	t.Helper()
	body := apiKeyJSON(t, map[string]any{"name": name, "access": access})
	response := do(t, client, http.MethodPost, base+"/auth/v1/api_keys", body, rbacMutationHeaders(csrf))
	secretBody, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	response.Body.Close()
	secret := string(secretBody)
	if response.StatusCode != http.StatusOK || err != nil || !strings.HasPrefix(secret, name+"$") || len(secret) != len(name)+1+64 {
		t.Fatalf("create API key status=%d secret shape valid=%t read=%v", response.StatusCode, strings.HasPrefix(secret, name+"$") && len(secret) == len(name)+1+64, err)
	}
	return secret
}

func listAdminAPIKeysWithoutSecret(t *testing.T, client *http.Client, base, secret string) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/api_keys", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || !bytes.Contains(body, []byte(`"name":"`+adminAPIKeyName+`"`)) || bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte(`"secret"`)) {
		t.Fatalf("list API keys status=%d has-name=%t leaks-secret=%t decode=%v", response.StatusCode, bytes.Contains(body, []byte(`"name":"`+adminAPIKeyName+`"`)), bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte(`"secret"`)), err)
	}
}

func apiKeyCreateRole(t *testing.T, client *http.Client, base, secret string) {
	t.Helper()
	apiKeyStatus(t, client, http.MethodPost, base+"/auth/v1/roles", apiKeyJSON(t, map[string]any{"role": adminAPIKeyRole, "meta": map[string]any{"source": "api-key"}}), map[string]string{"Authorization": "API-Key " + secret, "Content-Type": "application/json"}, http.StatusOK, "role create")
}

func apiKeyCreateAttribute(t *testing.T, client *http.Client, base, secret string) {
	t.Helper()
	apiKeyStatus(t, client, http.MethodPost, base+"/auth/v1/users/attr", apiKeyJSON(t, map[string]any{"name": adminAPIKeyAttribute, "desc": "API key E2E attribute"}), map[string]string{"Authorization": "API-Key " + secret, "Content-Type": "application/json"}, http.StatusOK, "attribute create")
}

func apiKeyCreateScope(t *testing.T, client *http.Client, base, secret string) {
	t.Helper()
	apiKeyStatus(t, client, http.MethodPost, base+"/auth/v1/scopes", apiKeyJSON(t, map[string]any{"scope": adminAPIKeyScope, "attr_include_id": []string{adminAPIKeyAttribute}}), map[string]string{"Authorization": "API-Key " + secret, "Content-Type": "application/json"}, http.StatusOK, "scope create")
}

func updateAdminAPIKeyAccess(t *testing.T, client *http.Client, base, csrf string, access []apiKeyAccess) {
	t.Helper()
	apiKeyStatus(t, client, http.MethodPut, base+"/auth/v1/api_keys/"+adminAPIKeyName, apiKeyJSON(t, map[string]any{"name": adminAPIKeyName, "access": access}), rbacMutationHeaders(csrf), http.StatusOK, "browser key access update")
}

func rotateAdminAPIKey(t *testing.T, client *http.Client, base, secret string) string {
	t.Helper()
	response := do(t, client, http.MethodPut, base+"/auth/v1/api_keys/"+adminAPIKeyName+"/secret", nil, map[string]string{"Authorization": "API-Key " + secret})
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	response.Body.Close()
	rotated := string(body)
	if response.StatusCode != http.StatusOK || err != nil || !strings.HasPrefix(rotated, adminAPIKeyName+"$") || rotated == secret {
		t.Fatalf("rotate API key status=%d changed=%t decode=%v", response.StatusCode, rotated != secret, err)
	}
	return rotated
}

func apiKeyStatus(t *testing.T, client *http.Client, method, endpoint string, body io.Reader, headers map[string]string, want int, label string) {
	t.Helper()
	response := do(t, client, method, endpoint, body, headers)
	response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("%s status=%d want=%d", label, response.StatusCode, want)
	}
}

func apiKeyJSON(t *testing.T, value any) io.Reader {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(body)
}
