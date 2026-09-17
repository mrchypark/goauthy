package browser

import (
	"bytes"
	"net/http"
	"os"
	"testing"
)

func TestAdmissionBeforeReplacement(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ADMISSION") != "before" {
		t.Skip("set GOAUTHY_E2E_ADMISSION=before")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	key := createAdminAPIKey(t, admin, primary, csrf, "admission-before", []apiKeyAccess{{Group: "Blacklist", AccessRights: []string{"read", "create", "update", "delete"}}, {Group: "ApiKeys", AccessRights: []string{"delete"}}})
	h := map[string]string{"Authorization": "API-Key " + key, "Content-Type": "application/json", "X-Forwarded-For": "203.0.113.11"}
	postBlacklist(t, primary, h, `{"ip":"203.0.113.10/24","exp":4102444800}`, http.StatusBadRequest)
	postBlacklist(t, primary, h, `{"ip":"203.0.113.11/32","exp":1}`, http.StatusBadRequest)
	h["X-Forwarded-For"] = "203.0.113.10"
	postBlacklist(t, primary, h, `{"ip":"203.0.113.10/32","exp":4102444800}`, http.StatusOK)
	apiKeyStatus(t, newBrowserClient(t), http.MethodGet, secondary+"/auth/v1/blacklist/203.0.113.10/32", nil, map[string]string{"Authorization": "API-Key " + key}, http.StatusOK, "replicated blacklist")
	apiKeyStatus(t, newBrowserClient(t), http.MethodGet, secondary+"/oidc/jwks.json", nil, h, http.StatusForbidden, "blacklisted peer")
	apiKeyStatus(t, newBrowserClient(t), http.MethodGet, secondary+"/readyz", nil, h, http.StatusNoContent, "health bypass")
}

func TestAdmissionAfterReplacement(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ADMISSION") != "after" {
		t.Skip("set GOAUTHY_E2E_ADMISSION=after")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	key := createAdminAPIKey(t, admin, primary, csrf, "admission-after", []apiKeyAccess{{Group: "Blacklist", AccessRights: []string{"read", "delete"}}, {Group: "ApiKeys", AccessRights: []string{"delete"}}})
	h := map[string]string{"Authorization": "API-Key " + key, "X-Forwarded-For": "203.0.113.10"}
	apiKeyStatus(t, newBrowserClient(t), http.MethodGet, secondary+"/auth/v1/blacklist/203.0.113.10/32", nil, h, http.StatusOK, "blacklist survives replacement")
	apiKeyStatus(t, newBrowserClient(t), http.MethodGet, secondary+"/oidc/jwks.json", nil, h, http.StatusForbidden, "replaced pod enforces blacklist")
	h["X-Forwarded-For"] = "203.0.113.11"
	apiKeyStatus(t, newBrowserClient(t), http.MethodDelete, secondary+"/auth/v1/blacklist/203.0.113.10/32", nil, h, http.StatusOK, "blacklist cleanup")
	apiKeyStatus(t, newBrowserClient(t), http.MethodDelete, primary+"/auth/v1/api_keys/admission-after", nil, map[string]string{"Authorization": "API-Key " + key}, http.StatusOK, "API key cleanup")
	apiKeyStatus(t, admin, http.MethodDelete, primary+"/auth/v1/api_keys/admission-before", nil, rbacMutationHeaders(csrf), http.StatusOK, "pre-replacement API key cleanup")
}

func postBlacklist(t *testing.T, base string, headers map[string]string, body string, want int) {
	t.Helper()
	apiKeyStatus(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/blacklist", bytes.NewBufferString(body), headers, want, "blacklist mutation")
}
