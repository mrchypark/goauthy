package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
)

func assertUserValuesConfig(t *testing.T, client *http.Client, base, mode string, headers map[string]string, want int) {
	t.Helper()
	r := do(t, client, http.MethodGet, base+"/auth/v1/users/values_config", nil, headers)
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	r.Body.Close()
	if err != nil || r.StatusCode != want || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("values config node=%s status=%d want=%d read=%v", base, r.StatusCode, want, err)
	}
	if want != 200 {
		if strings.Contains(string(raw), `"preferred_username"`) {
			t.Fatal("denied config exposed policy")
		}
		return
	}
	preferred := map[string]any{"preferred_username": "optional", "immutable": true, "blacklist": []any{"admin", "administrator", "root"}, "pattern_html": `^[a-z][a-z0-9_\-]{1,61}$`, "pattern_hint": nil, "email_fallback": true}
	if mode == "custom" {
		preferred["preferred_username"], preferred["immutable"] = "required", false
		preferred["blacklist"] = []any{"team_12"}
		preferred["pattern_html"], preferred["pattern_hint"] = `^Team_[0-9]{2}$`, "Team code"
	}
	wantBody := map[string]any{"given_name": "required", "family_name": "optional", "birthdate": "optional", "street": "optional", "zip": "optional", "city": "optional", "country": "optional", "phone": "optional", "tz": "optional", "revalidate_during_login": false, "preferred_username": preferred}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil || !reflect.DeepEqual(got, wantBody) {
		t.Fatalf("values config mismatch node=%s mode=%s body=%s err=%v", base, mode, raw, err)
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Fatal("configuration must be JSON")
	}
}

func TestUserValuesConfigPrivateAcrossPods(t *testing.T) {
	mode := os.Getenv("GOAUTHY_E2E_PREFERRED_USERNAME_POLICY")
	if mode == "" || os.Getenv("GOAUTHY_E2E_USER_VALUES_CONFIG_PRIVATE") != "1" {
		t.Skip("requires preferred policy fixture after closing registration")
	}
	if mode != "default" && mode != "custom" {
		t.Fatal("unknown fixture mode")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL"))
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	member, _ := rbacAuthenticatedClient(t, primary, secondary, "policy-admin-username-"+mode+"@goauthy.e2e", updateUserPassword)
	delegated, _ := rbacAuthenticatedClient(t, primary, secondary, "policy-delegated-"+mode+"@goauthy.e2e", updateUserPassword)
	anonymous := newBrowserClient(t)
	readName := "values-config-read-" + mode
	readKey := createAdminAPIKey(t, admin, primary, csrf, readName, []apiKeyAccess{{Group: "Users", AccessRights: []string{"read"}}})
	updateKey := createAdminAPIKey(t, admin, primary, csrf, "values-config-update-"+mode, []apiKeyAccess{{Group: "Users", AccessRights: []string{"update"}}})
	readHeaders := map[string]string{"Authorization": "API-Key " + readKey}
	for _, base := range nodes {
		assertUserValuesConfig(t, anonymous, base, mode, nil, 401)
		assertUserValuesConfig(t, member, base, mode, nil, 401)
		assertUserValuesConfig(t, admin, base, mode, nil, 200)
		assertUserValuesConfig(t, delegated, base, mode, nil, 200)
		assertUserValuesConfig(t, anonymous, base, mode, readHeaders, 200)
		assertUserValuesConfig(t, admin, base, mode, map[string]string{"Authorization": "API-Key " + updateKey}, 403)
		assertUserValuesConfig(t, admin, base, mode, map[string]string{"Authorization": "API-Key invalid"}, 401)
		assertUserValuesConfig(t, admin, base, mode, map[string]string{"Sec-Fetch-Site": "cross-site"}, 401)
	}
	apiKeyStatus(t, admin, http.MethodDelete, primary+"/auth/v1/api_keys/"+readName, nil, rbacMutationHeaders(csrf), 200, "revoke config read key")
	role := rbacAssertListed(t, admin, primary, "roles", rbacEntity{Name: "rauthy_admin:preferred/*"})
	apiKeyStatus(t, admin, http.MethodDelete, secondary+"/auth/v1/roles/"+role.ID, nil, rbacMutationHeaders(csrf), 200, "revoke delegated config reader")
	for _, base := range nodes {
		assertUserValuesConfig(t, anonymous, base, mode, readHeaders, 401)
		assertUserValuesConfig(t, delegated, base, mode, nil, 401)
		assertUserValuesConfig(t, admin, base, mode, nil, 200)
	}
}
