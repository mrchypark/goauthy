package chaos

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestDevicePendingGrantSurvivesPodReplacement proves that the pending device
// grant is replicated: issuance is on one pod, approval and redemption happen
// after that pod is replaced, and the same device code cannot be replayed.
func TestDevicePendingGrantSurvivesPodReplacement(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_DEVICE_PENDING_CHAOS") != "1" {
		t.Skip("set GOAUTHY_E2E_DEVICE_PENDING_CHAOS=1 to run device pending chaos E2E")
	}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	secret := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	username := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME")
	password := os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	contextName := os.Getenv("GOAUTHY_E2E_CHAOS_CONTEXT")
	pod := os.Getenv("GOAUTHY_E2E_CHAOS_DELETE_POD")
	prefix := os.Getenv("GOAUTHY_E2E_CHAOS_POD_PREFIX")
	namespace := os.Getenv("GOAUTHY_E2E_CHAOS_NAMESPACE")
	if namespace == "" {
		namespace = "goauthy"
	}
	if primary == "" || secondary == "" || tertiary == "" || secret == "" || username == "" || password == "" || contextName == "" || pod == "" || prefix == "" {
		t.Fatal("device pending chaos gate requires all three URLs, client secret/browser credentials, context, pod, and pod prefix")
	}
	if namespace != "goauthy" || !strings.HasPrefix(contextName, "kind-goauthy-") || pod != "goauthy-0" || prefix != "goauthy-" || strings.ContainsAny(pod, "/\n\r\t") {
		t.Fatalf("refusing pod outside explicit owned prefix: pod=%q prefix=%q namespace=%q", pod, prefix, namespace)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	oldUID := chaosPodUID(t, ctx, contextName, namespace, pod)
	noRedirect := func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: noRedirect}
	grant := issueChaosDeviceGrant(t, client, primary, secret)

	kubectl(t, ctx, "--context", contextName, "-n", namespace, "delete", "pod", pod, "--wait=true")
	kubectl(t, ctx, "--context", contextName, "-n", namespace, "wait", "--for=condition=Ready", "pod/"+pod, "--timeout=180s")
	newUID := chaosPodUID(t, ctx, contextName, namespace, pod)
	if newUID == "" || newUID == oldUID {
		t.Fatalf("pod replacement did not change UID: old=%q new=%q", oldUID, newUID)
	}

	verify := &http.Client{Timeout: 15 * time.Second, Jar: mustCookieJar(t), CheckRedirect: noRedirect}
	loginURL := secondary + "/oidc/device/login?" + url.Values{"user_code": {grant.UserCode}}.Encode()
	page := chaosRequest(t, verify, http.MethodGet, loginURL, nil, nil)
	pageBody := readChaosBody(t, page)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("device login page status=%d body=%q", page.StatusCode, pageBody)
	}
	interaction, csrf := hiddenChaosInputs(pageBody)
	if interaction == "" || csrf == "" {
		t.Fatal("device login page missing interaction or CSRF")
	}
	form := url.Values{"interaction": {interaction}, "csrf_token": {csrf}, "username": {username}, "password": {password}}
	response := chaosRequest(t, verify, http.MethodPost, secondary+"/oidc/device/login", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": primary, "Sec-Fetch-Site": "same-origin"})
	location := response.Header.Get("Location")
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || !strings.Contains(location, "/oidc/device/verify") {
		t.Fatalf("device login status=%d location=%q", response.StatusCode, location)
	}
	verifyPage := chaosRequest(t, verify, http.MethodGet, secondary+"/oidc/device/verify?"+url.Values{"user_code": {grant.UserCode}}.Encode(), nil, nil)
	verifyBody := readChaosBody(t, verifyPage)
	if verifyPage.StatusCode != http.StatusOK {
		t.Fatalf("verify page status=%d body=%q", verifyPage.StatusCode, verifyBody)
	}
	verifyCSRF := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(verifyBody)
	if len(verifyCSRF) != 2 {
		t.Fatal("verify page missing CSRF")
	}
	approve := url.Values{"user_code": {grant.UserCode}, "csrf_token": {verifyCSRF[1]}, "action": {"approve"}}
	response = chaosRequest(t, verify, http.MethodPost, tertiary+"/oidc/device/verify", strings.NewReader(approve.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": primary, "Sec-Fetch-Site": "same-origin"})
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("device approval status=%d", response.StatusCode)
	}

	token := redeemChaosDevice(t, client, tertiary, secret, grant.DeviceCode)
	assertChaosIntrospection(t, client, tertiary, secret, token, true)
	replayStatus, replayError := redeemChaosDeviceStatus(t, client, secondary, secret, grant.DeviceCode)
	if replayStatus != http.StatusBadRequest || replayError != "expired_token" {
		t.Fatalf("device code replay status=%d error=%q, want %d expired_token", replayStatus, replayError, http.StatusBadRequest)
	}
}

type chaosDeviceGrant struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
}

func issueChaosDeviceGrant(t *testing.T, client *http.Client, base, secret string) chaosDeviceGrant {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/oidc/device", strings.NewReader(url.Values{"client_id": {"goauthy-dev"}, "scope": {"goauthy.read"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("goauthy-dev", secret)
	r, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("device authorization status=%d", r.StatusCode)
	}
	var grant chaosDeviceGrant
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&grant); err != nil || grant.DeviceCode == "" || grant.UserCode == "" {
		t.Fatalf("invalid device grant: %#v err=%v", grant, err)
	}
	return grant
}

func chaosPodUID(t *testing.T, ctx context.Context, clusterContext, namespace, pod string) string {
	output, err := exec.CommandContext(ctx, "kubectl", "--context", clusterContext, "-n", namespace, "get", "pod", pod, "-o", "jsonpath={.metadata.uid}").CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) == "" {
		t.Fatalf("get owned pod UID: %v: %s", err, output)
	}
	return strings.TrimSpace(string(output))
}
func readChaosBody(t *testing.T, r *http.Response) string {
	b, err := io.ReadAll(io.LimitReader(r.Body, 32<<10))
	r.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func hiddenChaosInputs(body string) (string, string) {
	re := regexp.MustCompile(`name="(interaction|csrf_token)" value="([^"]+)"`)
	values := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		values[m[1]] = m[2]
	}
	return values["interaction"], values["csrf_token"]
}
func redeemChaosDevice(t *testing.T, client *http.Client, base, secret, code string) string {
	r := redeemChaosDeviceRequest(t, client, base, secret, code)
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("device redemption status=%d", r.StatusCode)
	}
	var v struct {
		AccessToken string `json:"access_token"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&v) != nil || v.AccessToken == "" {
		t.Fatal("device redemption missing access token")
	}
	return v.AccessToken
}
func redeemChaosDeviceStatus(t *testing.T, client *http.Client, base, secret, code string) (int, string) {
	r := redeemChaosDeviceRequest(t, client, base, secret, code)
	defer r.Body.Close()
	var payload struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&payload)
	return r.StatusCode, payload.Error
}
func redeemChaosDeviceRequest(t *testing.T, client *http.Client, base, secret, code string) *http.Response {
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/oidc/token", strings.NewReader(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {code}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("goauthy-dev", secret)
	out, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func assertChaosIntrospection(t *testing.T, client *http.Client, base, secret, token string, active bool) {
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("goauthy-dev", secret)
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var v struct {
		Active   bool   `json:"active"`
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
		Subject  string `json:"sub"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&v) != nil || v.Active != active {
		t.Fatalf("introspection status=%d active=%v want=%v", response.StatusCode, v.Active, active)
	}
	if active && (v.ClientID != "goauthy-dev" || !strings.Contains(" "+v.Scope+" ", " goauthy.read ") || v.Subject == "") {
		t.Fatalf("introspection identity client=%q scope=%q subject=%q", v.ClientID, v.Scope, v.Subject)
	}
}
func mustCookieJar(t *testing.T) http.CookieJar {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}
