package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	browser "github.com/mrchypark/goauthy/internal/browser"
)

type managedClientResponse struct {
	ID                   string  `json:"id"`
	Name                 string  `json:"name"`
	Revision             int64   `json:"revision"`
	Secret               string  `json:"secret"`
	BackchannelLogoutURI *string `json:"backchannel_logout_uri"`
}

func TestManagedClientsHTTPWorkflow(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_MANAGED_CLIENTS") != "1" {
		t.Skip("set GOAUTHY_E2E_MANAGED_CLIENTS=1 to run managed-client E2E")
	}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	username, password := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	if primary == "" || secondary == "" || username == "" || password == "" {
		t.Fatal("GOAUTHY_E2E_URL, GOAUTHY_E2E_SECONDARY_URL, and browser credentials are required")
	}
	bases := []string{primary, secondary}
	if tertiary != "" {
		bases = append(bases, tertiary)
	}
	client := managedBrowserClient(t)
	cookie := managedLogin(t, client, primary, secondary, username, password)
	csrf, err := browser.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	id := "managed-e2e-" + hex.EncodeToString(suffix[:])
	backchannelLogoutURI := "https://rp.example.test/backchannel"
	updatedBackchannelLogoutURI := "https://rp.example.test/backchannel-updated"
	createBody := []byte(fmt.Sprintf(`{"id":%q,"name":"Managed E2E","confidential":true,"redirect_uris":["https://rp.example.test/callback"],"backchannel_logout_uri":%q}`, id, backchannelLogoutURI))
	for _, base := range bases {
		r := managedDo(t, client, http.MethodGet, base+"/auth/v1/clients", nil, headers)
		b := managedBody(t, r)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("list status=%d on %s", r.StatusCode, base)
		}
		if bytes.Contains(b, []byte("secret")) {
			t.Fatalf("list leaked secret on %s", base)
		}
	}
	createResponse := managedDo(t, client, http.MethodPost, primary+"/auth/v1/clients", bytes.NewReader(createBody), headers)
	createRaw := managedBody(t, createResponse)
	if bytes.Contains(bytes.ToLower(createRaw), []byte(`"secret"`)) {
		t.Fatalf("create response leaked secret: %s", createRaw)
	}
	var created managedClientResponse
	if createResponse.StatusCode != http.StatusCreated || json.Unmarshal(createRaw, &created) != nil {
		t.Fatalf("create status=%d body=%s", createResponse.StatusCode, createRaw)
	}
	if created.ID != id || created.Secret != "" || created.BackchannelLogoutURI == nil || *created.BackchannelLogoutURI != backchannelLogoutURI {
		t.Fatalf("create response=%+v", created)
	}
	etag := created.Revision
	if created.Revision <= 0 {
		t.Fatal("create response missing revision/ETag")
	}
	currentRevision := etag
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		h := cloneHeaders(headers)
		h["If-Match"] = revisionHeader(currentRevision)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(id), nil)
		if err != nil {
			t.Errorf("cleanup request: %v", err)
			return
		}
		for k, v := range h {
			req.Header.Set(k, v)
		}
		r, err := client.Do(req)
		if err != nil {
			t.Errorf("cleanup client: %v", err)
			return
		}
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Errorf("cleanup client status=%d", r.StatusCode)
		}
	})
	for _, base := range bases {
		r := managedDo(t, client, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(id), nil, headers)
		got := managedJSON(t, r, http.StatusOK)
		if got.Secret != "" || got.ID != id || got.BackchannelLogoutURI == nil || *got.BackchannelLogoutURI != backchannelLogoutURI {
			t.Fatalf("detail=%+v", got)
		}
	}
	secret := managedSecret(t, client, primary, id, http.MethodPost, etag, headers)
	if secret == "" {
		t.Fatal("empty client secret")
	}

	updateBody := func(enabled bool, uri *string) []byte {
		uriJSON := "null"
		if uri != nil {
			uriJSON = strconv.Quote(*uri)
		}
		return []byte(fmt.Sprintf(`{"name":"Managed E2E Updated","confidential":true,"redirect_uris":["https://rp.example.test/callback"],"enabled":%t,"scopes":["profile"],"default_scopes":["profile"],"enabled_flows":["client_credentials","password","refresh_token"],"backchannel_logout_uri":%s}`, enabled, uriJSON))
	}
	update := func(enabled bool, revision int64, uri *string) managedClientResponse {
		h := cloneHeaders(headers)
		h["If-Match"] = revisionHeader(revision)
		return managedJSON(t, managedDo(t, client, http.MethodPut, primary+"/auth/v1/clients/"+url.PathEscape(id), bytes.NewReader(updateBody(enabled, uri)), h), http.StatusOK)
	}
	updated := update(true, etag, &updatedBackchannelLogoutURI)
	currentRevision = updated.Revision
	if updated.Revision <= etag {
		t.Fatalf("revision did not advance: %d -> %d", etag, updated.Revision)
	}
	if updated.BackchannelLogoutURI == nil || *updated.BackchannelLogoutURI != updatedBackchannelLogoutURI {
		t.Fatalf("updated backchannel logout URI=%v", updated.BackchannelLogoutURI)
	}
	for _, base := range bases {
		r := managedDo(t, client, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(id), nil, headers)
		got := managedJSON(t, r, http.StatusOK)
		if got.BackchannelLogoutURI == nil || *got.BackchannelLogoutURI != updatedBackchannelLogoutURI {
			t.Fatalf("updated detail on %s=%v", base, got.BackchannelLogoutURI)
		}
	}
	cleared := update(true, updated.Revision, nil)
	currentRevision = cleared.Revision
	if cleared.BackchannelLogoutURI != nil {
		t.Fatalf("cleared backchannel logout URI=%v", cleared.BackchannelLogoutURI)
	}
	for _, base := range bases {
		r := managedDo(t, client, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(id), nil, headers)
		got := managedJSON(t, r, http.StatusOK)
		if got.BackchannelLogoutURI != nil {
			t.Fatalf("cleared detail on %s=%v", base, got.BackchannelLogoutURI)
		}
	}
	stale := cloneHeaders(headers)
	stale["If-Match"] = revisionHeader(etag)
	staleResp := managedDo(t, client, http.MethodPut, primary+"/auth/v1/clients/"+url.PathEscape(id), bytes.NewReader(updateBody(true, nil)), stale)
	staleResp.Body.Close()
	if staleResp.StatusCode != http.StatusConflict {
		t.Fatalf("stale update status=%d", staleResp.StatusCode)
	}
	for _, base := range bases {
		managedTokenStatus(t, base, id, secret, http.StatusOK)
	}
	managedPasswordAcrossNodes(t, bases, id, secret, username, password)
	disabled := update(false, cleared.Revision, nil)
	currentRevision = disabled.Revision
	managedTokenStatus(t, primary, id, secret, http.StatusUnauthorized)
	reenabled := update(true, disabled.Revision, nil)
	currentRevision = reenabled.Revision
	if reenabled.Revision <= disabled.Revision {
		t.Fatal("reenable revision did not advance")
	}
	managedTokenStatus(t, primary, id, secret, http.StatusOK)
	rotated := managedSecret(t, client, primary, id, http.MethodPut, reenabled.Revision, headers)
	currentRevision = rotatedRevision(t, client, primary, id, headers)
	if rotated == secret {
		t.Fatal("rotation reused secret")
	}
	managedTokenStatus(t, primary, id, secret, http.StatusUnauthorized)
	for _, base := range bases {
		managedTokenStatus(t, base, id, rotated, http.StatusOK)
	}
	deleteHeaders := cloneHeaders(headers)
	deleteHeaders["If-Match"] = revisionHeader(reenabled.Revision)
	d := managedDo(t, client, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(id), nil, deleteHeaders)
	d.Body.Close()
	if d.StatusCode != http.StatusConflict {
		t.Fatalf("stale delete status=%d", d.StatusCode)
	}
	deleteHeaders["If-Match"] = revisionHeader(currentRevision)
	d = managedDo(t, client, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(id), nil, deleteHeaders)
	d.Body.Close()
	if d.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", d.StatusCode)
	}
	deleted = true
	managedTokenStatus(t, primary, id, rotated, http.StatusUnauthorized)
	r := managedDo(t, client, http.MethodGet, primary+"/auth/v1/clients/"+url.PathEscape(id), nil, headers)
	r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted detail status=%d", r.StatusCode)
	}
	r = managedDo(t, client, http.MethodPost, primary+"/auth/v1/clients", bytes.NewReader(createBody), headers)
	r.Body.Close()
	if r.StatusCode == http.StatusCreated {
		t.Fatal("deleted client ID was reusable")
	}
	bootstrap := cloneHeaders(headers)
	bootstrap["If-Match"] = revisionHeader(1)
	bootstrapID := os.Getenv("GOAUTHY_BOOTSTRAP_CLIENT_ID")
	if bootstrapID == "" {
		bootstrapID = "goauthy-dev"
	}
	r = managedDo(t, client, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(bootstrapID), nil, bootstrap)
	r.Body.Close()
	if r.StatusCode == http.StatusNoContent {
		t.Fatal("bootstrap client was deletable")
	}
}

func rotatedRevision(t *testing.T, c *http.Client, base, id string, headers map[string]string) int64 {
	r := managedDo(t, c, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(id), nil, headers)
	return managedJSON(t, r, http.StatusOK).Revision
}
func managedSecret(t *testing.T, c *http.Client, base, id string, method string, rev int64, h map[string]string) string {
	h = cloneHeaders(h)
	h["If-Match"] = revisionHeader(rev)
	r := managedDo(t, c, method, base+"/auth/v1/clients/"+url.PathEscape(id)+"/secret", nil, h)
	return managedJSON(t, r, http.StatusOK).Secret
}
func revisionHeader(rev int64) string { return strconv.Quote(strconv.FormatInt(rev, 10)) }
func managedTokenStatus(t *testing.T, base, id, secret string, want int) {
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"profile"}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	r, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != want {
		t.Fatalf("token status=%d want=%d", r.StatusCode, want)
	}
}
func managedJSON(t *testing.T, r *http.Response, want int) managedClientResponse {
	b := managedBody(t, r)
	if r.StatusCode != want {
		t.Fatalf("status=%d want=%d body=%s", r.StatusCode, want, b)
	}
	var v managedClientResponse
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Revision == 0 {
		if e := r.Header.Get("ETag"); e != "" {
			v.Revision, _ = strconv.ParseInt(strings.Trim(e, "\""), 10, 64)
		}
	}
	return v
}
func managedBody(t *testing.T, r *http.Response) []byte {
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func managedDo(t *testing.T, c *http.Client, m, e string, b io.Reader, h map[string]string) *http.Response {
	r, err := http.NewRequestWithContext(t.Context(), m, e, b)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range h {
		r.Header.Set(k, v)
	}
	out, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func cloneHeaders(h map[string]string) map[string]string {
	o := map[string]string{}
	for k, v := range h {
		o[k] = v
	}
	return o
}
func managedBrowserClient(t *testing.T) *http.Client {
	j, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: j, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func managedLogin(t *testing.T, c *http.Client, primary, secondary, user, password string) *http.Cookie {
	sum := sha256.Sum256([]byte("managed-client-e2e"))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	v := url.Values{"response_type": {"code"}, "client_id": {"goauthy-dev"}, "redirect_uri": {"http://localhost:5555/callback"}, "scope": {"openid goauthy.read"}, "state": {"managed-client-e2e"}, "code_challenge": {"" + challenge}, "code_challenge_method": {"S256"}}
	r := managedDo(t, c, http.MethodGet, primary+"/oidc/authorize?"+v.Encode(), nil, nil)
	body := managedBody(t, r)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("authorize status=%d", r.StatusCode)
	}
	marker := `name="interaction" value="`
	i := bytes.Index(body, []byte(marker))
	if i < 0 {
		t.Fatal("login interaction missing")
	}
	body = body[i+len(marker):]
	j := bytes.IndexByte(body, '"')
	interaction := string(body[:j])
	f := url.Values{"interaction": {interaction}, "username": {user}, "password": {password}}
	r = managedDo(t, c, http.MethodPost, secondary+"/auth/login", strings.NewReader(f.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if r.StatusCode != http.StatusFound && r.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status=%d", r.StatusCode)
	}
	for _, cookie := range r.Cookies() {
		if strings.Contains(cookie.Name, "goauthy_session") {
			r.Body.Close()
			return cookie
		}
	}
	t.Fatal("session cookie missing")
	return nil
}

func managedPasswordAcrossNodes(t *testing.T, bases []string, id, secret, username, password string) {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second}
	post := func(base string, form url.Values, want int) string {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/oidc/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(id, secret)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var tokens struct {
			Access  string `json:"access_token"`
			Refresh string `json:"refresh_token"`
			ID      string `json:"id_token"`
			Scope   string `json:"scope"`
		}
		if response.StatusCode != want {
			t.Fatalf("password workflow status=%d want=%d", response.StatusCode, want)
		}
		if want != http.StatusOK {
			return ""
		}
		if json.NewDecoder(response.Body).Decode(&tokens) != nil || tokens.Access == "" || tokens.Refresh == "" || tokens.ID == "" || tokens.Scope != "profile" {
			t.Fatal("password workflow token contract")
		}
		return tokens.Refresh
	}
	post(bases[0], url.Values{"grant_type": {"password"}, "username": {username}, "password": {"incorrect-password"}}, http.StatusBadRequest)
	for i, base := range bases {
		refresh := post(base, url.Values{"grant_type": {"password"}, "username": {username}, "password": {password}, "scope": {"offline_access"}}, http.StatusOK)
		post(bases[(i+1)%len(bases)], url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, http.StatusOK)
	}
}
