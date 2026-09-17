package browser

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/getkin/kin-openapi/openapi3"
)

// TestOpenAPIDocs is deliberately opt-in: it needs a running deployment and Chrome.
func TestOpenAPIDocs(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_OPENAPI") != "1" {
		t.Skip("set GOAUTHY_E2E_OPENAPI=1 to run OpenAPI E2E")
	}
	raw := strings.Split(strings.Trim(os.Getenv("GOAUTHY_E2E_OPENAPI_URLS"), ","), ",")
	if len(raw) != 1 && len(raw) != 3 {
		t.Fatal("GOAUTHY_E2E_OPENAPI_URLS must contain one or three URLs")
	}
	for i := range raw {
		raw[i] = strings.TrimRight(strings.TrimSpace(raw[i]), "/")
		if raw[i] == "" {
			t.Fatal("empty OpenAPI URL")
		}
	}
	mode := os.Getenv("GOAUTHY_E2E_OPENAPI_MODE")
	if mode != "disabled" && mode != "private" && mode != "public" {
		t.Fatal("GOAUTHY_E2E_OPENAPI_MODE must be disabled, private, or public")
	}
	var cookie *http.Cookie
	if mode == "private" {
		phase := os.Getenv("GOAUTHY_E2E_OPENAPI_PHASE")
		if phase != "initial" && phase != "post-restart" {
			t.Fatal("private phase must be initial or post-restart")
		}
		if os.Getenv("GOAUTHY_E2E_OPENAPI_STATE") == "" || os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME") == "" || os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD") == "" {
			t.Fatal("private mode requires credentials and state path")
		}
		if os.Getenv("GOAUTHY_E2E_OPENAPI_PHASE") == "post-restart" {
			b, err := os.ReadFile(os.Getenv("GOAUTHY_E2E_OPENAPI_STATE"))
			if err != nil {
				t.Fatal(err)
			}
			var s struct{ Name, Value string }
			if json.Unmarshal(b, &s) != nil || s.Name == "" || s.Value == "" {
				t.Fatal("invalid session state")
			}
			cookie = &http.Cookie{Name: s.Name, Value: s.Value}
		} else {
			v := pkceVerifier(t)
			_, cookie = loginForAuthorizationURL(t, newBrowserClient(t), oidcAuthorizationURL(t, raw[0], defaultRedirectURI, pkceChallenge(v), "openapi-docs", "openapi-docs-nonce"), raw[0], raw[0], os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD"), "openapi-docs")
			b, _ := json.Marshal(struct{ Name, Value string }{cookie.Name, cookie.Value})
			if err := os.WriteFile(os.Getenv("GOAUTHY_E2E_OPENAPI_STATE"), b, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, base := range raw {
		assertDocsMode(t, base, mode, cookie)
	}
	if mode != "disabled" {
		assertDocsAssets(t, raw[0], mode == "private")
	}
	if mode == "private" && os.Getenv("GOAUTHY_E2E_OPENAPI_PHASE") == "post-restart" {
		assertOpenAPIStaleLogout(t, raw)
	}
}

func assertOpenAPIStaleLogout(t *testing.T, bases []string) {
	t.Helper()
	b, err := os.ReadFile(os.Getenv("GOAUTHY_E2E_OPENAPI_STATE"))
	if err != nil {
		t.Fatal(err)
	}
	var s struct{ Name, Value string }
	if json.Unmarshal(b, &s) != nil || s.Name == "" {
		t.Fatal("invalid OpenAPI session state")
	}
	client := clientWithCookie(t, bases[0], &http.Cookie{Name: s.Name, Value: s.Value})
	stale := make([]*http.Client, len(bases))
	for i, base := range bases {
		stale[i] = clientWithCookie(t, base, &http.Cookie{Name: s.Name, Value: s.Value})
	}
	confirm := do(t, client, http.MethodGet, bases[0]+"/oidc/logout?client_id=goauthy-dev&post_logout_redirect_uri="+url.QueryEscape(defaultPostLogoutRedirectURI), nil, nil)
	if confirm.StatusCode != http.StatusOK {
		confirm.Body.Close()
		t.Fatalf("logout confirmation status=%d", confirm.StatusCode)
	}
	token, ok := hiddenInputValue(readLimitedBody(t, confirm), "confirmation")
	confirm.Body.Close()
	if !ok {
		t.Fatal("logout confirmation token missing")
	}
	// The logout mutation goes through a different node to prove replicated revocation.
	confirm = do(t, client, http.MethodPost, bases[len(bases)-1]+"/oidc/logout", strings.NewReader("confirmation="+url.QueryEscape(token)), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"})
	confirm.Body.Close()
	if confirm.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout status=%d", confirm.StatusCode)
	}
	for i, base := range bases {
		r := do(t, stale[i], http.MethodGet, base+"/auth/v1/docs/", nil, nil)
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("stale docs status=%d node=%s", r.StatusCode, base)
		}
	}
}

func assertDocsMode(t *testing.T, base, mode string, cookie *http.Cookie) {
	t.Helper()
	c := newBrowserClient(t)
	r := do(t, c, http.MethodGet, base+"/auth/v1/docs/", nil, nil)
	status := r.StatusCode
	r.Body.Close()
	want := http.StatusNotFound
	if mode == "private" {
		want = http.StatusUnauthorized
	}
	if mode == "public" {
		want = http.StatusOK
	}
	for _, path := range []string{"/", "/index.html", "/openapi.json", "/swagger-ui.css", "/swagger-ui-bundle.js", "/swagger-initializer.js"} {
		r := do(t, newBrowserClient(t), http.MethodGet, base+"/auth/v1/docs"+path, nil, nil)
		got := r.StatusCode
		r.Body.Close()
		if got != want {
			t.Fatalf("docs mode=%s %s status=%d want=%d", mode, base+path, got, want)
		}
	}
	if status != want {
		t.Fatalf("docs mode=%s %s status=%d want=%d", mode, base, status, want)
	}
	if mode != "private" {
		return
	}
	for _, headers := range []map[string]string{
		{"Authorization": "Bearer invalid", "Sec-Fetch-Site": "same-origin"},
		{"Authorization": "API-Key invalid", "Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Site": "cross-site"},
	} {
		r := do(t, clientWithCookie(t, base, cookie), http.MethodGet, base+"/auth/v1/docs/openapi.json", nil, headers)
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unsafe authenticated docs status=%d", r.StatusCode)
		}
	}
	for _, endpoint := range []string{"/", "/index.html", "/openapi.json"} {
		r := do(t, clientWithCookie(t, base, cookie), http.MethodGet, base+"/auth/v1/docs"+endpoint, nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
		if r.StatusCode != http.StatusOK {
			r.Body.Close()
			t.Fatalf("authenticated docs %s status=%d", endpoint, r.StatusCode)
		}
		if endpoint == "/openapi.json" {
			data, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
			if err != nil {
				r.Body.Close()
				t.Fatal(err)
			}
			spec, err := openapi3.NewLoader().LoadFromData(data)
			if err != nil || spec.Validate(t.Context()) != nil || spec.Paths.Value("/oidc/token") == nil || spec.Paths.Value("/auth/v1/kv/keys") == nil {
				r.Body.Close()
				t.Fatal("invalid OpenAPI document")
			}
		}
		r.Body.Close()
	}
}

func assertDocsAssets(t *testing.T, base string, private bool) {
	t.Helper()
	if private {
		// The authenticated client is established by assertDocsMode; use a fresh login here only
		// when the browser phase has not persisted state.
		state := os.Getenv("GOAUTHY_E2E_OPENAPI_STATE")
		b, err := os.ReadFile(state)
		if err != nil {
			t.Fatal(err)
		}
		var s struct{ Name, Value string }
		if json.Unmarshal(b, &s) != nil {
			t.Fatal("invalid OpenAPI session state")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alloc, cancelAlloc := chromedp.NewExecAllocator(ctx, append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Headless, chromedp.NoFirstRun)...)
	defer cancelAlloc()
	browser, cancelBrowser := chromedp.NewContext(alloc)
	defer cancelBrowser()
	origin, _ := url.Parse(base)
	var bad string
	var mu sync.Mutex
	var operations int
	chromedp.ListenTarget(browser, func(v any) {
		if e, ok := v.(*network.EventRequestWillBeSent); ok {
			u, _ := url.Parse(e.Request.URL)
			// Embedded Swagger CSS icons are local data URLs, not network egress.
			if strings.HasPrefix(e.Request.URL, "data:image/") {
				return
			}
			if u.Scheme != origin.Scheme || u.Host != origin.Host {
				mu.Lock()
				bad = e.Request.URL
				mu.Unlock()
			}
		}
	})
	actions := []chromedp.Action{network.Enable()}
	if private {
		b, _ := os.ReadFile(os.Getenv("GOAUTHY_E2E_OPENAPI_STATE"))
		var s struct{ Name, Value string }
		_ = json.Unmarshal(b, &s)
		actions = append(actions, chromedp.ActionFunc(func(c context.Context) error { return network.SetCookie(s.Name, s.Value).WithURL(base).Do(c) }))
	}
	actions = append(actions, chromedp.Navigate(base+"/auth/v1/docs/"), chromedp.WaitVisible("#swagger-ui"), chromedp.WaitVisible(".opblock"), chromedp.Evaluate(`document.querySelectorAll('.opblock').length`, &operations))
	if err := chromedp.Run(browser, actions...); err != nil {
		t.Fatalf("Swagger UI did not initialize: %v", err)
	}
	mu.Lock()
	external := bad
	mu.Unlock()
	if external != "" || operations == 0 {
		t.Fatalf("Swagger UI requests=%q operations=%d", external, operations)
	}
}
