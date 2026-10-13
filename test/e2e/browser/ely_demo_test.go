package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func TestElyDemoSSO(t *testing.T) {
	base, username, password := elyFixture(t)
	binary := os.Getenv("GOAUTHY_E2E_DEMO_BINARY")
	if binary == "" {
		t.Fatal("disposable demo binary is required")
	}
	u, _ := url.Parse(base)
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal("invalid fixture port")
	}
	admin, csrf := rbacAuthenticatedClient(t, base, base, username, password)
	headers := rbacMutationHeaders(csrf)
	email := "ely-demo-" + randomManagedUIID(t) + "@goauthy.e2e"
	const userPassword = "Ely-Demo-Service-1A"
	subject := createCatalogSessionUser(t, admin, base, headers, email, userPassword)
	t.Cleanup(func() {
		r := do(t, admin, http.MethodDelete, base+"/auth/v1/users/"+url.PathEscape(subject), nil, headers)
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Errorf("demo service-user cleanup status=%d", r.StatusCode)
		}
	})
	var origins [2]string
	var clientIDs [2]string
	for i := range origins {
		listen := "127.0.0.1:" + strconv.Itoa(port+3+i)
		origins[i] = "http://localhost:" + strconv.Itoa(port+3+i)
		id := "ely-demo-" + strconv.Itoa(i) + "-" + randomManagedUIID(t)
		clientIDs[i] = id
		body, err := json.Marshal(map[string]any{
			"id": id, "name": "Ely synthetic demo", "confidential": true,
			"redirect_uris": []string{origins[i] + "/callback"},
			"audience":      []string{defaultResourceIndicator}, "default_aud": []string{defaultResourceIndicator},
			"scopes": []string{"openid", "email", "profile"}, "default_scopes": []string{"openid", "email", "profile"},
			"enabled_flows": []string{"authorization_code"},
		})
		if err != nil {
			t.Fatal(err)
		}
		r := do(t, admin, http.MethodPost, base+"/auth/v1/clients", bytes.NewReader(body), headers)
		var managed crossClientExchanger
		err = json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&managed)
		r.Body.Close()
		if r.StatusCode != http.StatusCreated || err != nil || managed.ID != id || managed.Revision < 1 {
			t.Fatal("demo client creation failed")
		}
		t.Cleanup(func() { deleteCrossClientExchanger(t, admin, base, headers, &managed) })
		r = do(t, admin, http.MethodPost, base+"/auth/v1/clients/"+id+"/secret", nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(managed.Revision, 10))))
		var secret struct {
			Secret string `json:"secret"`
		}
		err = json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&secret)
		r.Body.Close()
		if r.StatusCode != http.StatusOK || err != nil || secret.Secret == "" {
			t.Fatal("demo client secret retrieval failed")
		}
		managed.Revision = revisionFromETag(t, r.Header.Get("ETag"), managed.Revision)
		secretFile := filepath.Join(t.TempDir(), "client-secret")
		if err := os.WriteFile(secretFile, []byte(secret.Secret), 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"-name", "Ely Demo " + strconv.Itoa(i), "-listen", listen, "-issuer", base, "-client-id", id, "-client-secret-file", secretFile}
		if i == 0 {
			args = append(args, "-force-login")
		}
		command := exec.Command(binary, args...)
		command.Stdout, command.Stderr = io.Discard, io.Discard
		if err := command.Start(); err != nil {
			t.Fatal("start disposable demo failed")
		}
		t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
		ready := false
		client := &http.Client{Timeout: time.Second}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			response, err := client.Get(origins[i] + "/healthz")
			if err == nil {
				response.Body.Close()
				ready = response.StatusCode == http.StatusNoContent
			}
			if ready {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		if !ready {
			t.Fatal("disposable demo did not become ready")
		}
	}
	ctx, cancel := newCollectionUIContext(t, nil, base)
	defer cancel()
	if err := chromedp.Run(ctx,
		chromedp.Navigate(origins[0]+"/"), chromedp.Click(`a[href="/login"]`),
		chromedp.WaitVisible(`input[name="username"]`),
		chromedp.SendKeys(`input[name="username"]`, email), chromedp.SendKeys(`input[name="password"]`, userPassword),
		chromedp.Click(`button[type="submit"]`), chromedp.WaitVisible(`#account-subject`),
	); err != nil {
		t.Fatal("Demo A browser OIDC login failed")
	}
	var subjectA, subjectB, emailA, emailB string
	if err := chromedp.Run(ctx, chromedp.Text(`#account-subject`, &subjectA), chromedp.Text(`#account-email`, &emailA),
		chromedp.Navigate(origins[1]+"/"), chromedp.Click(`a[href="/login"]`), chromedp.WaitVisible(`#account-subject`),
		chromedp.Text(`#account-subject`, &subjectB), chromedp.Text(`#account-email`, &emailB),
	); err != nil {
		t.Fatal("Demo B did not complete SSO without credentials")
	}
	if subjectA != subject || subjectB != subject || emailA != email || emailB != email {
		t.Fatal("demo apps did not verify the same synthetic identity")
	}
	var cookies []*network.Cookie
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		cookies, err = network.GetCookies().WithURLs(origins[:]).Do(ctx)
		return err
	})); err != nil {
		t.Fatal("read demo cookie metadata failed")
	}
	var appCookies [2]string
	for _, cookie := range cookies {
		for i, id := range clientIDs {
			if cookie.Name == "goauthy_demo_"+id+"_session" {
				appCookies[i] = cookie.Value
			}
		}
	}
	if appCookies[0] == "" || appCookies[1] == "" || appCookies[0] == appCookies[1] {
		t.Fatal("demo apps did not create separate sessions")
	}
	if err := chromedp.Run(ctx,
		chromedp.Navigate(origins[0]+"/"), chromedp.Click(`form[action="/logout"] button`), chromedp.WaitVisible(`a[href="/login"]`),
		chromedp.Click(`a[href="/login"]`), chromedp.WaitVisible(`input[name="username"]`),
		chromedp.Navigate(origins[1]+"/"), chromedp.WaitVisible(`#account-subject`), chromedp.Text(`#account-subject`, &subjectB),
	); err != nil || subjectB != subject {
		t.Fatal("A logout/forced login disturbed B session")
	}
}
