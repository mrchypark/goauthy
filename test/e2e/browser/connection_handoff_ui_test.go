package browser

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func testConnectionHandoffUI(t *testing.T, owner *http.Client, base string, cookie *http.Cookie, headers map[string]string, collection, connection string, create func(state string) (string, string)) {
	t.Helper()
	connectionURL := base + "/auth/v1/account/connections/" + url.PathEscape(collection) + "/" + url.PathEscape(connection)
	ctx, cancel := newCollectionUIContext(t, cookie, base)
	defer cancel()

	before := mustGrantList(t, owner, connectionURL, headers)
	state := strings.Repeat("U", 32)
	reviewURI, digest := create(state)
	_, _, user, password, _ := browserE2EConfig(t)
	if err := chromedp.Run(ctx, network.ClearBrowserCookies(), chromedp.Navigate(reviewURI),
		chromedp.WaitVisible(`input[name="username"]`), chromedp.SetValue(`input[name="username"]`, user), chromedp.SetValue(`input[name="password"]`, password)); err != nil {
		t.Fatalf("open cold handoff login: %v", err)
	}
	loginResponse, err := chromedp.RunResponse(ctx, chromedp.Click(`button[type="submit"]`))
	if err != nil || loginResponse == nil || loginResponse.Status != 200 {
		t.Fatalf("browser handoff login failed: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible("#handoff-approve")); err != nil {
		t.Fatalf("open handoff review: %v", err)
	}
	var validity struct {
		Checked  bool `json:"checked"`
		Validity bool `json:"valid"`
	}
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(() => { const c=document.querySelector('#handoff-approve input[name="reviewed"]'); const f=document.querySelector('#handoff-approve'); return {checked:c?.checked === true, valid:f?.checkValidity() === true}; })()`, &validity)); err != nil {
		t.Fatalf("inspect handoff approval form: %v", err)
	}
	if validity.Checked || validity.Validity {
		t.Fatal("handoff approval checkbox was preselected or form was valid before review")
	}
	if screenshot := os.Getenv("GOAUTHY_E2E_HANDOFF_SCREENSHOT"); screenshot != "" {
		var image []byte
		if err := chromedp.Run(ctx, chromedp.FullScreenshot(&image, 90)); err != nil {
			t.Fatalf("capture handoff screenshot: %v", err)
		}
		if err := os.WriteFile(screenshot, image, 0600); err != nil {
			t.Fatalf("write handoff screenshot: %v", err)
		}
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#handoff-approve button[type="submit"]`), chromedp.WaitVisible("#handoff-approve")); err != nil {
		t.Fatalf("unchecked handoff approval: %v", err)
	}
	if after := mustGrantList(t, owner, connectionURL, headers); string(after) != string(before) {
		t.Fatal("unchecked handoff approval created a grant")
	}

	if err := chromedp.Run(ctx,
		chromedp.Click(`#handoff-approve input[name="reviewed"]`),
		chromedp.Poll(`document.querySelector('#handoff-approve input[name="reviewed"]').checked && document.querySelector('#handoff-approve').checkValidity()`, nil),
	); err != nil {
		t.Fatalf("review handoff: %v", err)
	}
	response, err := chromedp.RunResponse(ctx, chromedp.Click(`#handoff-approve button[type="submit"]`))
	if err != nil || response == nil {
		t.Fatalf("submit handoff: %v", err)
	}
	if response.Status != 200 {
		t.Fatalf("handoff approval HTTP status=%v", response.Status)
	}
	var returnURI string
	var pageMessage string
	if err := chromedp.Run(ctx, chromedp.Text("body", &pageMessage)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.querySelector('#handoff-return')?.href || ''`, &returnURI)); err != nil {
		t.Fatalf("read approved handoff return: %v", err)
	}
	if returnURI == "" {
		t.Fatalf("approval response: %.200s", pageMessage)
	}
	assertHandoffReturn(t, returnURI, state, true)
	returned, _ := url.Parse(returnURI)
	after := mustGrantList(t, owner, connectionURL, headers)
	var grants []struct {
		ID      string `json:"id"`
		Digest  string `json:"connector_digest"`
		Revoked bool   `json:"revoked"`
	}
	if err := json.Unmarshal(after, &grants); err != nil {
		t.Fatal(err)
	}
	var grantID string
	for _, grant := range grants {
		if grant.ID == returned.Query().Get("grant_id") && grant.Digest == digest && !grant.Revoked {
			grantID = grant.ID
		}
	}
	if len(grants) != lenGrantList(t, before)+1 || grantID == "" {
		t.Fatal("approved handoff did not create exactly one grant")
	}
	revoke := do(t, owner, http.MethodDelete, connectionURL+"/grants/"+url.PathEscape(grantID), nil, sessionHeader(headers, "If-Match", `"1"`))
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke handoff grant status=%d", revoke.StatusCode)
	}
	grantBaseline := lenGrantList(t, mustGrantList(t, owner, connectionURL, headers))

	denialState := strings.Repeat("D", 32)
	denialURI, _ := create(denialState)
	if err := chromedp.Run(ctx, chromedp.Navigate(denialURI), chromedp.WaitVisible("#handoff-deny"), chromedp.Click(`#handoff-deny button[type="submit"]`), chromedp.WaitVisible("#handoff-return")); err != nil {
		t.Fatalf("deny handoff: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.querySelector('#handoff-return')?.href || ''`, &returnURI)); err != nil {
		t.Fatalf("read denied handoff return: %v", err)
	}
	assertHandoffReturn(t, returnURI, denialState, false)
	if denied := mustGrantList(t, owner, connectionURL, headers); lenGrantList(t, denied) != grantBaseline {
		t.Fatal("denied handoff changed grants")
	}
}

func lenGrantList(t *testing.T, body []byte) int {
	t.Helper()
	var grants []json.RawMessage
	if err := json.Unmarshal(body, &grants); err != nil {
		t.Fatal(err)
	}
	return len(grants)
}

func assertHandoffReturn(t *testing.T, raw, state string, approved bool) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != "https://rp.example.test/use-grant" || u.Query().Get("state") != state {
		t.Fatal("handoff return URL is invalid")
	}
	if approved {
		if u.Query().Get("grant_id") == "" || u.Query().Get("error") != "" || len(u.Query()) != 2 {
			t.Fatal("approved handoff return is invalid")
		}
	} else if u.Query().Get("error") != "access_denied" || u.Query().Get("grant_id") != "" || len(u.Query()) != 2 {
		t.Fatal("denied handoff return is invalid")
	}
}
