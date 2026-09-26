package browser

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"
)

// createOAuth2GrantUI creates the one explicit OAuth2 credential-delivery
// consent grant through the account UI and returns its public grant metadata.
func createOAuth2GrantUI(t *testing.T, owner *http.Client, base string, cookie *http.Cookie, headers map[string]string, collection, connection, consumer string, allowRefresh bool) ([]byte, int64) {
	t.Helper()
	connectionPath := base + "/auth/v1/account/connections/" + url.PathEscape(collection) + "/" + url.PathEscape(connection)
	var metadata struct {
		Provider string   `json:"provider_id"`
		Account  string   `json:"account_id"`
		Scopes   []string `json:"scopes"`
	}
	metadataResponse := do(t, owner, http.MethodGet, connectionPath+"/oauth2", nil, headers)
	if metadataResponse.StatusCode != http.StatusOK || json.NewDecoder(metadataResponse.Body).Decode(&metadata) != nil {
		metadataResponse.Body.Close()
		t.Fatal("OAuth2 metadata lookup failed")
	}
	metadataResponse.Body.Close()
	if metadata.Provider == "" || metadata.Account == "" || len(metadata.Scopes) == 0 {
		t.Fatal("OAuth2 metadata is incomplete")
	}

	before := mustGrantList(t, owner, connectionPath, headers)
	snapshotGrants := func(data []byte) map[string][]byte {
		var entries []json.RawMessage
		if err := json.Unmarshal(data, &entries); err != nil {
			t.Fatalf("decode OAuth2 grants: %v", err)
		}
		byID := make(map[string][]byte, len(entries))
		for _, entry := range entries {
			var identity struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(entry, &identity); err != nil || identity.ID == "" {
				t.Fatalf("OAuth2 grant snapshot entry is invalid: %v", err)
			}
			var value any
			if err := json.Unmarshal(entry, &value); err != nil {
				t.Fatalf("decode OAuth2 grant snapshot entry: %v", err)
			}
			canonical, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("canonicalize OAuth2 grant snapshot entry: %v", err)
			}
			if _, exists := byID[identity.ID]; exists {
				t.Fatalf("duplicate OAuth2 grant ID %q", identity.ID)
			}
			byID[identity.ID] = canonical
		}
		return byID
	}
	beforeByID := snapshotGrants(before)
	assertUnchanged := func(phase string) {
		afterByID := snapshotGrants(mustGrantList(t, owner, connectionPath, headers))
		if len(afterByID) != len(beforeByID) {
			t.Fatalf("OAuth2 grant %s changed grant count: before=%d after=%d", phase, len(beforeByID), len(afterByID))
		}
		for id, want := range beforeByID {
			if got, ok := afterByID[id]; !ok || string(got) != string(want) {
				t.Fatalf("OAuth2 grant %s changed existing grant %q", phase, id)
			}
		}
	}

	ctx, cancel := newCollectionUIContext(t, cookie, base)
	defer cancel()
	selector := func(name string) string { return `[data-` + name + `="` + connection + `"]` }
	js := func(name string) string {
		b, _ := json.Marshal(selector(name))
		return "document.querySelector(" + string(b) + ")"
	}
	if err := chromedp.Run(ctx,
		chromedp.Navigate(base+"/account"), connectionUIReady(),
		chromedp.SetValue("#connections-collection", collection),
		chromedp.Evaluate(`document.querySelector('#connections-collection').dispatchEvent(new Event('change', {bubbles:true}))`, nil),
		connectionUIReady(), chromedp.Click(selector("connection-grants")),
		chromedp.Poll(js("grant-review")+`?.disabled === false`, nil),
		chromedp.Poll(js("grant-create")+`?.disabled === true && `+js("grant-review")+`?.checked === false`, nil),
		chromedp.Poll(`(() => { const text = document.querySelector('[data-grant-panel="`+connection+`"]')?.textContent || ''; return text.includes(`+quoteJS(metadata.Provider)+`) && text.includes(`+quoteJS(metadata.Account)+`) && `+scopesJS(metadata.Scopes)+` && text.includes('access token') && text.includes('refresh token'); })()`, nil),
		chromedp.SetValue(selector("grant-consumer"), consumer),
		chromedp.SetValue(selector("grant-purpose"), "oauth-browser-consent"),
		chromedp.Evaluate(`(() => { const el = `+js("grant-expiry")+`; const date = new Date(Date.now()+3600000); date.setMinutes(date.getMinutes()-date.getTimezoneOffset()); el.value = date.toISOString().slice(0,16); el.dispatchEvent(new Event('input',{bubbles:true})); })()`, nil),
	); err != nil {
		t.Fatalf("open OAuth2 grant consent: %v", err)
	}
	var expiry int64
	if err := chromedp.Run(ctx, chromedp.Evaluate(`new Date(`+js("grant-expiry")+`.value).getTime()`, &expiry)); err != nil || expiry <= 0 {
		t.Fatalf("read OAuth2 grant expiry: %v", err)
	}
	if path := os.Getenv("GOAUTHY_E2E_OAUTH2_GRANT_SCREENSHOT"); path != "" {
		var screenshot []byte
		if err := chromedp.Run(ctx, chromedp.FullScreenshot(&screenshot, 90)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, screenshot, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if allowRefresh {
		if err := chromedp.Run(ctx, chromedp.Click(selector("grant-refresh"))); err != nil {
			t.Fatalf("select refresh consent: %v", err)
		}
	}
	assertUnchanged("review")
	if err := chromedp.Run(ctx,
		chromedp.Click(selector("grant-review")),
		chromedp.SetValue(selector("grant-purpose"), "changed-purpose"),
		chromedp.Evaluate(js("grant-purpose")+`.dispatchEvent(new Event('input',{bubbles:true}))`, nil),
		chromedp.Poll(js("grant-review")+`?.checked === false && `+js("grant-create")+`?.disabled === true`, nil),
		chromedp.SetValue(selector("grant-purpose"), "oauth-browser-consent"),
		chromedp.Click(selector("grant-review")),
		chromedp.Poll(js("grant-create")+`?.disabled === false`, nil),
		chromedp.Click(selector("grant-create")),
		chromedp.Poll(js("grant-status")+`?.textContent?.includes('created')`, nil),
	); err != nil {
		t.Fatalf("approve OAuth2 grant consent: %v", err)
	}

	type oauth2Grant struct {
		ID                 string `json:"id"`
		Owner              string `json:"owner_subject"`
		CollectionID       string `json:"collection_id"`
		ConnectionID       string `json:"connection_id"`
		Consumer           string `json:"consumer_client_id"`
		Mode               string `json:"mode"`
		Purpose            string `json:"purpose"`
		Resource           string `json:"resource"`
		Generation         string `json:"generation"`
		ConsumerGeneration string `json:"consumer_generation"`
		Provider           string `json:"provider_id"`
		Digest             string `json:"connector_digest"`
		Revision           int64  `json:"revision"`
		ProviderRevision   int64  `json:"provider_revision"`
		Expires            int64  `json:"expires_at_unix_ms"`
		AllowRefresh       bool   `json:"allow_refresh"`
		Revoked            bool   `json:"revoked"`
	}
	var grants []oauth2Grant
	after := mustGrantList(t, owner, connectionPath, headers)
	afterByID := snapshotGrants(after)
	if len(afterByID) != len(beforeByID)+1 {
		t.Fatal("OAuth2 approval did not add exactly one grant")
	}
	for id, want := range beforeByID {
		if got, ok := afterByID[id]; !ok || string(got) != string(want) {
			t.Fatalf("OAuth2 approval changed existing grant %q", id)
		}
	}
	if err := json.Unmarshal(after, &grants); err != nil {
		t.Fatal(err)
	}
	var created []oauth2Grant
	for _, grant := range grants {
		if _, existed := beforeByID[grant.ID]; !existed && grant.Consumer == consumer {
			created = append(created, grant)
		}
	}
	if len(created) != 1 {
		t.Fatalf("OAuth2 UI did not create exactly one new grant for %q: %#v", consumer, grants)
	}
	grant := created[0]
	if grant.ID == "" || grant.Owner == "" || grant.CollectionID != collection || grant.ConnectionID != connection || grant.Consumer != consumer || grant.Mode != "credential_delivery" || grant.Purpose != "oauth-browser-consent" || grant.Resource != useGrantResource || grant.Generation == "" || grant.ConsumerGeneration == "" || grant.Provider == "" || grant.Digest != "" || grant.Revision != 1 || grant.ProviderRevision <= 0 || grant.Revoked || grant.AllowRefresh != allowRefresh || grant.Expires != expiry {
		t.Fatalf("OAuth2 UI grant mismatch: %#v", grants)
	}
	grantJSON, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	return grantJSON, expiry
}

func quoteJS(value string) string {
	b, _ := json.Marshal(value)
	return string(b)
}

func scopesJS(scopes []string) string {
	parts := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		parts = append(parts, "text.includes("+quoteJS(scope)+")")
	}
	return strings.Join(parts, " && ")
}
