package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// createOAuth2GrantHandoffUI creates OAuth2 delivery consent through the
// resource-server handoff and native Chromium review page.
func createOAuth2GrantHandoffUI(t *testing.T, owner *http.Client, base string, cookie *http.Cookie, headers map[string]string, collection, connection, consumer string, allowRefresh bool) ([]byte, int64) {
	t.Helper()
	ensureResourcePermissionScope(t, owner, base, headers, "goauthy.connections.write")
	requester := "oauth2-handoff-requester-" + randomManagedUIID(t)
	const returnURI = "https://requester.example/callback"
	body := `{"id":"` + requester + `","name":"OAuth2 handoff requester","confidential":false,"redirect_uris":["https://rp.example.test/use-grant","` + returnURI + `"],"audience":["` + useGrantResource + `"],"scopes":["goauthy.connections.write"],"default_scopes":["goauthy.connections.write"],"enabled_flows":["authorization_code"]}`
	r := do(t, owner, http.MethodPost, base+"/auth/v1/clients", strings.NewReader(body), headers)
	var created struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&created)
	r.Body.Close()
	if r.StatusCode != http.StatusCreated || err != nil || created.ID != requester || created.Revision < 1 {
		t.Fatalf("OAuth2 handoff requester create status=%d", r.StatusCode)
	}
	t.Cleanup(func() {
		get := do(t, owner, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(requester), nil, headers)
		var current struct {
			Revision int64 `json:"revision"`
		}
		err := json.NewDecoder(io.LimitReader(get.Body, 4096)).Decode(&current)
		get.Body.Close()
		if get.StatusCode != http.StatusOK || err != nil || current.Revision < 1 {
			t.Errorf("OAuth2 handoff requester cleanup lookup status=%d", get.StatusCode)
			return
		}
		remove := do(t, owner, http.MethodDelete, base+"/auth/v1/clients/"+url.PathEscape(requester), nil, sessionHeader(headers, "If-Match", `"`+strconv.FormatInt(current.Revision, 10)+`"`))
		remove.Body.Close()
		if remove.StatusCode != http.StatusNoContent {
			t.Errorf("OAuth2 handoff requester cleanup status=%d", remove.StatusCode)
		}
	})
	requesterToken := issueGrantResourceToken(t, owner, base, requester, useGrantResource, "goauthy.connections.write")
	state := "oauth2-handoff-" + randomManagedUIID(t) + randomManagedUIID(t)
	expires := time.Now().Add(time.Hour).UnixMilli()
	handoffBody, _ := json.Marshal(map[string]any{"collection_id": collection, "connection_id": connection, "consumer_client_id": consumer, "mode": "credential_delivery", "purpose": "OAuth2 credential delivery", "expires_at_unix_ms": expires, "return_uri": returnURI, "state": state, "allow_refresh": allowRefresh})
	bearer := map[string]string{"Authorization": "Bearer " + requesterToken, "Content-Type": "application/json"}
	r = do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/connection-handoffs", strings.NewReader(string(handoffBody)), bearer)
	var start struct {
		ID        string `json:"id"`
		ReviewURI string `json:"review_uri"`
		Review    struct {
			ReturnURI    string `json:"return_uri"`
			ReviewDigest string `json:"review_digest"`
			Grant        struct {
				ID           string `json:"id"`
				Consumer     string `json:"consumer_client_id"`
				Mode         string `json:"mode"`
				Resource     string `json:"resource"`
				Expires      int64  `json:"expires_at_unix_ms"`
				AllowRefresh bool   `json:"allow_refresh"`
			} `json:"grant"`
			OAuth2 *struct {
				ProviderID string   `json:"provider_id"`
				AccountID  string   `json:"account_id"`
				Scopes     []string `json:"scopes"`
				Connected  bool     `json:"connected"`
				State      string   `json:"state"`
				Version    int64    `json:"version"`
			} `json:"oauth2"`
		} `json:"review"`
	}
	err = json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&start)
	r.Body.Close()
	if r.StatusCode != http.StatusCreated || err != nil || start.ID == "" || start.ReviewURI != base+"/account/connection-handoffs/"+start.ID || start.Review.ReturnURI != returnURI || start.Review.ReviewDigest == "" || start.Review.Grant.ID != "" || start.Review.Grant.Consumer != consumer || start.Review.Grant.Mode != "credential_delivery" || start.Review.Grant.Resource != useGrantResource || start.Review.Grant.Expires != expires || start.Review.Grant.AllowRefresh != allowRefresh || start.Review.OAuth2 == nil || !start.Review.OAuth2.Connected || start.Review.OAuth2.State != "ready" || start.Review.OAuth2.ProviderID == "" || start.Review.OAuth2.AccountID == "" || len(start.Review.OAuth2.Scopes) == 0 || start.Review.OAuth2.Version < 1 {
		t.Fatalf("OAuth2 handoff review metadata mismatch: status=%d", r.StatusCode)
	}

	before := mustGrantList(t, owner, base+"/auth/v1/account/connections/"+url.PathEscape(collection)+"/"+url.PathEscape(connection), headers)
	ctx, cancel := newCollectionUIContext(t, cookie, base)
	defer cancel()
	_, _, user, password, _ := browserE2EConfig(t)
	if err := chromedp.Run(ctx, network.ClearBrowserCookies(), chromedp.Navigate(start.ReviewURI), chromedp.WaitVisible(`input[name="username"]`), chromedp.SetValue(`input[name="username"]`, user), chromedp.SetValue(`input[name="password"]`, password)); err != nil {
		t.Fatalf("open OAuth2 handoff login: %v", err)
	}
	response, err := chromedp.RunResponse(ctx, chromedp.Click(`button[type="submit"]`))
	if err != nil || response == nil || response.Status != http.StatusOK {
		t.Fatalf("OAuth2 handoff login failed: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible("#handoff-approve")); err != nil {
		t.Fatalf("open OAuth2 handoff review: %v", err)
	}
	var review struct {
		Checked, Valid bool
		Digest         string
		Text           string
	}
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(() => { const f=document.querySelector('#handoff-approve'), c=f?.querySelector('input[name="reviewed"]'), d=f?.querySelector('input[name="review_digest"]'); return {checked:c?.checked===true, valid:f?.checkValidity()===true, digest:d?.value||'', text:document.body?.textContent||''}; })()`, &review)); err != nil {
		t.Fatalf("inspect OAuth2 handoff review: %v", err)
	}
	refreshWarning := strings.Contains(review.Text, "Refresh delegation is enabled")
	if review.Checked || review.Valid || review.Digest != start.Review.ReviewDigest || !strings.Contains(review.Text, start.Review.OAuth2.ProviderID) || !strings.Contains(review.Text, start.Review.OAuth2.AccountID) || !strings.Contains(review.Text, start.Review.OAuth2.Scopes[0]) || !strings.Contains(review.Text, "access token") || !strings.Contains(review.Text, "No refresh token or client secret") || refreshWarning != allowRefresh {
		t.Fatal("OAuth2 handoff review contract failed")
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#handoff-approve button[type="submit"]`), chromedp.WaitVisible("#handoff-approve")); err != nil {
		t.Fatalf("unchecked OAuth2 handoff approval: %v", err)
	}
	if after := mustGrantList(t, owner, base+"/auth/v1/account/connections/"+url.PathEscape(collection)+"/"+url.PathEscape(connection), headers); string(after) != string(before) {
		t.Fatal("unchecked OAuth2 handoff approval created a grant")
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#handoff-approve input[name="reviewed"]`), chromedp.Poll(`document.querySelector('#handoff-approve input[name="reviewed"]').checked && document.querySelector('#handoff-approve').checkValidity()`, nil)); err != nil {
		t.Fatalf("review OAuth2 handoff: %v", err)
	}
	response, err = chromedp.RunResponse(ctx, chromedp.Click(`#handoff-approve button[type="submit"]`))
	if err != nil || response == nil || response.Status != http.StatusOK {
		t.Fatalf("approve OAuth2 handoff: %v", err)
	}
	var returnLink string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.querySelector('#handoff-return')?.href || ''`, &returnLink)); err != nil {
		t.Fatal("read OAuth2 handoff return")
	}
	parsed, err := url.Parse(returnLink)
	if err != nil || parsed.Scheme+"://"+parsed.Host+parsed.Path != returnURI || parsed.Query().Get("state") != state || parsed.Query().Get("grant_id") == "" || len(parsed.Query()) != 2 {
		t.Fatal("OAuth2 handoff return mismatch")
	}
	grantID := parsed.Query().Get("grant_id")
	after := mustGrantList(t, owner, base+"/auth/v1/account/connections/"+url.PathEscape(collection)+"/"+url.PathEscape(connection), headers)
	var grants []json.RawMessage
	if json.Unmarshal(after, &grants) != nil || len(grants) != lenGrantList(t, before)+1 {
		t.Fatal("OAuth2 handoff approval did not create exactly one grant")
	}
	var grantJSON []byte
	for _, candidate := range grants {
		var identity struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(candidate, &identity)
		if identity.ID == grantID {
			grantJSON = candidate
			break
		}
	}
	if len(grantJSON) == 0 {
		t.Fatal("OAuth2 handoff grant missing from owner endpoint")
	}
	var grant struct {
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
		Revoked            bool   `json:"revoked"`
		AllowRefresh       bool   `json:"allow_refresh"`
	}
	if json.Unmarshal(grantJSON, &grant) != nil || grant.ID != grantID || grant.Owner == "" || grant.CollectionID != collection || grant.ConnectionID != connection || grant.Consumer != consumer || grant.Mode != "credential_delivery" || grant.Purpose != "OAuth2 credential delivery" || grant.Resource != useGrantResource || grant.Generation == "" || grant.ConsumerGeneration == "" || grant.Provider != start.Review.OAuth2.ProviderID || grant.Digest != "" || grant.Revision != 1 || grant.ProviderRevision < 1 || grant.Expires != expires || grant.Revoked || grant.AllowRefresh != allowRefresh {
		t.Fatal("OAuth2 handoff grant metadata mismatch")
	}
	return grantJSON, expires
}
