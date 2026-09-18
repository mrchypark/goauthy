package browser

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

// TestAuthCollectionsUIAcrossPods drives both sides of the metadata-only
// collection workflow through Chromium. It is opt-in because it needs the HA
// browser fixture and a disposable SMTP-backed account.
func TestAuthCollectionsUIAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_AUTH_COLLECTIONS_UI") != "1" {
		t.Skip("set GOAUTHY_E2E_AUTH_COLLECTIONS_UI=1 to run auth-collections UI E2E")
	}
	for _, name := range []string{"GOAUTHY_E2E_URL", "GOAUTHY_E2E_SECONDARY_URL", "GOAUTHY_E2E_TERTIARY_URL", "GOAUTHY_E2E_SMTP_SINK_URL", "GOAUTHY_E2E_BROWSER_USERNAME", "GOAUTHY_E2E_BROWSER_PASSWORD", "GOAUTHY_E2E_CLIENT_SECRET"} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is required when GOAUTHY_E2E_AUTH_COLLECTIONS_UI=1", name)
		}
	}
	primary, secondary, adminUser, adminPassword, _ := browserE2EConfig(t)
	tertiary := requiredE2EURL(t, "GOAUTHY_E2E_TERTIARY_URL")
	nodes := []string{primary, secondary, tertiary}
	admin := newBrowserClient(t)
	_, adminCookie := loginForCode(t, admin, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminUser, adminPassword, "auth-collections-ui-admin")
	csrf, err := browsersession.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	adminHeaders := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}

	id := uniqueCollectionID(t)
	name := "UI collection " + id
	ordinaryEmail := "auth-collections-ui-" + strings.ToLower(id) + "@goauthy.e2e"
	ordinaryPassword := "Auth-Collections-UI-Initial-1A"
	ordinaryID := createCatalogSessionUser(t, admin, primary, adminHeaders, ordinaryEmail, ordinaryPassword)
	t.Cleanup(func() {
		response := do(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(ordinaryID), nil, adminHeaders)
		if response.StatusCode != http.StatusNoContent {
			t.Errorf("ordinary user cleanup status=%d", response.StatusCode)
		}
		response.Body.Close()
	})
	ordinary := newBrowserClient(t)
	_, ordinaryCookie := loginForCode(t, ordinary, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), ordinaryEmail, ordinaryPassword, "auth-collections-ui-user")
	deniedMember := do(t, ordinary, http.MethodGet, primary+"/auth/v1/admin/collections", nil, nil)
	deniedMember.Body.Close()
	if deniedMember.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ordinary admin UI status=%d", deniedMember.StatusCode)
	}
	collectionDeleted := false
	t.Cleanup(func() {
		if !collectionDeleted {
			if own := readOwnConnectionCleanup(ordinary, primary, id); own != nil {
				if token, err := browsersession.DeriveCSRFToken(ordinaryCookie.Value); err == nil {
					h := map[string]string{"Content-Type": "application/json", "X-CSRF-Token": token, "If-Match": `"` + jsonNumber(own["revision"]) + `"`}
					r := do(t, ordinary, http.MethodDelete, primary+"/auth/v1/account/connections/"+url.PathEscape(id)+"/"+url.PathEscape(stringValue(own["id"])), nil, h)
					r.Body.Close()
				}
			}
			if def, rev := readDefinitionCleanup(admin, primary, id); def != nil {
				h := map[string]string{"Content-Type": "application/json", "If-Match": `"` + jsonNumber(rev) + `"`, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
				r := do(t, admin, http.MethodDelete, primary+"/auth/v1/auth-collections/"+url.PathEscape(id), nil, h)
				r.Body.Close()
			}
		}
	})

	unauthenticated := newBrowserClient(t)
	denied := do(t, unauthenticated, http.MethodGet, primary+"/auth/v1/admin/collections", nil, nil)
	denied.Body.Close()
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated admin collection status=%d", denied.StatusCode)
	}

	adminCtx, cancel := newCollectionUIContext(t, adminCookie, primary)
	defer cancel()
	if err := chromedp.Run(adminCtx, chromedp.Navigate(primary+"/auth/v1/admin/collections"), collectionUIListReady(), chromedp.Click(`a[href="/auth/v1/admin/collections/new"]`), chromedp.WaitVisible("#collection-form"), chromedp.SetValue("#collection-id", id), chromedp.SetValue("#collection-name", name), chromedp.Click("#add-collection-field"), chromedp.WaitVisible("#collection-fields .collection-field"), chromedp.SetValue(`#collection-fields [data-field-name]`, "workspace"), chromedp.SetValue(`#collection-fields [data-field-max]`, "80"), chromedp.Click(`#collection-fields [data-field-required]`), chromedp.Click("#add-collection-field"), chromedp.SetValue(`#collection-fields .collection-field:nth-child(2) [data-field-name]`, "enabled_flag"), chromedp.SetValue(`#collection-fields .collection-field:nth-child(2) [data-field-type]`, "boolean"), chromedp.Click("#add-collection-field"), chromedp.SetValue(`#collection-fields .collection-field:nth-child(3) [data-field-name]`, "count"), chromedp.SetValue(`#collection-fields .collection-field:nth-child(3) [data-field-type]`, "integer"), chromedp.Click("#add-collection-field"), chromedp.SetValue(`#collection-fields .collection-field:nth-child(4) [data-field-name]`, "tier"), chromedp.SetValue(`#collection-fields .collection-field:nth-child(4) [data-field-type]`, "enum"), chromedp.SetValue(`#collection-fields .collection-field:nth-child(4) [data-field-options]`, `[" work ","personal\nteam"]`), chromedp.Click("#collection-save"), collectionUIListReady()); err != nil {
		t.Fatalf("admin collection create UI: %v", err)
	}
	assertCollectionDefinitionUI(t, admin, nodes, id, name, true)

	if err := chromedp.Run(adminCtx, chromedp.Navigate(primary+"/auth/v1/admin/collections/"+id+"/edit"), chromedp.WaitVisible("#collection-form"), chromedp.SetValue("#collection-name", name+" updated"), chromedp.Click("#collection-save"), collectionUIListReady()); err != nil {
		t.Fatalf("admin collection edit UI: %v", err)
	}
	name = name + " updated"
	assertCollectionDefinitionUI(t, admin, nodes, id, name, true)

	ordinaryCtx, ordinaryCancel := newCollectionUIContext(t, ordinaryCookie, primary)
	defer ordinaryCancel()
	if err := chromedp.Run(ordinaryCtx, chromedp.Navigate(primary+"/account"), connectionUIReady()); err != nil {
		t.Fatalf("account connections UI unavailable: %v", err)
	}
	if err := chromedp.Run(ordinaryCtx, chromedp.SetValue("#connections-collection", id), chromedp.Evaluate(`document.querySelector('#connections-collection').dispatchEvent(new Event('change', {bubbles:true}))`, nil), connectionUIReady(), chromedp.WaitVisible("#connections-form"), chromedp.SetValue("#connection-field-workspace", "acme"), chromedp.SetValue("#connection-field-enabled_flag", "false"), chromedp.SetValue("#connection-field-count", "9223372036854775807"), chromedp.Click("#connections-save"), chromedp.Poll(`document.querySelector('#connections-status')?.textContent === 'Connection created.'`, nil)); err != nil {
		t.Fatalf("create draft connection UI: %v", err)
	}
	assertOwnConnectionUI(t, ordinary, nodes, id, ordinaryID, "acme")
	assertConnectionMetadataLiterals(t, ordinary, primary, id, map[string]string{"workspace": `"acme"`, "enabled_flag": "false", "count": "9223372036854775807"})
	if err := chromedp.Run(ordinaryCtx, chromedp.Click(`[data-connection-edit]`), chromedp.SetValue("#connection-field-workspace", "acme-roundtrip\nline"), chromedp.Click("#connections-save"), chromedp.Poll(`document.querySelector('#connections-status')?.textContent === 'Connection saved.'`, nil)); err != nil {
		t.Fatalf("full field roundtrip UI: %v", err)
	}
	assertConnectionMetadataLiterals(t, ordinary, primary, id, map[string]string{"workspace": `"acme-roundtrip\nline"`, "enabled_flag": "false", "count": "9223372036854775807"})

	// A disabled definition prevents another draft from being created.
	definition, revision := readCollectionDefinitionUI(t, admin, primary, id)
	definition = collectionDefinitionBody(definition)
	definition["enabled"] = false
	putDefinitionUI(t, admin, primary, id, revision, csrf, definition)
	if err := chromedp.Run(ordinaryCtx, chromedp.Click("#connections-refresh"), chromedp.Poll(`document.querySelector('#connections-collection')?.options?.[0]?.textContent?.includes('(disabled)')`, nil), chromedp.Poll(`document.querySelector('#connections-save')?.disabled === true`, nil)); err != nil {
		t.Fatalf("disabled collection UI: %v", err)
	}

	// The stale-revision path must leave the user's typed value intact.
	definition["enabled"] = true
	_, revision = putDefinitionUI(t, admin, primary, id, revision+1, csrf, definition)
	if err := chromedp.Run(ordinaryCtx, chromedp.Click("#connections-refresh"), connectionUIReady(), chromedp.Poll(`document.querySelector('#connections-save')?.disabled === false`, nil)); err != nil {
		t.Fatalf("re-enable collection UI: %v", err)
	}
	if err := chromedp.Run(ordinaryCtx, chromedp.Click(`[data-connection-edit]`), chromedp.SetValue("#connection-field-workspace", "ui-stale")); err != nil {
		t.Fatalf("edit draft connection UI: %v", err)
	}
	conn := readOwnConnectionUI(t, ordinary, primary, id, ordinaryID)
	_, currentDefinitionRevision := readCollectionDefinitionUI(t, admin, primary, id)
	update := []byte(`{"definition_revision":` + jsonNumber(currentDefinitionRevision) + `,"metadata":{"workspace":"external","enabled_flag":false,"count":9223372036854775807}}`)
	ordinaryCSRF, err := browsersession.DeriveCSRFToken(ordinaryCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	putConnectionUI(t, ordinary, primary, id, stringValue(conn["id"]), int64Value(conn["revision"]), ordinaryCSRF, update)
	if err := chromedp.Run(ordinaryCtx, chromedp.Click("#connections-save"), chromedp.Poll(`document.querySelector('#connections-status')?.textContent === 'This connection changed elsewhere. Reload and try again.'`, nil), chromedp.Poll(`document.querySelector('#connection-field-workspace')?.value === 'ui-stale'`, nil)); err != nil {
		t.Fatalf("stale connection preserved input UI: %v", err)
	}
	if err := chromedp.Run(ordinaryCtx, chromedp.Click("#connections-refresh"), connectionUIReady(), chromedp.Click(`[data-connection-edit]`), chromedp.SetValue("#connection-field-workspace", "ui-final"), chromedp.Click("#connections-save"), chromedp.Poll(`document.querySelector('#connections-status')?.textContent === 'Connection saved.'`, nil)); err != nil {
		t.Fatalf("resolve stale connection UI: %v", err)
	}
	assertOwnConnectionUI(t, ordinary, nodes, id, ordinaryID, "ui-final")
	if err := chromedp.Run(adminCtx, chromedp.Navigate(primary+"/auth/v1/admin/collections/"+id+"/edit"), chromedp.WaitVisible("#collection-form")); err != nil {
		t.Fatalf("open populated admin editor for screenshot: %v", err)
	}
	if err := chromedp.Run(ordinaryCtx, chromedp.Click(`[data-connection-edit]`), chromedp.WaitVisible("#connections-form")); err != nil {
		t.Fatalf("open populated account editor for screenshot: %v", err)
	}
	captureCollectionScreenshots(t, adminCtx, ordinaryCtx, os.Getenv("GOAUTHY_E2E_AUTH_COLLECTIONS_SCREENSHOT_DIR"))

	// Cleanup the record through the real account UI, then remove the definition
	// through the admin UI.
	var ordinaryDialog atomic.Value
	ordinaryDialog.Store("")
	chromedp.ListenTarget(ordinaryCtx, func(ev interface{}) {
		if dialog, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			accept := dialog.Message == ordinaryDialog.Load().(string)
			go func() { _ = chromedp.Run(ordinaryCtx, page.HandleJavaScriptDialog(accept)) }()
		}
	})
	conn = readOwnConnectionUI(t, ordinary, primary, id, ordinaryID)
	ordinaryDialog.Store("Delete connection “" + stringValue(conn["id"]) + "”?")
	if err := chromedp.Run(ordinaryCtx, chromedp.Click(`[data-connection-delete]`), chromedp.Poll(`document.querySelector('#connections-status')?.textContent === 'Connection deleted.'`, nil)); err != nil {
		t.Fatalf("delete draft connection UI: %v", err)
	}
	if err := chromedp.Run(adminCtx, chromedp.Navigate(primary+"/auth/v1/admin/collections/"+id), chromedp.WaitVisible("#collection-delete")); err != nil {
		t.Fatalf("open collection delete UI: %v", err)
	}
	var dialogReply atomic.Value
	dialogReply.Store("Delete collection " + name + " permanently?")
	chromedp.ListenTarget(adminCtx, func(ev interface{}) {
		if dialog, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			accept := dialog.Message == dialogReply.Load().(string)
			go func() { _ = chromedp.Run(adminCtx, page.HandleJavaScriptDialog(accept)) }()
		}
	})
	if err := chromedp.Run(adminCtx, chromedp.Click("#collection-delete"), collectionUIListReady()); err != nil {
		t.Fatalf("delete collection UI: %v", err)
	}
	collectionDeleted = true
	for _, base := range nodes {
		response := do(t, admin, http.MethodGet, base+"/auth/v1/auth-collections/"+url.PathEscape(id), nil, nil)
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("deleted definition node=%s status=%d", base, response.StatusCode)
		}
	}
}

func newCollectionUIContext(t *testing.T, cookie *http.Cookie, base string) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	options := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	options = append(options, chromedp.Headless, chromedp.NoFirstRun)
	if os.Getenv("GOAUTHY_E2E_TLS") == "1" && strings.HasPrefix(base, "https://") {
		// Go verifies the disposable fixture's CA and hostname first. Chromium's
		// isolated profile accepts only that verified leaf public key, not all TLS errors.
		r, err := newBrowserClient(t).Get(base + "/.well-known/openid-configuration")
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		r.Body.Close()
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			cancel()
			t.Fatal("fixture TLS identity was not verified")
		}
		pin := sha256.Sum256(r.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
		options = append(options, chromedp.Flag("ignore-certificate-errors-spki-list", base64.StdEncoding.EncodeToString(pin[:])))
	}
	alloc, cancelAlloc := chromedp.NewExecAllocator(ctx, options...)
	browser, cancelBrowser := chromedp.NewContext(alloc)
	if cookie != nil {
		u := mustE2EURL(t, base+"/")
		if err := chromedp.Run(browser, network.SetCookie(cookie.Name, cookie.Value).WithDomain(u.Hostname()).WithPath("/").WithSecure(u.Scheme == "https")); err != nil {
			cancelBrowser()
			cancelAlloc()
			cancel()
			t.Fatal(err)
		}
	}
	return browser, func() { cancelBrowser(); cancelAlloc(); cancel() }
}

func collectionUIListReady() chromedp.Tasks {
	return chromedp.Tasks{chromedp.WaitVisible("#collection-list"), chromedp.Poll(`document.querySelector('#collection-status')?.textContent !== 'Loading…'`, nil)}
}

func connectionUIReady() chromedp.Tasks {
	return chromedp.Tasks{chromedp.WaitVisible("#connections-section"), chromedp.Poll(`document.querySelector('#connections-refresh')?.disabled === false`, nil)}
}

func captureCollectionScreenshots(t *testing.T, adminCtx, accountCtx context.Context, dir string) {
	t.Helper()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, viewport := range []struct {
		name string
		w, h int
		dpr  float64
	}{
		{name: "desktop", w: 1280, h: 900, dpr: 1},
		{name: "mobile", w: 375, h: 812, dpr: 2},
	} {
		for _, screen := range []struct {
			name string
			ctx  context.Context
		}{
			{name: "admin", ctx: adminCtx},
			{name: "account", ctx: accountCtx},
		} {
			var image []byte
			var overflow bool
			if err := chromedp.Run(screen.ctx, emulation.SetDeviceMetricsOverride(int64(viewport.w), int64(viewport.h), viewport.dpr, false), chromedp.Evaluate(`document.documentElement.scrollWidth > window.innerWidth`, &overflow), chromedp.FullScreenshot(&image, 90)); err != nil {
				t.Fatalf("%s %s screenshot: %v", screen.name, viewport.name, err)
			}
			if overflow {
				t.Fatalf("%s %s viewport has horizontal overflow", screen.name, viewport.name)
			}
			if err := os.WriteFile(dir+"/collections-"+screen.name+"-"+viewport.name+".png", image, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := chromedp.Run(screen.ctx, emulation.ClearDeviceMetricsOverride()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func assertCollectionDefinitionUI(t *testing.T, client *http.Client, nodes []string, id, name string, enabled bool) {
	t.Helper()
	for _, base := range nodes {
		got, _ := readCollectionDefinitionUI(t, client, base, id)
		if got["name"] != name || got["enabled"] != enabled {
			t.Fatalf("definition node=%s value=%v", base, got)
		}
		fields, ok := got["fields"].([]any)
		if !ok || len(fields) != 4 {
			t.Fatalf("definition fields node=%s value=%v", base, got["fields"])
		}
		enum, ok := fields[3].(map[string]any)
		if !ok {
			t.Fatalf("enum field node=%s value=%v", base, fields[3])
		}
		options, err := json.Marshal(enum["options"])
		if err != nil || string(options) != `[" work ","personal\nteam"]` {
			t.Fatalf("enum whitespace/newline lost node=%s options=%s error=%v", base, options, err)
		}
	}
}

func readCollectionDefinitionUI(t *testing.T, client *http.Client, base, id string) (map[string]any, int64) {
	t.Helper()
	r := do(t, client, http.MethodGet, base+"/auth/v1/auth-collections/"+url.PathEscape(id), nil, nil)
	return readCollection(t, r, http.StatusOK)
}

func putDefinitionUI(t *testing.T, client *http.Client, base, id string, revision int64, csrf string, definition map[string]any) (map[string]any, int64) {
	t.Helper()
	body, _ := json.Marshal(definition)
	h := map[string]string{"Content-Type": "application/json", "If-Match": `"` + jsonNumber(revision) + `"`, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	r := do(t, client, http.MethodPut, base+"/auth/v1/auth-collections/"+url.PathEscape(id), bytes.NewReader(body), h)
	return readCollection(t, r, http.StatusOK)
}

func collectionDefinitionBody(definition map[string]any) map[string]any {
	return map[string]any{"name": definition["name"], "auth_method": definition["auth_method"], "enabled": definition["enabled"], "fields": definition["fields"]}
}

func assertOwnConnectionUI(t *testing.T, client *http.Client, nodes []string, id, owner, workspace string) {
	for _, base := range nodes {
		got := readOwnConnectionUI(t, client, base, id, owner)
		metadata, ok := got["metadata"].(map[string]any)
		if got["state"] != "draft" || got["owner_subject"] != owner || !ok || metadata["workspace"] != workspace {
			t.Fatalf("connection node=%s value=%v", base, got)
		}
	}
}

func assertConnectionMetadataLiterals(t *testing.T, client *http.Client, base, id string, want map[string]string) {
	t.Helper()
	r := do(t, client, http.MethodGet, base+"/auth/v1/account/connections/"+url.PathEscape(id), nil, nil)
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("connection literal read status=%d", r.StatusCode)
	}
	var rows []struct {
		Metadata map[string]json.RawMessage `json:"metadata"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.UseNumber()
	if err := dec.Decode(&rows); err != nil || len(rows) != 1 {
		t.Fatalf("connection literal decode rows=%d err=%v", len(rows), err)
	}
	for key, expected := range want {
		if string(rows[0].Metadata[key]) != expected {
			t.Fatalf("metadata %s=%s want %s", key, rows[0].Metadata[key], expected)
		}
	}
	if _, ok := rows[0].Metadata["tier"]; ok {
		t.Fatal("optional enum tier should be omitted when unset")
	}
}

func readOwnConnectionUI(t *testing.T, client *http.Client, base, id, owner string) map[string]any {
	t.Helper()
	r := do(t, client, http.MethodGet, base+"/auth/v1/account/connections/"+url.PathEscape(id), nil, nil)
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("connection list node=%s status=%d", base, r.StatusCode)
	}
	var rows []map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&rows); err != nil || len(rows) != 1 || rows[0]["owner_subject"] != owner {
		t.Fatalf("connection list node=%s rows=%v err=%v", base, rows, err)
	}
	return rows[0]
}

func readOwnConnectionCleanup(client *http.Client, base, id string) map[string]any {
	r, err := client.Get(base + "/auth/v1/account/connections/" + url.PathEscape(id))
	if err != nil {
		return nil
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil
	}
	var rows []map[string]any
	if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&rows) != nil || len(rows) == 0 {
		return nil
	}
	return rows[0]
}

func readDefinitionCleanup(client *http.Client, base, id string) (map[string]any, int64) {
	r, err := client.Get(base + "/auth/v1/auth-collections/" + url.PathEscape(id))
	if err != nil {
		return nil, 0
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, 0
	}
	var def map[string]any
	if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&def) != nil {
		return nil, 0
	}
	return def, int64Value(def["revision"])
}

func putConnectionUI(t *testing.T, client *http.Client, base, collectionID, connectionID string, revision int64, csrf string, body []byte) {
	t.Helper()
	r := do(t, client, http.MethodPut, base+"/auth/v1/account/connections/"+url.PathEscape(collectionID)+"/"+url.PathEscape(connectionID), bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "If-Match": `"` + jsonNumber(revision) + `"`, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("external connection update status=%d", r.StatusCode)
	}
}

func jsonNumber(v any) string  { b, _ := json.Marshal(v); return strings.Trim(string(b), `"`) }
func stringValue(v any) string { s, _ := v.(string); return s }
func int64Value(v any) int64   { n, _ := v.(float64); return int64(n) }
