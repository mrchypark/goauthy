package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// Uses the existing standalone pilot fixture and observable DOM states, not sleeps.
func testConnectionAPIKeyUI(t *testing.T, client *http.Client, primary string, cookie *http.Cookie, headers map[string]string, collection string, definitionRevision int64, connectorDigest string) {
	body, _ := json.Marshal(map[string]any{"definition_revision": definitionRevision, "metadata": map[string]any{}})
	r := do(t, client, http.MethodPost, primary+"/auth/v1/account/connections/"+collection, bytes.NewReader(body), headers)
	connection, revision := readCollection(t, r, http.StatusCreated)
	id := stringValue(connection["id"])
	base := primary + "/auth/v1/account/connections/" + collection + "/" + id
	t.Cleanup(func() {
		r := do(t, client, http.MethodDelete, base, nil, cloneCollectionHeaders(headers, revision))
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Errorf("UI connection cleanup=%d", r.StatusCode)
		}
	})
	ctx, cancel := newCollectionUIContext(t, cookie, primary)
	defer cancel()
	input := `[data-api-key-input="` + id + `"]`
	save := `[data-api-key-save="` + id + `"]`
	revoke := `[data-api-key-revoke="` + id + `"]`
	status := `[data-api-key-status="` + id + `"]`
	inputJS, _ := json.Marshal(input)
	saveJS, _ := json.Marshal(save)
	statusJS, _ := json.Marshal(status)
	review := `[data-api-key-review="` + id + `"]`
	reviewJS, _ := json.Marshal(review)
	approve := func() chromedp.Action {
		return chromedp.ActionFunc(func(ctx context.Context) error {
			if connectorDigest == "" {
				return nil
			}
			if err := chromedp.Run(ctx, chromedp.Poll(`document.querySelector(`+string(reviewJS)+`)?.disabled === false`, nil)); err != nil {
				return err
			}
			if path := os.Getenv("GOAUTHY_E2E_REGISTERED_KEY_SCREENSHOT"); path != "" {
				var screenshot []byte
				if err := chromedp.Run(ctx, chromedp.FullScreenshot(&screenshot, 90)); err != nil {
					return err
				}
				if err := os.WriteFile(path, screenshot, 0600); err != nil {
					return err
				}
			}
			return chromedp.Run(ctx,
				chromedp.Poll(`document.querySelector(`+string(reviewJS)+`)?.disabled === false`, nil),
				chromedp.Poll(`document.querySelector(`+string(saveJS)+`)?.disabled === true && document.querySelector(`+string(reviewJS)+`)?.checked === false`, nil),
				chromedp.Click(review),
			)
		})
	}
	if err := chromedp.Run(ctx,
		chromedp.Navigate(primary+"/account"), connectionUIReady(),
		chromedp.SetValue("#connections-collection", collection),
		chromedp.Evaluate(`document.querySelector('#connections-collection').dispatchEvent(new Event('change', {bubbles:true}))`, nil),
		connectionUIReady(), chromedp.Click(`[data-connection-api-key="`+id+`"]`),
		chromedp.WaitVisible(input),
		chromedp.Poll(`Array.from(document.querySelectorAll('[hidden]')).every(el => getComputedStyle(el).display === 'none')`, nil),
		approve(),
		chromedp.Poll(`document.querySelector(`+string(saveJS)+`)?.disabled === false`, nil),
	); err != nil {
		t.Fatalf("open API-key editor: %v", err)
	}
	assertStatus := func(registered bool, version int64) {
		t.Helper()
		r := do(t, client, http.MethodGet, base+"/api-key", nil, headers)
		defer r.Body.Close()
		var got struct {
			Registered bool  `json:"registered"`
			Version    int64 `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil || r.StatusCode != 200 || got.Registered != registered || got.Version != version {
			t.Fatalf("UI persisted status=%+v HTTP=%d err=%v", got, r.StatusCode, err)
		}
	}
	for i, key := range []string{"synthetic-ui-saas-key-first", "synthetic-ui-saas-key-rotated"} {
		if err := chromedp.Run(ctx,
			chromedp.SetValue(input, key),
			chromedp.Click(save),
			chromedp.Poll(`document.querySelector(`+string(inputJS)+`)?.value === '' && document.querySelector(`+string(saveJS)+`)?.disabled === false`, nil),
		); err != nil {
			t.Fatalf("API-key UI save %d: %v", i, err)
		}
		assertStatus(true, int64(i+1))
	}
	// A concurrent update must not be silently overwritten or retried by the UI.
	rotation := map[string]any{"api_key": "synthetic-ui-external-rotation", "version": 2}
	if connectorDigest != "" {
		rotation["connector_digest"] = connectorDigest
	}
	rotationBody, _ := json.Marshal(rotation)
	r = do(t, client, http.MethodPut, base+"/api-key", bytes.NewReader(rotationBody), headers)
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("concurrent rotation=%d", r.StatusCode)
	}
	if err := chromedp.Run(ctx, chromedp.SetValue(input, "synthetic-ui-stale-attempt"), chromedp.Click(save),
		chromedp.Poll(`document.querySelector(`+string(statusJS)+`)?.textContent?.includes('changed elsewhere') && document.querySelector(`+string(inputJS)+`)?.value === ''`, nil),
		chromedp.Click(`[data-api-key-cancel="`+id+`"]`),
		chromedp.Click(`[data-connection-api-key="`+id+`"]`),
		approve(),
		chromedp.Poll(`document.querySelector(`+string(saveJS)+`)?.disabled === false`, nil),
	); err != nil {
		t.Fatalf("stale key conflict and reload: %v", err)
	}
	assertStatus(true, 3)
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			go func() { _ = chromedp.Run(ctx, page.HandleJavaScriptDialog(true)) }()
		}
	})
	if err := chromedp.Run(ctx, chromedp.Click(revoke),
		chromedp.Poll(`document.querySelector(`+string(statusJS)+`)?.textContent?.includes('revoked')`, nil),
	); err != nil {
		t.Fatalf("API-key UI revoke: %v", err)
	}
	assertStatus(false, 3)
}
