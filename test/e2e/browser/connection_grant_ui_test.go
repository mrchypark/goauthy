package browser

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

func testConnectionGrantUI(t *testing.T, client *http.Client, primary string, cookie *http.Cookie, headers map[string]string, collection, connection, consumer string) {
	t.Helper()
	base := primary + "/auth/v1/account/connections/" + collection + "/" + connection
	ctx, cancel := newCollectionUIContext(t, cookie, primary)
	defer cancel()
	selector := func(name string) string { return `[data-` + name + `="` + connection + `"]` }
	js := func(name string) string {
		b, _ := json.Marshal(selector(name))
		return "document.querySelector(" + string(b) + ")"
	}
	if err := chromedp.Run(ctx,
		chromedp.Navigate(primary+"/account"), connectionUIReady(),
		chromedp.SetValue("#connections-collection", collection),
		chromedp.Evaluate(`document.querySelector('#connections-collection').dispatchEvent(new Event('change', {bubbles:true}))`, nil),
		connectionUIReady(), chromedp.Click(selector("connection-grants")),
		chromedp.Poll(js("grant-review")+`?.disabled === false`, nil),
		chromedp.Poll(js("grant-create")+`?.disabled === true && `+js("grant-review")+`?.checked === false`, nil),
		chromedp.SetValue(selector("grant-consumer"), consumer),
		chromedp.SetValue(selector("grant-purpose"), "browser-consent"),
		chromedp.Evaluate(`(() => {const el=`+js("grant-expiry")+`;const date=new Date(Date.now()+3600000);date.setMinutes(date.getMinutes()-date.getTimezoneOffset());el.value=date.toISOString().slice(0,16);el.dispatchEvent(new Event('input',{bubbles:true}));})()`, nil),
		chromedp.Click(selector("grant-review")),
		chromedp.Evaluate(js("grant-purpose")+`.dispatchEvent(new Event('input',{bubbles:true}))`, nil),
		chromedp.Poll(js("grant-create")+`?.disabled === true && `+js("grant-review")+`?.checked === false`, nil),
	); err != nil {
		t.Fatalf("open service access review: %v", err)
	}
	var before []map[string]any
	if err := json.Unmarshal(mustGrantList(t, client, base, headers), &before); err != nil || len(before) != 1 {
		t.Fatalf("review created implicit grant: count=%d err=%v", len(before), err)
	}
	if path := os.Getenv("GOAUTHY_E2E_GRANT_SCREENSHOT"); path != "" {
		var screenshot []byte
		if err := chromedp.Run(ctx, chromedp.FullScreenshot(&screenshot, 90)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, screenshot, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := chromedp.Run(ctx,
		chromedp.Click(selector("grant-review")),
		chromedp.Poll(js("grant-create")+`?.disabled === false`, nil),
		chromedp.Click(selector("grant-create")),
		chromedp.WaitVisible(`[data-grant-revoke]`),
	); err != nil {
		t.Fatalf("create service access consent: %v", err)
	}
	var grants []struct {
		ID       string `json:"id"`
		Consumer string `json:"consumer_client_id"`
		Purpose  string `json:"purpose"`
		Digest   string `json:"connector_digest"`
		Revoked  bool   `json:"revoked"`
	}
	if err := json.Unmarshal(mustGrantList(t, client, base, headers), &grants); err != nil {
		t.Fatal(err)
	}
	var id string
	for _, grant := range grants {
		if grant.Purpose == "browser-consent" && grant.Consumer == consumer && grant.Digest != "" && !grant.Revoked {
			id = grant.ID
		}
	}
	if id == "" || len(grants) != 2 {
		t.Fatal("browser consent not persisted as reviewed")
	}
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			go func() { _ = chromedp.Run(ctx, page.HandleJavaScriptDialog(true)) }()
		}
	})
	revoke := `[data-grant-revoke="` + id + `"]`
	revokeJSON, _ := json.Marshal(revoke)
	if err := chromedp.Run(ctx, chromedp.Click(revoke),
		chromedp.Poll(`!document.querySelector(`+string(revokeJSON)+`) || document.querySelector(`+string(revokeJSON)+`).disabled`, nil),
		chromedp.Poll(js("grant-status")+`?.textContent?.includes('revoked')`, nil),
	); err != nil {
		t.Fatalf("revoke service access consent: %v", err)
	}
	if err := json.Unmarshal(mustGrantList(t, client, base, headers), &grants); err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants {
		if grant.ID == id && grant.Revoked {
			return
		}
	}
	t.Fatal("browser revoke did not persist")
}
