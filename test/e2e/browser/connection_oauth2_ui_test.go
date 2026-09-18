package browser

import (
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// OAuth connection mutations use real controls; the synthetic provider's
// authorization/callback flow remains in the caller, not a SaaS login UI.
func oauth2ConnectionUIAction(t *testing.T, cookie *http.Cookie, base, collection, connection, provider, action, state string, version int64) string {
	t.Helper()
	ctx, cancel := newCollectionUIContext(t, cookie, base)
	defer cancel()
	chromedp.ListenTarget(ctx, func(event any) {
		if _, ok := event.(*page.EventJavascriptDialogOpening); ok {
			go func() { _ = chromedp.Run(ctx, page.HandleJavaScriptDialog(true)) }()
		}
	})
	selector := func(name string) string { return `[data-` + name + `="` + connection + `"]` }
	js := func(name string) string { return "document.querySelector(" + quoteJS(selector(name)) + ")" }
	if err := chromedp.Run(ctx,
		chromedp.Navigate(base+"/account"), connectionUIReady(),
		chromedp.SetValue("#connections-collection", collection),
		chromedp.Evaluate(`document.querySelector('#connections-collection').dispatchEvent(new Event('change',{bubbles:true}))`, nil),
		connectionUIReady(), chromedp.Click(selector("connection-oauth2")),
		chromedp.Poll(js("oauth2-check")+`?.disabled === false && `+js("oauth2-panel")+`?.dataset.oauth2State !== undefined`, nil),
	); err != nil {
		t.Fatalf("open OAuth connection controls: %v", err)
	}
	if action == "start" {
		var destination string
		if err := chromedp.Run(ctx,
			chromedp.SetValue(selector("oauth2-provider"), provider),
			chromedp.Evaluate(js("oauth2-provider")+`.dispatchEvent(new Event('change',{bubbles:true}))`, nil),
			chromedp.Click(selector("oauth2-start")),
			chromedp.Poll(js("oauth2-continue")+`?.hidden === false`, nil),
			chromedp.Evaluate(js("oauth2-continue")+`.href`, &destination),
		); err != nil {
			t.Fatalf("start OAuth authorization from UI: %v", err)
		}
		u, err := url.Parse(destination)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			t.Fatal("OAuth UI returned an invalid authorization destination")
		}
		return destination
	}
	if action != "refresh" && action != "revoke" && action != "reconnect" {
		t.Fatal("unsupported OAuth UI test action")
	}
	if action == "reconnect" {
		if path := os.Getenv("GOAUTHY_E2E_OAUTH2_CONNECTION_SCREENSHOT"); path != "" {
			var screenshot []byte
			if err := chromedp.Run(ctx, chromedp.FullScreenshot(&screenshot, 90)); err != nil {
				t.Fatal("capture OAuth connection panel failed")
			}
			if err := os.WriteFile(path, screenshot, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := chromedp.Run(ctx,
		chromedp.Click(selector("oauth2-"+action)),
		chromedp.Poll(js("oauth2-panel")+`.dataset.oauth2State === `+quoteJS(state)+` && `+js("oauth2-panel")+`.dataset.oauth2Version === `+quoteJS(strconv.FormatInt(version, 10))+` && `+js("oauth2-check")+`.disabled === false`, nil),
	); err != nil {
		t.Fatalf("OAuth connection UI %s: %v", action, err)
	}
	return ""
}

// The fixture redirects a real top-level browser navigation back to GoAuthy.
// A real SaaS provider's own login/consent UI is still outside this fixture.
func completeOAuth2Browser(t *testing.T, cookie *http.Cookie, base, authorizationURL, callbackURL string) {
	t.Helper()
	ctx, cancel := newCollectionUIContext(t, cookie, base)
	defer cancel()
	responses := make(chan *network.Response, 1)
	chromedp.ListenTarget(ctx, func(event any) {
		if received, ok := event.(*network.EventResponseReceived); ok && strings.HasPrefix(received.Response.URL, callbackURL+"?") {
			select {
			case responses <- received.Response:
			default:
			}
		}
	})
	var body, accountLink string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(authorizationURL),
		chromedp.WaitVisible("#oauth2-complete"),
		chromedp.OuterHTML("html", &body),
		chromedp.Evaluate(`document.querySelector('#oauth2-account-link').href`, &accountLink),
	); err != nil {
		t.Fatal("OAuth browser navigation did not reach the completion page")
	}
	select {
	case response := <-responses:
		header := func(name string) string {
			for key, value := range response.Headers {
				if strings.EqualFold(key, name) {
					text, _ := value.(string)
					return text
				}
			}
			return ""
		}
		if response.Status != 200 || !strings.HasPrefix(header("Content-Type"), "text/html") || header("Cache-Control") != "no-store" || header("Referrer-Policy") != "no-referrer" || header("X-Frame-Options") != "DENY" {
			t.Fatal("OAuth browser completion response contract failed")
		}
	default:
		t.Fatal("OAuth browser callback response was not observed")
	}
	if accountLink != base+"/account" {
		t.Fatal("OAuth completion return link escaped the account page")
	}
	authorization, _ := url.Parse(authorizationURL)
	for _, forbidden := range []string{authorization.Query().Get("state"), "access_token", "refresh_token", "client_secret"} {
		if forbidden != "" && strings.Contains(body, forbidden) {
			t.Fatal("OAuth completion page exposed credential or callback material")
		}
	}
	if path := os.Getenv("GOAUTHY_E2E_OAUTH2_CALLBACK_SCREENSHOT"); path != "" {
		var screenshot []byte
		if err := chromedp.Run(ctx, chromedp.FullScreenshot(&screenshot, 90)); err != nil {
			t.Fatal("capture OAuth completion page failed")
		}
		if err := os.WriteFile(path, screenshot, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := chromedp.Run(ctx, chromedp.Click("#oauth2-account-link"), connectionUIReady()); err != nil {
		t.Fatal("return from OAuth completion to account failed")
	}
}
