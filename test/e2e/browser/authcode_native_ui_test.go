package browser

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// TestAuthorizationCodeNativePasswordSubmit exercises the ordinary browser
// authorization-code flow through a real native form submission. The callback
// is fulfilled locally only after its registered origin/path is observed.
func TestAuthorizationCodeNativePasswordSubmit(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_AUTHCODE_NATIVE_UI") != "1" {
		t.Skip("set GOAUTHY_E2E_AUTHCODE_NATIVE_UI=1 to run native authorization-code UI E2E")
	}
	primary, _, username, password, clientSecret := browserE2EConfig(t)
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}
	registered, err := url.Parse(redirectURI)
	if err != nil || registered.Scheme == "" || registered.Host == "" || registered.Path == "" || registered.RawQuery != "" || registered.Fragment != "" {
		t.Fatal("invalid registered callback URI")
	}
	primaryURL, err := url.Parse(primary)
	if err != nil {
		t.Fatal("invalid E2E issuer URI")
	}

	state := "native-authcode-state-20260907"
	verifier := pkceVerifier(t)
	authorizeURL := oidcAuthorizationURL(t, primary, redirectURI, pkceChallenge(verifier), state, "native-authcode-nonce")
	ctx, cancel := newCollectionUIContext(t, nil, primary)
	defer cancel()

	type callbackResult struct {
		location *url.URL
	}
	callback := make(chan callbackResult, 1)
	blocked := make(chan struct{}, 1)
	var loginRequest network.RequestID
	chromedp.ListenTarget(ctx, func(event any) {
		if entry, ok := event.(*log.EventEntryAdded); ok && strings.Contains(entry.Entry.Text, "form-action") {
			// Record only the policy category, never the console's URL/query.
			select {
			case blocked <- struct{}{}:
			default:
			}
		}
		if request, ok := event.(*network.EventRequestWillBeSent); ok && request.Request.Method == "POST" && request.Request.URL == primary+"/auth/login" {
			loginRequest = request.RequestID
		}
		if failure, ok := event.(*network.EventLoadingFailed); ok && loginRequest != "" && failure.RequestID == loginRequest && (string(failure.BlockedReason) == "csp" || strings.Contains(failure.ErrorText, "ERR_BLOCKED_BY_CSP")) {
			select {
			case blocked <- struct{}{}:
			default:
			}
		}
		paused, ok := event.(*fetch.EventRequestPaused)
		if !ok {
			return
		}
		location, parseErr := url.Parse(paused.Request.URL)
		if parseErr != nil || location.Scheme != registered.Scheme || location.Host != registered.Host || location.Path != registered.Path {
			go func() { _ = chromedp.Run(ctx, fetch.ContinueRequest(paused.RequestID)) }()
			return
		}
		if location.Query().Get("state") != state || location.Query().Get("code") == "" {
			go func() {
				_ = chromedp.Run(ctx, fetch.ContinueRequest(paused.RequestID))
			}()
			return
		}
		select {
		case callback <- callbackResult{location: location}:
		default:
		}
		body := base64.StdEncoding.EncodeToString([]byte("<!doctype html><title>callback complete</title><p id=callback-success>success</p>"))
		go func() {
			_ = chromedp.Run(ctx, fetch.FulfillRequest(paused.RequestID, 200).
				WithResponseHeaders([]*fetch.HeaderEntry{{Name: "Content-Type", Value: "text/html; charset=utf-8"}}).
				WithBody(body))
		}()
	})

	if err := chromedp.Run(ctx,
		log.Enable(),
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{{URLPattern: redirectURI + "*", RequestStage: fetch.RequestStageRequest}}),
		chromedp.Navigate(authorizeURL),
		chromedp.WaitVisible(`input[name="username"]`),
		chromedp.SetValue(`input[name="username"]`, username),
		chromedp.SetValue(`input[name="password"]`, password),
		chromedp.Click(`button[type="submit"]`),
	); err != nil {
		t.Fatal("native password submission did not complete")
	}

	var callbackLocation *url.URL
	select {
	case result := <-callback:
		callbackLocation = result.location
		if callbackLocation.Query().Get("state") != state || callbackLocation.Query().Get("code") == "" {
			t.Fatal("registered callback did not return code and state")
		}
		if strings.EqualFold(callbackLocation.Scheme+"://"+callbackLocation.Host, primaryURL.Scheme+"://"+primaryURL.Host) {
			t.Fatal("callback navigation was not cross-origin")
		}
		if err := chromedp.Run(ctx, chromedp.WaitVisible(`#callback-success`)); err != nil {
			t.Fatal("callback navigation did not render success page")
		}
	case <-blocked:
		t.Fatal("native login navigation was blocked by CSP")
	case <-ctx.Done():
		t.Fatal("timed out waiting for registered callback navigation")
	}

	client := newBrowserClient(t)
	tokens := exchangeCode(t, client, primary, clientSecret, redirectURI, callbackLocation.Query().Get("code"), verifier)
	claims := verifyPublicIDToken(t, tokens.IDToken, publicJWKS(t, client, primary), primary)
	if claims.Subject != "bootstrap-admin" || claims.Nonce != "native-authcode-nonce" {
		t.Fatalf("unexpected ID-token subject or nonce: subject=%q nonce=%q", claims.Subject, claims.Nonce)
	}
	assertUserInfoSubject(t, client, primary, http.MethodGet, tokens.AccessToken, "bootstrap-admin")
	revokeAccessToken(t, client, primary, clientSecret, tokens.AccessToken)
	assertUserInfoRejected(t, client, primary, http.MethodGet, "Bearer "+tokens.AccessToken, "")
}
