package browser

import (
	"context"
	"encoding/base64"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func TestAccountErrorFeedbackUI(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ACCOUNT_ERROR_UI") != "1" {
		t.Skip("set GOAUTHY_E2E_ACCOUNT_ERROR_UI=1 to run account error-feedback UI E2E")
	}
	issuer := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	app := strings.TrimRight(os.Getenv("GOAUTHY_E2E_APP_URL"), "/")
	username, password := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	wantSubject := os.Getenv("GOAUTHY_E2E_BROWSER_SUBJECT")
	chromePath := os.Getenv("GOAUTHY_E2E_CHROME_BIN")
	if issuer == "" || app == "" || username == "" || password == "" || wantSubject == "" || chromePath == "" {
		t.Fatal("account error UI fixture configuration is incomplete")
	}
	issuerURL, issuerErr := url.Parse(issuer)
	appURL, appErr := url.Parse(app)
	if issuerErr != nil || appErr != nil || issuerURL.Scheme != "http" || appURL.Scheme != "http" ||
		(issuerURL.Hostname() != "localhost" && issuerURL.Hostname() != "127.0.0.1") ||
		(appURL.Hostname() != "localhost" && appURL.Hostname() != "127.0.0.1") {
		t.Fatal("account error UI requires loopback HTTP issuer and app origins")
	}

	root, cancelRoot := context.WithTimeout(context.Background(), 2*time.Minute)
	options := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	options = append(options, chromedp.ExecPath(chromePath), chromedp.Headless, chromedp.NoFirstRun, chromedp.NoDefaultBrowserCheck)
	allocator, cancelAllocator := chromedp.NewExecAllocator(root, options...)
	browser, cancelBrowser := chromedp.NewContext(allocator)
	stage := "browser-start"
	defer func() {
		if t.Failed() {
			writeLoginJourneyFailureArtifact(browser, os.Getenv("GOAUTHY_E2E_ARTIFACT_DIR"), stage)
		}
		cancelBrowser()
		cancelAllocator()
		cancelRoot()
	}()
	// Keep Chrome allocation on the long-lived browser context; a short-lived
	// stage context here can cancel the process as soon as setup returns.
	if err := chromedp.Run(browser,
		chromedp.EmulateViewport(1280, 1000),
		network.Enable(),
		englishUILocale(issuer),
		network.SetExtraHTTPHeaders(network.Headers{"Accept-Language": "en"}),
	); err != nil {
		t.Fatal("start account error UI browser")
	}

	// Authenticate through the fixture app's native OIDC flow, then use the
	// ordinary account link on the issuer admin page (no cookie or fetch spoof).
	stage = "app-start"
	if err := runLoginJourney(browser, 15*time.Second,
		chromedp.Navigate(app+"/"),
		chromedp.WaitVisible(`a[href="/login"]`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("app start: %v", err)
	}
	stage = "login-form"
	if err := runLoginJourney(browser, 15*time.Second,
		chromedp.Click(`a[href="/login"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`input[name="username"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`input[name="password"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`#login-client-context`, chromedp.ByQuery),
		chromedp.WaitVisible(`#login-submit`, chromedp.ByQuery),
		chromedp.Poll(`document.readyState === 'complete' && !!globalThis.GoAuthyI18n`, nil),
	); err != nil {
		t.Fatalf("login form: %v", err)
	}
	stage = "native-oidc-submit"
	if err := runLoginJourney(browser, 15*time.Second,
		chromedp.SetValue(`input[name="username"]`, username, chromedp.ByQuery),
		chromedp.SetValue(`input[name="password"]`, password, chromedp.ByQuery),
		chromedp.ScrollIntoView(`#login-submit`, chromedp.ByQuery),
		chromedp.Click(`#login-submit`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("native OIDC submit: %v", err)
	}
	stage = "native-oidc-return"
	if err := runLoginJourney(browser, 20*time.Second,
		chromedp.WaitVisible(`#account-subject`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("native OIDC app login: %v", err)
	}
	stage = "verify-native-oidc-subject"
	var subject string
	if err := runLoginJourney(browser, 10*time.Second, chromedp.Text(`#account-subject`, &subject, chromedp.ByQuery)); err != nil || subject != wantSubject {
		t.Fatalf("native OIDC app subject=%q, want configured synthetic subject", subject)
	}
	stage = "admin-dashboard-visible-login"
	if err := openAdminDashboardThroughVisibleLogin(browser, issuer); err != nil {
		t.Fatalf("open issuer admin dashboard through visible login: %v", err)
	}
	stage = "open-account-through-normal-link"
	if err := runLoginJourney(browser, 15*time.Second,
		chromedp.WaitVisible(`a[href="/account"]`, chromedp.ByQuery),
		chromedp.Click(`a[href="/account"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`#profile`, chromedp.ByQuery),
		chromedp.WaitVisible(`#profile-name`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("open account through normal issuer link: %v", err)
	}
	var initialProfileName, initialProfileContent string
	stage = "verify-loaded-profile"
	if err := runLoginJourney(browser, 10*time.Second,
		chromedp.Text(`#profile-name`, &initialProfileName, chromedp.ByQuery),
		chromedp.Text(`#profile-content`, &initialProfileContent, chromedp.ByQuery),
	); err != nil || strings.TrimSpace(initialProfileName) == "" || !strings.Contains(initialProfileContent, initialProfileName) {
		t.Fatalf("account profile heading/content not loaded: heading-empty=%t", strings.TrimSpace(initialProfileName) == "")
	}

	assertErrorFeedback := func(id, wantTitle string) {
		t.Helper()
		var role, live, iconHidden, title, detail string
		var bold bool
		selector := "#" + id
		stage = "read-feedback-" + id
		if err := runLoginJourney(browser, 10*time.Second,
			chromedp.AttributeValue(selector, "role", &role, nil, chromedp.ByQuery),
			chromedp.AttributeValue(selector, "aria-live", &live, nil, chromedp.ByQuery),
			chromedp.AttributeValue(selector+" .status-icon", "aria-hidden", &iconHidden, nil, chromedp.ByQuery),
			chromedp.Text(selector+" strong", &title, chromedp.ByQuery),
			chromedp.Text(selector+" .status-detail", &detail, chromedp.ByQuery),
			chromedp.Evaluate(`(() => { const e = document.querySelector('`+selector+` strong'); return !!e && parseInt(getComputedStyle(e).fontWeight, 10) >= 600; })()`, &bold),
		); err != nil {
			t.Fatalf("read %s error feedback: %v", id, err)
		}
		if role != "alert" || live != "assertive" || iconHidden != "true" || title != wantTitle || detail == "" || !bold {
			t.Fatalf("%s feedback role=%q live=%q icon-hidden=%q title=%q detail-empty=%t bold=%t", id, role, live, iconHidden, title, detail == "", bold)
		}
	}

	const badCurrent = "deliberately-wrong-current-password"
	const candidate = "Account-Error-Candidate-2B"
	stage = "submit-password-mismatch"
	if err := runLoginJourney(browser, 20*time.Second,
		chromedp.WaitVisible(`#password-form`, chromedp.ByQuery),
		chromedp.ScrollIntoView(`#password-form button[type="submit"]`, chromedp.ByQuery),
		chromedp.SetValue(`#password-current`, badCurrent, chromedp.ByQuery),
		chromedp.SetValue(`#password-new`, candidate, chromedp.ByQuery),
		chromedp.SetValue(`#password-confirm`, candidate, chromedp.ByQuery),
		chromedp.Click(`#password-form button[type="submit"]`, chromedp.ByQuery),
		chromedp.Poll(`document.querySelector('#password-status')?.getAttribute('role') === 'alert'`, nil),
	); err != nil {
		t.Fatalf("submit password mismatch: %v", err)
	}
	assertErrorFeedback("password-status", "Please check this message.")
	var currentValue, newValue, confirmValue, profileText, profileNameAfter string
	stage = "verify-password-form-preserved"
	if err := runLoginJourney(browser, 10*time.Second,
		chromedp.Value(`#password-current`, &currentValue, chromedp.ByQuery),
		chromedp.Value(`#password-new`, &newValue, chromedp.ByQuery),
		chromedp.Value(`#password-confirm`, &confirmValue, chromedp.ByQuery),
		chromedp.Text(`#profile-content`, &profileText, chromedp.ByQuery),
		chromedp.Text(`#profile-name`, &profileNameAfter, chromedp.ByQuery),
	); err != nil || currentValue != badCurrent || newValue != candidate || confirmValue != candidate || profileText != initialProfileContent || profileNameAfter != initialProfileName {
		t.Fatal("rejected password change cleared form values or changed the loaded profile")
	}

	// This controlled CDP response exercises only the browser's profile-load
	// error rendering; it is not evidence of a real backend failure.
	fulfilled := make(chan error, 1)
	chromedp.ListenTarget(browser, func(event any) {
		paused, ok := event.(*fetch.EventRequestPaused)
		if !ok {
			return
		}
		requestURL, err := url.Parse(paused.Request.URL)
		if err != nil || requestURL.Scheme != issuerURL.Scheme || requestURL.Host != issuerURL.Host || requestURL.Path != "/account/data" || requestURL.RawQuery != "" {
			go func() { _ = chromedp.Run(browser, fetch.ContinueRequest(paused.RequestID)) }()
			return
		}
		go func() {
			err := chromedp.Run(browser, fetch.FulfillRequest(paused.RequestID, 503).
				WithResponseHeaders([]*fetch.HeaderEntry{{Name: "Content-Type", Value: "application/json"}}).
				WithBody(base64.StdEncoding.EncodeToString([]byte(`{"error":"controlled UI fixture failure"}`))))
			select {
			case fulfilled <- err:
			default:
			}
		}()
	})
	pattern := issuerURL.Scheme + "://" + issuerURL.Host + "/account/data"
	stage = "controlled-profile-503-reload"
	if err := runLoginJourney(browser, 20*time.Second,
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{{URLPattern: pattern, RequestStage: fetch.RequestStageRequest}}),
		chromedp.Reload(),
		chromedp.Poll(`document.querySelector('#profile-status')?.getAttribute('role') === 'alert'`, nil),
	); err != nil {
		t.Fatalf("reload account with controlled profile 503: %v", err)
	}
	select {
	case err := <-fulfilled:
		if err != nil {
			t.Fatalf("fulfill controlled /account/data 503: %v", err)
		}
	case <-time.After(5 * time.Second):
		stage = "controlled-profile-503-intercept"
		t.Fatal("exact /account/data request was not intercepted")
	}
	assertErrorFeedback("profile-status", "Your account could not be loaded.")
	var profileAfterFailure string
	var passwordSectionHidden bool
	stage = "verify-profile-load-failure-cleared-data"
	if err := runLoginJourney(browser, 10*time.Second,
		chromedp.Text(`#profile-content`, &profileAfterFailure, chromedp.ByQuery),
		chromedp.Evaluate(`document.querySelector('#password-section')?.hidden === true`, &passwordSectionHidden),
		fetch.Disable(),
	); err != nil || strings.TrimSpace(profileAfterFailure) != "" || !passwordSectionHidden {
		t.Fatal("profile-load failure left stale profile data or password controls visible")
	}
}
