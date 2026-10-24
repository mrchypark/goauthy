package browser

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/mrchypark/goauthy/internal/branding"
	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestLoginFailureRetryAppReturnAndLogout(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_LOGIN_JOURNEY") != "1" {
		t.Skip("set GOAUTHY_E2E_LOGIN_JOURNEY=1 to run the isolated login journey")
	}
	if os.Getenv("GOAUTHY_LOGIN_JOURNEY_SLOT") != "granted" {
		t.Fatal("use the isolated login journey runner with a reserved fixture slot")
	}
	issuer := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	app := strings.TrimRight(os.Getenv("GOAUTHY_E2E_APP_URL"), "/")
	username, password := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	wantSubject := os.Getenv("GOAUTHY_E2E_BROWSER_SUBJECT")
	chromePath := os.Getenv("GOAUTHY_E2E_CHROME_BIN")
	if issuer == "" || app == "" || username == "" || password == "" || wantSubject == "" || chromePath == "" {
		t.Fatal("dedicated login journey fixture configuration is incomplete")
	}
	issuerURL, issuerErr := url.Parse(issuer)
	appURL, appErr := url.Parse(app)
	if issuerErr != nil || appErr != nil || issuerURL.Scheme != "http" || appURL.Scheme != "http" ||
		(issuerURL.Hostname() != "localhost" && issuerURL.Hostname() != "127.0.0.1") ||
		(appURL.Hostname() != "localhost" && appURL.Hostname() != "127.0.0.1") {
		t.Fatal("login journey requires local loopback HTTP origins")
	}
	seedLoginJourneyTheme(t, issuer, username, password, "login-journey-demo", app+"/callback")

	root, cancelRoot := context.WithTimeout(context.Background(), 3*time.Minute)
	options := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	options = append(options, chromedp.ExecPath(chromePath), chromedp.Headless, chromedp.NoFirstRun, chromedp.NoDefaultBrowserCheck)
	allocator, cancelAllocator := chromedp.NewExecAllocator(root, options...)
	browser, cancelBrowser := chromedp.NewContext(allocator)
	stage := "browser-start"
	var callbackSeen bool
	var callbackMu sync.Mutex
	var loginPostCount atomic.Int32
	chromedp.ListenTarget(browser, func(event any) {
		switch request := event.(type) {
		case *network.EventRequestWillBeSent:
			parsed, err := url.Parse(request.Request.URL)
			if err != nil {
				return
			}
			if parsed.Path == "/callback" && parsed.Host == appURL.Host {
				callbackMu.Lock()
				callbackSeen = true
				callbackMu.Unlock()
			}
			if parsed.Path == "/auth/login" && parsed.Host == issuerURL.Host && request.Request.Method == http.MethodPost {
				loginPostCount.Add(1)
			}
		}
	})
	t.Cleanup(func() {
		if t.Failed() {
			writeLoginJourneyFailureArtifact(browser, os.Getenv("GOAUTHY_E2E_ARTIFACT_DIR"), stage)
		}
		cancelBrowser()
		cancelAllocator()
		cancelRoot()
	})

	// Allocate Chrome on the journey context, not a short-lived stage context.
	if err := chromedp.Run(browser, network.Enable(), network.SetExtraHTTPHeaders(network.Headers{"Accept-Language": "en"})); err != nil {
		t.Fatal("stage browser-start failed")
	}

	stage = "app-start"
	if err := runLoginJourney(browser, 15*time.Second,
		chromedp.Navigate(app+"/"),
		chromedp.WaitVisible(`a[href="/login"]`),
	); err != nil {
		t.Fatal("stage app-start failed")
	}
	var signedOut string
	if err := runLoginJourney(browser, 10*time.Second, chromedp.Text(`.badge.out`, &signedOut)); err != nil || signedOut != "Signed out" {
		t.Fatal("stage initial-signed-out failed")
	}

	stage = "login-form"
	if err := runLoginJourney(browser, 15*time.Second,
		chromedp.Click(`a[href="/login"]`),
		chromedp.WaitVisible(`input[name="username"]`),
		chromedp.WaitVisible(`input[name="password"]`),
		chromedp.WaitVisible(`#login-client-context`),
		chromedp.WaitVisible(`#login-submit`),
		chromedp.Poll(`document.readyState === 'complete' && !!globalThis.GoAuthyI18n`, nil),
	); err != nil {
		t.Fatal("stage login-form failed")
	}
	var before loginJourneyPresentation
	if err := runLoginJourney(browser, 10*time.Second, chromedp.Evaluate(loginJourneyPresentationJS, &before)); err != nil || before.Brand != "Login Journey Brand" || before.Heading == "" || before.Context != "Continue to login-journey-demo" || before.PanelRadius != "19px" || before.Interaction == "" || !hasLoginJourneyThemeLink(before.ThemeLinks) {
		t.Fatal("stage login-brand failed")
	}

	stage = "bad-password"
	if err := runLoginJourney(browser, 10*time.Second,
		chromedp.SendKeys(`input[name="username"]`, username),
		chromedp.SendKeys(`input[name="password"]`, "Definitely-Wrong-Login-9!"),
	); err != nil {
		t.Fatal("stage bad-password-input failed")
	}
	// Check the duplicate-submit guard before the real native POST can unload this document.
	var submitGuards loginJourneySubmitGuards
	if err := runLoginJourney(browser, 5*time.Second, chromedp.Evaluate(`(() => {
		const form = document.querySelector('#login-form');
		const button = document.querySelector('#login-submit');
		const progress = document.querySelector('[data-login-progress]');
		if (!form || !button || !progress) return {firstBusy:false, secondPrevented:false, pageshowReset:false};
		form.dispatchEvent(new Event('submit', {bubbles:true, cancelable:true}));
		const firstBusy = form.getAttribute('aria-busy') === 'true' && button.disabled && !progress.hidden && getComputedStyle(progress).display !== 'none';
		const second = new Event('submit', {bubbles:true, cancelable:true});
		form.dispatchEvent(second);
		const secondPrevented = second.defaultPrevented;
		window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted:true}));
		const pageshowReset = !button.disabled && progress.hidden && !form.hasAttribute('aria-busy');
		return {firstBusy, secondPrevented, pageshowReset};
	})()`, &submitGuards)); err != nil || !submitGuards.FirstBusy || !submitGuards.SecondPrevented || !submitGuards.PageshowReset {
		t.Fatal("stage pending-submit-guard failed")
	}
	if err := runLoginJourney(browser, 10*time.Second, chromedp.Click(`#login-submit`)); err != nil {
		t.Fatal("stage bad-password-submit failed")
	}
	if err := runLoginJourney(browser, 20*time.Second, chromedp.WaitVisible(`#login-error`)); err != nil {
		t.Fatal("stage bad-password-response failed")
	}
	if got := loginPostCount.Load(); got != 1 {
		t.Fatalf("stage duplicate-login-post-count failed: observed %d /auth/login POSTs, want 1", got)
	}
	var enteredUsername, clearedPassword, interaction string
	if err := runLoginJourney(browser, 10*time.Second,
		chromedp.Value(`input[name="username"]`, &enteredUsername),
		chromedp.Value(`input[name="password"]`, &clearedPassword),
		chromedp.Value(`input[name="interaction"]`, &interaction),
	); err != nil || enteredUsername != username || clearedPassword != "" || interaction == "" {
		t.Fatal("stage retry-context-preserved failed")
	}
	if interaction != before.Interaction {
		t.Fatal("stage login-interaction-preserved failed")
	}
	var after loginJourneyPresentation
	if err := runLoginJourney(browser, 10*time.Second, chromedp.Evaluate(loginJourneyPresentationJS, &after)); err != nil || !sameLoginJourneyPresentation(before, after) {
		t.Fatal("stage branded-context-preserved failed")
	}
	var alertText string
	if err := runLoginJourney(browser, 10*time.Second, chromedp.Text(`#login-error`, &alertText)); err != nil || alertText != "Check your username or password" {
		t.Fatal("stage branded-login-error failed")
	}

	stage = "correct-password-retry"
	if err := runLoginJourney(browser, 20*time.Second,
		chromedp.Clear(`input[name="password"]`),
		chromedp.SendKeys(`input[name="password"]`, password),
		chromedp.Click(`#login-submit`),
		chromedp.WaitVisible(`#account-subject`),
	); err != nil {
		t.Fatal("stage correct-password-retry failed")
	}
	var subject string
	if err := runLoginJourney(browser, 10*time.Second, chromedp.Text(`#account-subject`, &subject)); err != nil || subject != wantSubject {
		t.Fatal("stage app-return-identity failed")
	}
	callbackMu.Lock()
	observedCallback := callbackSeen
	callbackMu.Unlock()
	if !observedCallback {
		t.Fatal("stage oidc-callback failed")
	}

	stage = "admin-role-session"
	if err := openAdminDashboardThroughVisibleLogin(browser, issuer); err != nil {
		t.Fatal("stage admin-role-dashboard failed")
	}
	if err := runLoginJourney(browser, 20*time.Second,
		chromedp.Navigate(app+"/"),
		chromedp.WaitVisible(`#account-subject`),
	); err != nil {
		t.Fatal("stage admin-role-and-app-session failed")
	}

	stage = "app-logout"
	if err := runLoginJourney(browser, 20*time.Second,
		chromedp.Click(`form[action="/logout"] button[type="submit"]`),
		chromedp.WaitVisible(`a[href="/login"]`),
	); err != nil {
		t.Fatal("stage app-logout failed")
	}
	stage = "app-reload-signed-out"
	if err := runLoginJourney(browser, 15*time.Second, chromedp.Reload(), chromedp.WaitVisible(`a[href="/login"]`), chromedp.Text(`.badge.out`, &signedOut)); err != nil || signedOut != "Signed out" {
		t.Fatal("stage app-reload-signed-out failed")
	}
	stage = "identity-provider-session-retained"
	if err := openAdminDashboardThroughVisibleLogin(browser, issuer); err != nil {
		t.Fatal("stage identity-provider-session-retained failed")
	}
}

type loginJourneyPresentation struct {
	Brand       string   `json:"brand"`
	Logo        string   `json:"logo"`
	Heading     string   `json:"heading"`
	Context     string   `json:"context"`
	ThemeLinks  []string `json:"themeLinks"`
	PanelRadius string   `json:"panelRadius"`
	Interaction string   `json:"interaction"`
	CSRF        string   `json:"csrf"`
}

type loginJourneySubmitGuards struct {
	FirstBusy       bool `json:"firstBusy"`
	SecondPrevented bool `json:"secondPrevented"`
	PageshowReset   bool `json:"pageshowReset"`
}

const loginJourneyPresentationJS = `(() => {
	const brand = document.querySelector('.auth-brand');
	const logo = brand ? brand.querySelector('img') : null;
	const heading = document.querySelector('h1');
	const context = document.querySelector('#login-client-context');
	return {
		brand: brand ? (brand.innerText.trim() || (logo ? logo.alt : '')) : '',
		logo: logo ? new URL(logo.src).pathname + new URL(logo.src).search : '',
		heading: heading ? heading.innerText.trim() : '',
		context: context ? context.innerText.trim() : '',
		themeLinks: [...document.querySelectorAll('link[rel="stylesheet"]')]
			.filter(link => new URL(link.href).pathname.includes('/auth/v1/theme/'))
			.map(link => new URL(link.href).pathname),
		panelRadius: getComputedStyle(document.body).getPropertyValue('--border-radius').trim(),
		interaction: document.querySelector('input[name="interaction"]')?.value || '',
		csrf: document.querySelector('input[name="csrf_token"]')?.value || ''
	};
})()`

func sameLoginJourneyPresentation(a, b loginJourneyPresentation) bool {
	if a.Brand != b.Brand || a.Logo != b.Logo || a.Heading != b.Heading || a.Context != b.Context || a.PanelRadius != b.PanelRadius || a.Interaction != b.Interaction || a.CSRF != b.CSRF || len(a.ThemeLinks) != len(b.ThemeLinks) || !hasLoginJourneyThemeLink(a.ThemeLinks) {
		return false
	}
	for i := range a.ThemeLinks {
		if a.ThemeLinks[i] != b.ThemeLinks[i] {
			return false
		}
	}
	return true
}

func hasLoginJourneyThemeLink(links []string) bool {
	for _, link := range links {
		if strings.Contains(link, "/auth/v1/theme/login-journey-demo/") {
			return true
		}
	}
	return false
}

func seedLoginJourneyTheme(t *testing.T, issuer, username, password, clientID, redirectURI string) {
	t.Helper()
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	authorize := oidcAuthorizationURLForClient(t, issuer, clientID, redirectURI, pkceChallenge(verifier), "journey-theme-state", "journey-theme-nonce", "openid")
	response := do(t, client, http.MethodGet, authorize, nil, nil)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("theme fixture authorize status=%d", response.StatusCode)
	}
	initCookie := assertSessionCookie(t, response.Cookies(), issuer)
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	response.Body.Close()
	if err != nil {
		t.Fatal("theme fixture authorize response unreadable")
	}
	interaction, ok := hiddenInputValue(string(body), "interaction")
	if !ok {
		t.Fatal("theme fixture login form missing interaction")
	}
	form := url.Values{"interaction": {interaction}, "username": {username}, "password": {password}}
	response = do(t, client, http.MethodPost, issuer+"/auth/login", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin",
	})
	rotatedCookie := assertSessionCookie(t, response.Cookies(), issuer)
	location, parseErr := url.Parse(response.Header.Get("Location"))
	response.Body.Close()
	if (response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther) || parseErr != nil || location.Scheme+"://"+location.Host+location.Path != redirectURI || rotatedCookie.Value == initCookie.Value {
		t.Fatal("theme fixture admin login did not complete")
	}
	csrf, err := browsersession.DeriveCSRFToken(rotatedCookie.Value)
	if err != nil {
		t.Fatal("theme fixture CSRF derivation failed")
	}
	global := branding.DefaultTheme(branding.GlobalBrandID)
	global.BrandName = "Login Journey Brand"
	putThemeUI(t, client, issuer, rbacMutationHeaders(csrf), branding.GlobalBrandID, global)
	theme := branding.DefaultTheme(clientID)
	theme.BorderRadius = "19px"
	putThemeUI(t, client, issuer, rbacMutationHeaders(csrf), clientID, theme)
}

func runLoginJourney(ctx context.Context, timeout time.Duration, actions ...chromedp.Action) error {
	stage, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return chromedp.Run(stage, actions...)
}

func openAdminDashboardThroughVisibleLogin(ctx context.Context, issuer string) error {
	var loginLinkVisible bool
	if err := runLoginJourney(ctx, 15*time.Second,
		chromedp.Navigate(issuer+"/auth/v1/admin/dashboard"),
		chromedp.WaitVisible(`#overview-identity, a[href="/account/login"]`),
		chromedp.Evaluate(`(() => {
			const link = document.querySelector('a[href="/account/login"]');
			return !!link && link.getClientRects().length > 0 && getComputedStyle(link).visibility !== 'hidden';
		})()`, &loginLinkVisible),
	); err != nil {
		return err
	}
	if loginLinkVisible {
		if err := runLoginJourney(ctx, 15*time.Second, chromedp.Click(`a[href="/account/login"]`)); err != nil {
			return err
		}
	}
	return runLoginJourney(ctx, 15*time.Second, chromedp.WaitVisible(`#overview-identity`))
}

func writeLoginJourneyFailureArtifact(ctx context.Context, directory, stage string) {
	if directory == "" {
		return
	}
	if os.MkdirAll(directory, 0o700) != nil {
		return
	}
	if err := os.WriteFile(filepath.Join(directory, "stage.txt"), []byte(stage+"\n"), 0o600); err != nil {
		return
	}
	var screenshot []byte
	mask := chromedp.Evaluate(`document.querySelectorAll('input,textarea,[contenteditable="true"]').forEach((node) => {
		node.value = '';
		node.textContent = '';
		node.style.visibility = 'hidden';
	});
	for (const selector of ['#account-subject', '#account-email', '#overview-identity']) {
		const node = document.querySelector(selector);
		if (node) node.textContent = '[redacted synthetic identity]';
	}`, nil)
	stageCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if chromedp.Run(stageCtx, mask, chromedp.CaptureScreenshot(&screenshot)) == nil && len(screenshot) != 0 {
		_ = os.WriteFile(filepath.Join(directory, "failure.png"), screenshot, 0o600)
	}
}
