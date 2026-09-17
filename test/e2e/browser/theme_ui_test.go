package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/mrchypark/goauthy/internal/branding"
)

// TestThemeLoginUI proves that an authorization-code login page loads both
// theme stylesheets and applies the client theme in the real browser. It is
// opt-in because it needs a deployed fixture and Chromium.
func TestThemeLoginUI(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_THEME_UI") != "1" {
		t.Skip("set GOAUTHY_E2E_THEME_UI=1 to run Chromium theme UI E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	managed := createThemeUIClient(t, admin, primary, headers)
	t.Cleanup(func() { deleteThemeUIClient(t, admin, primary, headers, managed) })

	initial := themeUIInitialTheme(managed.ID)
	putThemeUI(t, admin, primary, headers, managed.ID, initial)
	authorizeURL := oidcAuthorizationURLForClient(t, primary, managed.ID, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "theme-ui-initial", "theme-ui-initial-nonce", "openid")

	ctx, cancel := newCollectionUIContext(t, nil, primary)
	defer cancel()
	observer := newThemeUIObserver(ctx)
	if err := chromedp.Run(ctx,
		network.Enable(),
		emulation.SetEmulatedMedia().WithFeatures([]*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: "light"}}),
		chromedp.Navigate(authorizeURL),
		chromedp.WaitVisible(`input[name="username"]`),
		themeUILoaded(),
	); err != nil {
		t.Fatalf("navigate authorization login page: %v", err)
	}
	initialState := readThemeUIState(t, ctx, initial.Light)
	assertThemeUILinks(t, initialState.Links, managed.ID)
	assertThemeUIResponses(t, observer, initialState.Links)
	initialThemeURL := themeUIClientURL(t, initialState.Links, managed.ID)

	updated := themeUIUpdatedTheme(managed.ID)
	putThemeUI(t, admin, primary, headers, managed.ID, updated)
	if err := chromedp.Run(ctx,
		emulation.SetEmulatedMedia().WithFeatures([]*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: "dark"}}),
		chromedp.Reload(),
		chromedp.WaitVisible(`input[name="username"]`),
		themeUILoaded(),
	); err != nil {
		t.Fatalf("reload authorization login page: %v", err)
	}
	updatedState := readThemeUIState(t, ctx, updated.Dark)
	assertThemeUILinks(t, updatedState.Links, managed.ID)
	updatedThemeURL := themeUIClientURL(t, updatedState.Links, managed.ID)
	if updatedThemeURL == initialThemeURL {
		t.Fatalf("theme cache URL did not change after update: %q", updatedThemeURL)
	}
	assertThemeUIResponses(t, observer, updatedState.Links)
}

type themeUIClient struct {
	ID       string
	Revision int64
}

func createThemeUIClient(t *testing.T, admin *http.Client, primary string, headers map[string]string) *themeUIClient {
	t.Helper()
	id := "theme-ui-" + randomManagedUIID(t)
	body, err := json.Marshal(map[string]any{
		"id":             id,
		"name":           "Theme UI E2E",
		"confidential":   false,
		"redirect_uris":  []string{defaultRedirectURI},
		"audience":       []string{defaultResourceIndicator},
		"default_aud":    []string{defaultResourceIndicator},
		"scopes":         []string{"openid"},
		"default_scopes": []string{"openid"},
		"enabled_flows":  []string{"authorization_code"},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, admin, http.MethodPost, primary+"/auth/v1/clients", bytes.NewReader(body), headers)
	defer response.Body.Close()
	var created themeUIClient
	decodeErr := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&created)
	if response.StatusCode != http.StatusCreated || decodeErr != nil || created.ID != id || created.Revision <= 0 {
		t.Fatalf("theme UI client create status=%d id=%q revision=%d decode=%v", response.StatusCode, created.ID, created.Revision, decodeErr)
	}
	return &created
}

func deleteThemeUIClient(t *testing.T, admin *http.Client, primary string, headers map[string]string, client *themeUIClient) {
	t.Helper()
	theme := do(t, admin, http.MethodDelete, primary+"/auth/v1/theme/"+url.PathEscape(client.ID), nil, headers)
	theme.Body.Close()
	if theme.StatusCode != http.StatusOK && theme.StatusCode != http.StatusNotFound {
		t.Errorf("theme UI override cleanup status=%d", theme.StatusCode)
	}
	response := do(t, admin, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(client.ID), nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(client.Revision, 10))))
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Errorf("theme UI client cleanup status=%d", response.StatusCode)
	}
}

func putThemeUI(t *testing.T, admin *http.Client, primary string, headers map[string]string, clientID string, theme branding.Theme) {
	t.Helper()
	body, err := json.Marshal(theme)
	if err != nil {
		t.Fatal(err)
	}
	putHeaders := cloneThemeHeaders(headers)
	putHeaders["Content-Type"] = "application/json"
	response := do(t, admin, http.MethodPut, primary+"/auth/v1/theme/"+url.PathEscape(clientID), bytes.NewReader(body), putHeaders)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("theme UI PUT status=%d", response.StatusCode)
	}
}

func themeUIInitialTheme(clientID string) branding.Theme {
	theme := branding.DefaultTheme(clientID)
	theme.Light.Text = []uint16{214, 76, 27}
	theme.Light.Bg = []uint16{42, 38, 91}
	theme.Dark.Text = []uint16{318, 73, 82}
	theme.Dark.Bg = []uint16{231, 61, 12}
	return theme
}

func themeUIUpdatedTheme(clientID string) branding.Theme {
	theme := branding.DefaultTheme(clientID)
	theme.Light.Text = []uint16{152, 68, 24}
	theme.Light.Bg = []uint16{198, 44, 88}
	theme.Dark.Text = []uint16{92, 81, 86}
	theme.Dark.Bg = []uint16{174, 57, 15}
	return theme
}

type themeUIObserver struct {
	mu          sync.Mutex
	responses   map[string]int64
	cspFailures []string
}

func newThemeUIObserver(ctx context.Context) *themeUIObserver {
	observer := &themeUIObserver{responses: make(map[string]int64)}
	chromedp.ListenTarget(ctx, func(event any) {
		observer.mu.Lock()
		defer observer.mu.Unlock()
		switch event := event.(type) {
		case *network.EventResponseReceived:
			if event.Type == network.ResourceTypeStylesheet {
				observer.responses[event.Response.URL] = event.Response.Status
			}
		case *network.EventLoadingFailed:
			if event.Type == network.ResourceTypeStylesheet && (string(event.BlockedReason) == "csp" || strings.Contains(event.ErrorText, "ERR_BLOCKED_BY_CSP")) {
				observer.cspFailures = append(observer.cspFailures, event.ErrorText)
			}
		}
	})
	return observer
}

func themeUILoaded() chromedp.Action {
	return chromedp.Poll(`(() => { const links = [...document.querySelectorAll('link[rel="stylesheet"]')]; return links.length === 2 && links.every(link => link.sheet !== null); })()`, nil)
}

type themeUIState struct {
	Links                 []string `json:"links"`
	Foreground            string   `json:"foreground"`
	Background            string   `json:"background"`
	ExpectedForeground    string   `json:"expected_foreground"`
	ExpectedBackground    string   `json:"expected_background"`
	CSSSupportsForeground bool     `json:"css_supports_foreground"`
	CSSSupportsBackground bool     `json:"css_supports_background"`
	AssignedForeground    string   `json:"assigned_foreground"`
	AssignedBackground    string   `json:"assigned_background"`
}

func readThemeUIState(t *testing.T, ctx context.Context, theme branding.ThemeCSS) themeUIState {
	t.Helper()
	text := themeHSL(theme.Text)
	background := themeHSL(theme.Bg)
	var state themeUIState
	script := fmt.Sprintf(`(() => {
		const links = [...document.querySelectorAll('link[rel="stylesheet"]')];
		const expectedForeground = %s;
		const expectedBackground = %s;
		const probe = document.createElement('span');
		const cssSupportsForeground = CSS.supports('color', expectedForeground);
		const cssSupportsBackground = CSS.supports('background-color', expectedBackground);
		probe.style.color = expectedForeground;
		probe.style.backgroundColor = expectedBackground;
		probe.style.position = 'absolute';
		probe.style.visibility = 'hidden';
		document.body.appendChild(probe);
		const bodyStyle = getComputedStyle(document.body);
		const probeStyle = getComputedStyle(probe);
		const state = {
			links: links.map(link => link.href),
			foreground: bodyStyle.color,
			background: bodyStyle.backgroundColor,
			expected_foreground: probeStyle.color,
			expected_background: probeStyle.backgroundColor,
			css_supports_foreground: cssSupportsForeground,
			css_supports_background: cssSupportsBackground,
			assigned_foreground: probe.style.color,
			assigned_background: probe.style.backgroundColor
		};
		probe.remove();
		return state;
	})()`, strconv.Quote(text), strconv.Quote(background))
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &state)); err != nil {
		t.Fatalf("read computed theme colors: %v", err)
	}
	if !state.CSSSupportsForeground || !state.CSSSupportsBackground || state.AssignedForeground == "" || state.AssignedBackground == "" {
		t.Fatalf("theme probe CSS valid foreground_support=%t background_support=%t assigned_foreground=%q assigned_background=%q", state.CSSSupportsForeground, state.CSSSupportsBackground, state.AssignedForeground, state.AssignedBackground)
	}
	if state.Foreground != state.ExpectedForeground || state.Background != state.ExpectedBackground {
		t.Fatalf("computed theme colors foreground=%q want=%q background=%q want=%q", state.Foreground, state.ExpectedForeground, state.Background, state.ExpectedBackground)
	}
	return state
}

func assertThemeUILinks(t *testing.T, links []string, clientID string) {
	t.Helper()
	if len(links) != 2 {
		t.Fatalf("theme login stylesheet links=%d, want 2: %v", len(links), links)
	}
	global := false
	clientPrefix := "/auth/v1/theme/" + url.PathEscape(clientID) + "/"
	client := false
	for _, link := range links {
		parsed, err := url.Parse(link)
		if err != nil {
			t.Fatalf("invalid theme stylesheet URL %q: %v", link, err)
		}
		switch parsed.Path {
		case "/auth/v1/theme/global.css":
			global = true
		default:
			client = client || strings.HasPrefix(parsed.Path, clientPrefix)
		}
	}
	if !global || !client {
		t.Fatalf("theme login links global=%t client=%t links=%v", global, client, links)
	}
}

func assertThemeUIResponses(t *testing.T, observer *themeUIObserver, links []string) {
	t.Helper()
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if len(observer.cspFailures) != 0 {
		t.Fatalf("theme login stylesheet CSP failures=%v", observer.cspFailures)
	}
	for _, link := range links {
		if status, ok := observer.responses[link]; !ok || status != http.StatusOK {
			t.Fatalf("theme stylesheet was not fetched successfully url=%q status=%d fetched=%t", link, status, ok)
		}
	}
}

func themeUIClientURL(t *testing.T, links []string, clientID string) string {
	t.Helper()
	prefix := "/auth/v1/theme/" + url.PathEscape(clientID) + "/"
	for _, link := range links {
		parsed, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(parsed.Path, prefix) {
			return link
		}
	}
	t.Fatal("client theme stylesheet URL missing")
	return ""
}

func themeHSL(values []uint16) string {
	return fmt.Sprintf("hsl(%d %d%% %d%%)", values[0], values[1], values[2])
}
