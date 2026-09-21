package login

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestThemeLinksResolveOAuthClientAndDirectPagesUseGlobalClient(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	var clients []string
	h.SetThemeURLResolver(func(_ context.Context, clientID string) (string, error) {
		clients = append(clients, clientID)
		return "/auth/v1/theme/" + clientID + "/123", nil
	})

	oauthPage := httptest.NewRecorder()
	oauthRequest := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	oauthRequest.RemoteAddr = "198.51.100.10:1234"
	h.Authorize(oauthPage, oauthRequest)
	if oauthPage.Code != http.StatusOK || clientsString(clients) != "browser-client" {
		t.Fatalf("OAuth page status=%d resolver clients=%q", oauthPage.Code, clientsString(clients))
	}
	assertThemeLinks(t, oauthPage.Body.String(), `/auth/v1/theme/browser-client/123`)
	if got := oauthPage.Header().Get("Content-Security-Policy"); strings.Contains(got, "unsafe-inline") || !strings.Contains(got, "style-src 'self'") {
		t.Fatalf("OAuth CSP=%q", got)
	}

	h.issuer = "https://issuer.example.test"
	if err := h.EnableFedCM(true); err != nil {
		t.Fatal(err)
	}
	fedCMLanding := httptest.NewRecorder()
	fedCMRequest := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	fedCMRequest.RemoteAddr = "198.51.100.11:1234"
	h.FedCMLanding(fedCMLanding, fedCMRequest)
	if fedCMLanding.Code != http.StatusOK || clientsString(clients) != "browser-client,rauthy" {
		t.Fatalf("FedCM landing status=%d resolver clients=%q", fedCMLanding.Code, clientsString(clients))
	}
	assertThemeLinks(t, fedCMLanding.Body.String(), `/auth/v1/theme/rauthy/123`)
	fedCMCookies := fedCMLanding.Result().Cookies()
	if len(fedCMCookies) != 1 {
		t.Fatalf("FedCM landing cookies=%d", len(fedCMCookies))
	}
	interaction := interactionToken(t, fedCMLanding.Body.String())
	csrf := fedCMCSRFPattern.FindStringSubmatch(fedCMLanding.Body.String())
	if len(csrf) != 2 {
		t.Fatalf("FedCM landing CSRF missing")
	}
	fedCMValues := url.Values{"fedcm": {"1"}, "interaction": {interaction}, "csrf_token": {csrf[1]}, "username": {"alice"}, "password": {"correct password"}}
	fedCMPost := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(fedCMValues.Encode()))
	fedCMPost.RemoteAddr = fedCMRequest.RemoteAddr
	fedCMPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fedCMPost.Header.Set("Origin", "https://issuer.example.test")
	fedCMPost.Header.Set("Sec-Fetch-Site", "same-origin")
	fedCMPost.AddCookie(fedCMCookies[0])
	fedCMSuccess := httptest.NewRecorder()
	h.FedCMLanding(fedCMSuccess, fedCMPost)
	if fedCMSuccess.Code != http.StatusOK || clientsString(clients) != "browser-client,rauthy,rauthy" {
		t.Fatalf("FedCM success status=%d resolver clients=%q", fedCMSuccess.Code, clientsString(clients))
	}
	assertThemeLinks(t, fedCMSuccess.Body.String(), `/auth/v1/theme/rauthy/123`)

	devicePage := httptest.NewRecorder()
	deviceRequest := httptest.NewRequest(http.MethodGet, "/oidc/device/login?user_code=AB12CD34", nil)
	deviceRequest.RemoteAddr = "198.51.100.12:1234"
	h.DeviceLoginHandler(false).ServeHTTP(devicePage, deviceRequest)
	if devicePage.Code != http.StatusOK || clientsString(clients) != "browser-client,rauthy,rauthy,rauthy" {
		t.Fatalf("device page status=%d resolver clients=%q", devicePage.Code, clientsString(clients))
	}
	assertThemeLinks(t, devicePage.Body.String(), `/auth/v1/theme/rauthy/123`)

	connectionPage := httptest.NewRecorder()
	connectionRequest := httptest.NewRequest(http.MethodGet, "/account/connection-login?handoff_id="+testHandoffID, nil)
	connectionRequest.RemoteAddr = "198.51.100.13:1234"
	h.ConnectionHandoffLoginHandler(false).ServeHTTP(connectionPage, connectionRequest)
	if connectionPage.Code != http.StatusOK || clientsString(clients) != "browser-client,rauthy,rauthy,rauthy,rauthy" {
		t.Fatalf("connection page status=%d resolver clients=%q", connectionPage.Code, clientsString(clients))
	}
	assertThemeLinks(t, connectionPage.Body.String(), `/auth/v1/theme/rauthy/123`)
}

func TestThemeLinkEscapesUntrustedResolverURL(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	h.SetThemeURLResolver(func(context.Context, string) (string, error) {
		return `/auth/v1/theme/rauthy/123\"><script>alert(1)</script>`, nil
	})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	request.RemoteAddr = "198.51.100.14:1234"
	h.Authorize(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	body := response.Body.String()
	if strings.Contains(body, `/123"><`) || strings.Contains(body, `alert(1)`) {
		t.Fatalf("untrusted resolver value escaped into HTML: %q", body)
	}
	if strings.Contains(body, `<script>alert(1)</script>`) {
		t.Fatalf("literal injection script present in body: %q", body)
	}
	wantEscaped := `/auth/v1/theme/rauthy/123%5c%22%3e%3cscript%3ealert%281%29%3c/script%3e`
	if !strings.Contains(body, `<link rel="stylesheet" href="`+wantEscaped+`">`) {
		t.Fatalf("escaped malicious URL not in stylesheet href: %q", body)
	}
	if !strings.Contains(body, `<link rel="stylesheet" href="/auth/v1/theme/global.css">`) {
		t.Fatalf("missing global stylesheet link: %q", body)
	}
	nonceMatches := regexp.MustCompile(`<script nonce="([^"]+)"`).FindAllStringSubmatch(body, -1)
	if len(nonceMatches) == 0 {
		t.Fatalf("expected at least one legitimate nonce script: %q", body)
	}
}

func TestThemeResolverErrorStopsLoginPage(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	h.SetThemeURLResolver(func(context.Context, string) (string, error) {
		return "", errors.New("theme unavailable")
	})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	request.RemoteAddr = "198.51.100.15:1234"
	h.Authorize(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "Service Unavailable\n" {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func assertThemeLinks(t *testing.T, body, wantClientURL string) {
	t.Helper()
	if !strings.Contains(body, `<link rel="stylesheet" href="/auth/v1/theme/global.css">`) || !strings.Contains(body, `<link rel="stylesheet" href="`+wantClientURL+`">`) {
		t.Fatalf("stylesheet links missing from %q", body)
	}
}

func clientsString(clients []string) string { return strings.Join(clients, ",") }
