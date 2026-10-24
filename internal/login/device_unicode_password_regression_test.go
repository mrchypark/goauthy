package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestDeviceLoginAcceptsPolicyMaxMultibyteExistingPassword(t *testing.T) {
	h := testHandler(t)
	password := strings.Repeat("ẞ", 126) + "a4"
	if len(password) <= 256 {
		t.Fatalf("fixture has %d bytes; want more than the old device-login cap", len(password))
	}
	phc, err := testHash(context.Background(), []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.identity.BootstrapUser(context.Background(), "unicode-user", "unicode", phc); err != nil {
		t.Fatal(err)
	}

	page := httptest.NewRecorder()
	get := httptest.NewRequest(http.MethodGet, "/oidc/device/login?user_code=AB12CD34", nil)
	get.RemoteAddr = "203.0.113.8:1234"
	h.DeviceLoginHandler(false).ServeHTTP(page, get)
	if page.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", page.Code, page.Body.String())
	}
	interaction := regexp.MustCompile(`name="interaction" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if len(interaction) != 2 || len(csrf) != 2 || len(page.Result().Cookies()) == 0 {
		t.Fatal("device login page omitted its session or form fields")
	}
	form := url.Values{
		"interaction": {interaction[1]},
		"csrf_token":  {csrf[1]},
		"username":    {"unicode"},
		"password":    {password},
	}
	post := httptest.NewRequest(http.MethodPost, "/oidc/device/login", strings.NewReader(form.Encode()))
	post.RemoteAddr = get.RemoteAddr
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "http://localhost")
	post.AddCookie(page.Result().Cookies()[0])
	result := httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(result, post)
	if result.Code != http.StatusSeeOther || result.Header().Get("Location") != "http://localhost/oidc/device/verify?user_code=AB12CD34" {
		t.Fatalf("POST status=%d location=%q body=%s", result.Code, result.Header().Get("Location"), result.Body.String())
	}
}
