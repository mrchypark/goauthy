package captcha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUnconfiguredVerifierReturnsTrue(t *testing.T) {
	v := NewVerifier(func(string) string { return "" })
	if v.SiteKey() != "" {
		t.Fatalf("expected empty SiteKey, got %q", v.SiteKey())
	}
	ok, err := v.Verify(context.Background(), "anything", "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true from unconfigured verifier")
	}
}

func TestUnknownProviderReturnsTrue(t *testing.T) {
	v := NewVerifier(func(name string) string {
		switch name {
		case "GOAUTHY_CAPTCHA_PROVIDER":
			return "unknown"
		case "GOAUTHY_CAPTCHA_SITE_KEY":
			return "sk"
		case "GOAUTHY_CAPTCHA_SECRET_KEY":
			return "sk"
		}
		return ""
	})
	ok, err := v.Verify(context.Background(), "token", "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true from unknown provider verifier")
	}
}

func TestTurnstileVerifierRejectsEmptyResponse(t *testing.T) {
	v := NewVerifier(func(name string) string {
		switch name {
		case "GOAUTHY_CAPTCHA_PROVIDER":
			return "turnstile"
		case "GOAUTHY_CAPTCHA_SITE_KEY":
			return "site"
		case "GOAUTHY_CAPTCHA_SECRET_KEY":
			return "secret"
		}
		return ""
	})
	if v.SiteKey() != "site" {
		t.Fatalf("expected SiteKey 'site', got %q", v.SiteKey())
	}
	ok, err := v.Verify(context.Background(), "", "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected false for empty response")
	}
}

func TestHCaptchaVerifierRejectsEmptyResponse(t *testing.T) {
	v := NewVerifier(func(name string) string {
		switch name {
		case "GOAUTHY_CAPTCHA_PROVIDER":
			return "hcaptcha"
		case "GOAUTHY_CAPTCHA_SITE_KEY":
			return "site"
		case "GOAUTHY_CAPTCHA_SECRET_KEY":
			return "secret"
		}
		return ""
	})
	if v.SiteKey() != "site" {
		t.Fatalf("expected SiteKey 'site', got %q", v.SiteKey())
	}
	ok, err := v.Verify(context.Background(), "", "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected false for empty response")
	}
}

func TestHTTPVerifierVerifyPaths(t *testing.T) {
	t.Parallel()
	var status int
	var payload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	v := &httpVerifier{provider: "turnstile", verifyURL: srv.URL, siteKey: "site", secretKey: "secret"}

	status, payload = http.StatusOK, `{"success":true}`
	ok, err := v.Verify(context.Background(), "token-1", "192.0.2.1")
	if err != nil || !ok {
		t.Fatalf("expected true, nil; got ok=%t err=%v", ok, err)
	}

	status, payload = http.StatusOK, `{"success":false}`
	ok, err = v.Verify(context.Background(), "token-2", "")
	if err != nil || ok {
		t.Fatalf("expected false, nil; got ok=%t err=%v", ok, err)
	}

	status, payload = http.StatusBadGateway, `bad gateway`
	if ok, err = v.Verify(context.Background(), "token-3", ""); err == nil || ok {
		t.Fatalf("expected error on non-2xx, got ok=%t err=%v", ok, err)
	}

	status, payload = http.StatusOK, `{not-json`
	if ok, err = v.Verify(context.Background(), "token-4", ""); err == nil || ok {
		t.Fatalf("expected error on invalid JSON, got ok=%t err=%v", ok, err)
	}
}
