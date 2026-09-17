package captcha

import (
	"context"
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
