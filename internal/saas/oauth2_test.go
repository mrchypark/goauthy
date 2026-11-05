package saas

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

func TestOAuth2ConfiguredExchangeAndRefresh(t *testing.T) {
	t.Parallel()
	for _, style := range []oauth2.AuthStyle{oauth2.AuthStyleInHeader, oauth2.AuthStyleInParams} {
		t.Run(map[oauth2.AuthStyle]string{oauth2.AuthStyleInHeader: "basic", oauth2.AuthStyleInParams: "post"}[style], func(t *testing.T) {
			var calls atomic.Int32
			verifier := strings.Repeat("v", 43)
			fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				call := calls.Add(1)
				if r.Method != "POST" || r.URL.Path != "/token" {
					t.Error("unexpected exchange destination")
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if style == oauth2.AuthStyleInHeader {
					id, secret, ok := r.BasicAuth()
					if !ok || id != "client" || secret != "client-secret" || r.Form.Get("client_secret") != "" {
						t.Error("invalid Basic exchange")
					}
				} else if r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "client-secret" || r.Header.Get("Authorization") != "" {
					t.Error("invalid POST exchange")
				}
				if call == 1 {
					if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") != verifier || r.Form.Get("redirect_uri") != "https://auth.example/callback" {
						t.Error("invalid authorization code parameters")
					}
				} else if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-1" {
					t.Error("invalid refresh parameters")
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"access_token":"access-1","token_type":"Bearer","refresh_token":"refresh-1"}`)
			}))
			defer fixture.Close()
			cfg := OAuth2Config{ClientID: "client", AuthorizationURL: fixture.URL + "/authorize", TokenURL: fixture.URL + "/token", CallbackURL: "https://auth.example/callback", Scopes: []string{"read"}, AuthStyle: style}
			o, err := NewOAuth2(cfg, "client-secret")
			if err != nil {
				t.Fatal(err)
			}
			o.client.Transport = fixture.Client().Transport
			cfg.Scopes[0] = "mutated"
			authorize, err := o.AuthorizationURL("fixed-state", verifier)
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(authorize)
			if u.Query().Get("scope") != "read" || u.Query().Get("code_challenge") != oauth2.S256ChallengeFromVerifier(verifier) || u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("state") != "fixed-state" {
				t.Fatal("invalid authorization URL")
			}
			first, err := o.Exchange(t.Context(), "code", verifier)
			if err != nil || first.AccessToken != "access-1" {
				t.Fatalf("exchange: %v", err)
			}
			if first.Extra("scope") != nil {
				t.Fatal("invented provider-granted scope")
			}
			if _, err := o.Refresh(t.Context(), first.RefreshToken); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 2 {
				t.Fatalf("exchange attempts=%d want2", calls.Load())
			}
		})
	}
}

func TestOAuth2FailureDoesNotRetryOrLeakProviderBody(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"invalid_client","error_description":"private-provider-data"}`)
	}))
	defer fixture.Close()
	o, err := NewOAuth2(OAuth2Config{ClientID: "client", AuthorizationURL: fixture.URL + "/authorize", TokenURL: fixture.URL + "/token", CallbackURL: "https://auth.example/callback", Scopes: []string{"read"}, AuthStyle: oauth2.AuthStyleInHeader}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	o.client.Transport = fixture.Client().Transport
	if _, err := o.Exchange(t.Context(), "code", strings.Repeat("v", 43)); !errors.Is(err, ErrOAuth2Exchange) || strings.Contains(err.Error(), "private-provider-data") {
		t.Fatalf("unredacted error=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("auth style retry calls=%d", calls.Load())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := o.Refresh(ctx, "refresh"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("cancelled refresh contacted provider")
	}
}

func TestOAuth2RejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	base := OAuth2Config{ClientID: "client", AuthorizationURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token", CallbackURL: "https://auth.example/callback", Scopes: []string{"read"}, AuthStyle: oauth2.AuthStyleInHeader}
	for _, mutate := range []func(*OAuth2Config){
		func(c *OAuth2Config) { c.AuthStyle = oauth2.AuthStyleAutoDetect },
		func(c *OAuth2Config) { c.TokenURL = "http://provider.example/token" },
		func(c *OAuth2Config) { c.AuthorizationURL = "https://name:secret@provider.example/authorize" },
		func(c *OAuth2Config) { c.Scopes = []string{"read write"} },
		func(c *OAuth2Config) { c.Scopes = []string{"read", "read"} },
	} {
		cfg := base
		mutate(&cfg)
		if _, err := NewOAuth2(cfg, "secret"); !errors.Is(err, ErrOAuth2Config) {
			t.Fatalf("configuration accepted: %v", err)
		}
	}
}

func TestOAuth2LocalhostCallbackBoundary(t *testing.T) {
	t.Parallel()
	const callback = "http://localhost:18080/auth/v1/saas/callback/google-personal"
	for _, tc := range []struct {
		callback string
		want     bool
	}{
		{callback, true},
		{"http://LOCALHOST:18080/auth/v1/saas/callback/google-personal", true},
		{"http://127.0.0.1:18080/callback", true},
		{"http://[::1]:18080/callback", true},
		{"https://auth.example/callback", true},
		{"http://192.168.1.2:18080/callback", false},
		{"http://provider.example/callback", false},
		{"http://app.localhost:18080/callback", false},
		{"http://localhost.example:18080/callback", false},
		{"http://127.example:18080/callback", false},
		{"http://user@localhost:18080/callback", false},
		{callback + "?state=fixed", false},
		{callback + "#fragment", false},
		{"http:localhost:18080/callback", false},
		{"http://localhost:18080", false},
	} {
		t.Run(tc.callback, func(t *testing.T) {
			if got := validCallback(tc.callback); got != tc.want {
				t.Fatalf("validCallback=%v, want %v", got, tc.want)
			}
		})
	}
	base := OAuth2Config{ClientID: "client", AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token", CallbackURL: callback, Scopes: []string{"openid", "email", "profile"}, AuthStyle: oauth2.AuthStyleInParams, IdentityEndpoint: "https://openidconnect.googleapis.com/v1/userinfo", SubjectField: "sub"}
	o, err := NewOAuth2(base, "synthetic-client-secret")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := o.AuthorizationURL("fixed-state", strings.Repeat("v", 43))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Query().Get("redirect_uri") != callback {
		t.Fatal("authorization did not preserve the exact localhost callback")
	}
	for _, endpoint := range []string{callback, "http://127.0.0.1:18080/endpoint", "http://192.168.1.2/endpoint"} {
		for _, field := range []string{"authorization", "token", "identity"} {
			t.Run(field+"/"+endpoint, func(t *testing.T) {
				cfg := base
				switch field {
				case "authorization":
					cfg.AuthorizationURL = endpoint
				case "token":
					cfg.TokenURL = endpoint
				case "identity":
					cfg.IdentityEndpoint = endpoint
				}
				if _, err := NewOAuth2(cfg, "synthetic-client-secret"); !errors.Is(err, ErrOAuth2Config) {
					t.Fatal("HTTP outbound endpoint accepted")
				}
			})
		}
	}
}
