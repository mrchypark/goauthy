package saas

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestOAuth2IdentityUsesBearerAndAcceptsStringOrInteger(t *testing.T) {
	for _, tc := range []struct{ body, want string }{{`{"sub":"user-1"}`, "user-1"}, {`{"sub":123456789012345678}`, "123456789012345678"}} {
		fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("Accept") != "application/json" {
				t.Error("invalid identity request")
			}
			requestBody, err := io.ReadAll(r.Body)
			if err != nil || len(requestBody) != 0 || r.URL.RawQuery != "" || strings.Contains(r.Header.Get("Authorization"), "client-secret") || r.Header.Get("X-Client-Secret") != "" {
				t.Error("client secret sent")
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, tc.body)
		}))
		o, err := NewOAuth2(OAuth2Config{ClientID: "client", AuthorizationURL: "https://provider.example/auth", TokenURL: "https://provider.example/token", CallbackURL: "https://auth.example/callback", Scopes: []string{"openid"}, AuthStyle: oauth2.AuthStyleInHeader, IdentityEndpoint: fixture.URL, SubjectField: "sub"}, "client-secret")
		if err != nil {
			t.Fatal(err)
		}
		o.client.Transport = fixture.Client().Transport
		if got, err := o.Identity(t.Context(), "access-token"); err != nil || got != tc.want {
			t.Fatalf("identity=%q err=%v", got, err)
		}
		fixture.Close()
	}
}

func TestOAuth2IdentityRejectsMalformedResponsesAndConfig(t *testing.T) {
	base := OAuth2Config{ClientID: "client", AuthorizationURL: "https://provider.example/auth", TokenURL: "https://provider.example/token", CallbackURL: "https://auth.example/callback", Scopes: []string{"openid"}, AuthStyle: oauth2.AuthStyleInHeader}
	for _, mutate := range []func(*OAuth2Config){func(c *OAuth2Config) { c.IdentityEndpoint = "https://provider.example/user" }, func(c *OAuth2Config) { c.SubjectField = "sub" }, func(c *OAuth2Config) { c.IdentityEndpoint = "http://provider.example/user"; c.SubjectField = "sub" }, func(c *OAuth2Config) {
		c.IdentityEndpoint = "https://provider.example/user"
		c.SubjectField = "bad field"
	}} {
		cfg := base
		mutate(&cfg)
		if _, err := NewOAuth2(cfg, "secret"); err == nil {
			t.Fatal("invalid identity config accepted")
		}
	}
	for _, body := range []string{`{"sub":true}`, `{"sub":1.2}`, `{"sub":null}`, `{"sub":""}`, `{"sub":1,"sub":2}`, `[]`, `{}`, `{"sub":{}}`, `{"sub":[]}`, `{"sub":1e2}`, `{"sub":-0}`, `{"sub":9223372036854775808}`, `{"sub":"ok"} {}`, `{"sub":"ok"} garbage`, `{"sub":"ok","padding":"` + strings.Repeat("x", 64<<10) + `"}`} {
		fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, body)
		}))
		cfg := base
		cfg.IdentityEndpoint = fixture.URL
		cfg.SubjectField = "sub"
		o, err := NewOAuth2(cfg, "secret")
		if err != nil {
			t.Fatal(err)
		}
		o.client.Transport = fixture.Client().Transport
		if _, err := o.Identity(t.Context(), "token"); !errors.Is(err, ErrOAuth2Identity) {
			t.Fatalf("malformed identity error=%v", err)
		}
		fixture.Close()
	}
}

func TestOAuth2IdentityBoundaryFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		media  string
	}{{"status", http.StatusUnauthorized, "application/json"}, {"media", http.StatusOK, "text/html"}, {"redirect", http.StatusFound, "application/json"}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", tc.media)
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(tc.status)
				io.WriteString(w, `{"sub":"secret-response"}`)
			}))
			defer fixture.Close()
			o, err := NewOAuth2(OAuth2Config{ClientID: "client", AuthorizationURL: "https://provider.example/auth", TokenURL: "https://provider.example/token", CallbackURL: "https://auth.example/callback", Scopes: []string{"read"}, AuthStyle: oauth2.AuthStyleInHeader, IdentityEndpoint: fixture.URL, SubjectField: "sub"}, "secret")
			if err != nil {
				t.Fatal(err)
			}
			o.client.Transport = fixture.Client().Transport
			if _, err := o.Identity(t.Context(), "token"); err != ErrOAuth2Identity || calls != 1 {
				t.Fatalf("error=%v calls=%d", err, calls)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := o.Identity(ctx, "token"); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel error=%v", err)
			}
			o.identityEndpoint = ""
			if _, err := o.Identity(t.Context(), "token"); err != ErrOAuth2Identity {
				t.Fatalf("unconfigured error=%v", err)
			}
		})
	}
}
