package saas

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const testVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"

func TestGitHubUserAndRevokeUseFixedAPI(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer access-token" {
				t.Errorf("user request = %s auth=%q", r.Method, r.Header.Get("Authorization"))
			}
			if r.Header.Get("Accept") != githubAccept || r.Header.Get("X-GitHub-Api-Version") != githubAPIVersion {
				t.Errorf("user headers = %#v", r.Header)
			}
			_, _ = io.WriteString(w, `{"id":123,"login":"ignored"}`)
		case "/applications/client/token":
			if r.Method != http.MethodDelete {
				t.Errorf("revoke method = %s", r.Method)
			}
			wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("client:secret"))
			if r.Header.Get("Authorization") != wantAuth {
				t.Errorf("revoke auth = %q", r.Header.Get("Authorization"))
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"access_token":"access-token"}` {
				t.Errorf("revoke body = %q", body)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	g, err := NewGitHub("client", "secret", "https://app.example/callback")
	if err != nil {
		t.Fatal(err)
	}
	installGitHubTestTransport(g, server)
	user, err := g.User(context.Background(), "access-token")
	if err != nil || user.ID != "123" {
		t.Fatalf("User() = %#v, %v", user, err)
	}
	if err := g.Revoke(context.Background(), "access-token"); err != nil {
		t.Fatalf("Revoke() = %v", err)
	}
}

func TestGitHubAuthorizationURLDelegatesPKCEAndScopes(t *testing.T) {
	g, err := NewGitHub("client", "secret", "https://app.example/callback")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := g.AuthorizationURL("state", testVerifier)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "https" || u.Host != "github.com" || u.Path != "/login/oauth/authorize" {
		t.Fatalf("authorization URL = %s", raw)
	}
	if q.Get("scope") != "read:user offline_access" || q.Get("state") != "state" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("authorization query = %#v", q)
	}
	if !strings.Contains(q.Get("scope"), "offline_access") {
		t.Fatal("authorization URL omitted offline_access")
	}
}

func TestGitHubExchangeAndRefreshDelegateOneRequestEach(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/oauth/access_token" || r.Method != http.MethodPost {
			t.Fatalf("token request = %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		n := calls.Add(1)
		if n == 1 {
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "code" || r.Form.Get("code_verifier") != testVerifier || r.Form.Get("client_secret") != "secret" {
				t.Errorf("exchange form = %#v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"access","refresh_token":"refresh","token_type":"bearer","scope":"read:user","expires_in":3600}`)
			return
		}
		if n != 2 {
			t.Errorf("token calls = %d", n)
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh" || r.Form.Get("client_secret") != "secret" {
			t.Errorf("refresh form = %#v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"access-2","refresh_token":"refresh-2","token_type":"bearer","scope":"read:user","expires_in":3600}`)
	}))
	defer server.Close()
	g, err := NewGitHub("client", "secret", "https://app.example/callback")
	if err != nil {
		t.Fatal(err)
	}
	installGitHubTestTransport(g, server)
	tok, err := g.Exchange(context.Background(), "code", testVerifier)
	if err != nil || tok.AccessToken != "access" || tok.RefreshToken != "refresh" {
		t.Fatalf("Exchange() = %#v, %v", tok, err)
	}
	tok, err = g.Refresh(context.Background(), "refresh")
	if err != nil || tok.AccessToken != "access-2" || tok.RefreshToken != "refresh-2" {
		t.Fatalf("Refresh() = %#v, %v", tok, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("token calls = %d, want 2", got)
	}
}

func installGitHubTestTransport(g *GitHub, server *httptest.Server) {
	g.client.Transport = rewriteTransport{target: server.URL, base: server.Client().Transport}
}

type rewriteTransport struct {
	target string
	base   http.RoundTripper
}

func (t rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	u, _ := url.Parse(t.target)
	u.Path, u.RawQuery = r.URL.Path, r.URL.RawQuery
	clone := r.Clone(r.Context())
	clone.URL = u
	return t.base.RoundTrip(clone)
}
