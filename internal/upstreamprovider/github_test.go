package upstreamprovider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGitHubExchangeUsesFormAuthAndResolvesImmutableID(t *testing.T) {
	t.Parallel()
	var tokenRequests, userRequests atomic.Int32
	var gotForm url.Values
	var gotUser *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			tokenRequests.Add(1)
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
				t.Errorf("token request = %s auth=%q", r.Method, r.Header.Get("Authorization"))
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
			}
			gotForm = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","token_type":"bearer","scope":"user:email, read:user"}`))
		case "/user":
			userRequests.Add(1)
			gotUser = r
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":123,"login":"first-login","name":"ignored"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	configs := map[string]Config{"github": {
		Kind: ProviderKindGitHub, Issuer: "https://github.com",
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
		TokenEndpoint:         "https://github.com/login/oauth/access_token",
		UserInfoEndpoint:      "https://api.github.com/user", ClientID: "client", Scopes: []string{"read:user"},
	}}
	exchanger, err := NewOAuth2TokenExchanger(configs, map[string]string{"github": "secret"}, &http.Client{Transport: rewriteTransport{target: target}})
	if err != nil {
		t.Fatal(err)
	}

	result, err := exchanger.ExchangeCode(context.Background(), "github", "https://app.example.test/callback", "code", "verifier")
	if err != nil || result == nil || result.Subject == nil {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
	if got, want := *result.Subject, (SubjectResult{ProviderID: "github", Subject: "123"}); got != want {
		t.Fatalf("subject = %#v, want %#v", got, want)
	}
	if got, want := tokenRequests.Load(), int32(1); got != want {
		t.Fatalf("token requests = %d, want %d", got, want)
	}
	if got, want := userRequests.Load(), int32(1); got != want {
		t.Fatalf("user requests = %d, want %d", got, want)
	}
	for key, want := range map[string]string{"grant_type": "authorization_code", "code": "code", "redirect_uri": "https://app.example.test/callback", "code_verifier": "verifier", "client_id": "client", "client_secret": "secret"} {
		if got := gotForm.Get(key); got != want {
			t.Errorf("form %s = %q, want %q", key, got, want)
		}
	}
	if len(gotForm) != 6 {
		t.Fatalf("token form = %#v, want exactly six fields", gotForm)
	}
	if gotUser.Header.Get("Authorization") != "Bearer access" || gotUser.Header.Get("X-GitHub-Api-Version") != githubAPIVersion || gotUser.Header.Get("Accept") != githubAccept {
		t.Fatalf("user headers = %#v", gotUser.Header)
	}
}

func TestGitHubIDParsingRejectsNonCanonicalIDs(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"missing":        `{"login":"user"}`,
		"duplicate":      `{"id":123,"id":124}`,
		"string":         `{"id":"123"}`,
		"negative":       `{"id":-1}`,
		"zero":           `{"id":0}`,
		"exponent":       `{"id":1e3}`,
		"leading zero":   `{"id":"001"}`,
		"array":          `[{"id":123}]`,
		"trailing value": `{"id":123} true`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseGitHubUserID([]byte(body)); err == nil {
				t.Fatalf("parseGitHubUserID(%s) succeeded", body)
			}
		})
	}
}

func TestGitHubExchangeRejectsBadScopeTokenAndUserResponses(t *testing.T) {
	t.Parallel()
	for name, tokenResponse := range map[string]string{
		"missing scope":      `{"access_token":"access"}`,
		"missing read scope": `{"access_token":"access","scope":"user:email"}`,
		"id token":           `{"access_token":"access","scope":"read:user","id_token":"unexpected"}`,
	} {
		t.Run(name, func(t *testing.T) {
			exchanger, _, _ := testGitHubExchanger(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login/oauth/access_token" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(tokenResponse))
					return
				}
				t.Fatalf("unexpected user request")
			})
			if _, err := exchanger.ExchangeCode(context.Background(), "github", "https://app.example.test/callback", "code", "verifier"); !errors.Is(err, errTokenExchange) {
				t.Fatalf("ExchangeCode() error = %v", err)
			}
		})
	}
}

func TestGitHubExchangeRejectsRedirectAndOversizedUserResponse(t *testing.T) {
	t.Parallel()
	for name, userResponse := range map[string]string{
		"redirect":  "redirect",
		"oversized": strings.Repeat("x", githubUserMaxBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			exchanger, _, _ := testGitHubExchanger(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/login/oauth/access_token":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"access_token":"access","scope":"read:user"}`))
				case "/user":
					if userResponse == "redirect" {
						http.Redirect(w, r, "/follow", http.StatusFound)
						return
					}
					_, _ = w.Write([]byte(userResponse))
				case "/follow":
					t.Fatal("user request followed redirect")
				}
			})
			if _, err := exchanger.ExchangeCode(context.Background(), "github", "https://app.example.test/callback", "code", "verifier"); !errors.Is(err, errTokenExchange) {
				t.Fatalf("ExchangeCode() error = %v", err)
			}
		})
	}
}

func TestGitHubExchangeCancellation(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	exchanger, _, _ := testGitHubExchanger(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/oauth/access_token" {
			close(started)
			<-release
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := exchanger.ExchangeCode(ctx, "github", "https://app.example.test/callback", "code", "verifier")
		result <- err
	}()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("ExchangeCode() error = %v, want cancellation", err)
	}
}

func testGitHubExchanger(t *testing.T, handler func(http.ResponseWriter, *http.Request)) (*OAuth2TokenExchanger, map[string]Config, map[string]string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	configs := map[string]Config{"github": {
		Kind: ProviderKindGitHub, Issuer: "https://github.com",
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
		TokenEndpoint:         "https://github.com/login/oauth/access_token",
		UserInfoEndpoint:      "https://api.github.com/user", ClientID: "client", Scopes: []string{"read:user"},
	}}
	secrets := map[string]string{"github": "secret"}
	exchanger, err := NewOAuth2TokenExchanger(configs, secrets, &http.Client{Transport: rewriteTransport{target: target}})
	if err != nil {
		t.Fatal(err)
	}
	return exchanger, configs, secrets
}
