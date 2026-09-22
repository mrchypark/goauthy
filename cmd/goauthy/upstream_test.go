package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadUpstreamProvidersStrictAndOptIn(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("upstream-secret-123"), 0600); err != nil {
		t.Fatal(err)
	}
	config := `{"providers":[{"id":"example","issuer":"https://issuer.example.test","auth_endpoint":"https://issuer.example.test/authorize","token_endpoint":"https://issuer.example.test/token","jwks":"https://issuer.example.test/jwks","client_id":"client","client_secret_file":"` + secret + `","callback_uri":"https://goauthy.example.test/upstream/example/callback","scopes":["openid","profile"]}]}`
	path := filepath.Join(dir, "providers.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	providers, err := loadUpstreamProviders(path, "https://goauthy.example.test")
	if err != nil || providers["example"].secret != "upstream-secret-123" {
		t.Fatalf("failed to load provider: %v", err)
	}
	if got := providers["example"].config; got.Issuer != "https://issuer.example.test" || got.UserInfoEndpoint != "" {
		t.Fatalf("default OIDC config = %+v", got)
	}
	for _, invalid := range []string{
		`{"providers":[]}`,
		`{"providers":[` + strings.TrimPrefix(strings.TrimSuffix(config, `]}`), `{"providers":[`) + `,` + strings.TrimPrefix(strings.TrimSuffix(config, `]}`), `{"providers":[`) + `]}`,
		`{"providers":[` + strings.Repeat(strings.TrimPrefix(strings.TrimSuffix(config, `]}`), `{"providers":[`)+`,`, 16) + strings.TrimPrefix(strings.TrimSuffix(config, `]}`), `{"providers":[`) + `]}`,
		strings.Replace(config, `"id":"example"`, `"id":"Example"`, 1),
		strings.Replace(config, `"scopes":["openid","profile"]`, `"scopes":["profile"]`, 1),
		strings.Replace(config, `"scopes":["openid","profile"]`, `"scopes":["openid","openid"]`, 1),
		strings.Replace(config, `"callback_uri":"https://goauthy.example.test/upstream/example/callback"`, `"callback_uri":"https://other.example.test/upstream/example/callback"`, 1),
		strings.Replace(config, `"callback_uri":"https://goauthy.example.test/upstream/example/callback"`, `"callback_uri":"https://goauthy.example.test/upstream/example/callback?x=1"`, 1),
		strings.Replace(config, `"callback_uri":"https://goauthy.example.test/upstream/example/callback"`, `"callback_uri":"https://goauthy.example.test/upstream/example/callback#x"`, 1),
		strings.Replace(config, `"callback_uri":"https://goauthy.example.test/upstream/example/callback"`, `"callback_uri":"https://goauthy.example.test/upstream/example%2Fcallback"`, 1),
		strings.Replace(config, `"callback_uri":"https://goauthy.example.test/upstream/example/callback"`, `"callback_uri":"https://goauthy.example.test/upstream/other/callback"`, 1),
		strings.Replace(config, `"auth_endpoint":"https://issuer.example.test/authorize"`, `"auth_endpoint":"http://issuer.example.test/authorize"`, 1),
		strings.TrimSuffix(config, "}") + `,"unknown":true}`,
		config + `{}`,
	} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadUpstreamProviders(path, "https://goauthy.example.test"); err == nil {
			t.Fatal("accepted invalid upstream configuration")
		}
	}
}

func TestLoadUpstreamProvidersGitHub(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("github-secret-123456"), 0600); err != nil {
		t.Fatal(err)
	}
	githubConfig := `{"providers":[{"id":"github","kind":"github","client_id":"client","client_secret_file":"` + secret + `","callback_uri":"https://goauthy.example.test/upstream/github/callback","scopes":["read:user","user:email"]}]}`
	path := filepath.Join(dir, "providers.json")
	if err := os.WriteFile(path, []byte(githubConfig), 0600); err != nil {
		t.Fatal(err)
	}
	providers, err := loadUpstreamProviders(path, "https://goauthy.example.test")
	if err != nil {
		t.Fatalf("load GitHub provider: %v", err)
	}
	got := providers["github"]
	if got.secret != "github-secret-123456" || got.callbackURI != "https://goauthy.example.test/upstream/github/callback" {
		t.Fatalf("GitHub secret/callback = %q/%q", got.secret, got.callbackURI)
	}
	if got.config.Kind != "github" || got.config.Issuer != "https://github.com" || got.config.AuthorizationEndpoint != "https://github.com/login/oauth/authorize" || got.config.TokenEndpoint != "https://github.com/login/oauth/access_token" || got.config.UserInfoEndpoint != "https://api.github.com/user" || got.config.JWKSURI != "" || strings.Join(got.config.Scopes, ",") != "read:user,user:email" {
		t.Fatalf("GitHub config = %+v", got.config)
	}

	for _, field := range []string{"issuer", "auth_endpoint", "token_endpoint", "jwks"} {
		for _, value := range []string{`"https://example.test/forbidden"`, `""`, `null`} {
			invalid := strings.Replace(githubConfig, `,"scopes":`, `,"`+field+`":`+value+`,"scopes":`, 1)
			if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadUpstreamProviders(path, "https://goauthy.example.test"); err == nil {
				t.Fatalf("accepted GitHub provider with %s=%s", field, value)
			}
		}
	}
	for name, invalid := range map[string]string{
		"enterprise kind":   strings.Replace(githubConfig, `"kind":"github"`, `"kind":"github-enterprise"`, 1),
		"missing read:user": strings.Replace(githubConfig, `"read:user",`, ``, 1),
		"duplicate scope":   strings.Replace(githubConfig, `"user:email"]`, `"read:user"]`, 1),
		"openid scope":      strings.Replace(githubConfig, `"user:email"]`, `"openid"]`, 1),
		"space scope":       strings.Replace(githubConfig, `"user:email"]`, `"a b"]`, 1),
		"callback host":     strings.Replace(githubConfig, `https://goauthy.example.test/upstream/github/callback`, `https://other.example.test/upstream/github/callback`, 1),
	} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadUpstreamProviders(path, "https://goauthy.example.test"); err == nil {
			t.Fatalf("accepted invalid GitHub config: %s", name)
		}
	}
}

func TestLoadUpstreamProvidersMixedOIDCAndGitHub(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("github-secret-123456"), 0600); err != nil {
		t.Fatal(err)
	}
	config := `{"providers":[{"id":"github","kind":"github","client_id":"github-client","client_secret_file":"` + secret + `","callback_uri":"https://goauthy.example.test/upstream/github/callback","scopes":["read:user"]},{"id":"oidc","client_id":"oidc-client","client_secret_file":"` + secret + `","issuer":"https://issuer.example.test","auth_endpoint":"https://issuer.example.test/authorize","token_endpoint":"https://issuer.example.test/token","jwks":"https://issuer.example.test/jwks","callback_uri":"https://goauthy.example.test/upstream/oidc/callback","scopes":["openid"]}]}`
	path := filepath.Join(dir, "providers.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	providers, err := loadUpstreamProviders(path, "https://goauthy.example.test")
	if err != nil {
		t.Fatalf("load mixed providers: %v", err)
	}
	if len(providers) != 2 || providers["github"].config.Kind != "github" || providers["github"].config.JWKSURI != "" || providers["github"].config.UserInfoEndpoint != "https://api.github.com/user" || providers["oidc"].config.Kind != "" || providers["oidc"].config.JWKSURI != "https://issuer.example.test/jwks" {
		t.Fatalf("mixed configs = %+v", providers)
	}
}

func TestValidUpstreamScopes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		s    []string
		ok   bool
	}{
		{"rfc tokens", []string{"openid", "a!#[]~"}, true},
		{"missing openid", []string{"profile"}, false},
		{"duplicate", []string{"openid", "openid"}, false},
		{"space", []string{"openid", "a b"}, false},
		{"quote", []string{"openid", `a"b`}, false},
		{"backslash", []string{"openid", `a\b`}, false},
		{"unicode", []string{"openid", "한글"}, false},
		{"control", []string{"openid", "a\tb"}, false},
	} {
		if got := validUpstreamScopes(tc.s); got != tc.ok {
			t.Errorf("%s: got %t want %t", tc.name, got, tc.ok)
		}
	}
}

func TestValidGitHubScopes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		s    []string
		ok   bool
	}{
		{"read user", []string{"read:user"}, true},
		{"additional scope", []string{"read:user", "user:email"}, true},
		{"missing read user", []string{"user:email"}, false},
		{"openid", []string{"read:user", "openid"}, false},
		{"duplicate", []string{"read:user", "read:user"}, false},
		{"space", []string{"read:user", "a b"}, false},
	} {
		if got := validGitHubScopes(tc.s); got != tc.ok {
			t.Errorf("%s: got %t want %t", tc.name, got, tc.ok)
		}
	}
}

func TestLoadUpstreamClientSecret(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		data string
		ok   bool
	}{
		{"plain", "0123456789abcdef", true},
		{"terminal lf", "0123456789abcdef\n", true},
		{"terminal crlf", "0123456789abcdef\r\n", true},
		{"short", "0123456789abcde", false},
		{"empty", "", false},
		{"oversize", strings.Repeat("a", 4097), false},
		{"embedded newline", "01234567\n89abcdef", false},
		{"leading space", " 0123456789abcdef", false},
	} {
		path := filepath.Join(dir, tc.name)
		if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
			t.Fatal(err)
		}
		secret, err := loadUpstreamClientSecret(path)
		if (err == nil) != tc.ok {
			t.Errorf("%s: secret length=%d err=%v", tc.name, len(secret), err)
		}
	}
}

func TestUpstreamCallbackRequiresHTTPS(t *testing.T) {
	t.Parallel()
	if validUpstreamCallback("http://localhost:8080/upstream/example/callback", "http://localhost:8080", "example") {
		t.Fatal("accepted HTTP upstream callback")
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("0123456789abcdef"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "providers.json")
	config := `{"providers":[{"id":"example","issuer":"https://issuer.example.test","auth_endpoint":"https://issuer.example.test/authorize","token_endpoint":"https://issuer.example.test/token","jwks":"https://issuer.example.test/jwks","client_id":"client","client_secret_file":"` + secret + `","callback_uri":"http://localhost:8080/upstream/example/callback","scopes":["openid"]}]}`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadUpstreamProviders(path, "http://localhost:8080"); err == nil {
		t.Fatal("accepted upstream configuration with HTTP callback")
	}
}

func TestUpstreamCallbackUsesIssuerBasePath(t *testing.T) {
	t.Parallel()
	if !validUpstreamCallback("https://issuer.example.test/tenant/upstream/example/callback", "https://issuer.example.test/tenant", "example") {
		t.Fatal("rejected path issuer callback")
	}
	if validUpstreamCallback("https://issuer.example.test/upstream/example/callback", "https://issuer.example.test/tenant", "example") {
		t.Fatal("accepted callback outside issuer path")
	}
}

func TestUpstreamHandlerFromEnvDisabledWhenUnset(t *testing.T) {
	t.Parallel()
	runtime, err := upstreamHandlerFromEnv(func(string) string { return "" }, nil, nil, "https://goauthy.example.test", nil, nil, nil)
	if err != nil || runtime != nil {
		t.Fatalf("runtime=%v err=%v", runtime, err)
	}
}

func TestUpstreamRuntimeProviderIDsAreSortedCopies(t *testing.T) {
	t.Parallel()
	runtime := &upstreamRuntime{providerIDs_: []string{"example", "google"}}
	ids := runtime.providerIDs()
	if strings.Join(ids, ",") != "example,google" {
		t.Fatalf("provider IDs %v", ids)
	}
	ids[0] = "changed"
	if runtime.providerIDs_[0] != "example" {
		t.Fatal("provider IDs leaked mutable storage")
	}
	// An unset upstream runtime mounts neither provider callback nor account
	// link routes.
	mux := http.NewServeMux()
	mountUpstreamRoutes(mux, nil, nil, nil)
	for _, path := range []string{"/upstream/example/start", "/auth/v1/providers/example/link"} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d", path, response.Code)
		}
	}
}

func TestUpstreamStartRouteRequiresConfiguredCallback(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.PathValue("providerID"); got != "example" {
			t.Fatalf("provider ID %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	route := upstreamStartRoute("example", "https://goauthy.example.test/upstream/example/callback", next)
	for _, tc := range []struct {
		url  string
		want int
	}{
		{"/upstream/example/start?redirect_uri=https%3A%2F%2Fgoauthy.example.test%2Fupstream%2Fexample%2Fcallback", http.StatusNoContent},
		{"/upstream/example/start?redirect_uri=https%3A%2F%2Fgoauthy.example.test%2Fupstream%2Fother%2Fcallback", http.StatusForbidden},
		{"/upstream/example/start", http.StatusForbidden},
	} {
		response := httptest.NewRecorder()
		route.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.url, nil))
		if response.Code != tc.want {
			t.Fatalf("%s status=%d want=%d", tc.url, response.Code, tc.want)
		}
		assertUpstreamSecurityHeaders(t, response)
	}
}

func TestUpstreamCallbackSetsSecurityHeaders(t *testing.T) {
	t.Parallel()
	route := upstreamCallbackRoute("example", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	route.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/upstream/example/callback", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d", response.Code)
	}
	assertUpstreamSecurityHeaders(t, response)
}

func assertUpstreamSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	for key, want := range map[string]string{
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
	} {
		if got := response.Header().Get(key); got != want {
			t.Errorf("%s=%q want %q", key, got, want)
		}
	}
}

func TestDecodeUpstreamProviderFileConfigProtocolFlags(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		json      string
		wantZero  bool
		wantPKCE  bool
		wantBasic bool
		wantPost  bool
	}{
		{"explicit false", `{"id":"test","issuer":"https://issuer.example.test","auth_endpoint":"https://issuer.example.test/authorize","token_endpoint":"https://issuer.example.test/token","jwks":"https://issuer.example.test/jwks","client_id":"c","client_secret_file":"f","callback_uri":"https://goauthy.example.test/upstream/test/callback","scopes":["openid","profile"],"use_pkce":false,"client_secret_basic":false,"client_secret_post":false}`, false, false, false, false},
		{"explicit true", `{"id":"test","issuer":"https://issuer.example.test","auth_endpoint":"https://issuer.example.test/authorize","token_endpoint":"https://issuer.example.test/token","jwks":"https://issuer.example.test/jwks","client_id":"c","client_secret_file":"f","callback_uri":"https://goauthy.example.test/upstream/test/callback","scopes":["openid","profile"],"use_pkce":true,"client_secret_basic":true,"client_secret_post":true}`, false, true, true, true},
		{"omitted", `{"id":"test","issuer":"https://issuer.example.test","auth_endpoint":"https://issuer.example.test/authorize","token_endpoint":"https://issuer.example.test/token","jwks":"https://issuer.example.test/jwks","client_id":"c","client_secret_file":"f","callback_uri":"https://goauthy.example.test/upstream/test/callback","scopes":["openid","profile"]}`, true, false, false, false},
	}{
		fc, err := decodeUpstreamProviderFileConfig([]byte(tc.json))
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		if tc.wantZero {
			if fc.UsePKCE != nil || fc.ClientSecretBasic != nil || fc.ClientSecretPost != nil {
				t.Fatalf("%s: want zero protocol, got pkce=%v basic=%v post=%v", tc.name, fc.UsePKCE, fc.ClientSecretBasic, fc.ClientSecretPost)
			}
		} else {
			if fc.UsePKCE == nil || *fc.UsePKCE != tc.wantPKCE {
				t.Fatalf("%s: use_pkce=%v want %v", tc.name, fc.UsePKCE, tc.wantPKCE)
			}
			if fc.ClientSecretBasic == nil || *fc.ClientSecretBasic != tc.wantBasic {
				t.Fatalf("%s: client_secret_basic=%v want %v", tc.name, fc.ClientSecretBasic, tc.wantBasic)
			}
			if fc.ClientSecretPost == nil || *fc.ClientSecretPost != tc.wantPost {
				t.Fatalf("%s: client_secret_post=%v want %v", tc.name, fc.ClientSecretPost, tc.wantPost)
			}
		}
	}
}

func TestValidateUpstreamProviderProtocolRuntimeConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("0123456789abcdef"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "providers.json")
	for _, tc := range []struct {
		name       string
		config     string
		wantSecret string
	}{
		{"basic only", `{"id":"b","issuer":"https://issuer.example.test","auth_endpoint":"https://issuer.example.test/authorize","token_endpoint":"https://issuer.example.test/token","jwks":"https://issuer.example.test/jwks","client_id":"c","client_secret_file":"` + secret + `","callback_uri":"https://goauthy.example.test/upstream/b/callback","scopes":["openid","profile"],"client_secret_basic":true}`, "0123456789abcdef"},
		{"post only", `{"id":"p","issuer":"https://issuer.example.test","auth_endpoint":"https://issuer.example.test/authorize","token_endpoint":"https://issuer.example.test/token","jwks":"https://issuer.example.test/jwks","client_id":"c","client_secret_file":"` + secret + `","callback_uri":"https://goauthy.example.test/upstream/p/callback","scopes":["openid","profile"],"client_secret_post":true}`, "0123456789abcdef"},
		{"basic and post", `{"id":"bp","issuer":"https://issuer.example.test","auth_endpoint":"https://issuer.example.test/authorize","token_endpoint":"https://issuer.example.test/token","jwks":"https://issuer.example.test/jwks","client_id":"c","client_secret_file":"` + secret + `","callback_uri":"https://goauthy.example.test/upstream/bp/callback","scopes":["openid","profile"],"client_secret_basic":true,"client_secret_post":true}`, "0123456789abcdef"},
		{"legacy omitted", `{"id":"leg","issuer":"https://issuer.example.test","auth_endpoint":"https://issuer.example.test/authorize","token_endpoint":"https://issuer.example.test/token","jwks":"https://issuer.example.test/jwks","client_id":"c","client_secret_file":"` + secret + `","callback_uri":"https://goauthy.example.test/upstream/leg/callback","scopes":["openid","profile"]}`, "0123456789abcdef"},
	}{
		if err := os.WriteFile(path, []byte(tc.config), 0600); err != nil {
			t.Fatal(err)
		}
		providers, err := loadUpstreamProviders(path, "https://goauthy.example.test")
		if tc.wantSecret == "" && err == nil {
			if len(providers) != 1 {
				t.Fatalf("%s: want 1 provider, got %d", tc.name, len(providers))
			}
			for _, p := range providers {
				if p.secret != "" {
					t.Fatalf("%s: want empty secret, got %q", tc.name, p.secret)
				}
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s: want error, got providers", tc.name)
		}
	}
}

func TestUpstreamConfigProtocolInvariant(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("0123456789abcdef"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "providers.json")
	oidcBase := `{"providers":[{"id":"test","issuer":"https://issuer.example.test","auth_endpoint":"https://issuer.example.test/authorize","token_endpoint":"https://issuer.example.test/token","jwks":"https://issuer.example.test/jwks","client_id":"c","callback_uri":"https://goauthy.example.test/upstream/test/callback","scopes":["openid","profile"]`
	for _, tc := range []struct {
		name    string
		extra   string
		wantErr bool
	}{
		{"public pkce no secret", `,"use_pkce":true,"client_secret_basic":false,"client_secret_post":false`, false},
		{"public pkce valid secret", `,"use_pkce":true,"client_secret_basic":false,"client_secret_post":false,"client_secret_file":"` + secret + `"`, false},
		{"public pkce bad secret", `,"use_pkce":true,"client_secret_basic":false,"client_secret_post":false,"client_secret_file":"/nonexistent"`, true},
		{"no pkce no secret", `,"use_pkce":false,"client_secret_basic":false,"client_secret_post":false`, true},
		{"no pkce valid secret", `,"use_pkce":false,"client_secret_basic":false,"client_secret_post":false,"client_secret_file":"` + secret + `"`, false},
		{"legacy no secret", ``, true},
		{"legacy valid secret", `,"client_secret_file":"` + secret + `"`, false},
		{"basic no secret", `,"client_secret_basic":true`, true},
		{"basic valid secret", `,"client_secret_basic":true,"client_secret_file":"` + secret + `"`, false},
		{"post no secret", `,"client_secret_post":true`, true},
		{"post valid secret", `,"client_secret_post":true,"client_secret_file":"` + secret + `"`, false},
		{"optional pkce nil basic false post false", `,"client_secret_basic":false,"client_secret_post":false`, false},
	} {
		config := oidcBase + tc.extra + `}]}`
		if err := os.WriteFile(path, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := loadUpstreamProviders(path, "https://goauthy.example.test")
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}

func TestUpstreamConfigGitHubFlagPropagation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("github-secret-123456"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "providers.json")
	withFlags := `{"providers":[{"id":"gh","kind":"github","client_id":"c","client_secret_file":"` + secret + `","callback_uri":"https://goauthy.example.test/upstream/gh/callback","scopes":["read:user"],"use_pkce":true,"client_secret_basic":false,"client_secret_post":false}]}`
	if err := os.WriteFile(path, []byte(withFlags), 0600); err != nil {
		t.Fatal(err)
	}
	providers, err := loadUpstreamProviders(path, "https://goauthy.example.test")
	if err != nil {
		t.Fatalf("load GitHub with flags: %v", err)
	}
	gh := providers["gh"]
	if gh.config.Protocol.UsePKCE == nil || !*gh.config.Protocol.UsePKCE {
		t.Fatal("GitHub use_pkce not propagated")
	}
	if gh.config.Protocol.ClientSecretBasic == nil || *gh.config.Protocol.ClientSecretBasic {
		t.Fatal("GitHub client_secret_basic not propagated")
	}
	if gh.config.Protocol.ClientSecretPost == nil || *gh.config.Protocol.ClientSecretPost {
		t.Fatal("GitHub client_secret_post not propagated")
	}
	withoutFlags := `{"providers":[{"id":"gh","kind":"github","client_id":"c","client_secret_file":"` + secret + `","callback_uri":"https://goauthy.example.test/upstream/gh/callback","scopes":["read:user"]}]}`
	if err := os.WriteFile(path, []byte(withoutFlags), 0600); err != nil {
		t.Fatal(err)
	}
	providers, err = loadUpstreamProviders(path, "https://goauthy.example.test")
	if err != nil {
		t.Fatalf("load GitHub without flags: %v", err)
	}
	gh = providers["gh"]
	if gh.config.Protocol.UsePKCE != nil || gh.config.Protocol.ClientSecretBasic != nil || gh.config.Protocol.ClientSecretPost != nil {
		t.Fatal("GitHub legacy path should have zero protocol")
	}
}
