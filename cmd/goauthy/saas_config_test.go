package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSaaSConfig(t *testing.T, secret, config string) string {
	t.Helper()
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	config = strings.ReplaceAll(config, "SECRET_FILE", secretPath)
	path := filepath.Join(dir, "providers.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSaaSProvidersBuildsNonSecretAdapters(t *testing.T) {
	t.Parallel()
	path := writeSaaSConfig(t, "saas-secret-123456", `{"providers":[
		{"id":"acme","kind":"oauth2","client_id":"client","client_secret_file":"SECRET_FILE","callback_uri":"https://app.example.test/callback","auth_endpoint":"https://provider.example.test/authorize","token_endpoint":"https://provider.example.test/token","scopes":["read","write"],"auth_style":"params"},
		{"id":"github","kind":"github","client_id":"github-client","client_secret_file":"SECRET_FILE","callback_uri":"https://app.example.test/github/callback"}
	]}`)
	providers, err := loadSaaSProviders(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 2 || providers["acme"].OAuth2 == nil || providers["github"].GitHub == nil {
		t.Fatalf("providers=%+v", providers)
	}
	if providers["acme"].OAuth2 == nil && providers["acme"].GitHub != nil {
		t.Fatal("unexpected adapter shape")
	}
	if got := providers["acme"].Scopes; strings.Join(got, ",") != "read,write" {
		t.Fatalf("scopes=%v", got)
	}
	if strings.Contains(strings.TrimSpace(strings.Join(providers["acme"].Scopes, ",")), "saas-secret") {
		t.Fatal("secret leaked into provider metadata")
	}
	for id, provider := range providers {
		if _, err := url.Parse(provider.CallbackURI); err != nil {
			t.Fatalf("%s callback: %v", id, err)
		}
	}
	if _, err := providers["acme"].OAuth2.AuthorizationURL("state", strings.Repeat("v", 43)); err != nil {
		t.Fatalf("oauth2 adapter: %v", err)
	}
	if _, err := providers["github"].GitHub.AuthorizationURL("state", strings.Repeat("v", 43)); err != nil {
		t.Fatalf("github adapter: %v", err)
	}
}

func TestLoadSaaSProvidersDisabledWhenPathEmpty(t *testing.T) {
	t.Parallel()
	providers, err := loadSaaSProviders("")
	if err != nil || providers == nil || len(providers) != 0 {
		t.Fatalf("providers=%v err=%v", providers, err)
	}
}

func TestLoadSaaSProvidersStrictAndBounded(t *testing.T) {
	t.Parallel()
	base := `{"providers":[{"id":"acme","kind":"oauth2","client_id":"client","client_secret_file":"SECRET_FILE","callback_uri":"https://app.example.test/callback","auth_endpoint":"https://provider.example.test/authorize","token_endpoint":"https://provider.example.test/token","scopes":["read"],"auth_style":"header"}]}`
	for name, invalid := range map[string]string{
		"unknown field":         strings.Replace(base, `,"auth_style"`, `,"unknown":true,"auth_style"`, 1),
		"trailing document":     base + `{}`,
		"duplicate id":          strings.Replace(base, `}]}`, `},{"id":"acme","kind":"oauth2","client_id":"client","client_secret_file":"SECRET_FILE","callback_uri":"https://app.example.test/other","auth_endpoint":"https://provider.example.test/authorize","token_endpoint":"https://provider.example.test/token","scopes":["read"],"auth_style":"header"}]}`, 1),
		"invalid style":         strings.Replace(base, `"header"`, `"auto"`, 1),
		"github generic fields": strings.Replace(base, `"kind":"oauth2"`, `"kind":"github"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := writeSaaSConfig(t, "saas-secret-123456", invalid)
			if _, err := loadSaaSProviders(path); err == nil {
				t.Fatal("accepted invalid SaaS provider configuration")
			}
		})
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "oversize.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxUpstreamProvidersFileSize+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSaaSProviders(path); err == nil {
		t.Fatal("accepted oversized SaaS providers file")
	}
}

func TestLoadSaaSProvidersRequiresExplicitKindAndGenericPolicy(t *testing.T) {
	t.Parallel()
	base := `{"providers":[{"id":"acme","kind":"oauth2","client_id":"client","client_secret_file":"SECRET_FILE","callback_uri":"https://app.example.test/callback","auth_endpoint":"https://provider.example.test/authorize","token_endpoint":"https://provider.example.test/token","scopes":["read"],"auth_style":"params"}]}`
	for _, replacement := range []string{
		`"kind":"oidc"`,
		`"auth_style":"header"`,
		`"scopes":[]`,
		`"auth_endpoint":"http://provider.example.test/authorize"`,
	} {
		path := writeSaaSConfig(t, "saas-secret-123456", strings.Replace(base, `"kind":"oauth2"`, replacement, 1))
		if _, err := loadSaaSProviders(path); err == nil {
			t.Fatalf("accepted invalid replacement %s", replacement)
		}
	}
}
