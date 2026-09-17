package browser

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

const consumerFixtureResource = "https://compos.local.test"

var consumerFixtureFiles = map[string]string{
	"access-token":      "",
	"client-secret":     "",
	"issuer":            "",
	"client-id":         "goauthy-dev",
	"resource":          consumerFixtureResource,
	"subject":           "",
	"email":             "",
	"wrong-aud-token":   "",
	"wrong-scope-token": "",
	"revoked-token":     "",
}

func TestConsumerTokenFixture(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_CONSUMER_TOKEN_FIXTURE") != "1" {
		t.Skip("set GOAUTHY_E2E_CONSUMER_TOKEN_FIXTURE=1 to run consumer token fixture E2E")
	}
	dir := consumerFixtureOutputDir(t)
	primary, secondary, adminUsername, adminPassword, clientSecret := browserE2EConfig(t)

	admin := newBrowserClient(t)
	verifier := pkceVerifier(t)
	authorizeURL := oidcAuthorizationURLForClient(t, primary, "goauthy-dev", defaultRedirectURI, pkceChallenge(verifier), "consumer-fixture-admin", "consumer-fixture-admin-nonce", "openid")
	_, sessionCookie := loginForAuthorizationURL(t, admin, authorizeURL, primary, secondary, adminUsername, adminPassword, "consumer-fixture-admin")
	csrf, err := browsersession.DeriveCSRFToken(sessionCookie.Value)
	if err != nil {
		t.Fatal("derive admin CSRF token")
	}

	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal("generate fixture user identifier")
	}
	email := "compos-consumer-fixture-" + hex.EncodeToString(suffix) + "@goauthy.e2e"
	password := "Compos-Consumer-Fixture-Password-1A"
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	userID := createCatalogSessionUser(t, admin, primary, headers, email, password)

	issue := func(label, scope, resource string) string {
		client := newBrowserClient(t)
		verifier := pkceVerifier(t)
		raw := oidcAuthorizationURLForClient(t, primary, "goauthy-dev", defaultRedirectURI, pkceChallenge(verifier), label, label+"-nonce", scope)
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal("build authorization URL")
		}
		values := parsed.Query()
		values.Set("resource", resource)
		parsed.RawQuery = values.Encode()
		code, _ := loginForAuthorizationURL(t, client, parsed.String(), primary, secondary, email, password, label)
		tokens := exchangeCode(t, client, primary, clientSecret, defaultRedirectURI, code, verifier)
		if tokens.AccessToken == "" {
			t.Fatal("authorization-code exchange returned no access token")
		}
		return tokens.AccessToken
	}
	accessToken := issue("consumer-positive", "openid email profile", consumerFixtureResource)
	client := newBrowserClient(t)

	introspection := introspectConsumerFixtureToken(t, client, primary, clientSecret, accessToken)
	gotScopes := strings.Fields(introspection.Scope)
	slices.Sort(gotScopes)
	if !introspection.Active || introspection.Subject != userID || introspection.ClientID != "goauthy-dev" || !slices.Equal(gotScopes, []string{"email", "openid", "profile"}) || !containsAudience(introspection.Audience, consumerFixtureResource) {
		t.Fatal("consumer fixture token introspection claims did not validate")
	}
	userinfo := do(t, client, http.MethodGet, primary+"/oidc/userinfo", nil, map[string]string{"Authorization": "Bearer " + accessToken})
	var info struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	err = json.NewDecoder(io.LimitReader(userinfo.Body, 32<<10)).Decode(&info)
	userinfo.Body.Close()
	if userinfo.StatusCode != http.StatusOK || err != nil || info.Subject != introspection.Subject || info.Email != email || !info.EmailVerified {
		t.Fatal("consumer fixture UserInfo claims did not validate")
	}

	wrongAudience := issue("consumer-wrong-aud", "openid email profile", "https://other-consumer.local.test")
	wrongScope := issue("consumer-wrong-scope", "goauthy.read", consumerFixtureResource)
	wrongAudClaims := introspectConsumerFixtureToken(t, client, primary, clientSecret, wrongAudience)
	wrongScopeClaims := introspectConsumerFixtureToken(t, client, primary, clientSecret, wrongScope)
	if !wrongAudClaims.Active || containsAudience(wrongAudClaims.Audience, consumerFixtureResource) || !wrongScopeClaims.Active || slices.Contains(strings.Fields(wrongScopeClaims.Scope), "openid") {
		t.Fatal("negative fixture does not isolate audience or scope")
	}
	revoked := issue("consumer-revoked", "openid email profile", consumerFixtureResource)
	req, err := http.NewRequest(http.MethodPost, primary+"/oidc/revoke", strings.NewReader(url.Values{"token": {revoked}, "token_type_hint": {"access_token"}}.Encode()))
	if err != nil {
		t.Fatal("build revocation request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("goauthy-dev", clientSecret)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("revoke fixture request failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || introspectConsumerFixtureToken(t, client, primary, clientSecret, revoked).Active {
		t.Fatal("revoked fixture remains active")
	}
	fixtureValues := map[string]string{
		"access-token":      accessToken,
		"wrong-aud-token":   wrongAudience,
		"wrong-scope-token": wrongScope,
		"revoked-token":     revoked,
		"client-secret":     clientSecret,
		"issuer":            primary,
		"client-id":         "goauthy-dev",
		"resource":          consumerFixtureResource,
		"subject":           introspection.Subject,
		"email":             email,
	}
	if err := writeConsumerFixture(dir, fixtureValues); err != nil {
		t.Fatal(err)
	}
}

type consumerFixtureIntrospection struct {
	Active        bool            `json:"active"`
	Subject       string          `json:"sub"`
	Email         string          `json:"email"`
	EmailVerified bool            `json:"email_verified"`
	ClientID      string          `json:"client_id"`
	Scope         string          `json:"scope"`
	Audience      json.RawMessage `json:"aud"`
}

func introspectConsumerFixtureToken(t *testing.T, client *http.Client, issuer, secret, token string) consumerFixtureIntrospection {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, issuer+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal("build introspection request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("goauthy-dev", secret)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("introspection request")
	}
	defer response.Body.Close()
	var payload consumerFixtureIntrospection
	err = json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&payload)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("introspection status=%d", response.StatusCode)
	}
	return payload
}

func containsAudience(raw json.RawMessage, want string) bool {
	var values []string
	if json.Unmarshal(raw, &values) == nil {
		for _, value := range values {
			if value == want {
				return true
			}
		}
	}
	var value string
	return json.Unmarshal(raw, &value) == nil && value == want
}

func consumerFixtureOutputDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("GOAUTHY_E2E_CONSUMER_FIXTURE_DIR")
	if dir == "" || !filepath.IsAbs(dir) {
		t.Fatal("GOAUTHY_E2E_CONSUMER_FIXTURE_DIR must be an absolute directory")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal("consumer fixture directory is not usable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("consumer fixture directory must be a non-symlink directory with mode 0700")
	}
	for name := range consumerFixtureFiles {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("consumer fixture output already exists: %s", name)
		} else if !os.IsNotExist(err) {
			t.Fatalf("consumer fixture output cannot be checked: %s", name)
		}
	}
	return dir
}

func writeConsumerFixture(dir string, values map[string]string) error {
	for name := range consumerFixtureFiles {
		value, ok := values[name]
		if !ok {
			return fmt.Errorf("missing consumer fixture value: %s", name)
		}
		file, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("write consumer fixture %s: %w", name, err)
		}
		_, writeErr := file.WriteString(value + "\n")
		closeErr := file.Close()
		if writeErr != nil {
			return fmt.Errorf("write consumer fixture %s: %w", name, writeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close consumer fixture %s: %w", name, closeErr)
		}
	}
	return nil
}

func TestConsumerFixtureOutputGuard(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for name := range consumerFixtureFiles {
		values[name] = "value"
	}
	if err := writeConsumerFixture(dir, values); err != nil {
		t.Fatal(err)
	}
	if err := writeConsumerFixture(dir, values); err == nil {
		t.Fatal("fixture writer overwrote existing output")
	}
	for name := range consumerFixtureFiles {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal("fixture output stat failed")
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("fixture output %s mode=%v err=%v", name, info.Mode(), err)
		}
	}
}
