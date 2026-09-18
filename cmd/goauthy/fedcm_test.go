package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/fedcm"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestFedCMConfigIsBoundedAndExplicit(t *testing.T) {
	path := writeFedCMConfig(t, `{"client_origins":{"rp-client":"https://rp.example.test"},"login_url":"/auth/login"}`)
	config, err := loadFedCMConfig(path)
	if err != nil || config.LoginURL != "/auth/login" || config.ClientOrigins["rp-client"] != "https://rp.example.test" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for name, content := range map[string]string{
		"unknown field":   `{"client_origins":{"rp-client":"https://rp.example.test"},"login_url":"/auth/login","enabled":true}`,
		"missing login":   `{"client_origins":{"rp-client":"https://rp.example.test"}}`,
		"invalid origin":  `{"client_origins":{"rp-client":"https://rp.example.test/path"},"login_url":"/auth/login"}`,
		"http origin":     `{"client_origins":{"rp-client":"http://rp.example.test"},"login_url":"/auth/login"}`,
		"duplicate field": `{"client_origins":{"rp-client":"https://rp.example.test"},"login_url":"/auth/login","login_url":"/auth/other"}`,
		"empty clients":   `{"client_origins":{},"login_url":"/auth/login"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadFedCMConfig(writeFedCMConfig(t, content)); err == nil {
				t.Fatal("invalid FedCM config accepted")
			}
		})
	}
}

func TestFedCMLoginURLRejectsUnsafePaths(t *testing.T) {
	for _, value := range []string{"", "https://evil.example.test/login", "//evil.example.test/login", "/login?next=x", "/login#fragment", "/login/../account", "/login//account", "/login%2faccount"} {
		if err := validateFedCMLoginURL(value); err == nil {
			t.Errorf("validateFedCMLoginURL(%q) succeeded", value)
		}
	}
}

func TestFedCMLandingPathUsesExactAllowlist(t *testing.T) {
	for _, path := range []string{
		"/oidc/token", "/oidc/logout", "/oidc/userinfo", "/oidc/device", "/oidc/device/verify",
		"/auth/v1/roles", "/auth/v1/groups", "/auth/v1/scopes", "/auth/v1/api_keys", "/account/password",
		"/fedcm", "/auth/{path}", "/auth/login/extra", "/oidc/authorize",
		fedcm.ManifestPath, fedcm.ConfigPath, fedcm.AccountsPath, fedcm.ClientMetadataPath, fedcm.AssertionPath, fedcm.StatusPath,
	} {
		if err := validateFedCMLandingPath(path); err == nil {
			t.Errorf("validateFedCMLandingPath(%q) succeeded", path)
		}
	}
	for _, path := range []string{"/auth/login", "/auth/v1/account"} {
		if err := validateFedCMLandingPath(path); err != nil {
			t.Errorf("validateFedCMLandingPath(%q) error=%v", path, err)
		}
	}
}

func TestFedCMAwareLoginRejectsOversizedBodiesBeforeLegacy(t *testing.T) {
	var legacyCalls int
	legacy := func(w http.ResponseWriter, r *http.Request) {
		legacyCalls++
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusTeapot)
	}
	landing := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	body := strings.Repeat("a", fedCMLandingBodyLimit+1)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	response := httptest.NewRecorder()
	fedCMAwareLogin(landing, legacy)(response, req)
	if response.Code != http.StatusRequestEntityTooLarge || legacyCalls != 0 {
		t.Fatalf("oversized status=%d legacy_calls=%d body=%q", response.Code, legacyCalls, response.Body.String())
	}
}

func TestFedCMAwareLoginPreservesBoundedLegacyBody(t *testing.T) {
	want := strings.Repeat("a", fedCMLandingBodyLimit)
	var got []byte
	legacy := func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusTeapot)
	}
	landing := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte(want)))
	response := httptest.NewRecorder()
	fedCMAwareLogin(landing, legacy)(response, req)
	if response.Code != http.StatusTeapot || !bytes.Equal(got, []byte(want)) {
		t.Fatalf("legacy status=%d body_len=%d want=%d", response.Code, len(got), len(want))
	}
}

func TestFedCMRuntimeUsesOnlyBoundSessionCookieAndActiveProfile(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "fedcm-runtime-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStoreWithHasher(db, hasher)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.BootstrapUser(ctx, "subject-1", "alice@example.test", mustFedCMHash(t, "password")); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "fedcm-profile", SQL: `INSERT INTO identity_user_profiles (subject,email,email_verified,preferred_username,given_name) VALUES (?,?,?,?,?)`, Args: []any{"subject-1", "profile@example.test", int64(1), "Alice", "Alice"}}); err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateSession(ctx, "subject-1", "pwd", time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "198.51.100.9")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/fed_cm/accounts", nil).WithContext(browser.ContextWithPeerIP(ctx, "198.51.100.9"))
	req.AddCookie(&http.Cookie{Name: browser.FedCMSessionCookieName, Value: issued.Token})
	account, err := resolveFedCMCurrent(req.Context(), req, sessions, identities)
	if err != nil || account.ID != "subject-1" || account.Email != "profile@example.test" || account.Name != "Alice" {
		t.Fatalf("account=%#v err=%v", account, err)
	}
	normalName, err := browser.CookieName("https://issuer.example.test")
	if err != nil {
		t.Fatal(err)
	}
	normal := httptest.NewRequest(http.MethodGet, "/auth/v1/fed_cm/accounts", nil).WithContext(browser.ContextWithPeerIP(ctx, "198.51.100.9"))
	normal.AddCookie(&http.Cookie{Name: normalName, Value: issued.Token})
	if _, err := resolveFedCMCurrent(normal.Context(), normal, sessions, identities); err == nil {
		t.Fatal("normal session cookie was accepted by FedCM")
	}
	duplicate := httptest.NewRequest(http.MethodGet, "/auth/v1/fed_cm/accounts", nil).WithContext(browser.ContextWithPeerIP(ctx, "198.51.100.9"))
	duplicate.AddCookie(&http.Cookie{Name: browser.FedCMSessionCookieName, Value: issued.Token})
	duplicate.AddCookie(&http.Cookie{Name: browser.FedCMSessionCookieName, Value: issued.Token})
	if _, err := resolveFedCMCurrent(duplicate.Context(), duplicate, sessions, identities); err == nil {
		t.Fatal("duplicate FedCM cookies were accepted")
	}
	if err := sessions.RevokeSession(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveFedCMCurrent(req.Context(), req, sessions, identities); err == nil {
		t.Fatal("revoked FedCM session accepted")
	}
}

func TestFedCMRuntimeRejectsLegacyEmptyPeerSession(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "fedcm-legacy-peer-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStoreWithHasher(db, hasher)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.BootstrapUser(ctx, "subject-legacy", "legacy@example.test", mustFedCMHash(t, "password")); err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateSession(ctx, "subject-legacy", "pwd", time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/fed_cm/accounts", nil).WithContext(browser.ContextWithPeerIP(ctx, "198.51.100.9"))
	req.AddCookie(&http.Cookie{Name: browser.FedCMSessionCookieName, Value: issued.Token})
	if _, err := resolveFedCMCurrent(req.Context(), req, sessions, identities); err == nil {
		t.Fatal("legacy empty-peer session accepted by FedCM")
	}
}

func TestFedCMRuntimeDisabledWhenConfigUnset(t *testing.T) {
	runtime, err := fedcmRuntimeFromEnv(func(string) string { return "" }, nil, nil, "https://issuer.example.test", nil, nil)
	if err != nil || runtime != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
}

func writeFedCMConfig(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/fedcm.json"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustFedCMHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := credential.Hash([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
