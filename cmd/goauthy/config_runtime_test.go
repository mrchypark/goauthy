package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/credential"
)

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func applicationConfigTestEnv(t *testing.T, overrides map[string]string) func(string) string {
	t.Helper()
	values := map[string]string{
		"GOAUTHY_RHIZA_PROFILE": "dev",
		"GOAUTHY_CLUSTER_ID":    "test-cluster",
		"GOAUTHY_NODE_ID":       "test-node",
		"GOAUTHY_DATA_DIR":      filepath.Join(t.TempDir(), "data"),
	}
	for name, value := range overrides {
		values[name] = value
	}
	return func(name string) string { return values[name] }
}

func TestRunConfigCommandCheckValidatesWithoutStartingRuntime(t *testing.T) {
	var out bytes.Buffer
	if err := runConfigCommand([]string{"check"}, applicationConfigTestEnv(t, nil), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "configuration valid\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestRunConfigCommandRejectsInvalidRuntimeConfig(t *testing.T) {
	var out bytes.Buffer
	err := runConfigCommand([]string{"check"}, applicationConfigTestEnv(t, map[string]string{
		"GOAUTHY_RHIZA_PROFILE": "invalid",
	}), &out)
	if err == nil || !strings.Contains(err.Error(), "GOAUTHY_RHIZA_PROFILE") {
		t.Fatalf("error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("unexpected output = %q", out.String())
	}
}

func TestRunConfigCommandDumpEffectiveRedactsStorageCredentials(t *testing.T) {
	getenv := applicationConfigTestEnv(t, map[string]string{
		"GOAUTHY_RHIZA_PROFILE":                 "standalone",
		"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET":     "test-bucket",
		"GOAUTHY_RHIZA_OBJECT_STORE_PREFIX":     "goauthy/test",
		"GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY": "access-secret",
		"GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY": "storage-secret",
	})
	var out bytes.Buffer
	if err := runConfigCommand([]string{"dump-effective"}, getenv, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "access-secret") || strings.Contains(out.String(), "storage-secret") {
		t.Fatalf("effective configuration exposed storage credentials: %s", out.String())
	}
	var decoded effectiveConfig
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Storage.Profile != "standalone" || decoded.Storage.ObjectStoreBucket != "test-bucket" || !decoded.Storage.StaticCredentials {
		t.Fatalf("unexpected storage summary: %+v", decoded.Storage)
	}
}

func TestRunConfigCommandRejectsUnknownAction(t *testing.T) {
	var out bytes.Buffer
	if err := runConfigCommand([]string{"unknown"}, applicationConfigTestEnv(t, nil), &out); err == nil {
		t.Fatal("unknown config action accepted")
	}
}

// GA-CONFIG-001: every runtime parser that used to fail after Rhiza was opened
// must fail through the configuration command, before any storage side effect.
func TestRunConfigCommandRejectsInvalidRuntimeConfiguration(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	tokenFile := filepath.Join(t.TempDir(), "dcr-token")
	if err := os.WriteFile(tokenFile, []byte(strings.Repeat("a", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	credentialDir := t.TempDir()
	resetKeyFile := filepath.Join(credentialDir, "password-reset-key")
	if err := os.WriteFile(resetKeyFile, bytes.Repeat([]byte{'k'}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	phc, err := hasher.Hash(context.Background(), []byte("CorrectHorse42"))
	if err != nil {
		t.Fatal(err)
	}
	phcFile := filepath.Join(credentialDir, "bootstrap-user.phc")
	if err := os.WriteFile(phcFile, []byte(phc+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fedcmFile := writeTestFile(t, credentialDir, "fedcm.json", `{"client_origins":{"rp-client":"https://rp.example.test"},"login_url":"/auth/login"}`)
	passkeyKeyFile := filepath.Join(credentialDir, "passkey-key")
	if err := os.WriteFile(passkeyKeyFile, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{name: "argon2 policy", env: map[string]string{"GOAUTHY_ARGON2_MEMORY_KIB": "8192"}, wantErr: "invalid Argon2 password policy"},
		{name: "impossible password policy", env: map[string]string{"GOAUTHY_PASSWORD_LENGTH_MAX": "14", "GOAUTHY_PASSWORD_LOWER_CASE": "8", "GOAUTHY_PASSWORD_UPPER_CASE": "8"}, wantErr: "invalid password rules"},
		{name: "dcr anonymous", env: map[string]string{"GOAUTHY_DCR_ANONYMOUS": "yes"}, wantErr: "GOAUTHY_DCR_ANONYMOUS"},
		{name: "dcr anonymous cleanup", env: map[string]string{"GOAUTHY_DCR_ANONYMOUS": "true", "GOAUTHY_DCR_ANONYMOUS_CLEANUP_LIMIT": "0"}, wantErr: "GOAUTHY_DCR_ANONYMOUS_CLEANUP_LIMIT"},
		{name: "dcr token and anonymous", env: map[string]string{"GOAUTHY_DCR_ANONYMOUS": "true", "GOAUTHY_DCR_REGISTRATION_TOKEN_FILE": tokenFile}, wantErr: "cannot both be configured"},
		{name: "scopes", env: map[string]string{"GOAUTHY_DCR_DEFAULT_SCOPES": "openid unknown"}, wantErr: "GOAUTHY_DCR_ALLOWED_SCOPES"},
		{name: "hosted resource", env: map[string]string{"GOAUTHY_CONNECTIONS_RESOURCE": "https://example.test/connections"}, wantErr: "GOAUTHY_CONNECTIONS_RESOURCE"},
		{name: "event retention", env: map[string]string{"GOAUTHY_EVENTS_CLEANUP_DAYS": "0"}, wantErr: "GOAUTHY_EVENTS_CLEANUP_DAYS"},
		{name: "notification generation", env: map[string]string{"GOAUTHY_EVENT_NOTIFICATION_CONFIG_GENERATION": "0"}, wantErr: "GOAUTHY_EVENT_NOTIFICATION_CONFIG_GENERATION"},
		{name: "token events", env: map[string]string{"GOAUTHY_EVENT_GENERATE_TOKEN_ISSUED": "maybe"}, wantErr: "GOAUTHY_EVENT_GENERATE_TOKEN_ISSUED"},
		{name: "account expiry", env: map[string]string{"GOAUTHY_USER_EXPIRY_INTERVAL_MINUTES": "0"}, wantErr: "GOAUTHY_USER_EXPIRY_INTERVAL_MINUTES"},
		{name: "browser id mode", env: map[string]string{"GOAUTHY_BROWSER_ID_COOKIE_MODE": "loose"}, wantErr: "GOAUTHY_BROWSER_ID_COOKIE_MODE"},
		{name: "subject prefix", env: map[string]string{"GOAUTHY_EMAIL_SUB_PREFIX": "bad\nprefix"}, wantErr: "GOAUTHY_EMAIL_SUB_PREFIX"},
		{name: "session idle timeout", env: map[string]string{"GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT": "1s"}, wantErr: "GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT"},
		{name: "backchannel exceptions", env: map[string]string{"GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_HTTP": "true"}, wantErr: "GOAUTHY_BOOTSTRAP_BACKCHANNEL_LOGOUT_URI"},
		{name: "trusted proxies", env: map[string]string{"GOAUTHY_TRUSTED_PROXIES": "not-a-cidr"}, wantErr: "GOAUTHY_TRUSTED_PROXIES"},
		{name: "geoblock policy", env: map[string]string{"GOAUTHY_GEOBLOCK_ENABLED": "true"}, wantErr: "GOAUTHY_GEOBLOCK_TYPE"},
		{name: "geoblock header", env: map[string]string{"GOAUTHY_GEOBLOCK_ENABLED": "true", "GOAUTHY_GEOBLOCK_TYPE": "blacklist", "GOAUTHY_GEOBLOCK_COUNTRIES": "DE", "GOAUTHY_GEOBLOCK_COUNTRY_HEADER": "X-Country"}, wantErr: "GOAUTHY_GEOBLOCK_COUNTRY_HEADER"},
		{name: "metrics address", env: map[string]string{"GOAUTHY_METRICS_LISTEN_ADDR": "127.0.0.1"}, wantErr: "GOAUTHY_METRICS_LISTEN_ADDR"},
		{name: "metrics token required", env: map[string]string{"GOAUTHY_METRICS_LISTEN_ADDR": "127.0.0.1:9100"}, wantErr: "GOAUTHY_METRICS_TOKEN_FILE"},
		{name: "bootstrap audience", env: map[string]string{"GOAUTHY_BOOTSTRAP_DEFAULT_AUD": " https://example.test"}, wantErr: "GOAUTHY_BOOTSTRAP_DEFAULT_AUD"},
		{name: "forced mfa without passkey", env: map[string]string{"GOAUTHY_BOOTSTRAP_FORCE_MFA": "true"}, wantErr: "GOAUTHY_BOOTSTRAP_FORCE_MFA"},
		{name: "bootstrap roles without credential", env: map[string]string{"GOAUTHY_BOOTSTRAP_USER_ROLES": `["admin"]`}, wantErr: "GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE"},
		{name: "missing bootstrap credential file", env: map[string]string{"GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE": filepath.Join(credentialDir, "missing.phc")}, wantErr: "bootstrap user password credential"},
		{name: "bootstrap credential structure", env: map[string]string{"GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE": writeTestFile(t, credentialDir, "malformed.phc", "$argon2id$v=19$m=8192")}, wantErr: "bootstrap user password credential"},
		{name: "recovery without reset key", env: map[string]string{"GOAUTHY_PASSWORD_RECOVERY_ENABLED": "true"}, wantErr: "GOAUTHY_PASSWORD_RESET_KEY_FILE"},
		{name: "recovery without bootstrap email", env: map[string]string{"GOAUTHY_PASSWORD_RECOVERY_ENABLED": "true", "GOAUTHY_PASSWORD_RESET_KEY_FILE": resetKeyFile, "GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE": phcFile}, wantErr: "GOAUTHY_BOOTSTRAP_USER_EMAIL"},
		// GA66-CONFIG-002: conditions startup only rejected after Rhiza was
		// opened and bootstrap mutations had committed.
		{name: "backchannel endpoint", env: map[string]string{"GOAUTHY_BOOTSTRAP_BACKCHANNEL_LOGOUT_URI": "not-a-url"}, wantErr: "invalid bootstrap back-channel logout endpoint"},
		{name: "backchannel endpoint without http exception", env: map[string]string{"GOAUTHY_BOOTSTRAP_BACKCHANNEL_LOGOUT_URI": "http://logout.example.test/hook"}, wantErr: "invalid bootstrap back-channel logout endpoint"},
		{name: "fedcm with forced mfa", env: map[string]string{"GOAUTHY_FEDCM_CONFIG_FILE": fedcmFile, "GOAUTHY_BOOTSTRAP_FORCE_MFA": "true", "GOAUTHY_PASSKEY_RP_ID": "id.example.test", "GOAUTHY_PASSKEY_ORIGINS": "https://id.example.test", "GOAUTHY_PASSKEY_KEY_FILE": passkeyKeyFile}, wantErr: "FedCM cannot be enabled while bootstrap forced-MFA is active"},
		{name: "generated secrets without api key input", env: map[string]string{"GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_FILE": filepath.Join(credentialDir, "generated-secrets.json"), "GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_TTL_SECONDS": "900"}, wantErr: "generated bootstrap requires API-key bootstrap input"},
		{name: "bootstrap redirect uri", env: map[string]string{"GOAUTHY_BOOTSTRAP_REDIRECT_URI": "not-a-url"}, wantErr: "invalid bootstrap OAuth redirect URI"},
		{name: "bootstrap redirect uri without https", env: map[string]string{"GOAUTHY_BOOTSTRAP_REDIRECT_URI": "http://id.example.test/callback"}, wantErr: "invalid bootstrap OAuth redirect URI"},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := map[string]string{"GOAUTHY_DATA_DIR": dataDir}
			for name, value := range test.env {
				env[name] = value
			}
			var out bytes.Buffer
			err := runConfigCommand([]string{"check"}, applicationConfigTestEnv(t, env), &out)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v want %q", err, test.wantErr)
			}
			if out.Len() != 0 {
				t.Fatalf("unexpected output = %q", out.String())
			}
			if _, statErr := os.Stat(dataDir); statErr == nil {
				t.Fatalf("configuration rejection opened storage at %s", dataDir)
			}
		})
	}
}

// GA-CONFIG-001: configured files are content-validated, and a valid runtime
// configuration still passes the preflight.
func TestRunConfigCommandValidatesRuntimeFiles(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "metrics-token")
	if err := os.WriteFile(tokenFile, []byte("local-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runConfigCommand([]string{"check"}, applicationConfigTestEnv(t, map[string]string{
		"GOAUTHY_METRICS_LISTEN_ADDR":              "127.0.0.1:9100",
		"GOAUTHY_METRICS_TOKEN_FILE":               tokenFile,
		"GOAUTHY_PASSWORD_LENGTH_MAX":              "14",
		"GOAUTHY_PASSWORD_LOWER_CASE":              "8",
		"GOAUTHY_PASSWORD_UPPER_CASE":              "5",
		"GOAUTHY_TRUSTED_PROXIES":                  "10.0.0.0/8",
		"GOAUTHY_EVENTS_CLEANUP_DAYS":              "30",
		"GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT":     "30m",
		"GOAUTHY_BOOTSTRAP_BACKCHANNEL_RETRY_BASE": "30s",
	}), &out); err != nil {
		t.Fatalf("valid runtime configuration rejected: %v", err)
	}
	if out.String() != "configuration valid\n" {
		t.Fatalf("output = %q", out.String())
	}

	// GA-CONFIG-001: a credential created under an earlier Argon2 policy must not
	// block a restart under a stronger one; the identity layer keeps the exact
	// current-policy check for creation only.
	storedPHC := writeTestFile(t, dir, "stored-bootstrap.phc", "$argon2id$v=19$m=8192,t=1,p=8$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA")
	out.Reset()
	if err := runConfigCommand([]string{"check"}, applicationConfigTestEnv(t, map[string]string{
		"GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE": storedPHC,
	}), &out); err != nil {
		t.Fatalf("stored bootstrap credential under a stronger policy rejected: %v", err)
	}

	invalidToken := filepath.Join(dir, "invalid-token")
	if err := os.WriteFile(invalidToken, []byte("two words\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saasFile := writeTestFile(t, dir, "saas.json", "{not json")
	for _, test := range []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{name: "metrics token content", env: map[string]string{"GOAUTHY_METRICS_LISTEN_ADDR": "127.0.0.1:9100", "GOAUTHY_METRICS_TOKEN_FILE": invalidToken}, wantErr: "metrics token"},
		{name: "integration file", env: map[string]string{"GOAUTHY_SAAS_PROVIDERS_FILE": saasFile}, wantErr: "SaaS providers file"},
		{name: "hmac secret file", env: map[string]string{"GOAUTHY_OAUTH_HMAC_SECRET_FILE": invalidToken}, wantErr: "OAuth HMAC secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runConfigCommand([]string{"check"}, applicationConfigTestEnv(t, test.env), &out)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v want %q", err, test.wantErr)
			}
		})
	}
}
