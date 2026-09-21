package upstreamprovider

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// Valid 24-char mixed-case alphanumeric provider IDs.
const (
	testOIDC     = "rtOidc000000000000000001"
	testGitHub   = "rtGithub0000000000000001"
	testNoSec    = "rtNosec00000000000000001"
	testEmpSec   = "rtEmpSec0000000000000001"
	testTamper   = "rtTamper0000000000000001"
	testDisabled = "rtDisabled00000000000001"
	testCustom   = "rtCustom0000000000000001"
	testGoogle   = "rtGoogle0000000000000001"
	testUnsupp   = "rtUnsupp0000000000000001"
)

// Exact 24-char mixed-case alphanumeric provider ID for scope tests.
const testScopeID = "AbCdEfGhIjKlMnOpQrStUvWx"

// assertLen24 guards that a provider ID is exactly 24 characters.
func assertLen24(t *testing.T, id string) {
	t.Helper()
	if len(id) != 24 {
		t.Fatalf("provider ID %q has length %d, want 24", id, len(id))
	}
}

func TestRuntimeConfigOIDC(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testOIDC)
	seedProviderWithVersion(t, f, testOIDC)

	cfg, secret, err := f.store.RuntimeConfig(f.ctx, testOIDC)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kind != ProviderKindOIDC {
		t.Fatalf("Kind = %q, want %q", cfg.Kind, ProviderKindOIDC)
	}
	if cfg.Issuer != "https://issuer.test" {
		t.Fatalf("Issuer = %q, want %q", cfg.Issuer, "https://issuer.test")
	}
	if cfg.AuthorizationEndpoint != "https://issuer.test/auth" {
		t.Fatalf("AuthorizationEndpoint = %q", cfg.AuthorizationEndpoint)
	}
	if cfg.TokenEndpoint != "https://issuer.test/token" {
		t.Fatalf("TokenEndpoint = %q", cfg.TokenEndpoint)
	}
	if cfg.UserInfoEndpoint != "https://issuer.test/userinfo" {
		t.Fatalf("UserInfoEndpoint = %q", cfg.UserInfoEndpoint)
	}
	if cfg.ClientID != "test-client" {
		t.Fatalf("ClientID = %q", cfg.ClientID)
	}
	if cfg.ProviderSource != "registry" {
		t.Fatalf("ProviderSource = %q", cfg.ProviderSource)
	}
	if cfg.RuntimeVersion == "" {
		t.Fatal("RuntimeVersion is empty")
	}
	if len(cfg.Scopes) != 1 || cfg.Scopes[0] != "openid" {
		t.Fatalf("Scopes = %v, want [openid]", cfg.Scopes)
	}
	if cfg.Protocol.UsePKCE == nil || !*cfg.Protocol.UsePKCE {
		t.Fatal("UsePKCE should be true")
	}
	if cfg.Protocol.ClientSecretBasic == nil || !*cfg.Protocol.ClientSecretBasic {
		t.Fatal("ClientSecretBasic should be true")
	}
	if cfg.Protocol.ClientSecretPost == nil || *cfg.Protocol.ClientSecretPost {
		t.Fatal("ClientSecretPost should be false")
	}
	if secret != nil {
		t.Fatalf("secret = %q, want nil", *secret)
	}
}

func TestRuntimeConfigGitHub(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testGitHub)
	ghReq := validProviderMutationRequest()
	ghReq.Typ = AuthProviderTypeGitHub
	ghReq.Issuer = "https://github.com"
	ghReq.AuthorizationEndpoint = "https://github.com/login/oauth/authorize"
	ghReq.TokenEndpoint = "https://github.com/login/oauth/access_token"
	ghReq.UserinfoEndpoint = "https://api.github.com/user"
	ghReq.ClientID = "gh-cid"
	ghReq.Scope = "read:user"
	ghReq.UsePKCE = false
	ghReq.ClientSecretBasic = true
	ghReq.ClientSecretPost = false
	ghReq.ClientSecret = nil
	ghReq.JWKS = nil
	_, err := f.store.CreateAuthorized(f.ctx, testGitHub, f.newRequestID("seed-gh"), ghReq, f.keys, f.principal)
	if err != nil {
		t.Fatal(err)
	}

	cfg, _, err := f.store.RuntimeConfig(f.ctx, testGitHub)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kind != ProviderKindGitHub {
		t.Fatalf("Kind = %q, want %q", cfg.Kind, ProviderKindGitHub)
	}
	if cfg.Issuer != "https://github.com" {
		t.Fatalf("Issuer = %q", cfg.Issuer)
	}
	if cfg.AuthorizationEndpoint != "https://github.com/login/oauth/authorize" {
		t.Fatalf("AuthorizationEndpoint = %q", cfg.AuthorizationEndpoint)
	}
	if cfg.TokenEndpoint != "https://github.com/login/oauth/access_token" {
		t.Fatalf("TokenEndpoint = %q", cfg.TokenEndpoint)
	}
	if cfg.UserInfoEndpoint != "https://api.github.com/user" {
		t.Fatalf("UserInfoEndpoint = %q", cfg.UserInfoEndpoint)
	}
	if cfg.ClientID != "gh-cid" {
		t.Fatalf("ClientID = %q", cfg.ClientID)
	}
	if len(cfg.Scopes) != 1 || cfg.Scopes[0] != "read:user" {
		t.Fatalf("Scopes = %v, want [read:user]", cfg.Scopes)
	}
	if cfg.Protocol.UsePKCE == nil || *cfg.Protocol.UsePKCE {
		t.Fatal("UsePKCE should be false for GitHub")
	}
	if cfg.Protocol.ClientSecretBasic == nil || !*cfg.Protocol.ClientSecretBasic {
		t.Fatal("ClientSecretBasic should be true")
	}
	if cfg.Protocol.ClientSecretPost == nil || *cfg.Protocol.ClientSecretPost {
		t.Fatal("ClientSecretPost should be false")
	}
}

func TestRuntimeConfigInvalidID(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	_, _, err := f.store.RuntimeConfig(f.ctx, "")
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
}

func TestRuntimeConfigNotFound(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	_, _, err := f.store.RuntimeConfig(f.ctx, "abcdefghijklmnopqrstuvwx")
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("err = %v, want ErrProviderNotFound", err)
	}
}

func TestRuntimeConfigNilSecretPreserved(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testNoSec)
	seedProviderWithVersion(t, f, testNoSec)

	_, secret, err := f.store.RuntimeConfig(f.ctx, testNoSec)
	if err != nil {
		t.Fatal(err)
	}
	if secret != nil {
		t.Fatalf("expected nil secret, got %q", *secret)
	}
}

func TestRuntimeConfigEmptyEncryptedSecret(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testEmpSec)
	empty := ""
	req := validProviderMutationRequest()
	req.ClientSecret = &empty

	_, err := f.store.CreateAuthorized(f.ctx, testEmpSec, f.newRequestID("seed-empsec"), req, f.keys, f.principal)
	if err != nil {
		t.Fatal(err)
	}

	_, secret, err := f.store.RuntimeConfig(f.ctx, testEmpSec)
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil {
		t.Fatal("expected non-nil secret pointer")
	}
	if *secret != "" {
		t.Fatalf("secret = %q, want empty", *secret)
	}
}

func TestRuntimeConfigTamperDecryptFails(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testTamper)
	sec := "my-secret"
	req := validProviderMutationRequest()
	req.ClientSecret = &sec

	_, err := f.store.CreateAuthorized(f.ctx, testTamper, f.newRequestID("seed-tamp"), req, f.keys, f.principal)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "tamp-rt",
		SQL:       "UPDATE auth_providers SET secret=? WHERE id=?",
		Args:      []any{[]byte("tampered-ciphertext"), testTamper},
	}); err != nil {
		t.Fatal(err)
	}

	_, _, err = f.store.RuntimeConfig(f.ctx, testTamper)
	if err == nil {
		t.Fatal("expected error for tampered secret")
	}
}

func TestRuntimeConfigDisabledFails(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testDisabled)
	seedProviderWithVersion(t, f, testDisabled)

	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "dis-rt",
		SQL:       "UPDATE auth_providers SET enabled=0 WHERE id=?",
		Args:      []any{testDisabled},
	}); err != nil {
		t.Fatal(err)
	}

	_, _, err := f.store.RuntimeConfig(f.ctx, testDisabled)
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("err = %v, want ErrProviderNotFound", err)
	}
}

func TestRuntimeConfigCustomMapping(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testCustom)
	req := validProviderMutationRequest()
	req.Typ = AuthProviderTypeCustom

	_, err := f.store.CreateAuthorized(f.ctx, testCustom, f.newRequestID("seed-cust"), req, f.keys, f.principal)
	if err != nil {
		t.Fatal(err)
	}

	cfg, _, err := f.store.RuntimeConfig(f.ctx, testCustom)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kind != ProviderKindOIDC {
		t.Fatalf("Kind = %q, want %q (custom maps to oidc)", cfg.Kind, ProviderKindOIDC)
	}
}

func TestRuntimeConfigGoogleMapping(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testGoogle)
	req := validProviderMutationRequest()
	req.Typ = AuthProviderTypeGoogle

	_, err := f.store.CreateAuthorized(f.ctx, testGoogle, f.newRequestID("seed-gogl"), req, f.keys, f.principal)
	if err != nil {
		t.Fatal(err)
	}

	cfg, _, err := f.store.RuntimeConfig(f.ctx, testGoogle)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kind != ProviderKindOIDC {
		t.Fatalf("Kind = %q, want %q (google maps to oidc)", cfg.Kind, ProviderKindOIDC)
	}
}

func TestRuntimeConfigUnsupportedType(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testUnsupp)

	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-unsup",
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce,client_secret_basic,client_secret_post) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{testUnsupp, int64(1), "Unsupported", "unsupported", "https://issuer.test", "https://issuer.test/auth", "https://issuer.test/token", "https://issuer.test/userinfo", "test-client", "openid", int64(1), int64(1), int64(0)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-unsup-ver",
		SQL:       "INSERT INTO auth_provider_runtime_versions(provider_id,version) VALUES(?,?)",
		Args:      []any{testUnsupp, "v1"},
	}); err != nil {
		t.Fatal(err)
	}

	_, _, err := f.store.RuntimeConfig(f.ctx, testUnsupp)
	if !errors.Is(err, ErrInvalidProviderRow) {
		t.Fatalf("err = %v, want ErrInvalidProviderRow", err)
	}
}

// --- Scope tests: all use testScopeID ("AbCdEfGhIjKlMnOpQrStUvWx") ---

func TestRuntimeConfigPlusDelimitedScopes(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testScopeID)
	req := validProviderMutationRequest()
	req.Scope = "openid profile"
	req.ClientSecret = nil

	_, err := f.store.CreateAuthorized(f.ctx, testScopeID, f.newRequestID("seed-plus"), req, f.keys, f.principal)
	if err != nil {
		t.Fatal(err)
	}

	cfg, _, err := f.store.RuntimeConfig(f.ctx, testScopeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Scopes) != 2 || cfg.Scopes[0] != "openid" || cfg.Scopes[1] != "profile" {
		t.Fatalf("Scopes = %v, want [openid profile]", cfg.Scopes)
	}
}

func TestRuntimeConfigSingleScope(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testOIDC)
	seedProviderWithVersion(t, f, testOIDC)

	cfg, _, err := f.store.RuntimeConfig(f.ctx, testOIDC)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Scopes) != 1 || cfg.Scopes[0] != "openid" {
		t.Fatalf("Scopes = %v, want [openid]", cfg.Scopes)
	}
}

func TestRuntimeConfigEmptyScope(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testScopeID)
	req := validProviderMutationRequest()
	req.Scope = ""
	req.ClientSecret = nil

	_, err := f.store.CreateAuthorized(f.ctx, testScopeID, f.newRequestID("seed-empscope"), req, f.keys, f.principal)
	if err != nil {
		t.Fatal(err)
	}

	cfg, _, err := f.store.RuntimeConfig(f.ctx, testScopeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Scopes) != 0 {
		t.Fatalf("Scopes = %v, want empty", cfg.Scopes)
	}
}

func TestRuntimeConfigLegacyMultispaceScope(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	assertLen24(t, testScopeID)
	req := validProviderMutationRequest()
	// Legacy input: normalizeProviderScope joins as "openid+profile+email"
	req.Scope = "openid  profile  email"
	req.ClientSecret = nil

	_, err := f.store.CreateAuthorized(f.ctx, testScopeID, f.newRequestID("seed-legacy"), req, f.keys, f.principal)
	if err != nil {
		t.Fatal(err)
	}

	cfg, _, err := f.store.RuntimeConfig(f.ctx, testScopeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Scopes) != 3 || cfg.Scopes[0] != "openid" || cfg.Scopes[1] != "profile" || cfg.Scopes[2] != "email" {
		t.Fatalf("Scopes = %v, want [openid profile email]", cfg.Scopes)
	}
}

// --- GenerateAuthorizationURL: full CreateAuthorized → RuntimeConfig → GenerateURL chain ---

func TestGenerateAuthorizationURLScope(t *testing.T) {
	t.Parallel()
	assertLen24(t, testScopeID)
	f := runtimeFixture(t)

	// Step 1: CreateAuthorized with scope "openid profile".
	req := validProviderMutationRequest()
	req.Scope = "openid profile"
	req.ClientSecret = nil
	_, err := f.store.CreateAuthorized(f.ctx, testScopeID, f.newRequestID("seed-auth-scope"), req, f.keys, f.principal)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: RuntimeConfig returns the real Config with Scopes from DB.
	cfg, _, err := f.store.RuntimeConfig(f.ctx, testScopeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Scopes) != 2 {
		t.Fatalf("RuntimeConfig.Scopes = %v, want 2 entries", cfg.Scopes)
	}

	// Step 3: GenerateAuthorizationURL using cfg.Scopes as params.Scopes.
	p := newTestProvider(make([]byte, 256))
	store := newTestStore()
	binding := DigestSHA256("browser-session")
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	params := AuthorizationParams{
		CallbackURI:    "https://app.example.com/cb",
		Scopes:         cfg.Scopes,
		ProviderSource: cfg.ProviderSource,
		RuntimeVersion: cfg.RuntimeVersion,
	}

	result, err := GenerateAuthorizationURL(
		t.Context(), p, cfg, store, params, binding, testScopeID, now,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Step 4: Assert URL scope is space-separated, no literal "+".
	u, err := url.Parse(result.URL)
	if err != nil {
		t.Fatal(err)
	}
	qScope := u.Query().Get("scope")
	if strings.Contains(qScope, "+") {
		t.Fatalf("scope query param contains literal +: %q", qScope)
	}
	parts := strings.Split(qScope, " ")
	if len(parts) != 2 || parts[0] != "openid" || parts[1] != "profile" {
		t.Fatalf("scope = %q, want \"openid profile\"", qScope)
	}
}
