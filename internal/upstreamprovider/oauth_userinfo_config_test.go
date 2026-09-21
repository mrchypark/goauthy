package upstreamprovider

import (
	"encoding/json"
	"errors"
	"testing"
)

// --- Enum roundtrip ---

func TestOAuthUserInfoEnumRoundtrip(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(AuthProviderTypeOAuthUserInfo)
	if err != nil {
		t.Fatal(err)
	}
	want := `"oauth_userinfo"`
	if string(data) != want {
		t.Fatalf("marshal = %s, want %s", data, want)
	}
	var got AuthProviderType
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got != AuthProviderTypeOAuthUserInfo {
		t.Fatalf("unmarshal = %q, want %q", got, AuthProviderTypeOAuthUserInfo)
	}
}

func TestOAuthUserInfoValid(t *testing.T) {
	t.Parallel()
	if !AuthProviderTypeOAuthUserInfo.valid() {
		t.Fatal("oauth_userinfo should be valid")
	}
}

// --- Unknown type rejects ---

func TestAuthProviderTypeUnknownRejects(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"saml", "ldap", "oauth", "openid_connect"} {
		t.Run(raw, func(t *testing.T) {
			var at AuthProviderType
			if err := json.Unmarshal([]byte(`"`+raw+`"`), &at); err == nil {
				t.Fatalf("type %q should be rejected", raw)
			}
			if AuthProviderType(raw).valid() {
				t.Fatalf("type %q should not be valid", raw)
			}
		})
	}
}

// --- Existing types still map correctly ---

func TestMapProviderKindExistingTypes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		typ  AuthProviderType
		want ProviderKind
	}{
		{AuthProviderTypeOIDC, ProviderKindOIDC},
		{AuthProviderTypeCustom, ProviderKindOIDC},
		{AuthProviderTypeGoogle, ProviderKindOIDC},
		{AuthProviderTypeGitHub, ProviderKindGitHub},
	}
	for _, tc := range cases {
		t.Run(string(tc.typ), func(t *testing.T) {
			got, err := mapProviderKind(tc.typ)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("mapProviderKind(%q) = %q, want %q", tc.typ, got, tc.want)
			}
		})
	}
}

// --- New kind maps correctly ---

func TestMapProviderKindOAuthUserInfo(t *testing.T) {
	t.Parallel()
	got, err := mapProviderKind(AuthProviderTypeOAuthUserInfo)
	if err != nil {
		t.Fatal(err)
	}
	if got != ProviderKindOAuthUserInfo {
		t.Fatalf("mapProviderKind(oauth_userinfo) = %q, want %q", got, ProviderKindOAuthUserInfo)
	}
}

func TestMapProviderKindUnknownFailsClosed(t *testing.T) {
	t.Parallel()
	_, err := mapProviderKind("saml")
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unknown type: err=%v, want ErrInvalidConfig", err)
	}
}

// --- NormalizedKind for the new kind ---

func TestNormalizedKindOAuthUserInfo(t *testing.T) {
	t.Parallel()
	cfg := Config{Kind: ProviderKindOAuthUserInfo}
	if got := cfg.NormalizedKind(); got != ProviderKindOAuthUserInfo {
		t.Fatalf("NormalizedKind() = %q, want %q", got, ProviderKindOAuthUserInfo)
	}
}

// --- Valid config helpers ---

func validOAuthUserInfoConfig() *Config {
	return &Config{
		Kind:                  ProviderKindOAuthUserInfo,
		Issuer:                "https://issuer.example.test",
		AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint:         "https://issuer.example.test/token",
		UserInfoEndpoint:      "https://issuer.example.test/userinfo",
		ClientID:              "client",
		Scopes:                []string{"openid", "profile"},
		Protocol:              ProviderProtocol{UsePKCE: boolPtr(true)},
		ProviderSource:        "registry",
		RuntimeVersion:        "v1",
	}
}

// --- PKCE required ---

func TestOAuthUserInfoPKCERequired(t *testing.T) {
	t.Parallel()
	cfg := validOAuthUserInfoConfig()
	f := false
	cfg.Protocol = ProviderProtocol{UsePKCE: &f}
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("UsePKCE=false: err=%v, want ErrInvalidConfig", err)
	}
}

// --- UserInfoEndpoint required ---

func TestOAuthUserInfoEndpointRequired(t *testing.T) {
	t.Parallel()
	cfg := validOAuthUserInfoConfig()
	cfg.UserInfoEndpoint = ""
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty userinfo: err=%v, want ErrInvalidConfig", err)
	}
}

func TestOAuthUserInfoEndpointMustBeHTTPS(t *testing.T) {
	t.Parallel()
	cfg := validOAuthUserInfoConfig()
	cfg.UserInfoEndpoint = "http://issuer.example.test/userinfo"
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("http userinfo: err=%v, want ErrInvalidConfig", err)
	}
}

// --- No JWKS accepted ---

func TestOAuthUserInfoNoJWKS(t *testing.T) {
	t.Parallel()
	cfg := validOAuthUserInfoConfig()
	cfg.JWKSURI = "https://issuer.example.test/jwks"
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("JWKS present: err=%v, want ErrInvalidConfig", err)
	}
}

// --- Legacy/static provider source denied ---

func TestOAuthUserInfoLegacySourceDenied(t *testing.T) {
	t.Parallel()
	cfg := validOAuthUserInfoConfig()
	cfg.ProviderSource = ""
	cfg.RuntimeVersion = ""
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("legacy source: err=%v, want ErrInvalidConfig", err)
	}
}

// --- Valid config passes ---

func TestOAuthUserInfoValidConfig(t *testing.T) {
	t.Parallel()
	if err := validOAuthUserInfoConfig().Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}

// --- JWKSVerifier skips oauth_userinfo kind ---

func TestJWKSVerifierSkipsOAuthUserInfo(t *testing.T) {
	t.Parallel()
	cfgs := map[string]Config{
		"https://issuer.example.test": *validOAuthUserInfoConfig(),
	}
	verifier, err := NewJWKSVerifier(cfgs, nil)
	if err != nil {
		t.Fatalf("NewJWKSVerifier with oauth_userinfo: %v", err)
	}
	if verifier == nil {
		t.Fatal("verifier is nil")
	}
	if _, ok := verifier.jwksByIssuer["https://issuer.example.test"]; ok {
		t.Fatal("oauth_userinfo issuer should not have JWKS entry")
	}
}

// --- Clone protocol deep copy still works ---

func TestOAuthUserInfoCloneProtocol(t *testing.T) {
	t.Parallel()
	cfg := validOAuthUserInfoConfig()
	cloned := cloneProtocol(cfg.Protocol)
	f := false
	cloned.UsePKCE = &f
	if *cfg.Protocol.UsePKCE != true {
		t.Fatal("clone mutated original")
	}
}
