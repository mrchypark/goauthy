package upstreamprovider

import "testing"

func TestProviderKindAndGitHubConfig(t *testing.T) {
	oidc := Config{Issuer: "https://issuer.example.test", AuthorizationEndpoint: "https://issuer.example.test/auth", TokenEndpoint: "https://issuer.example.test/token", ClientID: "client"}
	if got := oidc.NormalizedKind(); got != ProviderKindOIDC {
		t.Fatalf("zero kind = %q, want %q", got, ProviderKindOIDC)
	}
	oidc.Kind = ProviderKindOIDC
	if got := oidc.NormalizedKind(); got != ProviderKindOIDC {
		t.Fatalf("oidc kind = %q, want %q", got, ProviderKindOIDC)
	}
	if err := oidc.Validate(); err != nil {
		t.Fatalf("OIDC config: %v", err)
	}

	github := Config{
		Kind:                  ProviderKindGitHub,
		Issuer:                "https://github.com",
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
		TokenEndpoint:         "https://github.com/login/oauth/access_token",
		UserInfoEndpoint:      "https://api.github.com/user",
		ClientID:              "client",
		Scopes:                []string{"read:user"},
	}
	if err := github.Validate(); err != nil {
		t.Fatalf("GitHub config: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"issuer":    func(c *Config) { c.Issuer = "https://github.example.test" },
		"userinfo":  func(c *Config) { c.UserInfoEndpoint = "https://github.example.test/user" },
		"jwks":      func(c *Config) { c.JWKSURI = "https://github.com/keys" },
		"audience":  func(c *Config) { c.Audience = "client" },
		"openid":    func(c *Config) { c.Scopes = []string{"read:user", "openid"} },
		"read:user": func(c *Config) { c.Scopes = []string{"user:email"} },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := github
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("GitHub config unexpectedly accepted")
			}
		})
	}
}
