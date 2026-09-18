package upstreamprovider

import "testing"

func TestProtocolEffectiveDefaults(t *testing.T) {
	// Nil protocol fields yield legacy defaults.
	cfg := Config{}
	ep := cfg.EffectiveProtocol()
	if !ep.UsePKCE || !ep.ClientSecretBasic || ep.ClientSecretPost {
		t.Fatalf("nil protocol: pkce=%v basic=%v post=%v", ep.UsePKCE, ep.ClientSecretBasic, ep.ClientSecretPost)
	}

	// Explicit false overrides.
	f := false
	cfg.Protocol = ProviderProtocol{UsePKCE: &f, ClientSecretBasic: &f, ClientSecretPost: &f}
	ep = cfg.EffectiveProtocol()
	if ep.UsePKCE || ep.ClientSecretBasic || ep.ClientSecretPost {
		t.Fatalf("explicit false: pkce=%v basic=%v post=%v", ep.UsePKCE, ep.ClientSecretBasic, ep.ClientSecretPost)
	}

	// Explicit true.
	t2 := true
	cfg.Protocol = ProviderProtocol{UsePKCE: &t2, ClientSecretBasic: &t2, ClientSecretPost: &t2}
	ep = cfg.EffectiveProtocol()
	if !ep.UsePKCE || !ep.ClientSecretBasic || !ep.ClientSecretPost {
		t.Fatalf("explicit true: pkce=%v basic=%v post=%v", ep.UsePKCE, ep.ClientSecretBasic, ep.ClientSecretPost)
	}
}

func TestProtocolIsZero(t *testing.T) {
	if !(ProviderProtocol{}).isZero() {
		t.Fatal("zero protocol reports non-zero")
	}
	v := true
	for name, p := range map[string]ProviderProtocol{
		"use_pkce":            {UsePKCE: &v},
		"client_secret_basic": {ClientSecretBasic: &v},
		"client_secret_post":  {ClientSecretPost: &v},
	} {
		if p.isZero() {
			t.Errorf("%s: zero when set", name)
		}
	}
}
