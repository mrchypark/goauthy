package upstreamprovider

import "testing"

func validTestConfig(src, ver string) Config {
	return Config{
		Kind:                  ProviderKindOIDC,
		Issuer:                "https://issuer.example.test",
		AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint:         "https://issuer.example.test/token",
		ClientID:              "client",
		ProviderSource:        src,
		RuntimeVersion:        ver,
	}
}

func TestIsPinned24ManagedID(t *testing.T) {
	for _, tt := range []struct {
		id   string
		want bool
	}{
		{"abcdefghijklmnopqrstuvwx", true},
		{"ABCDEFGHIJKLMNOPQRSTUVWX", true},
		{"AbCdEfGhIjKlMnOpQrStUvWx", true},
		{"123456789012345678901234", true},
		{"abcdefghijklmnopqrstuvw", false},  // 23
		{"abcdefghijklmnopqrstuvwxy", false}, // 25
		{"abcdefghijklm-nopqrstuvwx", false}, // hyphen
		{"abcdefghijklmnopqrstuvwx ", false},  // trailing space
		{"", false},
	} {
		if got := isPinned24ManagedID(tt.id); got != tt.want {
			t.Errorf("isPinned24ManagedID(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestValidConfigProviderID_LegacyLowercase(t *testing.T) {
	cfg := validTestConfig("", "")
	if !validConfigProviderID("google", cfg) {
		t.Error("lowercase id should be accepted for legacy")
	}
	if validConfigProviderID("Google", cfg) {
		t.Error("mixed case id should be rejected for legacy")
	}
	if validConfigProviderID("", cfg) {
		t.Error("empty id should be rejected")
	}
}

func TestValidConfigProviderID_ManagedMixedCase(t *testing.T) {
	cfg := validTestConfig("registry", "v1.0")
	id := "AbCdEfGhIjKlMnOpQrStUvWx"
	if !validConfigProviderID(id, cfg) {
		t.Errorf("mixed case 24-char id %q should be accepted for registry", id)
	}
}

func TestValidConfigProviderID_CaseDistinct(t *testing.T) {
	cfg := validTestConfig("registry", "v1.0")
	lower := "abcdefghijklmnopqrstuvwx"
	upper := "ABCDEFGHIJKLMNOPQRSTUVWX"
	if !validConfigProviderID(lower, cfg) {
		t.Error("lowercase managed id accepted")
	}
	if !validConfigProviderID(upper, cfg) {
		t.Error("uppercase managed id accepted")
	}
	if lower == upper {
		t.Error("ids must differ by case")
	}
}

func TestValidConfigProviderID_ManagedRejectsShortLong(t *testing.T) {
	cfg := validTestConfig("registry", "v1.0")
	if validConfigProviderID("short", cfg) {
		t.Error("short id rejected for registry")
	}
	if validConfigProviderID("abcdefghijklmnopqrstuvwxy", cfg) {
		t.Error("25-char id rejected for registry")
	}
}

func TestValidConfigProviderID_ManagedRejectsNonAlphanumeric(t *testing.T) {
	cfg := validTestConfig("registry", "v1.0")
	for _, bad := range []string{
		"abcdefghijklm-nopqrstuvwx", // hyphen
		"abcdefghijklmnopqrs_tuvwx", // underscore
		"abcdefghijklmnopqr+tuvwx",  // plus
		"abcdefghijklmnopqrstuvwx ", // trailing space
	} {
		if validConfigProviderID(bad, cfg) {
			t.Errorf("non-alphanumeric id %q should be rejected for registry", bad)
		}
	}
}

func TestValidConfigProviderID_UnknownSource(t *testing.T) {
	cfg := validTestConfig("external", "v1.0")
	if validConfigProviderID("abcdefghijklmnopqrstuvwx", cfg) {
		t.Error("unknown source should be rejected")
	}
}

func TestValidConfigProviderID_RegistryRequiresValidBinding(t *testing.T) {
	id := "abcdefghijklmnopqrstuvwx"
	for _, tt := range []struct {
		src, ver string
		want     bool
	}{
		{"registry", "", false},         // missing version
		{"registry", "v1.0", true},
		{"registry", "v1 0", false},     // spaces in version
	} {
		cfg := validTestConfig(tt.src, tt.ver)
		if got := validConfigProviderID(id, cfg); got != tt.want {
			t.Errorf("validConfigProviderID(%q, src=%q, ver=%q) = %v, want %v", id, tt.src, tt.ver, got, tt.want)
		}
	}
}

func TestValidConfigProviderID_LegacyNonEmpty(t *testing.T) {
	cfg := validTestConfig("", "")
	if validConfigProviderID("", cfg) {
		t.Error("empty id rejected for legacy")
	}
}
