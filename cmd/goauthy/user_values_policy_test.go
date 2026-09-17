package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/identity"
)

func TestUserValuesPolicyFromEnv(t *testing.T) {
	policy, err := userValuesPolicyFromEnv(func(string) string { return "" })
	if err != nil || policy != (identity.UserValuesPolicy{}) {
		t.Fatalf("default=%+v err=%v", policy, err)
	}
	for _, suffix := range []string{"GIVEN_NAME", "FAMILY_NAME", "BIRTHDATE", "STREET", "ZIP", "CITY", "COUNTRY", "PHONE", "TZ"} {
		key := "GOAUTHY_USER_VALUES_" + suffix
		for _, mode := range []string{"required", "optional", "hidden", "REQUIRED", " required", "false", "secret-invalid-input"} {
			t.Run(suffix+"/"+mode, func(t *testing.T) {
				policy, err := userValuesPolicyFromEnv(func(name string) string {
					if name == key {
						return mode
					}
					return ""
				})
				if mode != "required" && mode != "optional" && mode != "hidden" {
					if err == nil || !strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "secret-invalid-input") {
						t.Fatalf("expected bounded key-specific error, got %v", err)
					}
					return
				}
				fields := map[string]string{"GIVEN_NAME": policy.GivenName, "FAMILY_NAME": policy.FamilyName, "BIRTHDATE": policy.Birthdate, "STREET": policy.Street, "ZIP": policy.ZIP, "CITY": policy.City, "COUNTRY": policy.Country, "PHONE": policy.Phone, "TZ": policy.Timezone}
				if err != nil || fields[suffix] != mode {
					t.Fatalf("policy=%+v err=%v", policy, err)
				}
			})
		}
	}
}

func TestPreferredUsernamePolicyFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name, mode, pattern, blacklist string
		invalid                        bool
	}{{name: "default"}, {name: "custom", mode: "required", pattern: `^Team_[0-9]{2}$`, blacklist: `["team_12"]`},
		{name: "disabled blacklist", blacklist: `[]`}, {name: "bad mode", mode: "secret-invalid", invalid: true},
		{name: "bad regex", pattern: "[secret-invalid", invalid: true}, {name: "bad json", blacklist: "secret-invalid", invalid: true},
		{name: "null list", blacklist: "null", invalid: true}, {name: "null element", blacklist: "[null]", invalid: true}, {name: "wrong element", blacklist: "[1]", invalid: true},
		{name: "trailing value", blacklist: `[] []`, invalid: true}} {
		t.Run(tc.name, func(t *testing.T) {
			settings := map[string]string{"GOAUTHY_USER_VALUES_PREFERRED_USERNAME": tc.mode, "GOAUTHY_USER_VALUES_PREFERRED_USERNAME_REGEX": tc.pattern, "GOAUTHY_USER_VALUES_PREFERRED_USERNAME_BLACKLIST": tc.blacklist}
			policy, err := userValuesPolicyFromEnv(func(k string) string { return settings[k] })
			if tc.invalid {
				if err == nil || strings.Contains(err.Error(), "secret-invalid") {
					t.Fatalf("unsafe or missing config error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			value := "root"
			want := identity.ErrPreferredUsernameUnavailable
			if tc.name == "custom" {
				value = "Team_12"
			}
			if tc.name == "disabled blacklist" {
				want = nil
			}
			if err := policy.PreferredUsername.ValidateRegistration(&value); !errors.Is(err, want) {
				t.Fatalf("policy error=%v want=%v", err, want)
			}
			if tc.name == "custom" {
				if policy.PreferredUsername.ValidateRegistration(nil) == nil {
					t.Fatal("required policy not applied")
				}
				value = "Team_34"
				if err := policy.PreferredUsername.ValidateRegistration(&value); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestPreferredUsernameImmutableFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name, value   string
		want, invalid bool
	}{
		{"default", "", true, false},
		{"true", "true", true, false},
		{"false", "false", false, false},
		{"invalid", "TRUE", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := userValuesPolicyFromEnv(func(key string) string {
				if key == "GOAUTHY_USER_VALUES_PREFERRED_USERNAME_IMMUTABLE" {
					return tc.value
				}
				return ""
			})
			if tc.invalid {
				if err == nil || strings.Contains(err.Error(), "TRUE") {
					t.Fatalf("invalid immutable setting error=%v", err)
				}
				return
			}
			if err != nil || policy.PreferredUsername.Immutable() != tc.want {
				t.Fatalf("policy=%+v err=%v immutable=%v", policy, err, policy.PreferredUsername)
			}
			if tc.value == "" && policy.PreferredUsername != nil {
				t.Fatal("default must preserve nil policy")
			}
		})
	}
}

func TestPreferredUsernamePresentationFromEnv(t *testing.T) {
	settings := map[string]string{
		"GOAUTHY_USER_VALUES_PREFERRED_USERNAME":              "required",
		"GOAUTHY_USER_VALUES_PREFERRED_USERNAME_REGEX":        `^[a-z]+$`,
		"GOAUTHY_USER_VALUES_PREFERRED_USERNAME_BLACKLIST":    `[]`,
		"GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HTML": `[`,
		"GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HINT": "Use lowercase",
		"GOAUTHY_USER_VALUES_PREFERRED_USERNAME_IMMUTABLE":    "false",
	}
	policy, err := userValuesPolicyFromEnv(func(key string) string { return settings[key] })
	if err != nil {
		t.Fatal(err)
	}
	response := policy.ConfigResponse()
	if response.PreferredUsername.PatternHTML != "[" || response.PreferredUsername.PatternHint == nil || *response.PreferredUsername.PatternHint != "Use lowercase" || response.PreferredUsername.Immutable || response.PreferredUsername.Mode != "required" || response.PreferredUsername.Blacklist == nil {
		t.Fatalf("presentation=%+v", response.PreferredUsername)
	}
	for _, tc := range []struct {
		name, key, value string
	}{
		{"pattern oversized", "GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HTML", strings.Repeat("x", 4097)},
		{"pattern invalid utf8", "GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HTML", string([]byte{0xff})},
		{"hint oversized", "GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HINT", strings.Repeat("x", 513)},
		{"hint invalid utf8", "GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HINT", string([]byte{0xff})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := make(map[string]string, len(settings))
			for key, value := range settings {
				copy[key] = value
			}
			copy[tc.key] = tc.value
			if _, err := userValuesPolicyFromEnv(func(key string) string { return copy[key] }); err == nil || strings.Contains(err.Error(), "x") || strings.ContainsRune(err.Error(), '\ufffd') {
				t.Fatalf("expected bounded generic error, got %v", err)
			}
		})
	}
}
