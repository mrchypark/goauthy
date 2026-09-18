package main

import (
	"reflect"
	"testing"

	"github.com/mrchypark/goauthy/internal/identity"
)

func TestOIDCProfileMappingAndEmailFallback(t *testing.T) {
	email, given, family := "member@example.test", "Ada", "Lovelace"
	street, zip, city, country := "Main Street", "12345", "London", "GB"
	phone, locale := "+44123456789", "en"
	p := identity.ProfileClaims{Email: &email, GivenName: &given, FamilyName: &family,
		Street: &street, ZIP: &zip, City: &city, Country: &country, Phone: &phone, Language: &locale}
	got := oidcProfileClaims(p, true)
	wantAddress := map[string]string{"formatted": "Ada Lovelace\nMain Street\n12345, London\nGB\n", "street_address": street, "postal_code": zip, "locality": city, "country": country}
	if got.PreferredUsername == nil || *got.PreferredUsername != email || !reflect.DeepEqual(got.Address, wantAddress) || got.PhoneNumberVerified == nil || *got.PhoneNumberVerified || got.Locale == nil || *got.Locale != locale {
		t.Fatalf("profile projection mismatch: %#v", got)
	}
	if got := oidcProfileClaims(p, false); got.PreferredUsername != nil {
		t.Fatal("disabled email fallback exposed a username")
	}
	username := "ada"
	p.PreferredUsername = &username
	if got := oidcProfileClaims(p, true); *got.PreferredUsername != username {
		t.Fatal("fallback replaced an explicit username")
	}
	if got := oidcProfileClaims(identity.ProfileClaims{City: &city}, true); got.Address != nil || got.PreferredUsername != nil || got.PhoneNumberVerified != nil {
		t.Fatal("missing profile data was fabricated")
	}
}

func TestPreferredUsernameEmailFallbackConfiguration(t *testing.T) {
	for _, raw := range []string{"", "true", "false", "TRUE", "0", " false "} {
		t.Run(raw, func(t *testing.T) {
			p, err := userValuesPolicyFromEnv(func(key string) string {
				if key == "GOAUTHY_USER_VALUES_PREFERRED_USERNAME_EMAIL_FALLBACK" {
					return raw
				}
				return ""
			})
			valid := raw == "" || raw == "true" || raw == "false"
			if (err == nil) != valid {
				t.Fatalf("unexpected config error: %v", err)
			}
			if valid && (p.PreferredUsername.EmailFallback() != (raw != "false") || p.ConfigResponse().PreferredUsername.EmailFallback != (raw != "false")) {
				t.Fatal("config response and runtime policy disagree")
			}
		})
	}
	var original *identity.PreferredUsernamePolicy
	changed := original.WithEmailFallback(false)
	if !original.EmailFallback() || changed.EmailFallback() || !changed.Immutable() {
		t.Fatal("copy configuration changed defaults")
	}
}
