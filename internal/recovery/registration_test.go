package recovery

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/identity"
)

func TestRegistrationConfigValidate(t *testing.T) {
	t.Parallel()
	validator := ExactRedirectURIs([]string{"https://app.example.test/registered"})
	for _, test := range []struct {
		name   string
		config RegistrationConfig
		want   error
	}{
		{"valid allow", RegistrationConfig{AllowedDomains: []string{"example.test"}, RedirectValidator: validator}, nil},
		{"valid blacklist", RegistrationConfig{BlacklistedDomains: []string{"evil.test"}, RedirectValidator: validator}, nil},
		{"both lists", RegistrationConfig{AllowedDomains: []string{"example.test"}, BlacklistedDomains: []string{"evil.test"}, RedirectValidator: validator}, ErrRegistrationConfig},
		{"missing callback", RegistrationConfig{}, ErrRegistrationConfig},
		{"non canonical domain", RegistrationConfig{AllowedDomains: []string{"Example.test"}, RedirectValidator: validator}, ErrRegistrationConfig},
		{"duplicate domain", RegistrationConfig{AllowedDomains: []string{"example.test", "example.test"}, RedirectValidator: validator}, ErrRegistrationConfig},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.config.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRegistrationValidateRequest(t *testing.T) {
	t.Parallel()
	name := func(value string) *string { return &value }
	config := RegistrationConfig{Enabled: true, AllowedDomains: []string{"example.test"}, RedirectValidator: ExactRedirectURIs([]string{"https://app.example.test/registered"})}
	valid := RegistrationRequest{Email: "Alice@Example.Test", PreferredUsername: name("alice_user"), FamilyName: "O'Neil", GivenName: "Alice", UserValues: &UserValues{Birthdate: "2000-01-02", Phone: "+82101234", Timezone: "Asia/Seoul"}, ProofOfWork: "1:10:123:abcdefghijklmnop:abcdefghijklmnop:1", RedirectURI: "https://app.example.test/registered"}
	got, err := config.ValidateRequest(valid)
	if err != nil || got.Email != "alice@example.test" {
		t.Fatalf("ValidateRequest() = %#v, %v", got, err)
	}

	for _, test := range []struct {
		name    string
		request RegistrationRequest
		config  RegistrationConfig
		want    error
	}{
		{"disabled", valid, RegistrationConfig{AllowedDomains: config.AllowedDomains, RedirectValidator: config.RedirectValidator}, ErrRegistrationDisabled},
		{"suffix is not allow", RegistrationRequest{Email: "a@evil-example.test", ProofOfWork: valid.ProofOfWork}, config, ErrRegistrationRequest},
		{"suffix is not blacklist", RegistrationRequest{Email: "a@evil-example.test", ProofOfWork: valid.ProofOfWork}, RegistrationConfig{Enabled: true, BlacklistedDomains: []string{"example.test"}, RedirectValidator: config.RedirectValidator}, nil},
		{"blacklisted exact", RegistrationRequest{Email: "a@example.test", ProofOfWork: valid.ProofOfWork}, RegistrationConfig{Enabled: true, BlacklistedDomains: []string{"example.test"}, RedirectValidator: config.RedirectValidator}, ErrRegistrationRequest},
		{"display email", RegistrationRequest{Email: "Alice <alice@example.test>", ProofOfWork: valid.ProofOfWork}, config, ErrRegistrationRequest},
		{"control in name", RegistrationRequest{Email: "a@example.test", PreferredUsername: name("a\n"), ProofOfWork: valid.ProofOfWork}, config, ErrRegistrationRequest},
		{"oversized user value", RegistrationRequest{Email: "a@example.test", UserValues: &UserValues{City: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, ProofOfWork: valid.ProofOfWork}, config, ErrRegistrationRequest},
		{"empty proof", RegistrationRequest{Email: "a@example.test"}, config, ErrRegistrationRequest},
		{"unregistered exact redirect", RegistrationRequest{Email: "a@example.test", ProofOfWork: valid.ProofOfWork, RedirectURI: "https://app.example.test/registered/extra"}, config, ErrRegistrationRequest},
		{"relative redirect", RegistrationRequest{Email: "a@example.test", ProofOfWork: valid.ProofOfWork, RedirectURI: "/registered"}, config, ErrRegistrationRequest},
		{"empty redirect host", RegistrationRequest{Email: "a@example.test", ProofOfWork: valid.ProofOfWork, RedirectURI: "https://:443/registered"}, config, ErrRegistrationRequest},
		{"userinfo redirect", RegistrationRequest{Email: "a@example.test", ProofOfWork: valid.ProofOfWork, RedirectURI: "https://attacker@app.example.test/registered"}, config, ErrRegistrationRequest},
		{"fragment redirect", RegistrationRequest{Email: "a@example.test", ProofOfWork: valid.ProofOfWork, RedirectURI: "https://app.example.test/registered#x"}, config, ErrRegistrationRequest},
		{"http disabled", RegistrationRequest{Email: "a@example.test", ProofOfWork: valid.ProofOfWork, RedirectURI: "http://app.example.test/registered"}, config, ErrRegistrationRequest},
		{"CRLF redirect", RegistrationRequest{Email: "a@example.test", ProofOfWork: valid.ProofOfWork, RedirectURI: "https://app.example.test/registered\r\nLocation:https://evil.test"}, config, ErrRegistrationRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.request.GivenName = "Alice"
			_, err := test.config.ValidateRequest(test.request)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateRequest() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRegistrationRedirectAllowsConfiguredHTTPExactly(t *testing.T) {
	t.Parallel()
	config := RegistrationConfig{Enabled: true, AllowHTTPRedirectURI: true, RedirectValidator: ExactRedirectURIs([]string{"http://localhost:8080/callback"})}
	_, err := config.ValidateRequest(RegistrationRequest{Email: "a@example.test", GivenName: "Alice", ProofOfWork: "proof", RedirectURI: "http://localhost:8080/callback"})
	if err != nil {
		t.Fatalf("configured HTTP redirect rejected: %v", err)
	}
}

func TestRegistrationUserValuesPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		policy        identity.UserValuesPolicy
		given, family string
		values        *UserValues
		want          error
	}{
		{"default missing given name", identity.UserValuesPolicy{}, "", "", nil, ErrRegistrationRequest},
		{"optional names", identity.UserValuesPolicy{GivenName: "optional"}, "", "", nil, nil},
		{"hidden accepts submitted names", identity.UserValuesPolicy{GivenName: "hidden", FamilyName: "hidden"}, "Alice", "Kim", nil, nil},
		{"hidden still validates syntax", identity.UserValuesPolicy{GivenName: "hidden"}, "Alice\n", "", nil, ErrRegistrationRequest},
		{"family missing", identity.UserValuesPolicy{FamilyName: "required"}, "Alice", "", nil, ErrRegistrationRequest},
		{"city absent object exemption", identity.UserValuesPolicy{City: "required"}, "Alice", "", nil, nil},
		{"city missing in object", identity.UserValuesPolicy{City: "required"}, "Alice", "", &UserValues{}, ErrRegistrationRequest},
		{"city supplied", identity.UserValuesPolicy{City: "required"}, "Alice", "", &UserValues{City: "Seoul"}, nil},
		{"bad config", identity.UserValuesPolicy{Phone: "typo"}, "Alice", "", nil, ErrRegistrationConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := RegistrationConfig{Enabled: true, RedirectValidator: ExactRedirectURIs(nil), UserValuesPolicy: tc.policy}
			_, err := c.ValidateRequest(RegistrationRequest{Email: "alice@example.test", GivenName: tc.given, FamilyName: tc.family, UserValues: tc.values, ProofOfWork: "proof"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
