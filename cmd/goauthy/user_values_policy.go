package main

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/identity"
)

func userValuesPolicyFromEnv(getenv func(string) string) (identity.UserValuesPolicy, error) {
	policy := identity.UserValuesPolicy{}
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"GIVEN_NAME", &policy.GivenName}, {"FAMILY_NAME", &policy.FamilyName},
		{"BIRTHDATE", &policy.Birthdate}, {"STREET", &policy.Street},
		{"ZIP", &policy.ZIP}, {"CITY", &policy.City}, {"COUNTRY", &policy.Country},
		{"PHONE", &policy.Phone}, {"TZ", &policy.Timezone},
	} {
		key := "GOAUTHY_USER_VALUES_" + field.name
		*field.value = getenv(key)
		if policy.Validate() != nil {
			return identity.UserValuesPolicy{}, fmt.Errorf("%s must be required, optional or hidden", key)
		}
	}
	mode := getenv("GOAUTHY_USER_VALUES_PREFERRED_USERNAME")
	pattern := getenv("GOAUTHY_USER_VALUES_PREFERRED_USERNAME_REGEX")
	rawBlacklist := getenv("GOAUTHY_USER_VALUES_PREFERRED_USERNAME_BLACKLIST")
	rawImmutable := getenv("GOAUTHY_USER_VALUES_PREFERRED_USERNAME_IMMUTABLE")
	patternHTML := getenv("GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HTML")
	patternHint := getenv("GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HINT")
	rawEmailFallback := getenv("GOAUTHY_USER_VALUES_PREFERRED_USERNAME_EMAIL_FALLBACK")
	if rawEmailFallback != "" && rawEmailFallback != "true" && rawEmailFallback != "false" {
		return identity.UserValuesPolicy{}, fmt.Errorf("GOAUTHY_USER_VALUES_PREFERRED_USERNAME_EMAIL_FALLBACK must be true or false")
	}
	if rawImmutable != "" && rawImmutable != "true" && rawImmutable != "false" {
		return identity.UserValuesPolicy{}, fmt.Errorf("GOAUTHY_USER_VALUES_PREFERRED_USERNAME_IMMUTABLE must be true or false")
	}
	if mode != "" || pattern != "" || rawBlacklist != "" || rawImmutable != "" || patternHTML != "" || patternHint != "" {
		var blacklist []string
		if rawBlacklist != "" {
			// Pointer elements preserve JSON null: []string silently turns it into "".
			var entries []*string
			if len(rawBlacklist) > 65536 || !utf8.ValidString(rawBlacklist) || json.Unmarshal([]byte(rawBlacklist), &entries) != nil || entries == nil {
				return identity.UserValuesPolicy{}, fmt.Errorf("GOAUTHY_USER_VALUES_PREFERRED_USERNAME_BLACKLIST must be a JSON string array")
			}
			blacklist = make([]string, len(entries))
			for i, entry := range entries {
				if entry == nil {
					return identity.UserValuesPolicy{}, fmt.Errorf("GOAUTHY_USER_VALUES_PREFERRED_USERNAME_BLACKLIST must contain only strings")
				}
				blacklist[i] = *entry
			}
		}
		var err error
		policy.PreferredUsername, err = identity.NewPreferredUsernamePolicy(mode, pattern, blacklist)
		if err != nil {
			return identity.UserValuesPolicy{}, fmt.Errorf("invalid GOAUTHY_USER_VALUES_PREFERRED_USERNAME policy settings")
		}
		if rawImmutable == "false" {
			policy.PreferredUsername = policy.PreferredUsername.WithImmutable(false)
		}
		if patternHTML != "" || patternHint != "" {
			var hint *string
			if patternHint != "" {
				hint = &patternHint
			}
			policy.PreferredUsername, err = policy.PreferredUsername.WithPresentation(patternHTML, hint)
			if err != nil {
				return identity.UserValuesPolicy{}, fmt.Errorf("invalid GOAUTHY_USER_VALUES_PREFERRED_USERNAME presentation settings")
			}
		}
	}
	if rawEmailFallback == "false" {
		policy.PreferredUsername = policy.PreferredUsername.WithEmailFallback(false)
	}
	return policy, nil
}
