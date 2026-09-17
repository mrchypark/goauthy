package main

import (
	"strings"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
)

// Scope filtering stays in oauth; this adapter contains only the upstream
// profile projection and preferred-username presentation policy.
func oidcProfileClaims(p identity.ProfileClaims, emailFallback bool) oidc.ProfileClaims {
	out := oidc.ProfileClaims{
		Email: p.Email, EmailVerified: p.EmailVerified, PreferredUsername: p.PreferredUsername,
		GivenName: p.GivenName, FamilyName: p.FamilyName, Birthdate: p.Birthdate,
		PhoneNumber: p.Phone, Zoneinfo: p.Timezone, Locale: p.Language,
	}
	if out.PreferredUsername == nil && emailFallback {
		out.PreferredUsername = p.Email
	}
	if p.Phone != nil {
		verified := false // No SMS verification provider, matching Rauthy.
		out.PhoneNumberVerified = &verified
	}
	// Rauthy AddressClaim::try_build includes locality only alongside ZIP.
	if p.Street != nil || p.ZIP != nil || p.Country != nil {
		out.Address = make(map[string]string)
		var formatted strings.Builder
		if p.GivenName != nil {
			formatted.WriteString(*p.GivenName)
		}
		if p.FamilyName != nil {
			formatted.WriteString(" " + *p.FamilyName)
		}
		formatted.WriteByte('\n')
		if p.Street != nil {
			out.Address["street_address"] = *p.Street
			formatted.WriteString(*p.Street + "\n")
		}
		if p.ZIP != nil {
			out.Address["postal_code"] = *p.ZIP
			formatted.WriteString(*p.ZIP)
			if p.City != nil {
				out.Address["locality"] = *p.City
				formatted.WriteString(", " + *p.City)
			}
			formatted.WriteByte('\n')
		}
		if p.Country != nil {
			out.Address["country"] = *p.Country
			formatted.WriteString(*p.Country + "\n")
		}
		out.Address["formatted"] = formatted.String()
	}
	return out
}
