package identity

// UserValuesConfigResponse is the public configuration projection used by
// registration and profile editors. Internal validation regexes are omitted.
type UserValuesConfigResponse struct {
	GivenName             string                          `json:"given_name"`
	FamilyName            string                          `json:"family_name"`
	Birthdate             string                          `json:"birthdate"`
	Street                string                          `json:"street"`
	ZIP                   string                          `json:"zip"`
	City                  string                          `json:"city"`
	Country               string                          `json:"country"`
	Phone                 string                          `json:"phone"`
	Timezone              string                          `json:"tz"`
	RevalidateDuringLogin bool                            `json:"revalidate_during_login"`
	PreferredUsername     PreferredUsernameConfigResponse `json:"preferred_username"`
}

type PreferredUsernameConfigResponse struct {
	Mode          string   `json:"preferred_username"`
	Immutable     bool     `json:"immutable"`
	Blacklist     []string `json:"blacklist"`
	PatternHTML   string   `json:"pattern_html"`
	PatternHint   *string  `json:"pattern_hint"`
	EmailFallback bool     `json:"email_fallback"`
}

// ConfigResponse returns a detached public snapshot of this policy.
func (p UserValuesPolicy) ConfigResponse() UserValuesConfigResponse {
	preferred := p.PreferredUsername
	mode, _, blacklist := preferred.effective()
	patternHTML := defaultPreferredUsernamePatternHTML
	var hint *string
	immutable := preferred.Immutable()
	if preferred != nil {
		if preferred.patternHTML != "" {
			patternHTML = preferred.patternHTML
		}
		if preferred.patternHint != nil {
			value := *preferred.patternHint
			hint = &value
		}
		if preferred.blacklist != nil {
			blacklist = make([]string, len(preferred.blacklist))
			copy(blacklist, preferred.blacklist)
		}
	}
	return UserValuesConfigResponse{
		GivenName: userValueModeOrDefault(p.GivenName, true), FamilyName: userValueModeOrDefault(p.FamilyName, false),
		Birthdate: userValueModeOrDefault(p.Birthdate, false), Street: userValueModeOrDefault(p.Street, false),
		ZIP: userValueModeOrDefault(p.ZIP, false), City: userValueModeOrDefault(p.City, false),
		Country: userValueModeOrDefault(p.Country, false), Phone: userValueModeOrDefault(p.Phone, false),
		RevalidateDuringLogin: p.RevalidateDuringLogin,
		Timezone:              userValueModeOrDefault(p.Timezone, false), PreferredUsername: PreferredUsernameConfigResponse{
			Mode: mode, Immutable: immutable, Blacklist: blacklist, PatternHTML: patternHTML,
			PatternHint: hint, EmailFallback: preferred.EmailFallback(),
		},
	}
}

func userValueModeOrDefault(mode string, required bool) string {
	if mode == "" {
		if required {
			return "required"
		}
		return "optional"
	}
	return mode
}
