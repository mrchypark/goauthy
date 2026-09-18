package identity

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUserValuesConfigResponseDefaultsAndJSON(t *testing.T) {
	response := (UserValuesPolicy{}).ConfigResponse()
	if response.GivenName != "required" || response.FamilyName != "optional" || response.PreferredUsername.Mode != "optional" || !response.PreferredUsername.Immutable || response.PreferredUsername.PatternHTML != defaultPreferredUsernamePatternHTML || response.PreferredUsername.PatternHint != nil || !response.PreferredUsername.EmailFallback {
		t.Fatalf("defaults=%+v", response)
	}
	if response.PreferredUsername.Blacklist == nil || len(response.PreferredUsername.Blacklist) != 3 {
		t.Fatalf("default blacklist=%#v", response.PreferredUsername.Blacklist)
	}
	raw, err := json.Marshal(response)
	if err != nil || !strings.Contains(string(raw), `"pattern_hint":null`) || strings.Contains(string(raw), "regex_rust") {
		t.Fatalf("json=%s err=%v", raw, err)
	}
}

func TestUserValuesConfigResponseConfiguredSnapshot(t *testing.T) {
	policy, err := NewPreferredUsernamePolicy("hidden", `^internal$`, []string{"blocked"})
	if err != nil {
		t.Fatal(err)
	}
	hint := "Use your team name"
	policy = policy.WithImmutable(false)
	policy, err = policy.WithPresentation(`^Team_[0-9]{2}$`, &hint)
	if err != nil {
		t.Fatal(err)
	}
	response := (UserValuesPolicy{GivenName: "optional", FamilyName: "required", PreferredUsername: policy}).ConfigResponse()
	if response.GivenName != "optional" || response.FamilyName != "required" || response.PreferredUsername.Mode != "hidden" || response.PreferredUsername.Immutable || len(response.PreferredUsername.Blacklist) != 1 || response.PreferredUsername.PatternHTML != `^Team_[0-9]{2}$` || response.PreferredUsername.PatternHint == nil || *response.PreferredUsername.PatternHint != hint {
		t.Fatalf("configured=%+v", response)
	}
	hint = "caller mutation"
	response.PreferredUsername.Blacklist[0] = "mutated"
	*response.PreferredUsername.PatternHint = "mutated"
	again := (UserValuesPolicy{PreferredUsername: policy}).ConfigResponse()
	if len(again.PreferredUsername.Blacklist) != 1 || again.PreferredUsername.Blacklist[0] != "blocked" || *again.PreferredUsername.PatternHint != "Use your team name" {
		t.Fatal("config snapshot mutated policy")
	}
}

func TestPreferredUsernamePresentationBounds(t *testing.T) {
	p, err := NewPreferredUsernamePolicy("", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, pattern, hint string }{
		{"pattern too long", strings.Repeat("x", 4097), ""},
		{"pattern invalid utf8", string([]byte{0xff}), ""},
		{"hint too long", "", strings.Repeat("x", 513)},
		{"hint invalid utf8", "", string([]byte{0xff})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hint *string
			if tc.hint != "" {
				hint = &tc.hint
			}
			if _, err := p.WithPresentation(tc.pattern, hint); err != ErrPreferredUsernamePolicy {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
