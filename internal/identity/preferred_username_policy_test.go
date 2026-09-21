package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestPreferredUsernamePolicyDefaultsAndModes(t *testing.T) {
	t.Parallel()
	short, boundary := "ab", strings.Repeat("a", 62)
	tooLong := strings.Repeat("a", 63)
	for _, tc := range []struct {
		name  string
		mode  string
		value *string
		want  error
	}{
		{"default missing", "", nil, nil},
		{"default short boundary", "", &short, nil},
		{"default max boundary", "", &boundary, nil},
		{"default too long", "", &tooLong, ErrPreferredUsername},
		{"required missing", "required", nil, ErrPreferredUsername},
		{"required empty", "required", ptr(""), ErrPreferredUsername},
		{"optional empty", "optional", ptr(""), ErrPreferredUsername},
		{"one character", "", ptr("a"), ErrPreferredUsername},
		{"uppercase", "", ptr("Alice"), ErrPreferredUsername},
		{"dot", "", ptr("alice.name"), ErrPreferredUsername},
		{"digit first", "", ptr("1alice"), ErrPreferredUsername},
		{"underscore and terminal dash", "", ptr("alice_name-"), nil},
		{"hidden supplied", "hidden", ptr("alice"), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPreferredUsernamePolicy(tc.mode, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.ValidateRegistration(tc.value); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
	if err := (*PreferredUsernamePolicy)(nil).ValidateRegistration(&boundary); err != nil {
		t.Fatalf("nil receiver default rejected valid value: %v", err)
	}
	var zero PreferredUsernamePolicy
	if err := zero.ValidateRegistration(&boundary); err != nil {
		t.Fatalf("zero value default rejected valid value: %v", err)
	}
	if !(*PreferredUsernamePolicy)(nil).Immutable() || !zero.Immutable() {
		t.Fatal("nil and zero policies must default to immutable")
	}
	mutable := zero.WithImmutable(false)
	if mutable.Immutable() || !zero.Immutable() {
		t.Fatal("WithImmutable mutated the original policy")
	}
	if !mutable.WithImmutable(true).Immutable() {
		t.Fatal("WithImmutable(true) was not applied")
	}
	if (*PreferredUsernamePolicy)(nil).WithImmutable(false).Immutable() {
		t.Fatal("nil WithImmutable(false) was not applied")
	}
	disabled, err := NewPreferredUsernamePolicy("optional", "", []string{})
	if err != nil {
		t.Fatal(err)
	}
	name := "admin"
	for _, variant := range []*PreferredUsernamePolicy{disabled.WithImmutable(false), disabled.WithImmutable(true)} {
		if err := variant.ValidateRegistration(&name); err != nil {
			t.Fatalf("explicit empty blacklist was restored by WithImmutable: %v", err)
		}
	}
}

func TestPreferredUsernamePolicySyntaxAndAdminExemption(t *testing.T) {
	t.Parallel()
	reserved := "admin"
	if err := (*PreferredUsernamePolicy)(nil).ValidateSyntax(&reserved); err != nil {
		t.Fatalf("syntax should not apply blacklist: %v", err)
	}
	if err := (*PreferredUsernamePolicy)(nil).ValidateRegistration(&reserved); !errors.Is(err, ErrPreferredUsernameUnavailable) {
		t.Fatalf("registration error = %v, want unavailable", err)
	}
	custom, err := NewPreferredUsernamePolicy("required", `^x[0-9]+$`, []string{"taken"})
	if err != nil {
		t.Fatal(err)
	}
	if err := custom.ValidateSyntax(nil); err != nil {
		t.Fatalf("required policy must exempt admin POST absence: %v", err)
	}
	if err := custom.ValidateSyntax(ptr("x12")); err != nil {
		t.Fatalf("syntax rejected custom valid value: %v", err)
	}
	if err := custom.ValidateRegistration(ptr("x12")); err != nil {
		t.Fatalf("custom valid value rejected: %v", err)
	}
	if err := custom.ValidateRegistration(ptr("taken")); !errors.Is(err, ErrPreferredUsername) {
		t.Fatalf("blacklisted custom value syntax error = %v, want syntax error", err)
	}
	if err := custom.ValidateRegistration(ptr("x123")); err != nil {
		t.Fatalf("custom valid value rejected: %v", err)
	}
	blacklisted := "x12"
	custom, err = NewPreferredUsernamePolicy("required", `^x[0-9]+$`, []string{"x12"})
	if err != nil {
		t.Fatal(err)
	}
	if err := custom.ValidateRegistration(&blacklisted); !errors.Is(err, ErrPreferredUsernameUnavailable) {
		t.Fatalf("error = %v, want unavailable", err)
	}
	if err := custom.ValidateRegistration(ptr("X12")); !errors.Is(err, ErrPreferredUsername) {
		t.Fatalf("custom syntax error = %v, want invalid", err)
	}
}

func TestPreferredUsernamePolicyConfigBoundsAndClone(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, mode, pattern string
		blacklist           []string
	}{
		{"bad mode", "REQUIRED", "", nil},
		{"bad regex", "optional", "[", nil},
		{"regex too large", "optional", strings.Repeat("x", 4097), nil},
		{"regex invalid utf8", "optional", string([]byte{0xff}), nil},
		{"blacklist too many", "optional", "", make([]string, 257)},
		{"blacklist entry too large", "optional", "", []string{strings.Repeat("x", 129)}},
		{"blacklist invalid utf8", "optional", "", []string{string([]byte{0xff})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPreferredUsernamePolicy(tc.mode, tc.pattern, tc.blacklist); !errors.Is(err, ErrPreferredUsernamePolicy) {
				t.Fatalf("error = %v, want invalid policy", err)
			}
		})
	}
	list := []string{"taken"}
	p, err := NewPreferredUsernamePolicy("optional", "", list)
	if err != nil {
		t.Fatal(err)
	}
	list[0] = "changed"
	if err := p.ValidateRegistration(ptr("taken")); !errors.Is(err, ErrPreferredUsernameUnavailable) {
		t.Fatalf("blacklist clone changed after caller mutation: %v", err)
	}
	disabled, err := NewPreferredUsernamePolicy("optional", "", []string{})
	if err != nil {
		t.Fatal(err)
	}
	if err := disabled.ValidateRegistration(ptr("admin")); err != nil {
		t.Fatal("explicit empty blacklist did not disable defaults")
	}
	if err := p.ValidateRegistration(ptr("admin")); err != nil {
		t.Fatalf("custom blacklist should replace defaults: %v", err)
	}
	invalid := string([]byte{0xff})
	if err := p.ValidateSyntax(&invalid); !errors.Is(err, ErrPreferredUsername) {
		t.Fatalf("invalid UTF-8 value error = %v, want invalid preferred username", err)
	}
}

func ptr(v string) *string { return &v }

func TestPreferredUsernamePolicyBlacklistCase(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		entry string
		want  error
	}{{"taken", ErrPreferredUsernameUnavailable}, {"Taken", nil}} {
		p, err := NewPreferredUsernamePolicy("hidden", `^[A-Za-z]+$`, []string{tc.entry})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.ValidateRegistration(ptr("TAKEN")); !errors.Is(err, tc.want) {
			t.Fatalf("entry=%q got=%v want=%v", tc.entry, err, tc.want)
		}
	}
}
