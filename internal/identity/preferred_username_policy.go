package identity

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	ErrPreferredUsername            = errors.New("invalid preferred username")
	ErrPreferredUsernameUnavailable = errors.New("preferred username unavailable")
	ErrPreferredUsernamePolicy      = errors.New("invalid preferred username policy")
)

const defaultPreferredUsernamePattern = `^[a-z][a-z0-9_-]{1,61}$`
const defaultPreferredUsernamePatternHTML = `^[a-z][a-z0-9_\-]{1,61}$`

var defaultPreferredUsernameRegexp = regexp.MustCompile(defaultPreferredUsernamePattern)

// PreferredUsernamePolicy is immutable after construction. A zero value is
// equivalent to the upstream defaults.
type PreferredUsernamePolicy struct {
	mode            string
	pattern         *regexp.Regexp
	blacklist       []string
	mutable         bool
	patternHTML     string
	patternHint     *string
	noEmailFallback bool
}

// NewPreferredUsernamePolicy constructs a bounded preferred-username policy.
// A nil blacklist selects the upstream defaults; a non-nil empty list disables
// the blacklist. Entries are deliberately not normalized, matching upstream.
func NewPreferredUsernamePolicy(mode, pattern string, blacklist []string) (*PreferredUsernamePolicy, error) {
	if mode == "" {
		mode = "optional"
	}
	if mode != "required" && mode != "optional" && mode != "hidden" {
		return nil, ErrPreferredUsernamePolicy
	}
	if pattern == "" {
		pattern = defaultPreferredUsernamePattern
	}
	if len(pattern) > 4096 || !utf8.ValidString(pattern) {
		return nil, ErrPreferredUsernamePolicy
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, ErrPreferredUsernamePolicy
	}
	if blacklist != nil {
		if len(blacklist) > 256 {
			return nil, ErrPreferredUsernamePolicy
		}
		cloned := make([]string, len(blacklist))
		for i, entry := range blacklist {
			if len(entry) > 128 || !utf8.ValidString(entry) {
				return nil, ErrPreferredUsernamePolicy
			}
			cloned[i] = entry
		}
		blacklist = cloned
	}
	return &PreferredUsernamePolicy{mode: mode, pattern: re, blacklist: blacklist, patternHTML: defaultPreferredUsernamePatternHTML}, nil
}

// Immutable reports whether ordinary changes to an existing name are forbidden.
// The upstream default is true, including for nil and zero-value policies.
func (p *PreferredUsernamePolicy) Immutable() bool {
	return p == nil || !p.mutable
}

// WithImmutable returns a copy with the requested immutability setting.
func (p *PreferredUsernamePolicy) WithImmutable(value bool) *PreferredUsernamePolicy {
	var copy PreferredUsernamePolicy
	if p != nil {
		copy = *p
	}
	copy.mutable = !value
	return &copy
}

// EmailFallback uses the upstream default: a missing username falls back to email.
func (p *PreferredUsernamePolicy) EmailFallback() bool {
	return p == nil || !p.noEmailFallback
}

func (p *PreferredUsernamePolicy) WithEmailFallback(value bool) *PreferredUsernamePolicy {
	var result PreferredUsernamePolicy
	if p != nil {
		result = *p
	}
	result.noEmailFallback = !value
	return &result
}

// WithPresentation returns a copy with the browser-facing pattern and hint.
// These values are intentionally separate from the server validation regex.
func (p *PreferredUsernamePolicy) WithPresentation(patternHTML string, hint *string) (*PreferredUsernamePolicy, error) {
	var result PreferredUsernamePolicy
	if p != nil {
		result = *p
	}
	if patternHTML == "" {
		patternHTML = defaultPreferredUsernamePatternHTML
	}
	if len(patternHTML) > 4096 || !utf8.ValidString(patternHTML) {
		return nil, ErrPreferredUsernamePolicy
	}
	if hint != nil && (len(*hint) > 512 || !utf8.ValidString(*hint)) {
		return nil, ErrPreferredUsernamePolicy
	}
	result.patternHTML = patternHTML
	result.patternHint = nil
	if hint != nil {
		value := *hint
		result.patternHint = &value
	}
	return &result, nil
}

func (p *PreferredUsernamePolicy) effective() (mode string, pattern *regexp.Regexp, blacklist []string) {
	if p == nil {
		return "optional", defaultPreferredUsernameRegexp, []string{"admin", "administrator", "root"}
	}
	mode, pattern, blacklist = p.mode, p.pattern, p.blacklist
	if mode == "" {
		mode = "optional"
	}
	if pattern == nil {
		pattern = defaultPreferredUsernameRegexp
	}
	if blacklist == nil {
		blacklist = []string{"admin", "administrator", "root"}
	}
	return
}

// ValidateSyntax validates every supplied value, including an empty string.
// Missing values alone are exempt from the DTO's regex check.
func (p *PreferredUsernamePolicy) ValidateSyntax(value *string) error {
	if value == nil {
		return nil
	}
	_, pattern, _ := p.effective()
	if len(*value) > 128 || !utf8.ValidString(*value) || !pattern.MatchString(*value) {
		return ErrPreferredUsername
	}
	return nil
}

// ValidateRegistration applies syntax, required-mode, and blacklist checks.
func (p *PreferredUsernamePolicy) ValidateRegistration(value *string) error {
	if err := p.ValidateSyntax(value); err != nil {
		return err
	}
	mode, _, blacklist := p.effective()
	if value == nil || *value == "" {
		if mode == "required" {
			return ErrPreferredUsername
		}
		return nil
	}
	lower := strings.ToLower(*value)
	for _, entry := range blacklist {
		if lower == entry {
			return ErrPreferredUsernameUnavailable
		}
	}
	return nil
}
