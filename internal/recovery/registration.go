package recovery

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/captcha"
	"github.com/mrchypark/goauthy/internal/identity"
)

const (
	registrationFieldLimit = 2048
	registrationNameLimit  = 32
	registrationValueLimit = 48
)

var (
	ErrRegistrationDisabled = errors.New("open registration is disabled")
	ErrRegistrationConfig   = errors.New("invalid open registration configuration")
	ErrRegistrationRequest  = errors.New("invalid open registration request")
	registrationBirthdate   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	registrationPhone       = regexp.MustCompile(`^\+[0-9]{0,32}$`)
	registrationZIP         = regexp.MustCompile(`^[A-Za-z0-9]{0,24}$`)
)

// RedirectValidator must accept only an exact, already-safe URI. It is kept
// separate from URL parsing so the HTTP/service layer can use its current
// client-contact-URI lookup without inheriting any prefix/suffix matching.
type RedirectValidator func(string) bool

// ExactRedirectURIs returns the minimal safe validator for fixed redirect
// values. It deliberately compares the original strings, not URL prefixes.
func ExactRedirectURIs(values []string) RedirectValidator {
	allowed := make(map[string]struct{}, len(values))
	for _, value := range values {
		allowed[value] = struct{}{}
	}
	return func(value string) bool {
		_, ok := allowed[value]
		return ok
	}
}

// RegistrationConfig is the pure policy for Rauthy's opt-in public
// registration endpoint. Domain entries must be canonical lower-case DNS
// names; allowing and blacklisting domains together is ambiguous and refused.
type RegistrationConfig struct {
	Enabled              bool
	PasskeyEnabled       bool
	AllowedDomains       []string
	BlacklistedDomains   []string
	AllowHTTPRedirectURI bool
	RedirectValidator    RedirectValidator
	UserValuesPolicy     identity.UserValuesPolicy
}

// UserValues is the public registration subset of Rauthy's user_values
// request. The later persistence slice decides which configured attributes it
// accepts; this type only bounds the request before that lookup.
type UserValues struct {
	Birthdate string `json:"birthdate,omitempty"`
	Phone     string `json:"phone,omitempty"`
	Street    string `json:"street,omitempty"`
	ZIP       string `json:"zip,omitempty"`
	City      string `json:"city,omitempty"`
	Country   string `json:"country,omitempty"`
	Timezone  string `json:"tz,omitempty"`
}

// RegistrationRequest mirrors Rauthy v0.36.2's public registration payload.
type RegistrationRequest struct {
	Email             string      `json:"email"`
	PreferredUsername *string     `json:"preferred_username,omitempty"`
	FamilyName        string      `json:"family_name,omitempty"`
	GivenName         string      `json:"given_name,omitempty"`
	UserValues        *UserValues `json:"user_values,omitempty"`
	ProofOfWork       string      `json:"pow"`
	RedirectURI       string      `json:"redirect_uri,omitempty"`
	CaptchaResponse   string      `json:"captcha_response,omitempty"`
}

type CaptchaVerifier = captcha.Verifier

// Validate rejects malformed policy rather than silently broadening it.
func (c RegistrationConfig) Validate() error {
	if len(c.AllowedDomains) != 0 && len(c.BlacklistedDomains) != 0 || c.RedirectValidator == nil || c.UserValuesPolicy.Validate() != nil {
		return ErrRegistrationConfig
	}
	if err := validateDomains(c.AllowedDomains); err != nil {
		return err
	}
	return validateDomains(c.BlacklistedDomains)
}

// ValidateRequest returns a canonical copy suitable for the later service
// layer. It intentionally does no PoW, database, delivery, or account work.
func (c RegistrationConfig) ValidateRequest(request RegistrationRequest) (RegistrationRequest, error) {
	if err := c.Validate(); err != nil {
		return RegistrationRequest{}, err
	}
	if !c.Enabled {
		return RegistrationRequest{}, ErrRegistrationDisabled
	}
	email, domain, err := registrationEmail(request.Email)
	if err != nil || !c.domainAllowed(domain) || c.UserValuesPolicy.PreferredUsername.ValidateSyntax(request.PreferredUsername) != nil || !validRegistrationName(request.FamilyName) || !validRegistrationName(request.GivenName) || !validRegistrationValue(request.ProofOfWork, registrationFieldLimit) || !validUserValues(request.UserValues) {
		return RegistrationRequest{}, ErrRegistrationRequest
	}
	if c.UserValuesPolicy.ValidateFields(&request.GivenName, &request.FamilyName, nil) != nil {
		return RegistrationRequest{}, ErrRegistrationRequest
	}
	if err := c.UserValuesPolicy.PreferredUsername.ValidateRegistration(request.PreferredUsername); err != nil {
		if errors.Is(err, identity.ErrPreferredUsernameUnavailable) {
			return RegistrationRequest{}, err
		}
		return RegistrationRequest{}, ErrRegistrationRequest
	}
	var values *identity.UserValuesRequest
	if v := request.UserValues; v != nil {
		values = &identity.UserValuesRequest{Birthdate: &v.Birthdate, Phone: &v.Phone,
			Street: &v.Street, ZIP: &v.ZIP, City: &v.City, Country: &v.Country, Timezone: &v.Timezone}
	}
	if c.UserValuesPolicy.ValidateFields(&request.GivenName, &request.FamilyName, values) != nil {
		return RegistrationRequest{}, ErrRegistrationRequest
	}
	if request.RedirectURI != "" && !safeRedirectURI(request.RedirectURI, c.AllowHTTPRedirectURI, c.RedirectValidator) {
		return RegistrationRequest{}, ErrRegistrationRequest
	}
	request.Email = email
	return request, nil
}

func (c RegistrationConfig) domainAllowed(domain string) bool {
	if len(c.AllowedDomains) != 0 {
		return contains(c.AllowedDomains, domain)
	}
	return !contains(c.BlacklistedDomains, domain)
}

func validateDomains(domains []string) error {
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		if !validDomain(domain) {
			return ErrRegistrationConfig
		}
		if _, duplicate := seen[domain]; duplicate {
			return ErrRegistrationConfig
		}
		seen[domain] = struct{}{}
	}
	return nil
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func registrationEmail(value string) (string, string, error) {
	canonical, err := identity.CanonicalEmail(value)
	if err != nil {
		return "", "", ErrRegistrationRequest
	}
	at := strings.LastIndexByte(canonical, '@')
	if at <= 0 || at == len(canonical)-1 || !validDomain(canonical[at+1:]) {
		return "", "", ErrRegistrationRequest
	}
	return canonical, canonical[at+1:], nil
}

func validDomain(value string) bool {
	if len(value) == 0 || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func safeRedirectURI(raw string, allowHTTP bool, validate RedirectValidator) bool {
	if len(raw) > registrationFieldLimit || strings.ContainsAny(raw, "\r\n") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && (!allowHTTP || u.Scheme != "http")) {
		return false
	}
	if port := u.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return false
		}
	}
	return validate(raw)
}

func validRegistrationName(value string) bool {
	if value == "" {
		return true
	}
	if !validRegistrationValue(value, registrationNameLimit) {
		return false
	}
	for _, r := range value {
		if !(unicode.IsLetter(r) || unicode.IsNumber(r) || r == '-' || r == '\'' || unicode.IsSpace(r)) {
			return false
		}
	}
	return true
}

func validUserValues(values *UserValues) bool {
	if values == nil {
		return true
	}
	return (values.Birthdate == "" || registrationBirthdate.MatchString(values.Birthdate)) &&
		(values.Phone == "" || registrationPhone.MatchString(values.Phone)) &&
		validOptionalRegistrationValue(values.Street, registrationValueLimit) &&
		(values.ZIP == "" || registrationZIP.MatchString(values.ZIP)) &&
		validOptionalRegistrationValue(values.City, registrationValueLimit) &&
		validOptionalRegistrationValue(values.Country, registrationValueLimit) &&
		validOptionalRegistrationValue(values.Timezone, registrationValueLimit)
}

func validRegistrationValue(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && utf8.RuneCountInString(value) <= limit && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validOptionalRegistrationValue(value string, limit int) bool {
	return value == "" || validRegistrationValue(value, limit)
}

func validateCaptcha(ctx context.Context, v CaptchaVerifier, response, remoteIP string) error {
	if v == nil || v.SiteKey() == "" {
		return nil
	}
	ok, err := v.Verify(ctx, response, remoteIP)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRegistrationRequest
	}
	return nil
}
