package oauth

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Forward-auth identity headers are deliberately a closed set. A proxy must
// clear these names before forwarding a request; otherwise a caller could
// smuggle an identity in a duplicate, differently-cased map key.
const (
	ForwardAuthUserHeader              = "X-Forwarded-User"
	ForwardAuthRolesHeader             = "X-Forwarded-User-Roles"
	ForwardAuthGroupsHeader            = "X-Forwarded-User-Groups"
	ForwardAuthEmailHeader             = "X-Forwarded-User-Email"
	ForwardAuthEmailVerifiedHeader     = "X-Forwarded-User-Email-Verified"
	ForwardAuthFamilyNameHeader        = "X-Forwarded-User-Family-Name"
	ForwardAuthGivenNameHeader         = "X-Forwarded-User-Given-Name"
	ForwardAuthMFAHeader               = "X-Forwarded-User-MFA"
	ForwardAuthPreferredUsernameHeader = "X-Forwarded-User-Pref-Username"
)

const (
	maxForwardAuthHeaderValueBytes = 4096
	maxForwardAuthClaimValues      = 64
)

var managedForwardAuthHeaders = [...]string{
	ForwardAuthUserHeader,
	ForwardAuthRolesHeader,
	ForwardAuthGroupsHeader,
	ForwardAuthEmailHeader,
	ForwardAuthEmailVerifiedHeader,
	ForwardAuthFamilyNameHeader,
	ForwardAuthGivenNameHeader,
	ForwardAuthMFAHeader,
	ForwardAuthPreferredUsernameHeader,
}

// ForwardAuthIdentity is the current, already-authenticated end-user view.
// It must be resolved from current identity and authorization state, not from
// an OAuth request snapshot or any inbound HTTP header.
type ForwardAuthIdentity struct {
	Subject       string
	Roles         []string
	Groups        []string
	Email         string
	EmailVerified bool
	FamilyName    string
	GivenName     string
	// MFAEnabled reports account MFA enrollment, not the assurance of this
	// particular request or the method used for its authentication.
	MFAEnabled        bool
	PreferredUsername string
}

// ForwardAuthProfile is the current public profile projection used by the
// forward-auth resolver. Callers should populate it from the identity store.
type ForwardAuthProfile struct {
	Email             string
	EmailVerified     bool
	FamilyName        string
	GivenName         string
	PreferredUsername string
}

// clearForwardAuthHeaders removes every managed identity header, including
// non-canonical map keys. It is safe to call before forwarding an untrusted
// request.
func clearForwardAuthHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	for key := range headers {
		for _, managed := range managedForwardAuthHeaders {
			if strings.EqualFold(key, managed) {
				delete(headers, key)
				break
			}
		}
	}
}

// ApplyForwardAuthHeaders writes only the fixed identity-header allowlist. It
// clears existing values first, so invalid or disabled identities cannot leave
// spoofed values in the response. A validation error is fail-closed and leaves
// all managed headers absent.
func ApplyForwardAuthHeaders(headers http.Header, identity ForwardAuthIdentity, enabled bool) error {
	if headers == nil {
		return errors.New("forward auth headers are nil")
	}
	clearForwardAuthHeaders(headers)
	if !enabled {
		return nil
	}

	values, err := identity.forwardAuthHeaderValues()
	if err != nil {
		return err
	}
	for name, value := range values {
		headers.Set(name, value)
	}
	return nil
}

func (identity ForwardAuthIdentity) forwardAuthHeaderValues() (map[string]string, error) {
	subject, err := canonicalForwardAuthScalar(identity.Subject, true)
	if err != nil {
		return nil, errors.New("invalid forward auth subject")
	}
	roles, err := canonicalForwardAuthList(identity.Roles)
	if err != nil {
		return nil, errors.New("invalid forward auth roles")
	}
	groups, err := canonicalForwardAuthList(identity.Groups)
	if err != nil {
		return nil, errors.New("invalid forward auth groups")
	}
	email, err := canonicalForwardAuthScalar(identity.Email, false)
	if err != nil {
		return nil, errors.New("invalid forward auth email")
	}
	familyName, err := canonicalForwardAuthScalar(identity.FamilyName, false)
	if err != nil {
		return nil, errors.New("invalid forward auth family name")
	}
	givenName, err := canonicalForwardAuthScalar(identity.GivenName, false)
	if err != nil {
		return nil, errors.New("invalid forward auth given name")
	}
	preferredUsername, err := canonicalForwardAuthScalar(identity.PreferredUsername, false)
	if err != nil {
		return nil, errors.New("invalid forward auth preferred username")
	}
	values := map[string]string{
		ForwardAuthUserHeader:          subject,
		ForwardAuthRolesHeader:         strings.Join(roles, ","),
		ForwardAuthGroupsHeader:        strings.Join(groups, ","),
		ForwardAuthEmailHeader:         email,
		ForwardAuthEmailVerifiedHeader: strconv.FormatBool(identity.EmailVerified),
		ForwardAuthFamilyNameHeader:    familyName,
		ForwardAuthGivenNameHeader:     givenName,
		ForwardAuthMFAHeader:           strconv.FormatBool(identity.MFAEnabled),
	}
	// Rauthy emits this optional header only when a preferred username exists.
	if preferredUsername != "" {
		values[ForwardAuthPreferredUsernameHeader] = preferredUsername
	}
	return values, nil
}

func canonicalForwardAuthScalar(value string, required bool) (string, error) {
	if !utf8.ValidString(value) || len(value) > maxForwardAuthHeaderValueBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errors.New("invalid header value")
	}
	value = strings.TrimSpace(value)
	if required && value == "" {
		return "", errors.New("missing header value")
	}
	return value, nil
}

func canonicalForwardAuthList(values []string) ([]string, error) {
	if len(values) > maxForwardAuthClaimValues {
		return nil, errors.New("too many header values")
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value, err := canonicalForwardAuthScalar(value, true)
		if err != nil {
			return nil, err
		}
		// Rauthy uses comma-joined CSV for these headers. Reject the delimiter
		// rather than emitting an ambiguous value a downstream app may parse
		// as a different set of roles/groups.
		if strings.Contains(value, ",") {
			return nil, errors.New("claim contains CSV delimiter")
		}
		result = append(result, value)
	}
	sort.Strings(result)
	// Current claims are sets. Collapse duplicate values so encoding remains
	// deterministic when a resolver returns an accidentally repeated value.
	unique := result[:0]
	for _, value := range result {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	if len(strings.Join(unique, ",")) > maxForwardAuthHeaderValueBytes {
		return nil, errors.New("header value is too large")
	}
	return unique, nil
}
