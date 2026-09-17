package upstreamprovider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// AuthProviderType is the wire and persisted discriminator used by the pinned
// upstream-provider document. Its JSON spelling is lowercase.
type AuthProviderType string

const (
	AuthProviderTypeCustom          AuthProviderType = "custom"
	AuthProviderTypeGitHub          AuthProviderType = "github"
	AuthProviderTypeGoogle          AuthProviderType = "google"
	AuthProviderTypeOIDC            AuthProviderType = "oidc"
	AuthProviderTypeOAuthUserInfo   AuthProviderType = "oauth_userinfo"
)

func (t AuthProviderType) valid() bool {
	switch t {
	case AuthProviderTypeCustom, AuthProviderTypeGitHub, AuthProviderTypeGoogle, AuthProviderTypeOIDC, AuthProviderTypeOAuthUserInfo:
		return true
	default:
		return false
	}
}

// UnmarshalJSON accepts exactly the five lowercase enum values from
// rauthy_api_types::auth_providers::AuthProviderType.
func (t *AuthProviderType) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	next := AuthProviderType(value)
	if !next.valid() {
		return fmt.Errorf("invalid auth provider type %q", value)
	}
	*t = next
	return nil
}

var (
	// These are the pinned v0.36.2 regex constants referenced by the
	// ProviderRequest annotations. RE_URI is deliberately used for client_id
	// too; the source annotation does not use RE_CLIENT_ID there. Rust's
	// regex crate makes \s Unicode-aware, so Go spells that class explicitly.
	providerNamePattern  = regexp.MustCompile(`^[a-zA-Z0-9À-ɏ()\-\x{0009}-\x{000D}\x{0020}\x{0085}\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{3041}-\x{3096}\x{30A0}-\x{30FF}\x{3400}-\x{4DB5}\x{4E00}-\x{9FCB}\x{F900}-\x{FA6A}\x{2E80}-\x{2FD5}\x{FF66}-\x{FF9F}\x{FFA1}-\x{FFDC}\x{31F0}-\x{31FF}]{2,128}$`)
	providerURIpattern   = regexp.MustCompile(`^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%@]+$`)
	providerScopePattern = regexp.MustCompile(`^[a-zA-Z0-9-_/:\x{0009}-\x{000D}\x{0020}\x{0085}\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}*.]{0,512}$`)
)

// ProviderRequest is the pinned v0.36.2 create/update DTO. ID is generated
// by the persisted entity and is therefore intentionally absent here.
type ProviderRequest struct {
	Name                  string           `json:"name"`
	Typ                   AuthProviderType `json:"typ"`
	Enabled               bool             `json:"enabled"`
	Issuer                string           `json:"issuer"`
	AuthorizationEndpoint string           `json:"authorization_endpoint"`
	TokenEndpoint         string           `json:"token_endpoint"`
	UserinfoEndpoint      string           `json:"userinfo_endpoint"`
	JWKS                  *string          `json:"jwks_endpoint"`
	UsePKCE               bool             `json:"use_pkce"`
	ClientSecretBasic     bool             `json:"client_secret_basic"`
	ClientSecretPost      bool             `json:"client_secret_post"`
	AutoOnboarding        bool             `json:"auto_onboarding"`
	AutoLink              bool             `json:"auto_link"`
	ClientID              string           `json:"client_id"`
	ClientSecret          *string          `json:"client_secret"`
	Scope                 string           `json:"scope"`
	AdminClaimPath        *string          `json:"admin_claim_path"`
	AdminClaimValue       *string          `json:"admin_claim_value"`
	MFAClaimPath          *string          `json:"mfa_claim_path"`
	MFAClaimValue         *string          `json:"mfa_claim_value"`
}

// UnmarshalJSON preserves serde's required-versus-Option distinction. Rust
// serde rejects missing or null non-Option fields; optional string fields may
// be omitted or null. Unknown fields remain ignored, as with serde by default.
func (r *ProviderRequest) UnmarshalJSON(data []byte) error {
	type plain ProviderRequest
	var value plain
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{
		"name", "typ", "enabled", "issuer", "authorization_endpoint", "token_endpoint",
		"userinfo_endpoint", "use_pkce", "client_secret_basic", "client_secret_post",
		"auto_onboarding", "auto_link", "client_id", "scope",
	} {
		raw, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("missing required provider field %q", name)
		}
	}
	*r = ProviderRequest(value)
	return nil
}

// Validate applies the regex and length annotations on the pinned
// ProviderRequest. Endpoint reachability and protocol-specific checks belong
// to the endpoint/runtime layer, just as they do in the source API handler.
func (r ProviderRequest) Validate() error {
	if !providerNamePattern.MatchString(r.Name) {
		return invalidProviderField("name")
	}
	if !r.Typ.valid() {
		return invalidProviderField("typ")
	}
	for name, value := range map[string]string{
		"issuer":                 r.Issuer,
		"authorization_endpoint": r.AuthorizationEndpoint,
		"token_endpoint":         r.TokenEndpoint,
		"userinfo_endpoint":      r.UserinfoEndpoint,
		"client_id":              r.ClientID,
	} {
		if !providerURIpattern.MatchString(value) {
			return invalidProviderField(name)
		}
	}
	if r.JWKS != nil && !providerURIpattern.MatchString(*r.JWKS) {
		return invalidProviderField("jwks_endpoint")
	}
	if r.ClientSecret != nil && utf8.RuneCountInString(*r.ClientSecret) > 256 {
		return invalidProviderField("client_secret")
	}
	if !providerScopePattern.MatchString(r.Scope) {
		return invalidProviderField("scope")
	}
	for name, value := range map[string]*string{
		"admin_claim_path":  r.AdminClaimPath,
		"admin_claim_value": r.AdminClaimValue,
		"mfa_claim_path":    r.MFAClaimPath,
		"mfa_claim_value":   r.MFAClaimValue,
	} {
		if value != nil && !providerURIpattern.MatchString(*value) {
			return invalidProviderField(name)
		}
	}
	return nil
}

func invalidProviderField(name string) error {
	return fmt.Errorf("%w: invalid %s", ErrInvalidConfig, name)
}

// Normalize applies AuthProvider::cleanup_scope exactly: split on the
// literal ASCII space, trim each non-empty segment, and join with '+'.
func (r ProviderRequest) Normalize() ProviderRequest {
	r.Scope = normalizeProviderScope(r.Scope)
	return r
}

func (r ProviderRequest) Normalized() ProviderRequest { return r.Normalize() }

func normalizeProviderScope(scope string) string {
	parts := strings.Split(scope, " ")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		out = append(out, strings.TrimSpace(part))
	}
	return strings.Join(out, "+")
}

// ProviderResponse is the pinned v0.36.2 response DTO. The pointer is kept
// exactly as an optional client_secret; the caller decides whether an
// administrative read may populate it.
type ProviderResponse struct {
	ID                    string           `json:"id"`
	Name                  string           `json:"name"`
	Typ                   AuthProviderType `json:"typ"`
	Enabled               bool             `json:"enabled"`
	Issuer                string           `json:"issuer"`
	AuthorizationEndpoint string           `json:"authorization_endpoint"`
	TokenEndpoint         string           `json:"token_endpoint"`
	UserinfoEndpoint      string           `json:"userinfo_endpoint"`
	JWKS                  *string          `json:"jwks_endpoint"`
	ClientID              string           `json:"client_id"`
	ClientSecret          *string          `json:"client_secret"`
	Scope                 string           `json:"scope"`
	AdminClaimPath        *string          `json:"admin_claim_path"`
	AdminClaimValue       *string          `json:"admin_claim_value"`
	MFAClaimPath          *string          `json:"mfa_claim_path"`
	MFAClaimValue         *string          `json:"mfa_claim_value"`
	UsePKCE               bool             `json:"use_pkce"`
	ClientSecretBasic     bool             `json:"client_secret_basic"`
	ClientSecretPost      bool             `json:"client_secret_post"`
	AutoOnboarding        bool             `json:"auto_onboarding"`
	AutoLink              bool             `json:"auto_link"`
}

// ProviderLookupRequest and ProviderLookupResponse mirror the pinned lookup
// DTOs. Endpoint selection is metadata_url first, then issuer.
type ProviderLookupRequest struct {
	Issuer      *string `json:"issuer"`
	MetadataURL *string `json:"metadata_url"`
}

func (r ProviderLookupRequest) Validate() error {
	for name, value := range map[string]*string{"issuer": r.Issuer, "metadata_url": r.MetadataURL} {
		if value != nil && !providerURIpattern.MatchString(*value) {
			return invalidProviderField(name)
		}
	}
	return nil
}

// ValidateForLookup adds the handler-level requirement that at least one
// lookup input is supplied; the DTO's validator itself only validates options.
func (r ProviderLookupRequest) ValidateForLookup() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Issuer == nil && r.MetadataURL == nil {
		return fmt.Errorf("%w: issuer or metadata_url is required", ErrInvalidConfig)
	}
	return nil
}

// ResolveMetadataURL reproduces the pinned lookup endpoint construction without
// performing network I/O.
func (r ProviderLookupRequest) ResolveMetadataURL() (string, error) {
	if err := r.ValidateForLookup(); err != nil {
		return "", err
	}
	if r.MetadataURL != nil {
		return addHTTPS(*r.MetadataURL), nil
	}
	issuer := *r.Issuer
	if strings.HasSuffix(issuer, "/") {
		return addHTTPS(issuer + ".well-known/openid-configuration"), nil
	}
	return addHTTPS(issuer + "/.well-known/openid-configuration"), nil
}

func addHTTPS(value string) string {
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return value
	}
	return "https://" + value
}

type ProviderLookupResponse struct {
	Issuer                string  `json:"issuer"`
	AuthorizationEndpoint string  `json:"authorization_endpoint"`
	TokenEndpoint         string  `json:"token_endpoint"`
	UserinfoEndpoint      string  `json:"userinfo_endpoint"`
	JWKS                  *string `json:"jwks_endpoint"`
	Scope                 string  `json:"scope"`
	UsePKCE               bool    `json:"use_pkce"`
	ClientSecretBasic     bool    `json:"client_secret_basic"`
	ClientSecretPost      bool    `json:"client_secret_post"`
}

type ProviderLinkedUserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// ProviderDocument maps all 21 final auth_providers columns from the pinned
// schema. Secret is opaque ciphertext supplied by the future persistence
// layer; this package neither encrypts it nor turns it into JSON.
type ProviderDocument struct {
	ID                    string           // auth_providers.id
	Enabled               bool             // auth_providers.enabled
	Name                  string           // auth_providers.name
	Typ                   AuthProviderType // auth_providers.typ
	Issuer                string           // auth_providers.issuer
	AuthorizationEndpoint string           // auth_providers.authorization_endpoint
	TokenEndpoint         string           // auth_providers.token_endpoint
	UserinfoEndpoint      string           // auth_providers.userinfo_endpoint
	ClientID              string           // auth_providers.client_id
	Secret                []byte           // auth_providers.secret BLOB (opaque ciphertext)
	Scope                 string           // auth_providers.scope
	AdminClaimPath        *string          // auth_providers.admin_claim_path
	AdminClaimValue       *string          // auth_providers.admin_claim_value
	MFAClaimPath          *string          // auth_providers.mfa_claim_path
	MFAClaimValue         *string          // auth_providers.mfa_claim_value
	UsePKCE               bool             // auth_providers.use_pkce
	ClientSecretBasic     bool             // auth_providers.client_secret_basic
	ClientSecretPost      bool             // auth_providers.client_secret_post
	JWKS                  *string          // auth_providers.jwks_endpoint
	AutoOnboarding        bool             // auth_providers.auto_onboarding
	AutoLink              bool             // auth_providers.auto_link
}

const ProviderPersistedFieldCount = 21

// ToDocument maps a validated request to every persisted field. The caller
// supplies the already-encrypted secret bytes; no encryption is performed.
func (r ProviderRequest) ToDocument(id string, encryptedSecret []byte) (ProviderDocument, error) {
	if id == "" {
		return ProviderDocument{}, fmt.Errorf("%w: empty provider id", ErrInvalidConfig)
	}
	return ProviderDocument{
		ID: id, Enabled: r.Enabled, Name: r.Name, Typ: r.Typ,
		Issuer: r.Issuer, AuthorizationEndpoint: r.AuthorizationEndpoint,
		TokenEndpoint: r.TokenEndpoint, UserinfoEndpoint: r.UserinfoEndpoint,
		ClientID: r.ClientID, Secret: append([]byte(nil), encryptedSecret...), Scope: r.Scope,
		AdminClaimPath: r.AdminClaimPath, AdminClaimValue: r.AdminClaimValue,
		MFAClaimPath: r.MFAClaimPath, MFAClaimValue: r.MFAClaimValue,
		UsePKCE: r.UsePKCE, ClientSecretBasic: r.ClientSecretBasic,
		ClientSecretPost: r.ClientSecretPost, JWKS: r.JWKS,
		AutoOnboarding: r.AutoOnboarding, AutoLink: r.AutoLink,
	}, nil
}

// Response projects a persisted document while leaving client-secret
// disclosure entirely to the caller.
func (d ProviderDocument) Response(clientSecret *string) ProviderResponse {
	return ProviderResponse{
		ID: d.ID, Name: d.Name, Typ: d.Typ, Enabled: d.Enabled,
		Issuer: d.Issuer, AuthorizationEndpoint: d.AuthorizationEndpoint,
		TokenEndpoint: d.TokenEndpoint, UserinfoEndpoint: d.UserinfoEndpoint,
		JWKS: d.JWKS, ClientID: d.ClientID, ClientSecret: clientSecret, Scope: d.Scope,
		AdminClaimPath: d.AdminClaimPath, AdminClaimValue: d.AdminClaimValue,
		MFAClaimPath: d.MFAClaimPath, MFAClaimValue: d.MFAClaimValue,
		UsePKCE: d.UsePKCE, ClientSecretBasic: d.ClientSecretBasic,
		ClientSecretPost: d.ClientSecretPost, AutoOnboarding: d.AutoOnboarding,
		AutoLink: d.AutoLink,
	}
}
