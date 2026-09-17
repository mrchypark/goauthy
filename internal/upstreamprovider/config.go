package upstreamprovider

import (
	"net/url"
	"strings"
)

// ProviderKind identifies the upstream protocol used by a provider.
type ProviderKind string

const (
	// ProviderKindOIDC is the default kind for backwards-compatible configs.
	ProviderKindOIDC ProviderKind = "oidc"
	// ProviderKindGitHub is GitHub's OAuth 2.0 (non-OIDC) flow.
	ProviderKindGitHub ProviderKind = "github"
	// ProviderKindOAuthUserInfo is the pure OAuth 2.0 userinfo-based flow
	// with no JWKS/ID-token verification. This kind is only valid for
	// managed (registry) providers. Intentional strict OIDC non-parity:
	// this kind does not validate ID tokens or use JWKS.
	ProviderKindOAuthUserInfo ProviderKind = "oauth_userinfo"
)

// ProviderProtocol controls the OAuth 2.0 token-exchange protocol for a
// provider. Zero value (nil pointer fields) preserves legacy static
// behavior: PKCE enabled with client_secret_basic and no form-posted secret.
type ProviderProtocol struct {
	// UsePKCE enables PKCE code_verifier exchange. When true, ExchangeCode
	// requires a non-empty verifier. Nil defaults to true.
	UsePKCE *bool `json:"use_pkce,omitempty"`
	// ClientSecretBasic sends client_secret via Authorization: Basic header.
	// Nil defaults to true.
	ClientSecretBasic *bool `json:"client_secret_basic,omitempty"`
	// ClientSecretPost sends client_secret in the form body.
	// Nil defaults to false.
	ClientSecretPost *bool `json:"client_secret_post,omitempty"`
}

func (p ProviderProtocol) isZero() bool {
	return p.UsePKCE == nil && p.ClientSecretBasic == nil && p.ClientSecretPost == nil
}

// cloneProtocol returns a deep copy of p so that caller mutation of *bool
// fields cannot affect an exchanger or handler that retains the copy.
func cloneProtocol(p ProviderProtocol) ProviderProtocol {
	out := p
	if p.UsePKCE != nil {
		v := *p.UsePKCE
		out.UsePKCE = &v
	}
	if p.ClientSecretBasic != nil {
		v := *p.ClientSecretBasic
		out.ClientSecretBasic = &v
	}
	if p.ClientSecretPost != nil {
		v := *p.ClientSecretPost
		out.ClientSecretPost = &v
	}
	return out
}

// effectiveProtocol holds resolved protocol flags with non-pointer booleans.
type effectiveProtocol struct {
	UsePKCE           bool
	ClientSecretBasic bool
	ClientSecretPost  bool
}

// EffectiveProtocol returns the resolved protocol flags, substituting
// legacy defaults for nil pointer fields.
func (c Config) EffectiveProtocol() effectiveProtocol {
	return effectiveProtocol{
		UsePKCE:           c.Protocol.UsePKCE == nil || *c.Protocol.UsePKCE,
		ClientSecretBasic: c.Protocol.ClientSecretBasic == nil || *c.Protocol.ClientSecretBasic,
		ClientSecretPost:  c.Protocol.ClientSecretPost != nil && *c.Protocol.ClientSecretPost,
	}
}

// Config holds the static configuration for an upstream OAuth 2.0 / OIDC provider.
type Config struct {
	Kind                  ProviderKind
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSURI               string
	ClientID              string
	Scopes                []string
	Audience              string
	Protocol              ProviderProtocol
	ProviderSource        string
	RuntimeVersion        string
	AutoOnboarding        bool
	AutoLink              bool
	AdminClaimPath        *string
	AdminClaimValue       *string
	MFAClaimPath          *string
	MFAClaimValue         *string
}

// NormalizedKind returns the configured provider kind. Empty and oidc values
// are normalized to OIDC for compatibility.
func (c Config) NormalizedKind() ProviderKind {
	switch c.Kind {
	case "", ProviderKindOIDC:
		return ProviderKindOIDC
	case ProviderKindGitHub:
		return ProviderKindGitHub
	case ProviderKindOAuthUserInfo:
		return ProviderKindOAuthUserInfo
	default:
		return ""
	}
}

// cloneConfig returns a deep copy of c so that caller mutation of slice,
// Protocol, or pointer policy fields cannot affect an exchanger or handler
// that retains the copy.
func cloneConfig(c Config) Config {
	out := c
	if len(c.Scopes) > 0 {
		out.Scopes = make([]string, len(c.Scopes))
		copy(out.Scopes, c.Scopes)
	}
	out.Protocol = cloneProtocol(c.Protocol)
	if c.AdminClaimPath != nil {
		v := *c.AdminClaimPath
		out.AdminClaimPath = &v
	}
	if c.AdminClaimValue != nil {
		v := *c.AdminClaimValue
		out.AdminClaimValue = &v
	}
	if c.MFAClaimPath != nil {
		v := *c.MFAClaimPath
		out.MFAClaimPath = &v
	}
	if c.MFAClaimValue != nil {
		v := *c.MFAClaimValue
		out.MFAClaimValue = &v
	}
	return out
}

// Validate checks that the provider configuration is valid.
// It enforces absolute HTTPS URLs with no userinfo, fragment, or query
// parameters on the issuer.
func (c *Config) Validate() error {
	if c == nil || c.NormalizedKind() == "" {
		return ErrInvalidConfig
	}
	if err := validateRuntimeBinding(c.ProviderSource, c.RuntimeVersion); err != nil {
		return err
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return ErrInvalidConfig
	}
	if strings.TrimSpace(c.AuthorizationEndpoint) == "" {
		return ErrInvalidConfig
	}
	if strings.TrimSpace(c.TokenEndpoint) == "" {
		return ErrInvalidConfig
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return ErrInvalidConfig
	}

	if err := validateURL(c.Issuer, true); err != nil {
		return err
	}
	if err := validateURL(c.AuthorizationEndpoint, false); err != nil {
		return err
	}
	if err := validateURL(c.TokenEndpoint, false); err != nil {
		return err
	}
	if c.UserInfoEndpoint != "" {
		if err := validateURL(c.UserInfoEndpoint, false); err != nil {
			return err
		}
	}
	if c.JWKSURI != "" {
		if err := validateURL(c.JWKSURI, false); err != nil {
			return err
		}
	}
	if c.NormalizedKind() == ProviderKindGitHub {
		if c.Issuer != "https://github.com" ||
			c.AuthorizationEndpoint != "https://github.com/login/oauth/authorize" ||
			c.TokenEndpoint != "https://github.com/login/oauth/access_token" ||
			c.UserInfoEndpoint != "https://api.github.com/user" ||
			c.JWKSURI != "" || c.Audience != "" {
			return ErrInvalidConfig
		}
		readUser, openid := false, false
		for _, scope := range c.Scopes {
			readUser = readUser || scope == "read:user"
			openid = openid || scope == "openid"
		}
		if !readUser || openid {
			return ErrInvalidConfig
		}
	}
	if c.NormalizedKind() == ProviderKindOAuthUserInfo {
		// Managed-only: empty ProviderSource means legacy/static loader,
		// which must not accept this kind.
		if c.ProviderSource != "registry" {
			return ErrInvalidConfig
		}
		if strings.TrimSpace(c.UserInfoEndpoint) == "" {
			return ErrInvalidConfig
		}
		if err := validateURL(c.UserInfoEndpoint, false); err != nil {
			return err
		}
		if !c.EffectiveProtocol().UsePKCE {
			return ErrInvalidConfig
		}
		// JWKS is not required; presence is rejected.
		if c.JWKSURI != "" {
			return ErrInvalidConfig
		}
	}
	return nil
}

func validateURL(raw string, issuerStrict bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return ErrInvalidConfig
	}
	if u.Host == "" || u.Scheme == "" {
		return ErrInvalidConfig
	}
	if u.Scheme != "https" {
		return ErrInvalidConfig
	}
	if u.User != nil {
		return ErrInvalidConfig
	}
	if u.Fragment != "" || u.ForceQuery {
		return ErrInvalidConfig
	}
	if issuerStrict && u.RawQuery != "" {
		return ErrInvalidConfig
	}
	return nil
}
