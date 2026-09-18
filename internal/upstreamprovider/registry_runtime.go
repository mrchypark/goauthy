package upstreamprovider

import (
	"context"
	"strings"
)

// mapProviderKind maps the stored AuthProviderType discriminator to the
// Config ProviderKind. Custom, Google, and OIDC are all OIDC-protocol
// providers; GitHub maps to its own kind; OAuthUserInfo is the pure
// userinfo-based flow. Unknown types fail closed.
func mapProviderKind(typ AuthProviderType) (ProviderKind, error) {
	switch typ {
	case AuthProviderTypeOIDC, AuthProviderTypeCustom, AuthProviderTypeGoogle:
		return ProviderKindOIDC, nil
	case AuthProviderTypeGitHub:
		return ProviderKindGitHub, nil
	case AuthProviderTypeOAuthUserInfo:
		return ProviderKindOAuthUserInfo, nil
	default:
		return "", ErrInvalidConfig
	}
}

// RuntimeConfig returns the immutable runtime configuration for a managed
// provider identified by id. It calls GetRuntime exactly once for a
// linearizable read of the document and version, then maps the document
// fields to Config without any additional DB reads, discovery, or network
// calls.
func (s *RegistryStore) RuntimeConfig(ctx context.Context, id string) (Config, *string, error) {
	doc, version, err := s.GetRuntime(ctx, id)
	if err != nil {
		return Config{}, nil, err
	}

	kind, err := mapProviderKind(doc.Typ)
	if err != nil {
		return Config{}, nil, err
	}

	var scopes []string
	if doc.Scope != "" {
		scopes = strings.Fields(strings.ReplaceAll(doc.Scope, "+", " "))
	}

	cfg := Config{
		Kind:                  kind,
		Issuer:                doc.Issuer,
		AuthorizationEndpoint: doc.AuthorizationEndpoint,
		TokenEndpoint:         doc.TokenEndpoint,
		UserInfoEndpoint:      doc.UserinfoEndpoint,
		JWKSURI:               derefString(doc.JWKS),
		ClientID:              doc.ClientID,
		Scopes:                scopes,
		Protocol: ProviderProtocol{
			UsePKCE:           &doc.UsePKCE,
			ClientSecretBasic: &doc.ClientSecretBasic,
			ClientSecretPost:  &doc.ClientSecretPost,
		},
		ProviderSource:  "registry",
		RuntimeVersion:  version,
		AutoOnboarding:  doc.AutoOnboarding,
		AutoLink:        doc.AutoLink,
		AdminClaimPath:  doc.AdminClaimPath,
		AdminClaimValue: doc.AdminClaimValue,
		MFAClaimPath:    doc.MFAClaimPath,
		MFAClaimValue:   doc.MFAClaimValue,
	}

	if !validConfigProviderID(id, cfg) {
		return Config{}, nil, ErrInvalidConfig
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, nil, err
	}

	var secret *string
	if doc.Secret != nil {
		secret, err = s.SecretCleartext(doc)
		if err != nil {
			return Config{}, nil, err
		}
	}

	return cfg, secret, nil
}

// derefString dereferences a *string, returning "" for nil.
func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
