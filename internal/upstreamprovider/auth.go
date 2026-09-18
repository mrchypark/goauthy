package upstreamprovider

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// AuthorizationParams configures an authorization URL request.
type AuthorizationParams struct {
	// Purpose is login or link. Its zero value is login for compatibility.
	Purpose string

	// CallbackURI is the redirect URI. Must be an absolute HTTPS URL.
	CallbackURI string

	// Scopes are the requested scopes. Must be a subset of Config.Scopes
	// when Config.Scopes is non-empty.
	Scopes []string

	// SessionDigest and InteractionDigest optionally bind a local OAuth login
	// to its initiating browser session and interaction. They must be supplied
	// together as canonical SHA-256 digests.
	SessionDigest     string
	InteractionDigest string

	// LinkSubject and LinkSessionDigest bind an account-link transaction to the
	// initiating authenticated subject and browser session.
	LinkSubject       string
	LinkSessionDigest string

	// ProviderSource indicates the origin of the provider configuration
	// (e.g., "registry"). Empty for legacy flows.
	ProviderSource string

	// RuntimeVersion is a bounded opaque version string for managed providers.
	RuntimeVersion string
}

// AuthorizationResult is returned after successfully persisting the transaction.
type AuthorizationResult struct {
	URL         string
	Transaction Transaction
}

// GenerateAuthorizationURL builds an authorization URL and persists the
// associated transaction for callback verification. It validates the
// callback URI is an absolute HTTPS URL and that the requested scopes
// are a subset of the configured scopes when the config has scopes.
func GenerateAuthorizationURL(
	ctx context.Context,
	provider *cryptoProvider,
	cfg Config,
	store Store,
	params AuthorizationParams,
	browserBindingDigest string,
	providerID string,
	now time.Time,
) (*AuthorizationResult, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("generate auth URL: %w", err)
	}
	if browserBindingDigest == "" {
		return nil, fmt.Errorf("generate auth URL: %w", ErrInvalidConfig)
	}
	if providerID == "" {
		return nil, fmt.Errorf("generate auth URL: %w", ErrInvalidConfig)
	}
	if err := validateCallbackURI(params.CallbackURI); err != nil {
		return nil, fmt.Errorf("generate auth URL: callback URI: %w", err)
	}
	if err := validateScopes(cfg.Scopes, params.Scopes); err != nil {
		return nil, fmt.Errorf("generate auth URL: scopes: %w", err)
	}
	purpose := normalizeTransactionPurpose(params.Purpose)
	if !validPurposeBinding(purpose, browserBindingDigest, params.SessionDigest, params.InteractionDigest, params.LinkSubject, params.LinkSessionDigest) {
		return nil, fmt.Errorf("generate auth URL: transaction binding: %w", ErrInvalidConfig)
	}
	if err := validateRuntimeBinding(params.ProviderSource, params.RuntimeVersion); err != nil {
		return nil, fmt.Errorf("generate auth URL: runtime binding: %w", err)
	}

	verifier, challenge, err := provider.GeneratePKCEVerifier()
	if err != nil {
		return nil, fmt.Errorf("generate PKCE: %w", err)
	}
	_ = challenge // used only when PKCE is advertised

	state, err := provider.GenerateState()
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	var nonce string
	if cfg.NormalizedKind() == ProviderKindOIDC {
		nonce, err = provider.GenerateNonce()
		if err != nil {
			return nil, fmt.Errorf("generate nonce: %w", err)
		}
	}

	stateDigest := DigestSHA256(state)

	tx := Transaction{
		Purpose:              purpose,
		StateDigest:          stateDigest,
		BrowserBindingDigest: browserBindingDigest,
		SessionDigest:        params.SessionDigest,
		InteractionDigest:    params.InteractionDigest,
		LinkSubject:          params.LinkSubject,
		LinkSessionDigest:    params.LinkSessionDigest,
		ProviderID:           providerID,
		Nonce:                nonce,
		PKCEVerifier:         verifier,
		Issuer:               cfg.Issuer,
		Audience:             cfg.Audience,
		ClientID:             cfg.ClientID,
		Scopes:               params.Scopes,
		CallbackURI:          params.CallbackURI,
			ProviderSource:      params.ProviderSource,
			RuntimeVersion:     params.RuntimeVersion,
		ExpiresAt:            now.Add(10 * time.Minute),
		CreatedAt:            now,
	}

	if err := store.Save(ctx, tx); err != nil {
		return nil, fmt.Errorf("save transaction: %w", err)
	}

	// Build the authorization URL via net/url — never string concatenation.
	base, err := url.Parse(cfg.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parse authorization endpoint: %w", err)
	}

	q := base.Query()
	q.Set("client_id", cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", params.CallbackURI)
	q.Set("scope", strings.Join(params.Scopes, " "))
	q.Set("state", state)
	if nonce != "" {
		q.Set("nonce", nonce)
	}
	if cfg.EffectiveProtocol().UsePKCE {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	} else {
		q.Del("code_challenge")
		q.Del("code_challenge_method")
	}
	base.RawQuery = q.Encode()

	return &AuthorizationResult{
		URL:         base.String(),
		Transaction: tx,
	}, nil
}

// validateCallbackURI checks that raw is an absolute HTTPS URL with no
// userinfo or fragment.
func validateCallbackURI(raw string) error {
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
	if u.Fragment != "" {
		return ErrInvalidConfig
	}
	return nil
}

// validateScopes checks that each requested scope is present in the
// configured scope set. When configured is empty any scope is accepted.
// When configured is non-empty every requested scope must be in the set.
func validateScopes(configured, requested []string) error {
	if len(configured) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(configured))
	for _, s := range configured {
		set[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := set[s]; !ok {
			return ErrInvalidConfig
		}
	}
	return nil
}
