package upstreamprovider

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const upstreamTokenExchangeTimeout = 10 * time.Second

var errTokenExchange = errors.New("upstream provider: token exchange failed")

const tokenMaxBytes = 1 << 20 // 1 MiB

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// OAuth2TokenExchanger exchanges upstream authorization codes using OAuth 2.0.
type OAuth2TokenExchanger struct {
	configs map[string]Config
	secrets map[string]string
	client  *http.Client
}

// NewOAuth2TokenExchanger creates an exchanger for the configured providers.
// It copies caller-owned maps and deep-copies Protocol pointer fields so the
// caller can safely mutate its data after construction.
func NewOAuth2TokenExchanger(configs map[string]Config, secrets map[string]string, client *http.Client) (*OAuth2TokenExchanger, error) {
	if len(configs) == 0 {
		return nil, ErrInvalidConfig
	}

	clonedConfigs := make(map[string]Config, len(configs))
	clonedSecrets := make(map[string]string, len(secrets))
	for id, cfg := range configs {
		if !validConfigProviderID(id, cfg) || cfg.Validate() != nil {
			return nil, ErrInvalidConfig
		}
		cfg = cloneConfig(cfg)
		clonedConfigs[id] = cfg
		if sec, ok := secrets[id]; ok {
			clonedSecrets[id] = sec
		}
	}
	for id := range secrets {
		if _, ok := configs[id]; !ok {
			return nil, ErrInvalidConfig
		}
	}
	// Legacy path: nil Protocol fields require a non-empty secret.
	for id, cfg := range clonedConfigs {
		if cfg.Protocol.isZero() && clonedSecrets[id] == "" {
			return nil, ErrInvalidConfig
		}
	}
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DisableCompression = true
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
		client = &http.Client{Transport: transport, Timeout: upstreamTokenExchangeTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	} else {
		cloned := *client
		if cloned.Timeout == 0 || cloned.Timeout > upstreamTokenExchangeTimeout {
			cloned.Timeout = upstreamTokenExchangeTimeout
		}
		cloned.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &cloned
	}
	return &OAuth2TokenExchanger{configs: clonedConfigs, secrets: clonedSecrets, client: client}, nil
}

// ExchangeCode exchanges a code and returns the provider's verified input.
func (e *OAuth2TokenExchanger) ExchangeCode(ctx context.Context, providerID, callbackURI, code, pkceVerifier string) (*TokenExchangeResult, error) {
	if e == nil || ctx == nil || providerID == "" || callbackURI == "" || code == "" {
		return nil, errTokenExchange
	}
	cfg, ok := e.configs[providerID]
	if !ok || validateCallbackURI(callbackURI) != nil {
		return nil, errTokenExchange
	}

	proto := cfg.EffectiveProtocol()
	if proto.UsePKCE && pkceVerifier == "" {
		return nil, errTokenExchange
	}

	ctx, cancel := context.WithTimeout(ctx, upstreamTokenExchangeTimeout)
	defer cancel()

	// Legacy path: nil Protocol uses x/oauth2 for exact backward compat.
	if cfg.Protocol.isZero() {
		return e.exchangeCodeLegacy(ctx, providerID, cfg, callbackURI, code, pkceVerifier)
	}
	// Explicit protocol: manual HTTP for full Basic/Post/PKCE control.
	return e.exchangeCodeExplicit(ctx, providerID, cfg, callbackURI, code, pkceVerifier, proto)
}

func (e *OAuth2TokenExchanger) exchangeCodeLegacy(ctx context.Context, providerID string, cfg Config, callbackURI, code, pkceVerifier string) (*TokenExchangeResult, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, e.client)
	endpoint := oauth2.Endpoint{TokenURL: cfg.TokenEndpoint}
	if cfg.NormalizedKind() == ProviderKindGitHub {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	token, err := (&oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: e.secrets[providerID],
		RedirectURL:  callbackURI,
		Endpoint:     endpoint,
	}).Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errTokenExchange
	}
	if token == nil || token.AccessToken == "" {
		return nil, errTokenExchange
	}
	if cfg.NormalizedKind() == ProviderKindGitHub {
		return e.exchangeGitHubUser(ctx, providerID, cfg, token)
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		return nil, errTokenExchange
	}
	return &TokenExchangeResult{IDToken: idToken}, nil
}

func (e *OAuth2TokenExchanger) exchangeCodeExplicit(ctx context.Context, providerID string, cfg Config, callbackURI, code, pkceVerifier string, proto effectiveProtocol) (*TokenExchangeResult, error) {
	secret := e.secrets[providerID]
	_, secretPresent := e.secrets[providerID]

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cfg.ClientID)
	form.Set("redirect_uri", callbackURI)
	if proto.UsePKCE {
		form.Set("code_verifier", pkceVerifier)
	}
	if proto.ClientSecretPost && secretPresent {
		form.Set("client_secret", secret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errTokenExchange
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if proto.ClientSecretBasic {
		req.SetBasicAuth(cfg.ClientID, secret)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errTokenExchange
	}
	defer resp.Body.Close()

	// Accept any 2xx status -- upstream providers may return 201 or other
	// success codes. Aligns with Rauthy 2xx acceptance.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errTokenExchange
	}

	// Read at most limit+1 bytes; reject oversize bodies.
	data, err := io.ReadAll(io.LimitReader(resp.Body, tokenMaxBytes+1))
	if err != nil || len(data) > tokenMaxBytes {
		return nil, errTokenExchange
	}
	// Decode exactly one JSON object; reject trailing non-whitespace.
	var tokenResp tokenResponse
	if err := json.Unmarshal(data, &tokenResp); err != nil {
		return nil, errTokenExchange
	}
	if tokenResp.Error != "" {
		return nil, errTokenExchange
	}

	if cfg.NormalizedKind() == ProviderKindGitHub {
		extras := map[string]any{}
		if tokenResp.Scope != "" {
			extras["scope"] = tokenResp.Scope
		}
		token := (&oauth2.Token{
			AccessToken: tokenResp.AccessToken,
			TokenType:   tokenResp.TokenType,
		}).WithExtra(extras)
		return e.exchangeGitHubUser(ctx, providerID, cfg, token)
	}

	// OAuthUserInfo: require non-empty Bearer access_token, ignore id_token.
	if cfg.NormalizedKind() == ProviderKindOAuthUserInfo {
		if tokenResp.AccessToken == "" {
			return nil, errTokenExchange
		}
		if !strings.EqualFold(tokenResp.TokenType, "bearer") {
			return nil, errTokenExchange
		}
		return e.exchangeOAuthUserInfo(ctx, providerID, cfg, tokenResp.AccessToken)
	}

	// OIDC: try id_token first, fall back to userinfo if available.
	if cfg.NormalizedKind() == ProviderKindOIDC && tokenResp.IDToken == "" {
		if cfg.UserInfoEndpoint != "" && tokenResp.AccessToken != "" {
			return e.exchangeOAuthUserInfo(ctx, providerID, cfg, tokenResp.AccessToken)
		}
		return nil, errTokenExchange
	}
	return &TokenExchangeResult{IDToken: tokenResp.IDToken}, nil
}
