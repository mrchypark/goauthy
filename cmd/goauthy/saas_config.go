package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mrchypark/goauthy/internal/saas"
	"golang.org/x/oauth2"
)

const maxSaaSProviders = 32

type saasProvidersDocument struct {
	Providers []json.RawMessage `json:"providers"`
}

type saasProviderFileConfig struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	ClientID         string   `json:"client_id"`
	ClientSecretFile string   `json:"client_secret_file"`
	CallbackURI      string   `json:"callback_uri"`
	AuthorizationURL string   `json:"auth_endpoint"`
	TokenURL         string   `json:"token_endpoint"`
	Scopes           []string `json:"scopes"`
	AuthStyle        string   `json:"auth_style"`
}

// configuredSaaSProvider deliberately contains adapters, rather than client
// secrets. The adapters keep their credentials private inside internal/saas.
// Exactly one adapter is non-nil, according to Kind.
type configuredSaaSProvider struct {
	Kind        string
	CallbackURI string
	Scopes      []string
	OAuth2      *saas.OAuth2
	GitHub      *saas.GitHub
}

// loadSaaSProviders loads only explicitly configured, operator-trusted SaaS
// providers. It does not perform a login or any network request.
func loadSaaSProviders(path string) (map[string]configuredSaaSProvider, error) {
	if path == "" {
		return map[string]configuredSaaSProvider{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open SaaS providers file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxUpstreamProvidersFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read SaaS providers file: %w", err)
	}
	if len(data) > maxUpstreamProvidersFileSize {
		return nil, errors.New("SaaS providers file exceeds 65536 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document saasProvidersDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode SaaS providers file: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("SaaS providers file must contain exactly one JSON document")
	}
	if len(document.Providers) < 1 || len(document.Providers) > maxSaaSProviders {
		return nil, fmt.Errorf("SaaS providers must contain 1 to %d providers", maxSaaSProviders)
	}
	providers := make(map[string]configuredSaaSProvider, len(document.Providers))
	for _, raw := range document.Providers {
		cfg, fields, err := decodeSaaSProvider(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := providers[cfg.ID]; exists {
			return nil, errors.New("duplicate SaaS provider id")
		}
		provider, err := newConfiguredSaaSProvider(cfg, fields)
		if err != nil {
			return nil, err
		}
		providers[cfg.ID] = provider
	}
	return providers, nil
}

func decodeSaaSProvider(data []byte) (saasProviderFileConfig, map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg saasProviderFileConfig
	if err := decoder.Decode(&cfg); err != nil {
		return saasProviderFileConfig{}, nil, fmt.Errorf("decode SaaS provider: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return saasProviderFileConfig{}, nil, errors.New("SaaS provider must contain exactly one JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return saasProviderFileConfig{}, nil, fmt.Errorf("decode SaaS provider fields: %w", err)
	}
	return cfg, fields, nil
}

func newConfiguredSaaSProvider(cfg saasProviderFileConfig, fields map[string]json.RawMessage) (configuredSaaSProvider, error) {
	if !validUpstreamProviderID(cfg.ID) || cfg.Kind != "oauth2" && cfg.Kind != "github" {
		return configuredSaaSProvider{}, errors.New("invalid SaaS provider id or kind")
	}
	if !boundedValue(cfg.ClientID, 256) || !boundedValue(cfg.ClientSecretFile, 4096) || !boundedValue(cfg.CallbackURI, 2048) {
		return configuredSaaSProvider{}, errors.New("invalid SaaS provider value")
	}
	secret, err := loadUpstreamClientSecret(cfg.ClientSecretFile)
	if err != nil {
		return configuredSaaSProvider{}, err
	}
	if cfg.Kind == "github" {
		for _, name := range []string{"auth_endpoint", "token_endpoint", "scopes", "auth_style"} {
			if _, supplied := fields[name]; supplied {
				return configuredSaaSProvider{}, errors.New("github SaaS provider rejects generic OAuth2 fields")
			}
		}
		adapter, err := saas.NewGitHub(cfg.ClientID, secret, cfg.CallbackURI)
		if err != nil {
			return configuredSaaSProvider{}, errors.New("invalid GitHub SaaS provider configuration")
		}
		return configuredSaaSProvider{Kind: cfg.Kind, CallbackURI: cfg.CallbackURI, Scopes: []string{"read:user", "offline_access"}, GitHub: adapter}, nil
	}
	if !boundedValue(cfg.AuthorizationURL, 2048) || !boundedValue(cfg.TokenURL, 2048) || len(cfg.Scopes) == 0 || cfg.AuthStyle == "" {
		return configuredSaaSProvider{}, errors.New("invalid OAuth2 SaaS provider value")
	}
	var style oauth2.AuthStyle
	switch cfg.AuthStyle {
	case "header":
		style = oauth2.AuthStyleInHeader
	case "params":
		style = oauth2.AuthStyleInParams
	default:
		return configuredSaaSProvider{}, errors.New("invalid OAuth2 SaaS provider auth_style")
	}
	adapter, err := saas.NewOAuth2(saas.OAuth2Config{ClientID: cfg.ClientID, AuthorizationURL: cfg.AuthorizationURL, TokenURL: cfg.TokenURL, CallbackURL: cfg.CallbackURI, Scopes: cfg.Scopes, AuthStyle: style}, secret)
	if err != nil {
		return configuredSaaSProvider{}, errors.New("invalid OAuth2 SaaS provider configuration")
	}
	return configuredSaaSProvider{Kind: cfg.Kind, CallbackURI: cfg.CallbackURI, Scopes: append([]string(nil), cfg.Scopes...), OAuth2: adapter}, nil
}
