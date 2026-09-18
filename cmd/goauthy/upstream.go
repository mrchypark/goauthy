package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/account"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/login"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

const maxUpstreamProvidersFileSize = 64 << 10
const maxUpstreamClientSecretFileSize = 4096

type upstreamProvidersDocument struct {
	Providers []json.RawMessage `json:"providers"`
}

type upstreamProviderFileConfig struct {
	ID                    string   `json:"id"`
	Kind                  string   `json:"kind"`
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"auth_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks"`
	ClientID              string   `json:"client_id"`
	ClientSecretFile      string   `json:"client_secret_file"`
	CallbackURI           string   `json:"callback_uri"`
	Scopes                []string `json:"scopes"`
	// Protocol flags control the OAuth 2.0 token-exchange protocol.
	// Omitted fields preserve legacy static-file defaults.
	UsePKCE           *bool `json:"use_pkce,omitempty"`
	ClientSecretBasic *bool `json:"client_secret_basic,omitempty"`
	ClientSecretPost  *bool `json:"client_secret_post,omitempty"`
}

type configuredUpstreamProvider struct {
	config      upstreamprovider.Config
	secret      string
	callbackURI string
}

type upstreamRuntime struct {
	handler      *upstreamprovider.Handler
	callbacks    map[string]string
	providerIDs_ []string
	localHooks   upstreamprovider.LocalLoginHooks
	linkHooks    upstreamprovider.LinkHooks
}

func (r *upstreamRuntime) providerIDs() []string { return append([]string(nil), r.providerIDs_...) }

func upstreamHandlerFromEnv(getenv func(string) string, db *rhiza.DB, keyring upstreamprovider.EnvelopeKeyring, issuer string, loginHandler *login.Handler, accountHandler *account.Handler, identityStore *identity.Store) (*upstreamRuntime, error) {
	path := getenv("GOAUTHY_UPSTREAM_PROVIDERS_FILE")
	if path == "" {
		return nil, nil
	}
	providers, err := loadUpstreamProviders(path, issuer)
	if err != nil {
		return nil, err
	}
	configs := make(map[string]upstreamprovider.Config, len(providers))
	secrets := make(map[string]string, len(providers))
	allowedCallbacks := make(map[string]bool, len(providers))
	callbacks := make(map[string]string, len(providers))
	providerIDs := make([]string, 0, len(providers))
	for id, provider := range providers {
		configs[id] = provider.config
		allowedCallbacks[provider.callbackURI] = true
		callbacks[id] = provider.callbackURI
		if provider.secret != "" {
			secrets[id] = provider.secret
		}
		providerIDs = append(providerIDs, id)
	}
	sort.Strings(providerIDs)
	store, err := upstreamprovider.NewRhizaStore(db, keyring)
	if err != nil {
		return nil, fmt.Errorf("configure upstream transaction store: %w", err)
	}
	exchanger, err := upstreamprovider.NewOAuth2TokenExchanger(configs, secrets, nil)
	if err != nil {
		return nil, fmt.Errorf("configure upstream token exchanger: %w", err)
	}
	verifier, err := upstreamprovider.NewJWKSVerifier(configs, nil)
	if err != nil {
		return nil, fmt.Errorf("configure upstream JWKS verifier: %w", err)
	}
	localHooks := upstreamprovider.LocalLoginHooks{
		Prepare: loginHandler.PrepareExternalAuthentication,
		Current: loginHandler.CurrentExternalInitSession,
		Resolve: func(ctx context.Context, external upstreamprovider.SubjectResult) (string, error) {
			subject, found, err := identityStore.FindExternalLink(ctx, external)
			if err != nil || !found {
				return "", errors.New("upstream identity unavailable")
			}
			return subject, nil
		},
		ResolveVerified: staticResolveVerified(&FederatedIdentityResolver{IdentityStore: identityStore}),
		Complete: func(w http.ResponseWriter, r *http.Request, token, interaction, subject string, upstream *upstreamprovider.OIDCSession) {
			var binding *browser.UpstreamSessionBinding
			if upstream != nil {
				binding = &browser.UpstreamSessionBinding{Issuer: upstream.Issuer, ClientID: upstream.ClientID, Subject: upstream.Subject, SessionID: upstream.SessionID, MFAPassed: upstream.MFAPassed}
			}
			loginHandler.CompleteUpstreamAuthentication(w, r, token, interaction, subject, binding)
		},
	}
	linkHooks := upstreamprovider.LinkHooks{
		Current: accountHandler.CurrentExternalLinkSession,
		Link: func(ctx context.Context, localSubject string, external upstreamprovider.SubjectResult, now time.Time) (upstreamprovider.LinkDecision, error) {
			return identityStore.LinkExternal(ctx, localSubject, external, now)
		},
	}
	handler, err := upstreamprovider.NewLocalLoginAndLinkHandler(configs, store, exchanger, verifier, nil, allowedCallbacks, localHooks, callbacks, linkHooks)
	if err != nil {
		return nil, fmt.Errorf("configure upstream local login: %w", err)
	}
	return &upstreamRuntime{handler: handler, callbacks: callbacks, providerIDs_: providerIDs, localHooks: localHooks, linkHooks: linkHooks}, nil
}
func loadUpstreamProviders(path, issuer string) (map[string]configuredUpstreamProvider, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open upstream providers file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxUpstreamProvidersFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read upstream providers file: %w", err)
	}
	if len(data) > maxUpstreamProvidersFileSize {
		return nil, errors.New("upstream providers file exceeds 65536 bytes")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var document upstreamProvidersDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode upstream providers file: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("upstream providers file must contain exactly one JSON document")
	}
	if len(document.Providers) < 1 || len(document.Providers) > 16 {
		return nil, errors.New("upstream providers must contain 1 to 16 providers")
	}
	providers := make(map[string]configuredUpstreamProvider, len(document.Providers))
	for _, rawConfig := range document.Providers {
		fileConfig, err := decodeUpstreamProviderFileConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		provider, err := validateUpstreamProvider(fileConfig, issuer)
		if err != nil {
			return nil, err
		}
		if _, exists := providers[fileConfig.ID]; exists {
			return nil, errors.New("duplicate upstream provider id")
		}
		providers[fileConfig.ID] = provider
	}
	return providers, nil
}

func decodeUpstreamProviderFileConfig(data []byte) (upstreamProviderFileConfig, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var fileConfig upstreamProviderFileConfig
	if err := decoder.Decode(&fileConfig); err != nil {
		return upstreamProviderFileConfig{}, fmt.Errorf("decode upstream provider: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return upstreamProviderFileConfig{}, errors.New("upstream provider must contain exactly one JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return upstreamProviderFileConfig{}, fmt.Errorf("decode upstream provider fields: %w", err)
	}
	if rawKind, supplied := fields["kind"]; supplied {
		var kind string
		if err := json.Unmarshal(rawKind, &kind); err != nil || kind == "" {
			return upstreamProviderFileConfig{}, errors.New("invalid upstream provider kind")
		}
	}
	if fileConfig.Kind == "github" {
		for _, field := range []string{"issuer", "auth_endpoint", "token_endpoint", "jwks"} {
			if _, supplied := fields[field]; supplied {
				return upstreamProviderFileConfig{}, errors.New("github upstream provider rejects OIDC fields")
			}
		}
	}
	return fileConfig, nil
}

func validateUpstreamProvider(fileConfig upstreamProviderFileConfig, issuer string) (configuredUpstreamProvider, error) {
	if !validUpstreamProviderID(fileConfig.ID) {
		return configuredUpstreamProvider{}, errors.New("invalid upstream provider id")
	}
	kind := fileConfig.Kind
	if kind == "" {
		kind = "oidc"
	}
	if kind != "oidc" && kind != "github" {
		return configuredUpstreamProvider{}, errors.New("invalid upstream provider kind")
	}
	if !boundedValue(fileConfig.Issuer, 2048) || !boundedValue(fileConfig.AuthorizationEndpoint, 2048) || !boundedValue(fileConfig.TokenEndpoint, 2048) || !boundedValue(fileConfig.JWKSURI, 2048) || !boundedValue(fileConfig.ClientID, 256) || !boundedValue(fileConfig.CallbackURI, 2048) {
		if kind == "oidc" {
			return configuredUpstreamProvider{}, errors.New("invalid upstream provider value")
		}
	}
	if kind == "github" {
		if fileConfig.Issuer != "" || fileConfig.AuthorizationEndpoint != "" || fileConfig.TokenEndpoint != "" || fileConfig.JWKSURI != "" {
			return configuredUpstreamProvider{}, errors.New("github upstream provider rejects OIDC fields")
		}
		if !boundedValue(fileConfig.ClientID, 256) || !boundedValue(fileConfig.ClientSecretFile, 4096) || !boundedValue(fileConfig.CallbackURI, 2048) {
			return configuredUpstreamProvider{}, errors.New("invalid upstream provider value")
		}
		if !validGitHubScopes(fileConfig.Scopes) {
			return configuredUpstreamProvider{}, errors.New("invalid GitHub upstream provider scopes")
		}
		if !validUpstreamCallback(fileConfig.CallbackURI, issuer, fileConfig.ID) {
			return configuredUpstreamProvider{}, errors.New("invalid upstream provider callback URI")
		}
		config := upstreamprovider.Config{
			Kind:                  upstreamprovider.ProviderKindGitHub,
			Issuer:                "https://github.com",
			AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
			TokenEndpoint:         "https://github.com/login/oauth/access_token",
			UserInfoEndpoint:      "https://api.github.com/user",
			ClientID:              fileConfig.ClientID,
			Scopes:                append([]string(nil), fileConfig.Scopes...),
			Protocol: upstreamprovider.ProviderProtocol{
				UsePKCE:           fileConfig.UsePKCE,
				ClientSecretBasic: fileConfig.ClientSecretBasic,
				ClientSecretPost:  fileConfig.ClientSecretPost,
			},
		}
		if config.Validate() != nil || !strictHTTPSURL(config.AuthorizationEndpoint) || !strictHTTPSURL(config.TokenEndpoint) || !strictHTTPSURL(config.UserInfoEndpoint) {
			return configuredUpstreamProvider{}, errors.New("invalid GitHub upstream provider URL")
		}
		secret, err := loadUpstreamClientSecret(fileConfig.ClientSecretFile)
		if err != nil {
			return configuredUpstreamProvider{}, err
		}
		return configuredUpstreamProvider{config: config, secret: secret, callbackURI: fileConfig.CallbackURI}, nil
	}
	config := upstreamprovider.Config{Issuer: fileConfig.Issuer, AuthorizationEndpoint: fileConfig.AuthorizationEndpoint, TokenEndpoint: fileConfig.TokenEndpoint, JWKSURI: fileConfig.JWKSURI, ClientID: fileConfig.ClientID, Scopes: append([]string(nil), fileConfig.Scopes...)}
	config.Protocol = upstreamprovider.ProviderProtocol{UsePKCE: fileConfig.UsePKCE, ClientSecretBasic: fileConfig.ClientSecretBasic, ClientSecretPost: fileConfig.ClientSecretPost}
	if config.Validate() != nil || !strictHTTPSURL(config.AuthorizationEndpoint) || !strictHTTPSURL(config.TokenEndpoint) || !strictHTTPSURL(config.JWKSURI) {
		return configuredUpstreamProvider{}, errors.New("invalid upstream provider URL")
	}
	if !validUpstreamScopes(config.Scopes) {
		return configuredUpstreamProvider{}, errors.New("invalid upstream provider scopes")
	}
	if !validUpstreamCallback(fileConfig.CallbackURI, issuer, fileConfig.ID) {
		return configuredUpstreamProvider{}, errors.New("invalid upstream provider callback URI")
	}
	var secret string
	if secretRequiredForOIDC(fileConfig) {
		var err error
		secret, err = loadUpstreamClientSecret(fileConfig.ClientSecretFile)
		if err != nil {
			return configuredUpstreamProvider{}, err
		}
	} else if fileConfig.ClientSecretFile != "" {
		// Explicitly public but secret file provided: validate it.
		var err error
		secret, err = loadUpstreamClientSecret(fileConfig.ClientSecretFile)
		if err != nil {
			return configuredUpstreamProvider{}, err
		}
	}
	return configuredUpstreamProvider{config: config, secret: secret, callbackURI: fileConfig.CallbackURI}, nil
}

// secretRequiredForOIDC reports whether the resolved protocol flags require
// a client secret file for an OIDC provider. All-nil fields preserve legacy
// defaults: a secret file is required. When at least one flag is explicitly
// set, the effective protocol is resolved: PKCE defaults true, basic
// defaults true, post defaults false. A public provider (PKCE true,
// basic false, post false) needs no secret; all other combinations
// require a valid secret file.
func secretRequiredForOIDC(fileConfig upstreamProviderFileConfig) bool {
	if fileConfig.UsePKCE == nil && fileConfig.ClientSecretBasic == nil && fileConfig.ClientSecretPost == nil {
		return true
	}
	usePKCE := fileConfig.UsePKCE == nil || *fileConfig.UsePKCE
	basic := fileConfig.ClientSecretBasic == nil || *fileConfig.ClientSecretBasic
	post := fileConfig.ClientSecretPost != nil && *fileConfig.ClientSecretPost
	if usePKCE && !basic && !post {
		return false
	}
	return true
}

func validGitHubScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > 64 {
		return false
	}
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if scope == "" || len(scope) > 256 || scope == "openid" || seen[scope] {
			return false
		}
		for _, b := range []byte(scope) {
			if b != 0x21 && (b < 0x23 || b > 0x5b) && (b < 0x5d || b > 0x7e) {
				return false
			}
		}
		seen[scope] = true
	}
	return seen["read:user"]
}

func validUpstreamProviderID(id string) bool {
	if id == "" || id != upstreamprovider.NormalizeProviderID(id) || len(id) > 64 {
		return false
	}
	for i, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') || (i == 0 && (r == '-' || r == '_')) {
			return false
		}
	}
	return true
}

func boundedValue(value string, limit int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= limit
}

func strictHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery
}

func validUpstreamScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > 64 {
		return false
	}
	seen, openid := make(map[string]bool, len(scopes)), false
	for _, scope := range scopes {
		if scope == "" || len(scope) > 256 || seen[scope] {
			return false
		}
		for _, b := range []byte(scope) {
			if b != 0x21 && (b < 0x23 || b > 0x5b) && (b < 0x5d || b > 0x7e) {
				return false
			}
		}
		seen[scope] = true
		openid = openid || scope == "openid"
	}
	return openid
}

func validUpstreamCallback(raw, issuer, id string) bool {
	callback, err := url.Parse(raw)
	base, baseErr := url.Parse(issuer)
	if err != nil || baseErr != nil || callback.Scheme != "https" || callback.User != nil || callback.RawQuery != "" || callback.Fragment != "" || callback.ForceQuery || callback.RawPath != "" || callback.Path != strings.TrimRight(base.Path, "/")+"/upstream/"+id+"/callback" {
		return false
	}
	return callback.Scheme == base.Scheme && strings.EqualFold(callback.Host, base.Host)
}

func loadUpstreamClientSecret(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open upstream client secret: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxUpstreamClientSecretFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read upstream client secret: %w", err)
	}
	if len(data) > maxUpstreamClientSecretFileSize {
		return "", errors.New("upstream client secret file exceeds 4096 bytes")
	}
	secret := strings.TrimSuffix(string(data), "\r\n")
	if secret == string(data) {
		secret = strings.TrimSuffix(secret, "\n")
	}
	if len(secret) < 16 || len(secret) > maxUpstreamClientSecretFileSize || strings.ContainsAny(secret, "\r\n\x00") || strings.TrimSpace(secret) != secret {
		return "", errors.New("upstream client secret must be 16 to 4096 bytes with no whitespace, NUL, or line breaks")
	}
	return secret, nil
}

func mountUpstreamRoutes(mux *http.ServeMux, runtime *upstreamRuntime, accountHandler *account.Handler, revoke func(context.Context, oauth.UpstreamLogout) error) {
	if runtime == nil {
		return
	}
	logout := runtime.handler.BackchannelLogoutHandler(func(ctx context.Context, clientID string, claims *upstreamprovider.LogoutTokenClaims, digest string) error {
		if revoke == nil {
			return errors.New("upstream logout unavailable")
		}
		return revoke(ctx, oauth.UpstreamLogout{Issuer: claims.Issuer, ClientID: clientID, Subject: claims.Subject, SessionID: claims.SessionID, JTI: claims.JTI, TokenDigest: digest, ExpiresAt: claims.ReplayUntil})
	})
	for _, id := range runtime.providerIDs_ {
		callbackURI := runtime.callbacks[id]
		start, callback := runtime.handler.LocalStartHandler(), runtime.handler.CombinedCallbackHandler()
		mux.Handle("GET /upstream/"+id+"/start", upstreamStartRoute(id, callbackURI, start))
		mux.Handle("GET /upstream/"+id+"/callback", upstreamCallbackRoute(id, callback))
		mux.Handle("POST /upstream/"+id+"/backchannel-logout", upstreamCallbackRoute(id, logout))
	}
	mux.HandleFunc("POST /auth/v1/providers/{providerID}/link", accountHandler.StartExternalLink)
	mux.HandleFunc("DELETE /auth/v1/providers/{providerID}/link", accountHandler.UnlinkExternal)
}

func mountDynamicUpstreamRoutes(mux *http.ServeMux, dynamic *dynamicUpstreamDispatcher, accountHandler *account.Handler) {
	if dynamic == nil {
		return
	}
	mux.Handle("GET /upstream/{providerID}/start", dynamic)
	mux.Handle("GET /upstream/{providerID}/callback", dynamic)
	mux.Handle("POST /upstream/{providerID}/backchannel-logout", dynamic)
	if accountHandler != nil {
		mux.HandleFunc("POST /auth/v1/providers/{providerID}/link", accountHandler.StartExternalLink)
		mux.HandleFunc("DELETE /auth/v1/providers/{providerID}/link", accountHandler.UnlinkExternal)
	}
}

func upstreamStartRoute(id, callbackURI string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setUpstreamSecurityHeaders(w)
		redirects := r.URL.Query()["redirect_uri"]
		if len(redirects) != 1 || redirects[0] != callbackURI {
			http.Error(w, "Redirect URI not allowed", http.StatusForbidden)
			return
		}
		r.SetPathValue("providerID", id)
		next.ServeHTTP(w, r)
	})
}

func upstreamCallbackRoute(id string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setUpstreamSecurityHeaders(w)
		r.SetPathValue("providerID", id)
		next.ServeHTTP(w, r)
	})
}

func setUpstreamSecurityHeaders(w http.ResponseWriter) {
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
}

// isValidManagedProviderID checks if id is exactly 24 ASCII alphanumeric
// characters (case-sensitive), matching the format created by the provider
// registry for managed providers.
func isValidManagedProviderID(id string) bool {
	if len(id) != 24 {
		return false
	}
	for i := 0; i < 24; i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// dynamicUpstreamDispatcher handles runtime-resolved upstream OAuth routes
// for DB-managed providers. It constructs per-request Handler+exchanger+
// verifier from a single linearizable RuntimeConfig snapshot while sharing
// the RhizaStore, hooks, and transport.
type dynamicUpstreamDispatcher struct {
	issuer          string
	registryStore   *upstreamprovider.RegistryStore
	rhizaStore      upstreamprovider.Store
	staticIDs       map[string]bool
	staticLinkStart http.Handler
	localHooks      upstreamprovider.LocalLoginHooks
	linkHooks       upstreamprovider.LinkHooks
	revoke          func(context.Context, oauth.UpstreamLogout) error
}

func newDynamicUpstreamDispatcher(
	issuer string,
	registryStore *upstreamprovider.RegistryStore,
	rhizaStore upstreamprovider.Store,
	staticIDs []string,
	staticLinkStart http.Handler,
	localHooks upstreamprovider.LocalLoginHooks,
	linkHooks upstreamprovider.LinkHooks,
	revoke func(context.Context, oauth.UpstreamLogout) error,
) *dynamicUpstreamDispatcher {
	ids := make(map[string]bool, len(staticIDs))
	for _, id := range staticIDs {
		ids[id] = true
	}
	return &dynamicUpstreamDispatcher{
		issuer:          issuer,
		registryStore:   registryStore,
		rhizaStore:      rhizaStore,
		staticIDs:       ids,
		staticLinkStart: staticLinkStart,
		localHooks:      localHooks,
		linkHooks:       linkHooks,
		revoke:          revoke,
	}
}

func (d *dynamicUpstreamDispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("providerID")
	if providerID == "" || !isValidManagedProviderID(providerID) || d.staticIDs[providerID] {
		http.NotFound(w, r)
		return
	}
	setUpstreamSecurityHeaders(w)
	cfg, secret, err := d.registryStore.RuntimeConfig(r.Context(), providerID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	configs := map[string]upstreamprovider.Config{providerID: cfg}
	secrets := map[string]string{}
	if secret != nil {
		secrets[providerID] = *secret
	}
	callbackURI := d.issuer + "/upstream/" + providerID + "/callback"
	allowedCallbacks := map[string]bool{callbackURI: true}
	linkCallbacks := map[string]string{providerID: callbackURI}
	exchanger, err := upstreamprovider.NewOAuth2TokenExchanger(configs, secrets, nil)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	verifier, err := upstreamprovider.NewJWKSVerifier(configs, nil)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	handler, err := upstreamprovider.NewLocalLoginAndLinkHandler(configs, d.rhizaStore, exchanger, verifier, nil, allowedCallbacks, d.localHooks, linkCallbacks, d.linkHooks)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, "/start"):
		handler.LocalStartHandler().ServeHTTP(w, r)
	case strings.HasSuffix(path, "/callback"):
		handler.CombinedCallbackHandler().ServeHTTP(w, r)
	case strings.HasSuffix(path, "/backchannel-logout"):
		logout := handler.BackchannelLogoutHandler(func(ctx context.Context, clientID string, claims *upstreamprovider.LogoutTokenClaims, digest string) error {
			if d.revoke == nil {
				return errors.New("upstream logout unavailable")
			}
			return d.revoke(ctx, oauth.UpstreamLogout{Issuer: claims.Issuer, ClientID: clientID, Subject: claims.Subject, SessionID: claims.SessionID, JTI: claims.JTI, TokenDigest: digest, ExpiresAt: claims.ReplayUntil})
		})
		logout.ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (d *dynamicUpstreamDispatcher) linkStartHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerID := r.PathValue("providerID")
		if d.staticIDs[providerID] && d.staticLinkStart != nil {
			d.staticLinkStart.ServeHTTP(w, r)
			return
		}
		if !isValidManagedProviderID(providerID) {
			http.NotFound(w, r)
			return
		}
		cfg, secret, err := d.registryStore.RuntimeConfig(r.Context(), providerID)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		configs := map[string]upstreamprovider.Config{providerID: cfg}
		secrets := map[string]string{}
		if secret != nil {
			secrets[providerID] = *secret
		}
		callbackURI := d.issuer + "/upstream/" + providerID + "/callback"
		linkCallbacks := map[string]string{providerID: callbackURI}
		exchanger, err := upstreamprovider.NewOAuth2TokenExchanger(configs, secrets, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		verifier, err := upstreamprovider.NewJWKSVerifier(configs, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		handler, err := upstreamprovider.NewLinkHandler(configs, d.rhizaStore, exchanger, verifier, nil, linkCallbacks, d.linkHooks)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		handler.LinkStartHandler().ServeHTTP(w, r)
	})
}

func (d *dynamicUpstreamDispatcher) exists(ctx context.Context, providerID string) (bool, error) {
	if d.staticIDs[providerID] {
		return true, nil
	}
	_, err := d.registryStore.Get(ctx, providerID)
	if err != nil {
		if errors.Is(err, upstreamprovider.ErrProviderNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
