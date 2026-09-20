package oauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/backchannel"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/cimd"
	"github.com/mrchypark/goauthy/internal/claims"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/dpop"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/metrics"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/redirecturi"
	"github.com/mrchypark/goauthy/internal/tracing"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var (
	principalRolePattern  = regexp.MustCompile(`^[a-zA-Z0-9\-_/,:*.]{2,64}$`)
	principalGroupPattern = regexp.MustCompile(`^[a-zA-Z0-9\-_/,:*]{2,64}$`)
)

// Zero keeps Fosite's security default in production. Package tests lower the
// cost because race instrumentation otherwise exceeds Go's test timeout.
var bcryptHashCost int

var errInvalidTarget = &fosite.RFC6749Error{
	ErrorField:       "invalid_target",
	DescriptionField: "The requested resource is invalid, unknown, or malformed.",
	CodeField:        http.StatusBadRequest,
}

// ErrInvalidAuthorizationRequest intentionally hides Fosite implementation
// errors from the login and consent layer.
var ErrInvalidAuthorizationRequest = errors.New("invalid authorization request")

var (
	errCIMDDynamicClientLookup = errors.New("CIMD dynamic client lookup failed")
	errCIMDMetadataResolution  = errors.New("CIMD metadata resolution failed")
)

const (
	cimdPrefetchStageDynamicClientLookup = "dynamic_client_lookup"
	cimdPrefetchStageMetadataResolution  = "metadata_resolution"
	cimdPrefetchStageUnknown             = "unknown"
)

const maxAuthorizationMaxAgeSeconds int64 = 366 * 24 * 60 * 60

const (
	openidScope            = "openid"
	groupsScope            = "groups"
	maxNonceLength         = 512
	oidcNonceExtra         = "goauthy_oidc_nonce"
	oidcAuthTimeExtra      = "goauthy_oidc_auth_time"
	oidcSessionIDExtra     = "goauthy_oidc_session_id"
	oidcAuthMethodExtra    = "goauthy_oidc_auth_method"
	oidcAuthMethodPwd      = "pwd"
	oidcAuthMethodWebAuthn = "webauthn"
	oidcAuthMethodMFA      = "mfa"
	oidcAuthMethodExternal = "external"
)

// PrincipalClaims is the current authorization data for an end user. It is
// resolved at token and UserInfo boundaries; persisted OAuth session data is
// deliberately not an authority for roles or groups.
type PrincipalClaims struct {
	Roles    []string
	Groups   []string
	Revision int64
}

type customClaimsSnapshot struct {
	id, access      oidc.CustomClaims
	catalogRevision int64
	enabled         bool
}

// clientCredentialsClaimsSnapshot is deliberately separate from end-user
// custom claims: it is emitted only in a signed access token, never through
// UserInfo or introspection's Fosite session-extra projection.
type clientCredentialsClaimsSnapshot struct {
	claims   oidc.CustomClaims
	revision int64
	set      bool
}

// ClientGroupPolicy is the current group-admission policy for one client.
// Managed distinguishes a static bootstrap client from dynamic/CIMD clients.
// A managed policy with revision zero means no policy row and unrestricted.
type ClientGroupPolicy struct {
	managedClient bool
	Managed       bool
	Prefix        string
	Revision      int64
}

type principalSnapshotContextKey struct{}

type principalSnapshot struct {
	signature      string
	subject        string
	revision       int64
	claims         PrincipalClaims
	custom         customClaimsSnapshot
	policy         ClientGroupPolicy
	policySet      bool
	policyClientID string
	clientClaims   clientCredentialsClaimsSnapshot
}

// AuthorizationRequest is the safe authorize-request view for login and
// consent rendering. It deliberately excludes Fosite request/session state.
type AuthorizationRequest struct {
	ClientID           string
	RedirectURI        string
	RequestID          string
	RequestedScopes    []string
	RequestedResources []string
	Prompt             []string
	MaxAgeSeconds      *int64
	ForceMFA           bool
}

type Server struct {
	passwordLoginObserver                   func(http.ResponseWriter, *http.Request, string) error
	tokenIssued                             func(context.Context, string, string, string) error
	provider                                fosite.OAuth2Provider
	store                                   *Store
	accessTokens                            oauth2.AccessTokenStrategy
	authorizeCodes                          oauth2.AuthorizeCodeStrategy
	allowedResources                        map[string]struct{}
	defaultAudiences                        map[string]string
	ephemeralDangerAllowUnvalidatedResource bool
	redirectPolicy                          redirecturi.Policy
	oidc                                    *OIDCConfig
	dpop                                    *dpop.Store
	metrics                                 *metrics.Registry
	// beforeTokenIssue is package-test-only deterministic race injection.
	beforeTokenIssue func()
	// beforeAuthorizationIssue is package-test-only deterministic race injection.
	beforeAuthorizationIssue func()
	// userValuesPolicy is the static profile revalidation policy. Default is
	// zero (off). When RevalidateDuringLogin is true, needsProfileUpdate must
	// be non-nil. The policy is validated at setter time; it is not activated
	// through main/env/config response surfaces.
	userValuesPolicy   identity.UserValuesPolicy
	needsProfileUpdate func(context.Context, identity.UserValuesPolicy, string, string) (bool, error)
}

// SetMetrics attaches a metrics registry for token counters.
func (s *Server) SetMetrics(reg *metrics.Registry) { s.metrics = reg }

// tokenStatusWriter captures the first WriteHeader status for metrics.
type tokenStatusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (tw *tokenStatusWriter) WriteHeader(code int) {
	if tw.wroteHeader {
		return
	}
	tw.wroteHeader = true
	tw.status = code
	tw.ResponseWriter.WriteHeader(code)
}

type cimdResolver interface {
	Lookup(context.Context, string) (cimd.Metadata, error)
	Resolve(context.Context, string) (cimd.Metadata, error)
}

// OIDCConfig enables the narrow ID-token extension to the OAuth server. The
// callback is deliberately request-scoped so a rotated Rhiza-backed key is
// loaded before every ID-token-bearing exchange.
type OIDCConfig struct {
	// PasswordUsers registers password authentication; clients must separately enable the flow.
	PasswordUsers   *identity.Store
	PasswordExpired func(context.Context, string) error
	Issuer          string
	LoadSigningKey  func(context.Context) (oidc.SigningKey, error)
	// DefaultAudiences selects one validated default resource audience per
	// client when authorization, device and client-credentials requests omit resource.
	// Refresh audiences remain bound to their source grant. Token exchange adds
	// the exchanger default independently of any explicit requested target.
	DefaultAudiences map[string]string
	// LoadVerificationKeys returns active and retiring public keys so JWT access
	// tokens remain valid through the signing-key retirement window.
	// Nil falls back to the active signing key for narrow in-process callers.
	LoadVerificationKeys func(context.Context) ([]jose.JSONWebKey, error)
	// ValidateSubject must reject unknown or disabled subjects before UserInfo
	// returns claims. A nil callback leaves UserInfo fail-closed.
	ValidateSubject func(context.Context, string) error
	// ResolvePrincipal reads current end-user authorization data. An error
	// fails an authorization-code or refresh exchange before it can commit.
	ResolvePrincipal func(context.Context, string) (PrincipalClaims, error)
	// ResolveProfile returns the current standard OIDC profile projection. It
	// is evaluated at each authorization-code/refresh ID-token boundary and by
	// UserInfo; client-credentials grants never invoke it.
	ResolveProfile func(context.Context, string) (oidc.ProfileClaims, error)
	// ForwardAuthEnabled controls issuance of identity headers. When enabled,
	// all forward-auth resolvers are required and are evaluated per request.
	ForwardAuthEnabled                  bool
	ResolveForwardAuthProfile           func(context.Context, string) (ForwardAuthProfile, error)
	ResolveForwardAuthPasskeyEnrollment func(context.Context, string) (bool, error)
	ResolveCustomClaims                 func(context.Context, string, []string) (claims.Resolved, error)
	BootstrapClientScopes               func(context.Context, string) (claims.ClientScopes, error)
	// ResolveClientCredentialsClaims returns the current bootstrap machine
	// client access-token claims. Dynamic, CIMD, exchange, and user grants do
	// not invoke it.
	ResolveClientCredentialsClaims func(context.Context, string) (claims.ClientCredentialsClaims, error)
	// CustomScopeExists identifies a currently configured custom user scope.
	// Dynamic-client metadata is rejected when it names a deleted scope.
	CustomScopeExists        func(context.Context, string) (bool, error)
	DynamicClientScopePolicy dcr.ScopePolicy
	ManagedClients           *clients.Store
	// BrowserSessionIdleTimeout must match the browser session store policy so
	// OIDC code issuance cannot outlive a browser session that became idle.
	// Zero uses browser.DefaultIdleTimeout.
	BrowserSessionIdleTimeout time.Duration
	// ClientCredentialsTokenLifespan applies only to client_credentials access
	// tokens. Zero uses Fosite's one-hour server default.
	ClientCredentialsTokenLifespan time.Duration
	// ClientCredentialsMapSub maps machine-token sub to its issuing client ID.
	ClientCredentialsMapSub bool
	// RFC8252LoopbackRedirects permits a public dynamic native client to use a
	// different port on a registered 127.0.0.1 or ::1 HTTP redirect URI.
	// Static/bootstrap clients always require an exact redirect URI.
	RFC8252LoopbackRedirects bool
	// BootstrapForceMFA requires an MFA-authenticated browser session for the
	// bootstrap client. Dynamic clients are always unforced, matching Rauthy's
	// dynamic-registration policy.
	BootstrapForceMFA bool
	// ClientGroupPolicy returns the static client group-admission policy. It
	// must return Managed=false for dynamic and CIMD clients. A managed policy
	// is bound to every authorization and token mutation by its revision.
	ClientGroupPolicy func(context.Context, string) (ClientGroupPolicy, error)
	// CIMD resolves an explicitly enabled, HTTPS client_id metadata document.
	// Resolution is limited to the authorization boundary; every other lookup
	// is cache-only or uses the persisted OAuth request snapshot.
	CIMD cimdResolver
	// CIMDDangerAllowUnvalidatedResource permits an ephemeral CIMD client
	// without an allowed_resources list to request any valid HTTPS resource.
	// The default is false; a document allow-list always remains exact.
	CIMDDangerAllowUnvalidatedResource bool
	// BackChannelLogoutURI is the bootstrap client's registered back-channel
	// logout endpoint. An empty URI disables back-channel delivery.
	BackChannelLogoutURI          string
	BackChannelLogoutAllowPrivate bool
	BackChannelLogoutAllowHTTP    bool
}

type Store struct {
	db                        *rhiza.DB
	client                    fosite.Client
	dynamicClients            *dcr.Store
	managedClients            *clients.Store
	cimd                      cimdResolver
	now                       func() time.Time
	browserSessionIdleTimeout time.Duration
	backChannelLogoutURI      string
	backChannelAllowPrivate   bool
	backChannelAllowHTTP      bool
	bootstrapClientScopes     func(context.Context, string) (claims.ClientScopes, error)
	customScopeExists         func(context.Context, string) (bool, error)
	// beforeAccessTokenLookup is package-test-only verification that malformed
	// compact JWTs do not reach a token-row query.
	beforeAccessTokenLookup func()
}

func LoadSecret(path string) ([]byte, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read OAuth HMAC secret: %w", err)
	}
	secret, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || !validHMACSecret(secret) {
		return nil, fmt.Errorf("OAuth HMAC secret must be 32 non-zero raw-base64url bytes")
	}
	return secret, nil
}

func LoadClientSecret(path string) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read bootstrap OAuth client secret: %w", err)
	}
	secret := strings.TrimSpace(string(value))
	if len(secret) < 16 {
		return "", fmt.Errorf("bootstrap OAuth client secret must be at least 16 bytes")
	}
	return secret, nil
}

func NewServer(ctx context.Context, db *rhiza.DB, hmacSecret []byte, clientID, clientSecret, redirectURI string) (*Server, error) {
	return NewServerWithResourceIndicators(ctx, db, hmacSecret, clientID, clientSecret, redirectURI, nil)
}

// NewServerWithResourceIndicators permits client-credentials resource
// indicators only when they exactly match an allowed HTTPS resource URL.
func NewServerWithResourceIndicators(ctx context.Context, db *rhiza.DB, hmacSecret []byte, clientID, clientSecret, redirectURI string, allowedResources []string) (*Server, error) {
	return newServer(ctx, db, hmacSecret, clientID, clientSecret, redirectURI, allowedResources, nil, nil)
}

// NewServerWithResourceIndicatorsAndDefaultAudiences configures one default
// resource audience per client. A default is used only when a request omits
// resource; explicit resources and restored refresh audiences remain authoritative.
// The OIDC-enabled exchange handler uses the exchanging client policy.
func NewServerWithResourceIndicatorsAndDefaultAudiences(ctx context.Context, db *rhiza.DB, hmacSecret []byte, clientID, clientSecret, redirectURI string, allowedResources []string, defaultAudiences map[string]string) (*Server, error) {
	return newServer(ctx, db, hmacSecret, clientID, clientSecret, redirectURI, allowedResources, defaultAudiences, nil)
}

// NewServerWithOIDC enables ID tokens for authorization-code and refresh
// grants while retaining the existing OAuth factories.
func NewServerWithOIDC(ctx context.Context, db *rhiza.DB, hmacSecret []byte, clientID, clientSecret, redirectURI string, allowedResources []string, oidcConfig OIDCConfig) (*Server, error) {
	if oidcConfig.Issuer == "" || oidcConfig.LoadSigningKey == nil {
		return nil, fmt.Errorf("OIDC issuer and signing-key loader are required")
	}
	if oidcConfig.BrowserSessionIdleTimeout < 0 {
		return nil, fmt.Errorf("OIDC browser session idle timeout must be positive")
	}
	if oidcConfig.BrowserSessionIdleTimeout == 0 {
		oidcConfig.BrowserSessionIdleTimeout = browser.DefaultIdleTimeout
	}
	if oidcConfig.ClientCredentialsTokenLifespan < 0 || oidcConfig.ClientCredentialsTokenLifespan > oidc.MaxAccessTokenLifetime {
		return nil, fmt.Errorf("client-credentials token lifespan must be at most 24 hours")
	}
	if oidcConfig.BackChannelLogoutURI == "" {
		if oidcConfig.BackChannelLogoutAllowPrivate || oidcConfig.BackChannelLogoutAllowHTTP {
			return nil, fmt.Errorf("back-channel logout endpoint is required when its network exceptions are enabled")
		}
	} else if err := backchannel.ValidateEndpoint(oidcConfig.BackChannelLogoutURI, oidcConfig.BackChannelLogoutAllowPrivate, oidcConfig.BackChannelLogoutAllowHTTP); err != nil {
		return nil, fmt.Errorf("invalid bootstrap back-channel logout endpoint: %w", err)
	}
	issuer, err := oidc.NormalizeIssuer(oidcConfig.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC issuer: %w", err)
	}
	oidcConfig.Issuer = issuer
	return newServer(ctx, db, hmacSecret, clientID, clientSecret, redirectURI, allowedResources, oidcConfig.DefaultAudiences, &oidcConfig)
}

// RevokeOIDCSession invalidates every OAuth artifact associated with a browser
// session ID. It is safe to call repeatedly during logout.
func (s *Server) RevokeOIDCSession(ctx context.Context, sid string) error {
	if s.oidc == nil {
		return errors.New("OIDC is not enabled")
	}
	return s.store.RevokeOIDCSession(ctx, sid)
}

func newServer(ctx context.Context, db *rhiza.DB, hmacSecret []byte, clientID, clientSecret, redirectURI string, allowedResources []string, defaultAudiences map[string]string, oidcConfig *OIDCConfig) (*Server, error) {
	if !validHMACSecret(hmacSecret) {
		return nil, fmt.Errorf("OAuth HMAC secret must be 32 non-zero bytes")
	}
	if !clientIDPattern.MatchString(clientID) || len(clientSecret) < 16 {
		return nil, fmt.Errorf("invalid bootstrap OAuth client credentials")
	}
	redirect, err := url.Parse(redirectURI)
	if err != nil || !redirect.IsAbs() || redirect.Fragment != "" || !fosite.IsRedirectURISecure(ctx, redirect) {
		return nil, fmt.Errorf("invalid bootstrap OAuth redirect URI")
	}
	resources, err := resourceAllowList(allowedResources)
	if err != nil {
		return nil, err
	}
	defaults, err := resourceDefaults(resources, defaultAudiences)
	if err != nil {
		return nil, err
	}
	config := &fosite.Config{
		AccessTokenLifespan:            time.Hour,
		AuthorizeCodeLifespan:          5 * time.Minute,
		RefreshTokenLifespan:           30 * 24 * time.Hour,
		GlobalSecret:                   append([]byte(nil), hmacSecret...),
		ScopeStrategy:                  fosite.ExactScopeStrategy,
		AudienceMatchingStrategy:       ephemeralAudienceMatchingStrategy,
		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
		RefreshTokenScopes:             []string{"offline_access"},
		SendDebugMessagesToClients:     false,
		HashCost:                       bcryptHashCost,
		// Fosite's default getter lazily writes this field. Construct it before
		// the provider is published so concurrent requests only read it.
		JWKSFetcherStrategy: fosite.NewDefaultJWKSFetcherStrategy(),
	}
	hasher := &fosite.BCrypt{Config: config}
	config.ClientSecretsHasher = hasher
	hash, err := hasher.Hash(ctx, []byte(clientSecret))
	if err != nil {
		return nil, fmt.Errorf("hash bootstrap OAuth client secret: %w", err)
	}
	scopes := []string{"goauthy.read", "offline_access"}
	if oidcConfig != nil {
		scopes = append(scopes, openidScope, groupsScope, "profile", "email", "address", "phone")
	}
	idleTimeout := browser.DefaultIdleTimeout
	var backChannelURI string
	var backChannelAllowPrivate, backChannelAllowHTTP bool
	if oidcConfig != nil {
		idleTimeout = oidcConfig.BrowserSessionIdleTimeout
		backChannelURI = oidcConfig.BackChannelLogoutURI
		backChannelAllowPrivate = oidcConfig.BackChannelLogoutAllowPrivate
		backChannelAllowHTTP = oidcConfig.BackChannelLogoutAllowHTTP
	}
	grants := []string{"authorization_code", "refresh_token", "client_credentials", DeviceGrantType}
	if oidcConfig != nil {
		grants = append(grants, TokenExchangeGrantType)
	}
	baseClient := &fosite.DefaultClient{
		ID: clientID, Secret: hash, RedirectURIs: []string{redirectURI},
		GrantTypes: grants, ResponseTypes: []string{"code"},
		Scopes: scopes, Audience: append([]string(nil), allowedResources...),
	}
	var client fosite.Client = baseClient
	if oidcConfig != nil && oidcConfig.ClientCredentialsTokenLifespan > 0 {
		client = &fosite.DefaultClientWithCustomTokenLifespans{DefaultClient: baseClient, TokenLifespans: &fosite.ClientLifespanConfig{
			ClientCredentialsGrantAccessTokenLifespan: &oidcConfig.ClientCredentialsTokenLifespan,
		}}
	}
	var cimds cimdResolver
	if oidcConfig != nil {
		cimds = oidcConfig.CIMD
	}
	dynamicConfig := dcr.Config{AllowRFC8252LoopbackRedirects: oidcConfig != nil && oidcConfig.RFC8252LoopbackRedirects, ReservedClientIDs: []string{clientID}}
	if oidcConfig != nil {
		dynamicConfig.ScopePolicy = oidcConfig.DynamicClientScopePolicy
	}
	store := &Store{db: db, client: client, dynamicClients: dcr.NewStore(db, dynamicConfig), cimd: cimds, now: time.Now, browserSessionIdleTimeout: idleTimeout, backChannelLogoutURI: backChannelURI, backChannelAllowPrivate: backChannelAllowPrivate, backChannelAllowHTTP: backChannelAllowHTTP}
	if oidcConfig != nil {
		store.managedClients = oidcConfig.ManagedClients
		store.bootstrapClientScopes = oidcConfig.BootstrapClientScopes
		store.customScopeExists = oidcConfig.CustomScopeExists
	}
	hmacAccessTokens := compose.NewOAuth2HMACStrategy(config)
	var accessTokens oauth2.CoreStrategy = hmacAccessTokens
	if oidcConfig != nil {
		accessTokens = newSignedAccessTokenStrategy(accessTokens, oidcConfig.Issuer, oidcConfig.LoadSigningKey, oidcConfig.LoadVerificationKeys, time.Now)
	}
	deviceHandler := newDeviceGrantHandler(store, device.NewStore(db), accessTokens, config, func(ctx context.Context, scope string) (bool, error) {
		return customUserScope(ctx, oidcConfig, clientID, scope)
	}, oidcConfig != nil)
	config.TokenEndpointHandlers.Append(deviceHandler)
	if oidcConfig != nil {
		config.TokenEndpointHandlers.Append(newTokenExchangeHandler(store, accessTokens, config, resources, defaults))
		if oidcConfig.PasswordUsers != nil {
			passwordHandler := newPasswordGrantHandler(store, oidcConfig.PasswordUsers, accessTokens, config)
			passwordHandler.onPasswordExpired = oidcConfig.PasswordExpired
			config.TokenEndpointHandlers.Append(passwordHandler)
		}
	}
	provider := compose.Compose(config, store, accessTokens,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		passwordRefreshFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
	)
	policy := redirecturi.Policy{}
	if oidcConfig != nil {
		policy.AllowLoopback = oidcConfig.RFC8252LoopbackRedirects
	}
	dangerResource := oidcConfig != nil && oidcConfig.CIMDDangerAllowUnvalidatedResource
	server := &Server{provider: provider, store: store, accessTokens: accessTokens, authorizeCodes: accessTokens, allowedResources: resources, defaultAudiences: defaults, ephemeralDangerAllowUnvalidatedResource: dangerResource, redirectPolicy: policy, oidc: oidcConfig, dpop: dpop.NewStore(db)}
	deviceHandler.validateResource = server.validateDeviceResource
	return server, nil
}

// Internal storage/transport failures are not OAuth protocol errors. Fosite's
// fallback code is "error"; normalize it without exposing the wrapped details.
func (s *Server) writeTokenError(ctx context.Context, w http.ResponseWriter, request fosite.AccessRequester, err error) {
	// Fosite wraps client lookup failures in invalid_client. Preserve availability
	// semantics using the underlying typed cause, never error-message matching.
	if errors.Is(err, rhiza.ErrQuorumUnavailable) || errors.Is(err, rhiza.ErrNotReady) ||
		errors.Is(err, rhiza.ErrDurabilityUnavailable) || errors.Is(err, rhiza.ErrCommitUnknown) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		err = fosite.ErrServerError
	}
	publicError := fosite.ErrorToRFC6749Error(err)
	if publicError.ErrorField == "error" && publicError.CodeField == http.StatusInternalServerError {
		publicError = fosite.ErrServerError
	}
	s.provider.WriteAccessError(ctx, w, request, publicError)
}

func (s *Server) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, span := tracing.NewTracer("goauthy/oauth").Start(r.Context(), "token",
			trace.WithAttributes(attribute.String("grant_type", r.PostForm.Get("grant_type"))),
		)
		defer span.End()
		// Retain the exact client snapshot used to authenticate this request.
		// Later grant loads must not hide a concurrent secret/policy change.
		r = r.WithContext(context.WithValue(r.Context(), managedClientSnapshotsKey{}, make(map[string]fosite.Client)))
		sw := &tokenStatusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if s.metrics == nil {
				return
			}
			if sw.status >= 200 && sw.status < 300 {
				s.metrics.TokenOK()
			} else {
				s.metrics.TokenReject()
			}
		}()
		if err := formRequest(sw, r); err != nil {
			s.writeTokenError(r.Context(), sw, fosite.NewAccessRequest(&fosite.DefaultSession{}), err)
			return
		}
		request, err := s.provider.NewAccessRequest(r.Context(), r, &fosite.DefaultSession{})
		responseStarted := false
		if request != nil && request.GetGrantTypes().ExactOne(DeviceGrantType) {
			if session, ok := request.GetSession().(*fosite.DefaultSession); ok {
				claim, _ := session.Extra[deviceClaimExtra].(string)
				defer func() {
					// Fosite claims during NewAccessRequest. Pre-issuance rejection
					// (including a DPoP nonce challenge) must allow a fresh retry.
					// Once NewAccessResponse starts, the grant handler owns cleanup;
					// never release here after a possibly committed transaction.
					if claim != "" && !responseStarted {
						if releaseErr := device.NewStore(s.store.db).Complete(r.Context(), claim, false, time.Now().UTC()); releaseErr != nil {
							slog.Error("Device pre-issuance claim release failed")
						}
					}
				}()
			}
		}
		if err != nil {
			s.writeTokenError(r.Context(), sw, request, err)
			return
		}
		if err := s.applyTokenResourceIndicator(request, r.PostForm); err != nil {
			s.writeTokenError(r.Context(), sw, request, err)
			return
		}
		if request.GetGrantTypes().ExactOne("client_credentials") && request.GetRequestedScopes().Has(openidScope) {
			s.writeTokenError(r.Context(), sw, request, fosite.ErrInvalidScope.WithHint("openid requires an authenticated end-user authorization grant."))
			return
		}
		if request.GetGrantTypes().ExactOne("client_credentials") && request.GetRequestedScopes().Has(groupsScope) {
			s.writeTokenError(r.Context(), sw, request, fosite.ErrInvalidScope.WithHint("groups requires an authenticated end-user authorization grant."))
			return
		}
		if request.GetGrantTypes().ExactOne("client_credentials") {
			custom, err := s.hasCustomUserScope(r.Context(), request.GetRequestedScopes())
			if err != nil {
				s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
				return
			}
			if custom {
				s.writeTokenError(r.Context(), sw, request, fosite.ErrInvalidScope.WithHint("custom user scopes require an authenticated end-user authorization grant."))
				return
			}
		}
		for _, scope := range request.GetRequestedScopes() {
			request.GrantScope(scope)
		}
		jkt, err := s.verifyDPoPTokenRequest(r.Context(), r, request)
		if err != nil {
			var nonceErr *dpopNonceError
			if errors.As(err, &nonceErr) {
				sw.Header().Set("DPoP-Nonce", nonceErr.nonce)
				s.writeTokenError(r.Context(), sw, request, errUseDPoPNonce)
				return
			}
			s.writeTokenError(r.Context(), sw, request, err)
			return
		}
		if client, dynamic := request.GetClient().(interface{ DPoPRequired() bool }); dynamic {
			if client.DPoPRequired() && jkt == "" {
				s.writeTokenError(r.Context(), sw, request, fosite.ErrInvalidRequest)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), dpopPolicyContextKey{}, dpopPolicySnapshot{clientID: request.GetClient().GetID(), proofPresent: jkt != ""}))
		}
		if jkt != "" {
			if err := setSessionDPoPJKT(request.GetSession(), jkt); err != nil {
				s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
				return
			}
		}
		_, machine, machineErr := machineTokenSubject(request)
		if machineErr != nil {
			s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
			return
		}
		if machine {
			if err := markMachineToken(request, s.oidc != nil && s.oidc.ClientCredentialsMapSub); err != nil {
				s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
				return
			}
		}
		principal, err := s.applyCurrentPrincipalClaims(r.Context(), request)
		if err != nil {
			slog.Error("OAuth principal resolution failed", "error", err)
			s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
			return
		}
		custom := customClaimsSnapshot{}
		if request.GetGrantTypes().ExactOne("authorization_code") || request.GetGrantTypes().ExactOne("refresh_token") || request.GetGrantTypes().ExactOne(DeviceGrantType) || request.GetGrantTypes().ExactOne("password") || (request.GetGrantTypes().ExactOne(TokenExchangeGrantType) && !machine) {
			custom, err = s.currentCustomClaims(r.Context(), request.GetSession().GetSubject(), request.GetGrantedScopes())
		}
		if err != nil || setCustomAccessClaims(request, custom.access) != nil {
			s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
			return
		}
		clientClaims := clientCredentialsClaimsSnapshot{}
		if request.GetGrantTypes().ExactOne("client_credentials") && request.GetClient().GetID() == s.store.client.GetID() {
			clientClaims, err = s.currentClientCredentialsClaims(r.Context(), request.GetClient().GetID())
			if err != nil || setClientCredentialsAccessClaims(request, clientClaims.claims) != nil {
				s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
				return
			}
			issueContext := context.WithValue(r.Context(), principalSnapshotContextKey{}, principalSnapshot{clientClaims: clientClaims})
			r = r.WithContext(context.WithValue(issueContext, clientCredentialsClaimsClientIDContextKey{}, request.GetClient().GetID()))
		}
		var policy ClientGroupPolicy
		var policySet bool
		if request.GetGrantTypes().ExactOne("authorization_code") || request.GetGrantTypes().ExactOne("refresh_token") || request.GetGrantTypes().ExactOne(DeviceGrantType) || request.GetGrantTypes().ExactOne("password") {
			policy, policySet, err = s.clientGroupPolicy(r.Context(), request.GetClient().GetID())
			if err != nil {
				slog.Error("OAuth client group policy resolution failed", "error", err)
				s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
				return
			}
			admissionClaims := principal
			if policy.Prefix != "" {
				session, ok := request.GetSession().(*fosite.DefaultSession)
				if !ok || session.Subject == "" {
					s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
					return
				}
				admissionClaims, err = s.currentPrincipal(r.Context(), session.Subject)
				if err != nil {
					slog.Error("OAuth principal admission resolution failed", "error", err)
					s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
					return
				}
				principal = admissionClaims
				if !request.GetGrantedScopes().Has(groupsScope) {
					principal.Groups = nil
				}
				if err := setPrincipalClaims(request, principal); err != nil {
					s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
					return
				}
			}
			if err := enforceClientGroupPolicy(admissionClaims, policy); err != nil {
				s.writeTokenError(r.Context(), sw, request, fosite.ErrAccessDenied)
				return
			}
		}
		if request.GetGrantTypes().ExactOne("authorization_code") || request.GetGrantTypes().ExactOne("refresh_token") {
			value, ok := exactlyOne(request.GetRequestForm(), "code")
			if request.GetGrantTypes().ExactOne("refresh_token") {
				value, ok = exactlyOne(request.GetRequestForm(), "refresh_token")
			}
			if !ok || (request.GetGrantTypes().ExactOne("authorization_code") && s.authorizeCodes == nil) {
				s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
				return
			}
			var signature string
			if request.GetGrantTypes().ExactOne("authorization_code") {
				signature = s.authorizeCodes.AuthorizeCodeSignature(r.Context(), value)
			} else if refresh, ok := s.accessTokens.(oauth2.RefreshTokenStrategy); ok {
				signature = refresh.RefreshTokenSignature(r.Context(), value)
			} else {
				s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
				return
			}
			session, ok := request.GetSession().(*fosite.DefaultSession)
			if !ok || session.Subject == "" {
				s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), principalSnapshotContextKey{}, principalSnapshot{signature: signature, subject: session.Subject, revision: principal.Revision, claims: principal, custom: custom, policy: policy, policySet: policySet, policyClientID: request.GetClient().GetID()}))
		}
		if request.GetGrantTypes().ExactOne("password") || request.GetGrantTypes().ExactOne(DeviceGrantType) || (request.GetGrantTypes().ExactOne(TokenExchangeGrantType) && !machine) {
			r = r.WithContext(context.WithValue(r.Context(), principalSnapshotContextKey{}, principalSnapshot{subject: request.GetSession().GetSubject(), revision: principal.Revision, claims: principal, custom: custom, policy: policy, policySet: policySet, policyClientID: request.GetClient().GetID()}))
		}
		issueContext, err := s.store.issuanceAccounts(r.Context(), request)
		if err != nil {
			s.writeTokenError(r.Context(), sw, request, fosite.ErrInvalidGrant)
			return
		}
		r = r.WithContext(issueContext)
		if s.beforeTokenIssue != nil {
			s.beforeTokenIssue()
		}
		var signingKey oidc.SigningKey
		idTokenNeeded := s.needsIDToken(request)
		if idTokenNeeded {
			signingKey, err = s.oidc.LoadSigningKey(r.Context())
			if err != nil {
				slog.Error("OIDC signing key load failed", "error", err)
				s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
				return
			}
			if _, err := s.signIDToken(r.Context(), request, signingKey, "preflight", principal, custom.id); err != nil {
				slog.Error("OIDC ID token preflight failed", "error", err)
				s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
				return
			}
		}
		responseStarted = true
		response, err := s.provider.NewAccessResponse(r.Context(), request)
		if err != nil {
			slog.Error("OAuth token issuance failed", "class", fosite.ErrorToRFC6749Error(err).Error())
			s.writeTokenError(r.Context(), sw, request, err)
			return
		}
		if idTokenNeeded {
			token, err := s.signIDToken(r.Context(), request, signingKey, response.GetAccessToken(), principal, custom.id)
			if err != nil {
				slog.Error("OIDC ID token signing failed", "error", err)
				s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
				return
			}
			response.SetExtra("id_token", token)
		}
		if jkt != "" {
			response.SetTokenType("DPoP")
			response.SetExtra(dpopCNFExtra, map[string]string{dpopJKTClaim: jkt})
		}
		if err := s.store.validateIssuanceAccounts(r.Context()); err != nil {
			s.writeTokenError(r.Context(), sw, request, fosite.ErrInvalidGrant)
			return
		}
		if accounts, _ := r.Context().Value(accountExpiryContextKey{}).([]accountExpiry); len(accounts) != 0 {
			remaining := request.GetSession().GetExpiresAt(fosite.AccessToken).Sub(s.store.now().UTC())
			if remaining <= 0 {
				s.writeTokenError(r.Context(), sw, request, fosite.ErrInvalidGrant)
				return
			}
			response.SetExpiresIn(remaining)
		}
		if err := s.emitTokenIssued(r.Context(), r.PostForm.Get("grant_type"), request.GetClient().GetID(), request.GetSession().GetSubject()); err != nil {
			slog.Error("OAuth token-issued event failed")
			s.writeTokenError(r.Context(), sw, request, fosite.ErrServerError)
			return
		}
		if r.PostForm.Get("grant_type") == "password" && s.passwordLoginObserver != nil {
			if err := s.passwordLoginObserver(sw, r, request.GetSession().GetSubject()); err != nil {
				s.writeTokenError(r.Context(), sw, request, err)
				return
			}
		}
		s.provider.WriteAccessResponse(r.Context(), sw, request, response)
	})
}

func resourceAllowList(resources []string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		if !validResourceURL(resource) {
			return nil, fmt.Errorf("invalid OAuth resource allow-list entry")
		}
		if _, duplicate := allowed[resource]; duplicate {
			return nil, fmt.Errorf("duplicate OAuth resource allow-list entry")
		}
		allowed[resource] = struct{}{}
	}
	return allowed, nil
}

func resourceDefaults(allowed map[string]struct{}, defaults map[string]string) (map[string]string, error) {
	validated := make(map[string]string, len(defaults))
	for clientID, resource := range defaults {
		if clientID == "" || len(clientID) > 2048 || strings.TrimSpace(clientID) != clientID || !validResourceURL(resource) {
			return nil, fmt.Errorf("invalid OAuth default audience")
		}
		if _, ok := allowed[resource]; !ok {
			return nil, fmt.Errorf("OAuth default audience is not in the resource allow-list")
		}
		validated[clientID] = resource
	}
	return validated, nil
}

func (s *Server) applyTokenResourceIndicator(request fosite.AccessRequester, form url.Values) error {
	if request.GetGrantTypes().ExactOne("password") || request.GetGrantTypes().ExactOne(TokenExchangeGrantType) {
		return nil
	}
	resources, hasResource := form["resource"]
	if len(form["audience"]) != 0 {
		return fosite.ErrInvalidRequest.WithHint("audience is not accepted; use resource at authorization or client_credentials token requests.")
	}
	if !hasResource {
		if request.GetGrantTypes().ExactOne("client_credentials") {
			return s.applyDefaultAudience(request)
		}
		return nil
	}
	if !request.GetGrantTypes().ExactOne("client_credentials") && !request.GetGrantTypes().ExactOne(TokenExchangeGrantType) {
		return errInvalidTarget.WithHint("resource narrowing at the token endpoint is not supported for this grant.")
	}
	return s.applyResourceAudience(request, resources)
}

func (s *Server) applyAuthorizationResourceIndicator(request fosite.AuthorizeRequester, form url.Values) error {
	if len(form["audience"]) != 0 {
		return fosite.ErrInvalidRequest.WithHint("audience is not accepted; use resource.")
	}
	resources, hasResource := form["resource"]
	if !hasResource {
		return s.applyDefaultAudience(request)
	}
	return s.applyResourceAudience(request, resources)
}

func (s *Server) applyDefaultAudience(request fosite.Requester) error {
	resource, configured := s.defaultAudiences[request.GetClient().GetID()]
	if !configured || len(request.GetRequestedAudience()) != 0 || len(request.GetGrantedAudience()) != 0 {
		return nil
	}
	return s.applyResourceAudience(request, []string{resource})
}

func (s *Server) applyResourceAudience(request fosite.Requester, resources []string) error {
	if len(resources) != 1 {
		return fosite.ErrInvalidRequest.WithHint("resource is accepted once per request.")
	}
	resource := resources[0]
	if !validResourceURL(resource) {
		return errInvalidTarget.WithHint("resource must be an absolute HTTPS URL without userinfo, query, or fragment.")
	}
	if client, ok := request.GetClient().(*clients.Client); ok && !containsExact(client.GetAudience(), resource) {
		return errInvalidTarget.WithHint("resource is not allowed for this OAuth client.")
	}
	ephemeralResource := false
	if ephemeral, ok := request.GetClient().(*ephemeralClient); ok {
		if ephemeral.metadata.AllowedResourcesPresent || ephemeral.metadata.AllowedResources != nil {
			if !containsExact(ephemeral.metadata.AllowedResources, resource) {
				return errInvalidTarget.WithHint("resource is not allowed for this OAuth client.")
			}
			ephemeralResource = true
		} else if !s.ephemeralDangerAllowUnvalidatedResource {
			return errInvalidTarget.WithHint("resource is not allowed for this OAuth client.")
		} else {
			ephemeralResource = true
		}
	}
	if !ephemeralResource {
		if _, allowed := s.allowedResources[resource]; !allowed {
			return errInvalidTarget.WithHint("resource is not allowed for this OAuth client.")
		}
	}
	request.SetRequestedAudience(fosite.Arguments{resource})
	request.GrantAudience(resource)
	return nil
}

const ephemeralAnyResourceAudience = "goauthy:ephemeral-any-resource"

func ephemeralAudienceMatchingStrategy(haystack, needle []string) error {
	for _, allowed := range haystack {
		if allowed == ephemeralAnyResourceAudience {
			return nil
		}
	}
	return fosite.DefaultAudienceMatchingStrategy(haystack, needle)
}

func containsExact(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validResourceURL(raw string) bool {
	u, err := url.ParseRequestURI(raw)
	return err == nil && len(raw) <= 2048 && !strings.ContainsFunc(raw, unicode.IsSpace) && u.IsAbs() && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(raw, "#")
}

// ValidateAuthorizationRequest validates an incoming request without issuing
// authorization state. The original request can later be passed unchanged to
// CompleteAuthorization after login and consent.
func (s *Server) ValidateAuthorizationRequest(r *http.Request) (AuthorizationRequest, error) {
	authorizeRequest, err := s.validatedAuthorizationRequest(r)
	if err != nil {
		return AuthorizationRequest{}, ErrInvalidAuthorizationRequest
	}
	view, err := s.authorizationRequestView(r.Context(), authorizeRequest)
	if err != nil {
		return AuthorizationRequest{}, ErrInvalidAuthorizationRequest
	}
	return view, nil
}

// ValidateAuthorizationRequestForLogin validates an authorization request for
// the browser login endpoint. It writes an invalid_target protocol error only
// when Fosite has established a registered redirect URI. Other malformed
// requests, including PKCE failures, and unregistered redirect URIs remain a
// local 400 response. It does not issue authorization state and parses the
// request exactly once.
func (s *Server) ValidateAuthorizationRequestForLogin(w http.ResponseWriter, r *http.Request) (AuthorizationRequest, bool) {
	authorizeRequest, err := s.validatedAuthorizationRequest(r)
	if err != nil {
		if isInvalidTargetError(err) {
			s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, err)
		} else {
			http.Error(w, "Invalid authorization request", http.StatusBadRequest)
		}
		return AuthorizationRequest{}, false
	}
	view, err := s.authorizationRequestView(r.Context(), authorizeRequest)
	if err != nil {
		// The request and callback have already been validated. Do not expose a
		// storage failure through the browser endpoint.
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrServerError)
		return AuthorizationRequest{}, false
	}
	return view, true
}

func isInvalidTargetError(err error) bool {
	var oauthErr *fosite.RFC6749Error
	return errors.As(err, &oauthErr) && oauthErr.ErrorField == errInvalidTarget.ErrorField
}

func (s *Server) validatedAuthorizationRequest(r *http.Request) (fosite.AuthorizeRequester, error) {
	authorizeRequest, err := s.parseAuthorizationRequest(r)
	if err != nil {
		return authorizeRequest, err
	}
	txCtx, err := s.store.BeginTX(r.Context())
	if err != nil {
		return authorizeRequest, err
	}
	_, err = s.provider.NewAuthorizeResponse(txCtx, authorizeRequest, &fosite.DefaultSession{})
	rollbackErr := s.store.Rollback(txCtx)
	if err != nil {
		return authorizeRequest, err
	}
	if rollbackErr != nil {
		return authorizeRequest, rollbackErr
	}
	return authorizeRequest, nil
}

func (s *Server) authorizationRequestView(ctx context.Context, authorizeRequest fosite.AuthorizeRequester) (AuthorizationRequest, error) {
	resources := append([]string(nil), authorizeRequest.GetRequestedAudience()...)
	prompt, maxAge, err := authorizationPromptAndMaxAge(authorizeRequest.GetRequestForm())
	if err != nil {
		return AuthorizationRequest{}, err
	}
	forceMFA := s.forceMFA(authorizeRequest.GetClient())
	return AuthorizationRequest{
		ClientID:           authorizeRequest.GetClient().GetID(),
		RedirectURI:        authorizeRequest.GetRedirectURI().String(),
		RequestID:          authorizeRequest.GetID(),
		RequestedScopes:    append([]string(nil), authorizeRequest.GetRequestedScopes()...),
		RequestedResources: resources,
		Prompt:             prompt,
		MaxAgeSeconds:      maxAge,
		ForceMFA:           forceMFA,
	}, nil
}

// forceMFA reads the MFA policy from the exact client snapshot Fosite resolved
// for this request. A separate managed-client lookup could fail on its own and
// silently downgrade a force-MFA client to "MFA not required"; the snapshot
// read already fails the whole request when that client cannot be loaded.
func (s *Server) forceMFA(client fosite.Client) bool {
	if client.GetID() == s.store.client.GetID() {
		return s.oidc != nil && s.oidc.BootstrapForceMFA
	}
	if managed, ok := client.(*clients.Client); ok {
		return managed.ForceMFA
	}
	// Dynamic registration never admits a force_mfa policy. This also ignores
	// legacy rows written before that public metadata was removed.
	return false
}

func (s *Server) parseAuthorizationRequest(r *http.Request) (fosite.AuthorizeRequester, error) {
	if err := r.ParseForm(); err != nil {
		return fosite.NewAuthorizeRequest(), fosite.ErrInvalidRequest.WithHint("invalid authorization request")
	}
	if r.Form.Get("client_id") == s.store.client.GetID() && r.Form.Get("scope") == "" && s.store.bootstrapClientScopes != nil {
		policy, err := s.store.bootstrapClientScopes(r.Context(), s.store.client.GetID())
		if err != nil || policy.ClientID != s.store.client.GetID() || policy.Revision < 0 {
			return fosite.NewAuthorizeRequest(), fosite.ErrInvalidRequest
		}
		if len(policy.Default) != 0 {
			r.Form.Set("scope", strings.Join(policy.Default, " "))
		}
	}
	if _, provided := r.Form["scope"]; !provided {
		clientID := r.Form.Get("client_id")
		managed := false
		if s.store.managedClients != nil {
			owned, err := s.store.managedClients.Owns(r.Context(), clientID)
			if err != nil {
				return fosite.NewAuthorizeRequest(), fosite.ErrInvalidRequest
			}
			if owned {
				managed = true
				client, err := s.store.managedClients.GetClient(r.Context(), clientID)
				if err != nil {
					return fosite.NewAuthorizeRequest(), fosite.ErrInvalidRequest
				}
				if c, ok := client.(*clients.Client); ok && len(c.DefaultScopes) != 0 {
					r.Form.Set("scope", strings.Join(c.DefaultScopes, " "))
				}
			}
		}
		if !managed {
			defaults, err := s.store.dynamicClients.DefaultScopes(r.Context(), clientID)
			if err == nil && len(defaults) != 0 {
				r.Form.Set("scope", strings.Join(defaults, " "))
			} else if err != nil && !errors.Is(err, fosite.ErrNotFound) {
				return fosite.NewAuthorizeRequest(), fosite.ErrInvalidRequest
			}
		}
	}
	if err := s.store.resolveCIMDAuthorizationClient(r.Context(), r.Form.Get("client_id")); err != nil {
		// Deliberately log only the fixed failure class: client IDs and resolver
		// errors can contain untrusted URLs, database details, or credentials.
		log.Printf("oauth CIMD prefetch failed stage=%s", cimdPrefetchFailureStage(err))
		// Do not redirect to a document-supplied URI when metadata resolution
		// failed or was rejected.
		return fosite.NewAuthorizeRequest(), fosite.ErrInvalidRequest.WithHint("invalid client metadata document")
	}
	client, clientErr := s.store.GetClient(r.Context(), r.Form.Get("client_id"))
	if clientErr != nil {
		class := "storage"
		switch {
		case errors.Is(clientErr, fosite.ErrNotFound):
			class = "not_found"
		case errors.Is(clientErr, rhiza.ErrInvalidRequest):
			class = "invalid_request"
		case errors.Is(clientErr, rhiza.ErrQuorumUnavailable):
			class = "quorum_unavailable"
		case errors.Is(clientErr, rhiza.ErrNotReady):
			class = "not_ready"
		case errors.Is(clientErr, rhiza.ErrDurabilityUnavailable):
			class = "durability_unavailable"
		}
		if strings.Contains(clientErr.Error(), "no such savepoint") {
			class = "savepoint_unavailable"
		}
		log.Printf("oauth authorization client lookup failed class=%s", class)
	}
	redirectURI := r.Form.Get("redirect_uri")
	if redirectURI == "" {
		// A port-less RFC 8252 URI is a template, not a usable callback. Require
		// native clients to send the concrete runtime port explicitly.
		if clientErr == nil && s.publicDynamicClient(client) {
			for _, registered := range client.GetRedirectURIs() {
				if redirecturi.IsPortlessLoopbackTemplate(registered) {
					return fosite.NewAuthorizeRequest(), fosite.ErrInvalidRequest.WithHint("redirect_uri is required for loopback clients")
				}
			}
		}
	} else if clientErr == nil && !s.redirectPolicy.Matches(client.GetRedirectURIs(), redirectURI, s.publicDynamicClient(client)) {
		// Returning an empty requester keeps Fosite from redirecting an error to
		// the URI that this policy rejected.
		return fosite.NewAuthorizeRequest(), fosite.ErrInvalidRequest.WithHint("redirect_uri does not match a registered redirect URI")
	}
	authorizeRequest, err := s.provider.NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		class := "other"
		var oauthErr *fosite.RFC6749Error
		if errors.As(err, &oauthErr) {
			class = oauthErr.ErrorField
		}
		log.Printf("oauth authorization validation failed class=%s", class)
		return authorizeRequest, err
	}
	if err := s.applyAuthorizationResourceIndicator(authorizeRequest, authorizeRequest.GetRequestForm()); err != nil {
		return authorizeRequest, err
	}
	if _, _, err := authorizationPromptAndMaxAge(authorizeRequest.GetRequestForm()); err != nil {
		return authorizeRequest, err
	}
	if err := authorizationNonce(authorizeRequest.GetRequestForm(), authorizeRequest.GetRequestedScopes().Has(openidScope)); err != nil {
		return authorizeRequest, err
	}
	return authorizeRequest, nil
}

func (s *Server) publicDynamicClient(client fosite.Client) bool {
	return !isEphemeralClient(client) && client.GetID() != s.store.client.GetID() && client.IsPublic()
}

func authorizationNonce(form url.Values, openid bool) error {
	if !openid {
		return nil
	}
	nonces, found := form["nonce"]
	if !found {
		return nil
	}
	if len(nonces) != 1 || nonces[0] == "" || len(nonces[0]) > maxNonceLength {
		return fosite.ErrInvalidRequest.WithHint("nonce must be supplied once and be between 1 and 512 bytes.")
	}
	return nil
}

func authorizationPromptAndMaxAge(form url.Values) ([]string, *int64, error) {
	promptValues, hasPrompt := form["prompt"]
	var prompt []string
	if hasPrompt {
		if len(promptValues) != 1 || len(strings.Fields(promptValues[0])) == 0 {
			return nil, nil, fosite.ErrInvalidRequest.WithHint("prompt must be specified once.")
		}
		seen := make(map[string]struct{})
		for _, value := range strings.Fields(promptValues[0]) {
			if value != "none" && value != "login" && value != "consent" {
				return nil, nil, fosite.ErrInvalidRequest.WithHint("prompt contains an unsupported value.")
			}
			if _, duplicate := seen[value]; duplicate {
				return nil, nil, fosite.ErrInvalidRequest.WithHint("prompt contains a duplicate value.")
			}
			seen[value] = struct{}{}
			prompt = append(prompt, value)
		}
		if _, none := seen["none"]; none && len(prompt) != 1 {
			return nil, nil, fosite.ErrInvalidRequest.WithHint("prompt=none must not be combined with other values.")
		}
	}
	maxAgeValues, hasMaxAge := form["max_age"]
	if !hasMaxAge {
		return prompt, nil, nil
	}
	if len(maxAgeValues) != 1 || maxAgeValues[0] == "" {
		return nil, nil, fosite.ErrInvalidRequest.WithHint("max_age must be specified once as a non-negative integer.")
	}
	for _, digit := range maxAgeValues[0] {
		if digit < '0' || digit > '9' {
			return nil, nil, fosite.ErrInvalidRequest.WithHint("max_age must be a non-negative integer.")
		}
	}
	maxAge, err := strconv.ParseInt(maxAgeValues[0], 10, 64)
	if err != nil || maxAge > maxAuthorizationMaxAgeSeconds {
		return nil, nil, fosite.ErrInvalidRequest.WithHint("max_age exceeds the supported maximum.")
	}
	return prompt, &maxAge, nil
}

// CompleteAuthorization completes an already-authenticated user's consent.
// The login/session layer must supply the subject and approved scopes; this
// method never authenticates a browser request by itself.
func (s *Server) CompleteAuthorization(w http.ResponseWriter, r *http.Request, subject string, approvedScopes []string) {
	s.completeAuthorization(w, r, subject, approvedScopes, time.Time{}, "", "", false)
}

// CompleteAuthorizationWithSession binds an OAuth or OIDC authorization to the
// authenticated browser session without exposing its raw cookie token.
func (s *Server) CompleteAuthorizationWithSession(w http.ResponseWriter, r *http.Request, subject string, approvedScopes []string, authTime time.Time, sessionID, authMethod string) {
	s.completeAuthorization(w, r, subject, approvedScopes, authTime, sessionID, authMethod, true)
}

func (s *Server) completeAuthorization(w http.ResponseWriter, r *http.Request, subject string, approvedScopes []string, authTime time.Time, sessionID, authMethod string, sessionBound bool) {
	authorizeRequest, err := s.parseAuthorizationRequest(r)
	if err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, err)
		return
	}
	if subject == "" {
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrAccessDenied.WithHint("Authentication is required."))
		return
	}
	approved := make(map[string]bool, len(approvedScopes))
	for _, scope := range approvedScopes {
		approved[scope] = true
	}
	for _, scope := range authorizeRequest.GetRequestedScopes() {
		if approved[scope] {
			authorizeRequest.GrantScope(scope)
		}
	}
	policy, policySet, err := s.clientGroupPolicy(r.Context(), authorizeRequest.GetClient().GetID())
	if err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrServerError)
		return
	}
	issueContext := r.Context()
	principal := PrincipalClaims{}
	custom, customErr := s.currentCustomClaims(issueContext, subject, authorizeRequest.GetGrantedScopes())
	if customErr != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrServerError)
		return
	}
	if custom.enabled {
		principal, err = s.currentPrincipal(issueContext, subject)
		if err != nil {
			s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrServerError)
			return
		}
	}
	if policySet {
		if policy.Prefix != "" {
			principal, err = s.currentPrincipal(issueContext, subject)
			if err != nil {
				s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrServerError)
				return
			}
			if err := enforceClientGroupPolicy(principal, policy); err != nil {
				s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrAccessDenied)
				return
			}
		}
		issueContext = context.WithValue(issueContext, principalSnapshotContextKey{}, principalSnapshot{subject: subject, revision: principal.Revision, claims: principal, custom: custom, policy: policy, policySet: true, policyClientID: authorizeRequest.GetClient().GetID()})
	} else if custom.enabled {
		issueContext = context.WithValue(issueContext, principalSnapshotContextKey{}, principalSnapshot{subject: subject, revision: principal.Revision, claims: principal, custom: custom})
	}
	issueContext, err = s.store.accountContext(issueContext, subject)
	if err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrAccessDenied)
		return
	}
	// Capture the raw identity_user_profiles snapshot BEFORE ResolveProfile
	// and NeedsProfileUpdate. The snapshot fences the code commit so a
	// concurrent profile mutation cannot issue a code on a stale profile.
	if s.needsProfileUpdate != nil && s.userValuesPolicy.RevalidateDuringLogin && authorizeRequest.GetClient().GetID() != "rauthy" {
		profileSnap, snapErr := s.store.captureProfileSnapshot(issueContext, subject)
		if snapErr != nil {
			s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrServerError)
			return
		}
		issueContext = context.WithValue(issueContext, profileRevalidationContextKey{}, profileSnap)
		needs, checkErr := s.needsProfileUpdate(issueContext, s.userValuesPolicy, subject, authorizeRequest.GetClient().GetID())
		if checkErr != nil {
			s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrServerError)
			return
		}
		if needs {
			s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, errInteractionRequired)
			return
		}
	}
	if s.beforeAuthorizationIssue != nil {
		s.beforeAuthorizationIssue()
	}

	session := &fosite.DefaultSession{Subject: subject, Username: subject}
	if sessionBound && !validOIDCSessionID(sessionID) {
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrServerError)
		return
	}
	if sessionID != "" {
		if !validOIDCSessionID(sessionID) {
			s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrServerError)
			return
		}
		session.Extra = map[string]interface{}{oidcSessionIDExtra: sessionID}
	}
	// Enforce the authentication strength against the client snapshot Fosite
	// just resolved for this issuance, not the view the login layer rendered.
	// The login layer already refuses session reuse without MFA, but a stale or
	// unavailable policy read must never let a password-only session mint an
	// authorization code for a force-MFA client revision.
	if s.forceMFA(authorizeRequest.GetClient()) && authMethod != oidcAuthMethodMFA {
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrAccessDenied.WithHint("MFA is required."))
		return
	}
	if s.oidc != nil && approved[openidScope] && authorizeRequest.GetRequestedScopes().Has(openidScope) {
		if authTime.IsZero() || sessionID == "" || !validOIDCAuthMethod(authMethod) {
			s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrServerError)
			return
		}
		session.Extra = map[string]interface{}{
			oidcSessionIDExtra:  sessionID,
			oidcNonceExtra:      authorizeRequest.GetRequestForm().Get("nonce"),
			oidcAuthTimeExtra:   strconv.FormatInt(authTime.UTC().Unix(), 10),
			oidcAuthMethodExtra: authMethod,
		}
	}
	txCtx, err := s.store.BeginTX(issueContext)
	if err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, err)
		return
	}
	response, err := s.provider.NewAuthorizeResponse(txCtx, authorizeRequest, session)
	if err == nil {
		err = s.store.Commit(txCtx)
	}
	if err != nil {
		_ = s.store.Rollback(txCtx)
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, err)
		return
	}
	if err := s.store.validateIssuanceAccounts(txCtx); err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrAccessDenied)
		return
	}
	s.provider.WriteAuthorizeResponse(r.Context(), w, authorizeRequest, response)
}

func (s *Server) needsIDToken(request fosite.AccessRequester) bool {
	if session, ok := request.GetSession().(*fosite.DefaultSession); ok && s.oidc != nil {
		if _, passwordOrigin := session.Extra[passwordAuthTimeExtra]; passwordOrigin && (request.GetGrantTypes().ExactOne("password") || request.GetGrantTypes().ExactOne("refresh_token")) {
			return true
		}
	}
	return s.oidc != nil && (request.GetGrantTypes().ExactOne("authorization_code") || request.GetGrantTypes().ExactOne("refresh_token") || request.GetGrantTypes().ExactOne(DeviceGrantType)) && request.GetGrantedScopes().Has(openidScope)
}

func (s *Server) applyCurrentPrincipalClaims(ctx context.Context, request fosite.AccessRequester) (PrincipalClaims, error) {
	if request.GetGrantTypes().ExactOne(TokenExchangeGrantType) {
		if _, machine, err := machineTokenSubject(request); err != nil || machine {
			return PrincipalClaims{}, err
		}
	}
	if s.oidc == nil || (!request.GetGrantTypes().ExactOne("authorization_code") && !request.GetGrantTypes().ExactOne("refresh_token") && !request.GetGrantTypes().ExactOne(DeviceGrantType) && !request.GetGrantTypes().ExactOne(TokenExchangeGrantType) && !request.GetGrantTypes().ExactOne("password")) {
		return PrincipalClaims{}, nil
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok || session.Subject == "" {
		return PrincipalClaims{}, errors.New("end-user OAuth session is missing")
	}
	claims, err := s.currentPrincipal(ctx, session.Subject)
	if err != nil {
		return PrincipalClaims{}, err
	}
	emittedClaims := claims
	if !request.GetGrantedScopes().Has(groupsScope) {
		emittedClaims.Groups = nil
	}
	if err := setPrincipalClaims(request, emittedClaims); err != nil {
		return PrincipalClaims{}, err
	}
	return emittedClaims, nil
}

func (s *Server) currentPrincipal(ctx context.Context, subject string) (PrincipalClaims, error) {
	claims := PrincipalClaims{Roles: []string{}}
	if s.oidc == nil || s.oidc.ResolvePrincipal == nil {
		if s.oidc != nil && s.oidc.ResolveCustomClaims != nil {
			// Attribute changes share the principal revision even when role/group
			// resolution is disabled. Capture it before resolving custom values.
			rows, err := s.store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COALESCE((SELECT revision FROM rbac_principal_versions WHERE subject=?),1) FROM identity_users WHERE subject=? AND disabled=0`, Args: []any{subject, subject}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
				return PrincipalClaims{}, errors.New("resolve custom principal revision")
			}
			var ok bool
			if claims.Revision, ok = rows.Rows[0][0].(int64); !ok || claims.Revision < 1 {
				return PrincipalClaims{}, errors.New("custom principal revision is invalid")
			}
		}
		return claims, nil
	}
	var err error
	claims, err = s.oidc.ResolvePrincipal(ctx, subject)
	if err != nil {
		return PrincipalClaims{}, fmt.Errorf("resolve principal: %w", err)
	}
	if claims.Revision < 1 {
		return PrincipalClaims{}, errors.New("principal revision is invalid")
	}
	return canonicalPrincipalClaims(claims)
}

func (s *Server) currentCustomClaims(ctx context.Context, subject string, granted []string) (customClaimsSnapshot, error) {
	if s.oidc == nil || s.oidc.ResolveCustomClaims == nil || subject == "" {
		return customClaimsSnapshot{}, nil
	}
	resolved, err := s.oidc.ResolveCustomClaims(ctx, subject, append([]string(nil), granted...))
	if err != nil || resolved.CatalogRevision < 0 {
		return customClaimsSnapshot{}, errors.New("resolve custom claims")
	}
	id, err := oidc.NormalizeCustomClaims(oidc.CustomClaims{Nested: resolved.ID, Root: resolved.IDRoot})
	if err != nil {
		return customClaimsSnapshot{}, err
	}
	access, err := oidc.NormalizeCustomClaims(oidc.CustomClaims{Nested: resolved.Access, Root: resolved.AccessRoot})
	if err != nil {
		return customClaimsSnapshot{}, err
	}
	return customClaimsSnapshot{id: id, access: access, catalogRevision: resolved.CatalogRevision, enabled: true}, nil
}

func (s *Server) currentClientCredentialsClaims(ctx context.Context, clientID string) (clientCredentialsClaimsSnapshot, error) {
	if s.oidc == nil || s.oidc.ResolveClientCredentialsClaims == nil {
		return clientCredentialsClaimsSnapshot{}, nil
	}
	resolved, err := s.oidc.ResolveClientCredentialsClaims(ctx, clientID)
	if err != nil || resolved.ClientID != clientID || resolved.Revision < 0 {
		return clientCredentialsClaimsSnapshot{}, errors.New("resolve client credentials claims")
	}
	custom, err := oidc.NormalizeCustomClaims(oidc.CustomClaims{Values: resolved.Values, AtRoot: resolved.AtRoot})
	if err != nil {
		return clientCredentialsClaimsSnapshot{}, err
	}
	return clientCredentialsClaimsSnapshot{claims: custom, revision: resolved.Revision, set: true}, nil
}

func (s *Server) hasCustomUserScope(ctx context.Context, scopes []string) (bool, error) {
	if s == nil || s.store == nil {
		return false, errors.New("custom scope policy is unavailable")
	}
	for _, scope := range scopes {
		custom, err := customUserScope(ctx, s.oidc, s.store.client.GetID(), scope)
		if err != nil || custom {
			return custom, err
		}
	}
	return false, nil
}

func customUserScope(ctx context.Context, config *OIDCConfig, clientID, scope string) (bool, error) {
	if config == nil || standardScope(scope) {
		return false, nil
	}
	if config.CustomScopeExists != nil {
		exists, err := config.CustomScopeExists(ctx, scope)
		if err != nil {
			return false, errors.New("lookup custom scope")
		}
		return exists, nil
	}
	if config.BootstrapClientScopes == nil {
		return false, nil
	}
	policy, err := config.BootstrapClientScopes(ctx, clientID)
	if err != nil || policy.ClientID != clientID || policy.Revision < 0 {
		return false, errors.New("invalid bootstrap custom scopes")
	}
	return containsScope(policy.Allowed, scope), nil
}

func standardScope(scope string) bool {
	switch scope {
	case "address", "email", groupsScope, openidScope, "phone", "profile", "offline_access", "goauthy.read":
		return true
	default:
		return false
	}
}

func setCustomAccessClaims(request fosite.Requester, custom oidc.CustomClaims) error {
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return errors.New("custom claim session is invalid")
	}
	if session.Extra == nil {
		session.Extra = map[string]interface{}{}
	}
	for _, name := range customRootNames(session.Extra) {
		delete(session.Extra, name)
	}
	delete(session.Extra, "custom")
	delete(session.Extra, "goauthy_custom_root")
	if len(custom.Nested) != 0 {
		session.Extra["custom"] = custom.Nested
	}
	if len(custom.Root) != 0 {
		names := make([]string, 0, len(custom.Root))
		for name, value := range custom.Root {
			if _, exists := session.Extra[name]; exists {
				return errors.New("custom root claim collision")
			}
			session.Extra[name], names = value, append(names, name)
		}
		sort.Strings(names)
		session.Extra["goauthy_custom_root"] = names
	}
	return nil
}

const (
	clientCredentialsClaimsExtra       = "goauthy_client_credentials_claims"
	clientCredentialsClaimsAtRootExtra = "goauthy_client_credentials_claims_at_root"
)

func setClientCredentialsAccessClaims(request fosite.Requester, custom oidc.CustomClaims) error {
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return errors.New("client credentials claim session is invalid")
	}
	if session.Extra == nil {
		session.Extra = map[string]interface{}{}
	}
	delete(session.Extra, clientCredentialsClaimsExtra)
	delete(session.Extra, clientCredentialsClaimsAtRootExtra)
	if len(custom.Values) == 0 {
		return nil
	}
	session.Extra[clientCredentialsClaimsExtra] = custom.Values
	session.Extra[clientCredentialsClaimsAtRootExtra] = custom.AtRoot
	return nil
}

func addCustomClaims(response map[string]any, custom oidc.CustomClaims) error {
	if len(custom.Nested) != 0 {
		if _, exists := response["custom"]; exists {
			return errors.New("custom nested claim collision")
		}
		response["custom"] = custom.Nested
	}
	for name, value := range custom.Root {
		if _, exists := response[name]; exists {
			return errors.New("custom root claim collision")
		}
		response[name] = value
	}
	return nil
}

func customRootNames(extra map[string]interface{}) []string {
	switch raw := extra["goauthy_custom_root"].(type) {
	case []string:
		return raw
	case []interface{}:
		names := make([]string, 0, len(raw))
		for _, value := range raw {
			name, ok := value.(string)
			if !ok {
				return nil
			}
			names = append(names, name)
		}
		return names
	default:
		return nil
	}
}

func (s *Server) clientGroupPolicy(ctx context.Context, clientID string) (ClientGroupPolicy, bool, error) {
	if s.store.managedClients != nil {
		owned, err := s.store.managedClients.Owns(ctx, clientID)
		if err != nil {
			return ClientGroupPolicy{}, false, err
		}
		if owned {
			resolved, err := s.store.GetClient(ctx, clientID)
			if err != nil {
				return ClientGroupPolicy{}, false, err
			}
			client, ok := resolved.(*clients.Client)
			if !ok {
				return ClientGroupPolicy{}, false, errors.New("invalid managed client policy")
			}
			policy := ClientGroupPolicy{managedClient: true, Revision: client.Revision}
			if client.RestrictGroupPrefix != nil {
				policy.Prefix = *client.RestrictGroupPrefix
			}
			return policy, true, nil
		}
	}

	if s.oidc == nil || s.oidc.ClientGroupPolicy == nil {
		return ClientGroupPolicy{}, false, nil
	}
	policy, err := s.oidc.ClientGroupPolicy(ctx, clientID)
	if err != nil {
		return ClientGroupPolicy{}, false, err
	}
	if !policy.Managed {
		if policy.Revision != 0 || policy.Prefix != "" {
			return ClientGroupPolicy{}, false, errors.New("unmanaged client group policy is not empty")
		}
		return ClientGroupPolicy{}, false, nil
	}
	if policy.Revision == 0 && policy.Prefix == "" {
		return policy, true, nil
	}
	if policy.Revision < 1 {
		return ClientGroupPolicy{}, false, errors.New("invalid client group policy")
	}
	return policy, true, nil
}

func enforceClientGroupPolicy(claims PrincipalClaims, policy ClientGroupPolicy) error {
	if policy.Revision == 0 || policy.Prefix == "" {
		return nil
	}
	if claims.Revision < 1 {
		return errors.New("principal revision is invalid")
	}
	for _, group := range claims.Groups {
		if strings.HasPrefix(group, policy.Prefix) {
			return nil
		}
	}
	return errors.New("client group policy denied")
}

func setPrincipalClaims(request fosite.Requester, claims PrincipalClaims) error {
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return errors.New("principal session is invalid")
	}
	if session.Extra == nil {
		session.Extra = make(map[string]interface{})
	}
	// []string is a simple JSON value for opaque-token introspection.
	session.Extra["roles"] = claims.Roles
	if request.GetGrantedScopes().Has(groupsScope) && claims.Groups != nil {
		session.Extra["groups"] = claims.Groups
	} else {
		delete(session.Extra, "groups")
	}
	return nil
}

func canonicalPrincipalClaims(claims PrincipalClaims) (PrincipalClaims, error) {
	roles, err := canonicalClaimValues(claims.Roles, principalRolePattern)
	if err != nil {
		return PrincipalClaims{}, err
	}
	groups, err := canonicalClaimValues(claims.Groups, principalGroupPattern)
	if err != nil {
		return PrincipalClaims{}, err
	}
	return PrincipalClaims{Roles: roles, Groups: groups, Revision: claims.Revision}, nil
}

func canonicalClaimValues(values []string, pattern *regexp.Regexp) ([]string, error) {
	if len(values) > 64 {
		return nil, errors.New("too many principal claims")
	}
	result := append([]string(nil), values...)
	for _, value := range result {
		if !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.IndexFunc(value, unicode.IsControl) >= 0 || !pattern.MatchString(value) {
			return nil, errors.New("invalid principal claim")
		}
	}
	sort.Strings(result)
	for i := 1; i < len(result); i++ {
		if result[i-1] == result[i] {
			return nil, errors.New("duplicate principal claim")
		}
	}
	if result == nil {
		return []string{}, nil
	}
	return result, nil
}

func (s *Server) signIDToken(ctx context.Context, request fosite.AccessRequester, signingKey oidc.SigningKey, accessToken string, principal PrincipalClaims, custom oidc.CustomClaims) (string, error) {
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok || session.Subject == "" {
		return "", errors.New("OIDC session is missing")
	}
	var authTime time.Time
	var sessionID, nonce string
	var methods []string
	var err error
	deviceOrigin, _ := session.Extra[deviceOIDCExtra].(bool)
	if deviceOrigin && !request.GetGrantTypes().ExactOne(DeviceGrantType) && !request.GetGrantTypes().ExactOne("refresh_token") {
		return "", errors.New("invalid device OIDC grant origin")
	}
	passwordRaw, passwordOrigin := session.Extra[passwordAuthTimeExtra]
	if passwordOrigin {
		raw, ok := passwordRaw.(string)
		seconds, parseErr := strconv.ParseInt(raw, 10, 64)
		if !ok || parseErr != nil || seconds <= 0 || deviceOrigin || (!request.GetGrantTypes().ExactOne("password") && !request.GetGrantTypes().ExactOne("refresh_token")) {
			return "", errors.New("invalid password OIDC grant origin")
		}
		authTime = time.Unix(seconds, 0).UTC()
		methods = []string{oidcAuthMethodPwd}
	} else if !deviceOrigin {
		var authMethod string
		authTime, sessionID, nonce, authMethod, err = oidcSessionClaims(session.Extra)
		if err != nil {
			return "", err
		}
		methods = []string{oidcAMR(authMethod)}
	}
	if request.GetGrantTypes().ExactOne("refresh_token") {
		nonce = ""
	}
	now := time.Now().UTC()
	expires := now.Add(oidc.MaxIDTokenLifetime)
	if limit := accountDeadline(ctx); !limit.IsZero() && limit.Before(expires) {
		expires = limit
	}
	profile := oidc.ProfileClaims{}
	if s.oidc.ResolveProfile != nil && request.GetGrantedScopes().HasOneOf("profile", "email", "address", "phone") {
		profile, err = s.oidc.ResolveProfile(ctx, session.Subject)
		if err != nil {
			return "", fmt.Errorf("resolve OIDC profile: %w", err)
		}
	}
	profile = scopedProfile(profile, request.GetGrantedScopes())
	return oidc.SignIDToken(signingKey, oidc.IDTokenClaims{
		Issuer: s.oidc.Issuer, Subject: session.Subject, Audience: []string{request.GetClient().GetID()},
		IssuedAt: now, NotBefore: now, ExpiresAt: expires, Nonce: nonce,
		AuthTime: authTime, AuthorizedParty: request.GetClient().GetID(), SessionID: sessionID,
		AccessTokenHash: oidc.AccessTokenHash(accessToken), AuthenticationMethods: methods,
		Roles: principal.Roles, Groups: principal.Groups,
		CustomClaims: custom, Profile: profile,
	})
}

func scopedProfile(profile oidc.ProfileClaims, scopes fosite.Arguments) oidc.ProfileClaims {
	if !scopes.Has("email") {
		profile.Email, profile.EmailVerified = nil, nil
	}
	if !scopes.Has("profile") {
		profile.PreferredUsername, profile.GivenName, profile.FamilyName = nil, nil, nil
		profile.Birthdate, profile.Zoneinfo, profile.Locale = nil, nil, nil
	}
	if !scopes.Has("address") {
		profile.Address = nil
	}
	if !scopes.Has("phone") {
		profile.PhoneNumber, profile.PhoneNumberVerified = nil, nil
	}
	return profile
}

func oidcSessionClaims(extra map[string]interface{}) (time.Time, string, string, string, error) {
	if extra == nil {
		return time.Time{}, "", "", "", errors.New("OIDC session claims are missing")
	}
	authRaw, authOK := extra[oidcAuthTimeExtra].(string)
	sessionID, sessionOK := extra[oidcSessionIDExtra].(string)
	nonce, nonceOK := extra[oidcNonceExtra].(string)
	authMethod, methodOK := extra[oidcAuthMethodExtra].(string)
	seconds, err := strconv.ParseInt(authRaw, 10, 64)
	if !authOK || !sessionOK || !nonceOK || !methodOK || sessionID == "" || !validOIDCAuthMethod(authMethod) || err != nil {
		return time.Time{}, "", "", "", errors.New("OIDC session claims are invalid")
	}
	return time.Unix(seconds, 0).UTC(), sessionID, nonce, authMethod, nil
}

func validOIDCAuthMethod(method string) bool {
	return method == oidcAuthMethodPwd || method == oidcAuthMethodWebAuthn || method == oidcAuthMethodMFA || method == oidcAuthMethodExternal
}

func oidcAMR(method string) string {
	switch method {
	case oidcAuthMethodPwd:
		return oidcAuthMethodPwd
	case oidcAuthMethodWebAuthn, oidcAuthMethodMFA:
		return oidcAuthMethodMFA
	case oidcAuthMethodExternal:
		return oidcAuthMethodExternal
	}
	return ""
}

// WriteLoginRequired responds to an otherwise valid authorize request without
// issuing authorization state when an interactive login is required.
func (s *Server) WriteLoginRequired(w http.ResponseWriter, r *http.Request) {
	authorizeRequest, err := s.parseAuthorizationRequest(r)
	if err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, err)
		return
	}
	s.provider.WriteAuthorizeError(r.Context(), w, authorizeRequest, fosite.ErrLoginRequired)
}

// WriteAuthorization is kept for compatibility with existing callers.
func (s *Server) WriteAuthorization(w http.ResponseWriter, r *http.Request, subject string, approvedScopes []string) {
	s.CompleteAuthorization(w, r, subject, approvedScopes)
}

func validHMACSecret(secret []byte) bool {
	return len(secret) == 32 && subtle.ConstantTimeCompare(secret, make([]byte, 32)) == 0
}

type managedClientSnapshotsKey struct{}

func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	snapshots, _ := ctx.Value(managedClientSnapshotsKey{}).(map[string]fosite.Client)
	if client := snapshots[id]; client != nil {
		return client, nil
	}
	if s.client != nil && id == s.client.GetID() {
		if s.bootstrapClientScopes != nil {
			custom, err := s.bootstrapClientScopes(ctx, id)
			if err != nil {
				return nil, err
			}
			if custom.ClientID != id || custom.Revision < 0 {
				return nil, errors.New("invalid bootstrap custom scopes")
			}
			return &bootstrapScopedClient{Client: s.client, scopes: append(append(fosite.Arguments(nil), s.client.GetScopes()...), custom.Allowed...)}, nil
		}
		return s.client, nil
	}
	if s.managedClients != nil {
		owned, err := s.managedClients.Owns(ctx, id)
		if err != nil {
			return nil, err
		}
		if owned {
			client, err := s.managedClients.GetClient(ctx, id)
			if err != nil {
				return nil, err
			}
			for _, grant := range client.GetGrantTypes() {
				if grant != "password" && grant != "authorization_code" && grant != "refresh_token" && grant != "client_credentials" && grant != DeviceGrantType && grant != TokenExchangeGrantType {
					return nil, errors.New("managed client uses unsupported grant type")
				}
			}
			if snapshots != nil {
				snapshots[id] = client
			}
			return client, nil
		}
	}
	client, err := s.dynamicClients.GetClient(ctx, id)
	if err == nil {
		if err := s.validateDynamicClientScopes(ctx, client); err != nil {
			return nil, err
		}
		return client, nil
	}
	if !errors.Is(err, fosite.ErrNotFound) {
		return nil, err
	}
	if s.cimd == nil || !cimdClientIDCandidate(id) {
		return nil, fosite.ErrNotFound
	}
	metadata, err := s.cimd.Lookup(ctx, id)
	if err != nil {
		if errors.Is(err, cimd.ErrNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	return newEphemeralClient(metadata)
}

func (s *Store) validateDynamicClientScopes(ctx context.Context, client fosite.Client) error {
	for _, scope := range client.GetScopes() {
		if standardScope(scope) {
			continue
		}
		if s.customScopeExists == nil {
			return errors.New("dynamic custom scope catalog is unavailable")
		}
		exists, err := s.customScopeExists(ctx, scope)
		if err != nil || !exists {
			return errors.New("dynamic client contains an unknown custom scope")
		}
	}
	return nil
}

type bootstrapScopedClient struct {
	fosite.Client
	scopes fosite.Arguments
}

func (c *bootstrapScopedClient) GetScopes() fosite.Arguments {
	return append(fosite.Arguments(nil), c.scopes...)
}
func (c *bootstrapScopedClient) GetEffectiveLifespan(gt fosite.GrantType, tt fosite.TokenType, fallback time.Duration) time.Duration {
	if v, ok := c.Client.(fosite.ClientWithCustomTokenLifespans); ok {
		return v.GetEffectiveLifespan(gt, tt, fallback)
	}
	return fallback
}

// resolveCIMDAuthorizationClient is the only path allowed to cause remote
// metadata I/O. Static and DCR clients retain priority even if a future
// registration policy permits an URL-shaped identifier.
func (s *Store) resolveCIMDAuthorizationClient(ctx context.Context, id string) error {
	if s == nil || s.cimd == nil || !cimdClientIDCandidate(id) || id == s.client.GetID() {
		return nil
	}
	if _, err := s.dynamicClients.GetClient(ctx, id); err == nil {
		return nil
	} else if !errors.Is(err, fosite.ErrNotFound) {
		return fmt.Errorf("%w: %w", errCIMDDynamicClientLookup, err)
	}
	_, err := s.cimd.Resolve(ctx, id)
	if err != nil {
		return fmt.Errorf("%w: %w", errCIMDMetadataResolution, err)
	}
	return nil
}

func cimdPrefetchFailureStage(err error) string {
	switch {
	case errors.Is(err, errCIMDDynamicClientLookup):
		return cimdPrefetchStageDynamicClientLookup
	case errors.Is(err, errCIMDMetadataResolution):
		return cimdPrefetchStageMetadataResolution
	default:
		return cimdPrefetchStageUnknown
	}
}

func cimdClientIDCandidate(id string) bool {
	if id == "" || len(id) > 2048 || strings.TrimSpace(id) != id {
		return false
	}
	u, err := url.ParseRequestURI(id)
	return err == nil && u.IsAbs() && u.Opaque == "" && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

type ephemeralClient struct {
	*fosite.DefaultOpenIDConnectClient
	metadata ephemeralClientRecord
}

func newEphemeralClient(metadata cimd.Metadata) (fosite.Client, error) {
	record := ephemeralClientRecord{ID: metadata.ID, Name: metadata.Name, RedirectURIs: append([]string(nil), metadata.RedirectURIs...), Scopes: ephemeralScopes(metadata.Scopes), AllowedResources: cloneStringsPreserveNil(metadata.AllowedResources), AllowedResourcesPresent: metadata.AllowedResourcesPresent || metadata.AllowedResources != nil}
	return newEphemeralClientRecord(record)
}

func newEphemeralClientRecord(record ephemeralClientRecord) (fosite.Client, error) {
	if !cimdClientIDCandidate(record.ID) || len(record.RedirectURIs) == 0 {
		return nil, errors.New("invalid ephemeral client snapshot")
	}
	if !sameEphemeralScopes(record.Scopes, ephemeralScopes(record.Scopes)) {
		return nil, errors.New("invalid ephemeral client scopes")
	}
	if record.AllowedResourcesPresent && record.AllowedResources == nil {
		return nil, errors.New("invalid ephemeral client resources")
	}
	if !validEphemeralResources(record.AllowedResources) {
		return nil, errors.New("invalid ephemeral client resources")
	}
	clientURL, _ := url.ParseRequestURI(record.ID)
	redirects := make(map[string]struct{}, len(record.RedirectURIs))
	for _, redirect := range record.RedirectURIs {
		parsed, err := url.ParseRequestURI(redirect)
		if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !sameEphemeralOrigin(clientURL, parsed) {
			return nil, errors.New("invalid ephemeral client redirect")
		}
		if _, duplicate := redirects[redirect]; duplicate {
			return nil, errors.New("duplicate ephemeral client redirect")
		}
		redirects[redirect] = struct{}{}
	}
	return &ephemeralClient{DefaultOpenIDConnectClient: &fosite.DefaultOpenIDConnectClient{
		DefaultClient:           &fosite.DefaultClient{ID: record.ID, RedirectURIs: append([]string(nil), record.RedirectURIs...), GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, Scopes: append([]string(nil), record.Scopes...), Audience: ephemeralAudienceList(record), Public: true},
		TokenEndpointAuthMethod: "none",
	}, metadata: record.clone()}, nil
}

func validEphemeralResources(values []string) bool {
	if len(values) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validResourceURL(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func ephemeralAudienceList(record ephemeralClientRecord) []string {
	if record.AllowedResourcesPresent || record.AllowedResources != nil {
		return cloneStringsPreserveNil(record.AllowedResources)
	}
	return []string{ephemeralAnyResourceAudience}
}

func cloneStringsPreserveNil(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func sameEphemeralOrigin(left, right *url.URL) bool {
	if !strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	port := func(value *url.URL) string {
		if value.Port() != "" {
			return value.Port()
		}
		return "443"
	}
	return port(left) == port(right)
}

func isEphemeralClient(client fosite.Client) bool {
	_, ok := client.(*ephemeralClient)
	return ok
}

func ephemeralScopes(values []string) []string {
	allowed := map[string]struct{}{openidScope: {}, "goauthy.read": {}}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := allowed[value]; !ok {
			continue
		}
		if _, duplicate := seen[value]; !duplicate {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

func sameEphemeralScopes(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (*Store) ClientAssertionJWTValid(context.Context, string) error { return fosite.ErrNotFound }
func (*Store) SetClientAssertionJWT(context.Context, string, time.Time) error {
	return errors.New("JWT client assertions are not enabled")
}

// SetPasswordLoginObserver attaches location bookkeeping after password issuance.
// Configure before serving requests, as with other Server callbacks.
func (s *Server) SetPasswordLoginObserver(observer func(http.ResponseWriter, *http.Request, string) error) {
	s.passwordLoginObserver = observer
}
