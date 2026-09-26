package upstreamprovider

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
)

const (
	stateCookieName     = "__Host-goauthy_upstream_state"
	browserCookieName   = "__Host-goauthy_upstream_browser"
	maxQueryLen         = 2048
	maxRedirectURIBytes = 2048
	browserSessionLen   = 32
)

// canonicalSessionDigest returns the persisted browser-canonical digest of a
// raw session token. It fails closed on malformed tokens.
func canonicalSessionDigest(rawToken string) (string, error) {
	return browser.CanonicalTokenDigest(rawToken)
}

// Handler provides net/http handlers for the upstream OAuth 2.0 start
// and callback flows. It wires together the package's core transaction
// and token verification primitives with HTTP transport concerns.
type Handler struct {
	configs          map[string]Config
	store            Store
	exchanger        TokenExchanger
	verifier         TokenVerifier
	provider         *cryptoProvider
	allowedRedirects map[string]bool
	now              func() time.Time
	localLogin       *LocalLoginHooks
	linkCallbacks    map[string]string
	linkHooks        *LinkHooks
}

// LocalLoginHooks connects an upstream callback to an existing local OAuth
// login without exposing the local login implementation to this package.
type LocalLoginHooks struct {
	Prepare                    func(r *http.Request, rawInteraction string) (rawSessionToken, sessionDigest, interactionDigest string, err error)
	RequireFreshAuthentication func(r *http.Request, rawInteraction string) (bool, error)
	Current                    func(r *http.Request) (rawSessionToken, sessionDigest string, err error)
	Resolve                    func(ctx context.Context, upstream SubjectResult) (localSubject string, err error)
	// ResolveVerified, when non-nil, is preferred over Resolve at LocalCallback.
	// It receives the full VerifiedIdentity with deep-cloned config, verified
	// claims, and raw payload — enabling federated onboarding/profile policy.
	ResolveVerified func(ctx context.Context, identity VerifiedIdentity) (localSubject string, err error)
	Complete        func(w http.ResponseWriter, r *http.Request, rawSessionToken, interactionDigest, localSubject string, upstream *OIDCSession)
}

// OIDCSession contains only claims verified against the consumed login transaction.
// Its SID is upstream-scoped, never a local browser session identifier.
type OIDCSession struct {
	Issuer             string
	ClientID           string
	Subject            string
	SessionID          string
	MFAPassed          bool
	AuthenticationTime int64
}

// VerifiedIdentity carries the full verified upstream identity through the
// local-login callback pipeline. It preserves the validated SubjectResult,
// a deep-cloned Config snapshot, and (for OIDC) the verified IDTokenClaims
// including typed profile claims and raw JSON payload. For GitHub and
// OAuthUserInfo flows, IDTokenClaims is nil because these protocols do not
// carry signed ID tokens.
type VerifiedIdentity struct {
	Subject       SubjectResult
	Config        Config         // deep-cloned snapshot of the handler config
	IDTokenClaims *IDTokenClaims // nil for GitHub/OAuthUserInfo
}

// cloneIDTokenClaims returns a deep copy of claims. Pointer fields and
// the unexported rawClaims byte slice are duplicated so the caller
// cannot alias the original.
func cloneIDTokenClaims(claims *IDTokenClaims) *IDTokenClaims {
	if claims == nil {
		return nil
	}
	out := *claims
	if len(claims.Audience) > 0 {
		out.Audience = make([]string, len(claims.Audience))
		copy(out.Audience, claims.Audience)
	}
	if claims.Email != nil {
		v := *claims.Email
		out.Email = &v
	}
	if claims.EmailVerified != nil {
		v := *claims.EmailVerified
		out.EmailVerified = &v
	}
	if claims.GivenName != nil {
		v := *claims.GivenName
		out.GivenName = &v
	}
	if claims.FamilyName != nil {
		v := *claims.FamilyName
		out.FamilyName = &v
	}
	if len(claims.rawClaims) > 0 {
		out.rawClaims = make(json.RawMessage, len(claims.rawClaims))
		copy(out.rawClaims, claims.rawClaims)
	}
	return &out
}

// LinkHooks connects an authenticated local account to explicit upstream link
// decisions without importing an account implementation.
type LinkHooks struct {
	Current func(r *http.Request) (localSubject, rawSessionToken, sessionDigest string, err error)
	Link    func(ctx context.Context, localSubject string, upstream SubjectResult, now time.Time) (LinkDecision, error)
}

// NewHandler creates a Handler. configs must be keyed by provider ID
// (case-sensitive). allowedRedirects is an exact-match allowlist for
// redirect_uri values accepted in the callback.
//
// The constructor clones all maps and slices so the caller's data can
// be safely mutated after construction.
func NewHandler(
	configs map[string]Config,
	store Store,
	exchanger TokenExchanger,
	verifier TokenVerifier,
	provider *cryptoProvider,
	allowedRedirects map[string]bool,
) (*Handler, error) {
	if len(configs) == 0 {
		return nil, errHandlerConfig
	}
	if store == nil {
		return nil, errHandlerStore
	}
	if exchanger == nil {
		return nil, errHandlerExchanger
	}
	if verifier == nil {
		return nil, errHandlerVerifier
	}
	if provider == nil {
		provider = DefaultCryptoProvider()
	}

	// Clone configs map and each Config's Scopes slice.
	cloned := make(map[string]Config, len(configs))
	for k, v := range configs {
		if !validConfigProviderID(k, v) || v.Validate() != nil {
			return nil, errHandlerConfig
		}
		c := cloneConfig(v)
		cloned[k] = c
	}

	// Clone allowedRedirects.
	ar := make(map[string]bool, len(allowedRedirects))
	for k, v := range allowedRedirects {
		ar[k] = v
	}

	return &Handler{
		configs:          cloned,
		store:            store,
		exchanger:        exchanger,
		verifier:         verifier,
		provider:         provider,
		allowedRedirects: ar,
		now:              time.Now,
	}, nil
}

// NewLocalLoginHandler creates the explicitly injected local-login variant.
// NewHandler remains the legacy subject-JSON boundary.
func NewLocalLoginHandler(
	configs map[string]Config,
	store Store,
	exchanger TokenExchanger,
	verifier TokenVerifier,
	provider *cryptoProvider,
	allowedRedirects map[string]bool,
	hooks LocalLoginHooks,
) (*Handler, error) {
	if hooks.Prepare == nil || hooks.Current == nil || (hooks.Resolve == nil && hooks.ResolveVerified == nil) || hooks.Complete == nil {
		return nil, errHandlerLocalHooks
	}
	h, err := NewHandler(configs, store, exchanger, verifier, provider, allowedRedirects)
	if err != nil {
		return nil, err
	}
	h.localLogin = &hooks
	return h, nil
}

// NewLinkHandler creates the explicitly configured account-link variant.
func NewLinkHandler(configs map[string]Config, store Store, exchanger TokenExchanger, verifier TokenVerifier, provider *cryptoProvider, linkCallbacks map[string]string, hooks LinkHooks) (*Handler, error) {
	h, err := NewHandler(configs, store, exchanger, verifier, provider, nil)
	if err != nil {
		return nil, err
	}
	if err := configureLink(h, linkCallbacks, hooks); err != nil {
		return nil, err
	}
	return h, nil
}

// NewLocalLoginAndLinkHandler combines the two explicitly injected callback
// modes while retaining their separate start and callback handlers.
func NewLocalLoginAndLinkHandler(configs map[string]Config, store Store, exchanger TokenExchanger, verifier TokenVerifier, provider *cryptoProvider, allowedRedirects map[string]bool, localHooks LocalLoginHooks, linkCallbacks map[string]string, linkHooks LinkHooks) (*Handler, error) {
	h, err := NewLocalLoginHandler(configs, store, exchanger, verifier, provider, allowedRedirects, localHooks)
	if err != nil {
		return nil, err
	}
	if err := configureLink(h, linkCallbacks, linkHooks); err != nil {
		return nil, err
	}
	return h, nil
}

func configureLink(h *Handler, linkCallbacks map[string]string, hooks LinkHooks) error {
	if hooks.Current == nil || hooks.Link == nil {
		return errHandlerLinkHooks
	}
	if len(linkCallbacks) == 0 {
		return errHandlerLinkCallbacks
	}
	callbacks := make(map[string]string, len(linkCallbacks))
	for providerID, callbackURI := range linkCallbacks {
		cfg, ok := h.configs[providerID]
		if !ok || !validConfigProviderID(providerID, cfg) || !validLinkCallback(h.configs, providerID, callbackURI) {
			return errHandlerLinkCallbacks
		}
		callbacks[providerID] = callbackURI
	}
	h.linkCallbacks, h.linkHooks = callbacks, &hooks
	return nil
}

func validLinkCallback(configs map[string]Config, providerID, callbackURI string) bool {
	_, ok := configs[providerID]
	return ok && validateCallbackURI(callbackURI) == nil
}

var (
	errHandlerConfig        = errStr("upstreamprovider: at least one provider config required")
	errHandlerStore         = errStr("upstreamprovider: store required")
	errHandlerExchanger     = errStr("upstreamprovider: token exchanger required")
	errHandlerVerifier      = errStr("upstreamprovider: token verifier required")
	errHandlerLocalHooks    = errStr("upstreamprovider: local login hooks required")
	errHandlerLinkHooks     = errStr("upstreamprovider: link hooks required")
	errHandlerLinkCallbacks = errStr("upstreamprovider: link callbacks required")
	errRuntimeBinding       = errStr("upstreamprovider: runtime binding mismatch")
)

type errStr string

func (e errStr) Error() string { return string(e) }

// StartHandler returns an http.Handler that initiates the upstream OAuth
// authorization flow. It reads:
//
//	GET /upstream/{providerID}/start?redirect_uri=...
//
// It validates the redirect_uri against the exact allowlist before any
// transaction is saved or redirect emitted, generates the authorization
// URL, stores the transaction, sets a SameSite secure state cookie and
// browser session cookie, and issues a 302 redirect.
func (h *Handler) StartHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		providerID := r.PathValue("providerID")
		if providerID == "" {
			providerID = extractProviderID(r.URL.Path)
		}
		if providerID == "" {
			http.Error(w, "Invalid provider", http.StatusBadRequest)
			return
		}

		callbackURI := r.URL.Query().Get("redirect_uri")
		if callbackURI == "" {
			http.Error(w, "Missing redirect_uri", http.StatusBadRequest)
			return
		}
		if len(callbackURI) > maxRedirectURIBytes {
			http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
			return
		}

		// Validate redirect_uri against the exact allowlist before
		// any transaction is saved or redirect emitted.
		if !h.allowedRedirects[callbackURI] {
			http.Error(w, "Redirect URI not allowed", http.StatusForbidden)
			return
		}

		cfg, ok := h.configs[providerID]
		if !ok {
			http.Error(w, "Provider not found", http.StatusNotFound)
			return
		}

		// Generate a raw browser cookie secret; pass DigestSHA256(raw)
		// to GenerateAuthorizationURL so the transaction stores only a digest.
		rawBrowser, err := generateBrowserSecret(h.provider)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		browserDigest := DigestSHA256(rawBrowser)

		now := h.now()
		result, err := GenerateAuthorizationURL(
			r.Context(), h.provider, cfg, h.store,
			AuthorizationParams{
				CallbackURI:    callbackURI,
				Scopes:         cfg.Scopes,
				ProviderSource: cfg.ProviderSource,
				RuntimeVersion: cfg.RuntimeVersion,
			},
			browserDigest, providerID, now,
		)
		if err != nil {
			http.Error(w, "Failed to start upstream flow", http.StatusInternalServerError)
			return
		}

		authURL, err := url.Parse(result.URL)
		if err != nil {
			http.Error(w, "Failed to start upstream flow", http.StatusInternalServerError)
			return
		}
		rawState := authURL.Query().Get("state")
		if rawState == "" {
			http.Error(w, "Failed to start upstream flow", http.StatusInternalServerError)
			return
		}

		// Store raw browser secret in cookie (not the digest).
		setCookie(w, browserCookieName, rawBrowser, 600)
		setCookie(w, stateCookieName, rawState, 600)

		w.Header().Set("Location", result.URL)
		w.WriteHeader(http.StatusFound)
	})
}

// LocalStartHandler initiates an upstream authorization bound to the current
// local OAuth init session and one unconsumed authorization interaction.
func (h *Handler) LocalStartHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if h.localLogin == nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		providerID := r.PathValue("providerID")
		if providerID == "" {
			providerID = extractProviderID(r.URL.Path)
		}
		if providerID == "" {
			http.Error(w, "Invalid provider", http.StatusBadRequest)
			return
		}
		callbackURI := r.URL.Query().Get("redirect_uri")
		if callbackURI == "" || len(callbackURI) > maxRedirectURIBytes {
			http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
			return
		}
		if !h.allowedRedirects[callbackURI] {
			http.Error(w, "Redirect URI not allowed", http.StatusForbidden)
			return
		}
		cfg, ok := h.configs[providerID]
		if !ok {
			http.Error(w, "Provider not found", http.StatusNotFound)
			return
		}
		interactions := r.URL.Query()["interaction"]
		if len(interactions) != 1 || interactions[0] == "" || len(interactions[0]) > maxQueryLen {
			http.Error(w, "Invalid interaction", http.StatusBadRequest)
			return
		}
		rawSessionToken, sessionDigest, interactionDigest, err := h.localLogin.Prepare(r, interactions[0])
		canonical, canonErr := canonicalSessionDigest(rawSessionToken)
		if err != nil || canonErr != nil || rawSessionToken == "" || ValidateLocalOAuthBinding(sessionDigest, interactionDigest) != nil ||
			subtle.ConstantTimeCompare([]byte(canonical), []byte(sessionDigest)) != 1 {
			http.Error(w, "Failed to start upstream flow", http.StatusBadRequest)
			return
		}
		fresh := false
		if h.localLogin.RequireFreshAuthentication != nil {
			fresh, err = h.localLogin.RequireFreshAuthentication(r, interactions[0])
			if err != nil {
				http.Error(w, "Invalid login request", http.StatusBadRequest)
				return
			}
		}
		result, err := GenerateAuthorizationURL(r.Context(), h.provider, cfg, h.store, AuthorizationParams{
			CallbackURI: callbackURI, Scopes: cfg.Scopes,
			SessionDigest: sessionDigest, InteractionDigest: interactionDigest,
			ProviderSource: cfg.ProviderSource, RuntimeVersion: cfg.RuntimeVersion,
		}, sessionDigest, providerID, h.now())
		if err != nil {
			http.Error(w, "Failed to start upstream flow", http.StatusInternalServerError)
			return
		}
		authURL, err := url.Parse(result.URL)
		if err != nil || authURL.Query().Get("state") == "" {
			http.Error(w, "Failed to start upstream flow", http.StatusInternalServerError)
			return
		}
		if fresh {
			query := authURL.Query()
			query.Set("prompt", "login")
			query.Set("max_age", "0")
			authURL.RawQuery = query.Encode()
			result.URL = authURL.String()
		}
		setCookie(w, stateCookieName, authURL.Query().Get("state"), 600)
		w.Header().Set("Location", result.URL)
		w.WriteHeader(http.StatusFound)
	})
}

// LinkStartHandler starts an explicit authenticated account-link flow.
func (h *Handler) LinkStartHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if h.linkHooks == nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		providerID := r.PathValue("providerID")
		if providerID == "" {
			providerID = extractProviderID(r.URL.Path)
		}
		callbackURI, ok := h.linkCallbacks[providerID]
		if !ok {
			http.Error(w, "Provider not found", http.StatusNotFound)
			return
		}
		localSubject, rawSessionToken, sessionDigest, err := h.linkHooks.Current(r)
		canonical, canonErr := canonicalSessionDigest(rawSessionToken)
		if err != nil || canonErr != nil || !validLinkSubject(localSubject) || rawSessionToken == "" || !validDigest(sessionDigest) || subtle.ConstantTimeCompare([]byte(canonical), []byte(sessionDigest)) != 1 {
			http.Error(w, "Invalid link request", http.StatusForbidden)
			return
		}
		result, err := GenerateAuthorizationURL(r.Context(), h.provider, h.configs[providerID], h.store, AuthorizationParams{Purpose: PurposeLink, CallbackURI: callbackURI, Scopes: h.configs[providerID].Scopes, LinkSubject: localSubject, LinkSessionDigest: sessionDigest, ProviderSource: h.configs[providerID].ProviderSource, RuntimeVersion: h.configs[providerID].RuntimeVersion}, sessionDigest, providerID, h.now())
		if err != nil {
			http.Error(w, "Failed to start link", http.StatusInternalServerError)
			return
		}
		authURL, err := url.Parse(result.URL)
		if err != nil || authURL.Query().Get("state") == "" {
			http.Error(w, "Failed to start link", http.StatusInternalServerError)
			return
		}
		setCookie(w, stateCookieName, authURL.Query().Get("state"), 600)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"authorization_url": result.URL})
	})
}

// callbackReject clears both cookies then writes the single canonical
// rejection response used for every callback failure path: missing
// params, oversized query, state mismatch, validation, exchange,
// verifier, and subject failures.
func callbackReject(w http.ResponseWriter) {
	setCookie(w, stateCookieName, "", -1)
	setCookie(w, browserCookieName, "", -1)
	http.Error(w, "State mismatch", http.StatusBadRequest)
}

func linkConflict(w http.ResponseWriter) {
	setCookie(w, stateCookieName, "", -1)
	http.Error(w, "Link conflict", http.StatusConflict)
}

func linkReject(w http.ResponseWriter) {
	setCookie(w, stateCookieName, "", -1)
	http.Error(w, "State mismatch", http.StatusBadRequest)
}

func callbackFailure(w http.ResponseWriter) { http.Error(w, "State mismatch", http.StatusBadRequest) }

// CallbackHandler returns an http.Handler that completes the upstream
// OAuth callback. It reads:
//
//	GET /upstream/{providerID}/callback?state=...&code=...
//
// It validates the state against the stored transaction, exchanges the
// authorization code for tokens, verifies the id_token, and returns
// the subject as JSON.
func (h *Handler) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		if len(r.URL.RawQuery) > maxQueryLen {
			callbackReject(w)
			return
		}

		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		if state == "" || code == "" {
			callbackReject(w)
			return
		}

		// Constant-time comparison of state cookie vs query parameter.
		stateCookie, err := r.Cookie(stateCookieName)
		if err != nil || stateCookie.Value == "" ||
			subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(state)) != 1 {
			callbackReject(w)
			return
		}

		providerID := r.PathValue("providerID")
		if providerID == "" {
			providerID = extractProviderID(r.URL.Path)
		}

		browserCookie, err := r.Cookie(browserCookieName)
		if err != nil || browserCookie.Value == "" {
			callbackReject(w)
			return
		}

		now := h.now()
		result, err := ValidateCallback(
			r.Context(), h.store,
			CallbackParams{State: state, Code: code},
			DigestSHA256(browserCookie.Value), providerID, now,
		)
		if err != nil {
			callbackReject(w)
			return
		}
		if result.Transaction.Purpose != PurposeLogin {
			callbackReject(w)
			return
		}
		if cfg, ok := h.configs[providerID]; !ok || checkRuntimeBinding(cfg, result.Transaction) != nil {
			callbackReject(w)
			return
		}

		tokenResult, err := h.exchanger.ExchangeCode(r.Context(), providerID, result.Transaction.CallbackURI, result.Code, result.Transaction.PKCEVerifier)
		if err != nil || tokenResult == nil {
			callbackReject(w)
			return
		}

		sr, _, _, err := h.resolveSubject(r.Context(), providerID, tokenResult, result.Transaction)
		if err != nil {
			callbackReject(w)
			return
		}

		// Success: clear cookies before writing the response body.
		setCookie(w, stateCookieName, "", -1)
		setCookie(w, browserCookieName, "", -1)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"provider_id": sr.ProviderID,
			"subject":     sr.Subject,
		})
	})
}

// LocalCallbackHandler completes a verified upstream identity through the
// injected local-login transition. It never returns an upstream subject.
func (h *Handler) LocalCallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if h.localLogin == nil || len(r.URL.RawQuery) > maxQueryLen {
			callbackReject(w)
			return
		}
		state, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
		if state == "" || code == "" {
			callbackReject(w)
			return
		}
		stateCookie, err := r.Cookie(stateCookieName)
		if err != nil || stateCookie.Value == "" || subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(state)) != 1 {
			callbackReject(w)
			return
		}
		providerID := r.PathValue("providerID")
		if providerID == "" {
			providerID = extractProviderID(r.URL.Path)
		}
		rawSessionToken, sessionDigest, err := h.localLogin.Current(r)
		canonical, canonErr := canonicalSessionDigest(rawSessionToken)
		if err != nil || canonErr != nil || rawSessionToken == "" || !validDigest(sessionDigest) ||
			subtle.ConstantTimeCompare([]byte(canonical), []byte(sessionDigest)) != 1 {
			callbackReject(w)
			return
		}
		// Consume precedes exchange; transient failures restart the one-use flow.
		now := h.now()
		result, err := ValidateCallback(r.Context(), h.store, CallbackParams{State: state, Code: code}, sessionDigest, providerID, now)
		if err != nil {
			callbackReject(w)
			return
		}
		if result.Transaction.Purpose != PurposeLogin {
			callbackReject(w)
			return
		}
		if ValidateLocalOAuthBinding(result.Transaction.SessionDigest, result.Transaction.InteractionDigest) != nil ||
			ValidateLocalOAuthBinding(sessionDigest, result.Transaction.InteractionDigest) != nil ||
			subtle.ConstantTimeCompare([]byte(result.Transaction.SessionDigest), []byte(sessionDigest)) != 1 {
			callbackReject(w)
			return
		}
		if cfg, ok := h.configs[providerID]; !ok || checkRuntimeBinding(cfg, result.Transaction) != nil {
			callbackReject(w)
			return
		}
		tokenResult, err := h.exchanger.ExchangeCode(r.Context(), providerID, result.Transaction.CallbackURI, result.Code, result.Transaction.PKCEVerifier)
		if err != nil || tokenResult == nil {
			callbackReject(w)
			return
		}
		sr, upstream, vi, err := h.resolveSubject(r.Context(), providerID, tokenResult, result.Transaction)
		if err != nil {
			callbackReject(w)
			return
		}
		if upstream != nil && vi.IDTokenClaims != nil && vi.Config.MFAClaimPath != nil {
			raw := vi.IDTokenClaims.RawClaims()
			if len(raw) > 0 {
				matched, evalErr := EvaluateClaimMapping(raw, vi.Config.MFAClaimPath, vi.Config.MFAClaimValue)
				if evalErr != nil {
					callbackReject(w)
					return
				}
				if matched != nil {
					upstream.MFAPassed = *matched
				}
			}
		}
		var localSubject string
		if h.localLogin.ResolveVerified != nil {
			localSubject, err = h.localLogin.ResolveVerified(r.Context(), vi)
		} else {
			localSubject, err = h.localLogin.Resolve(r.Context(), sr)
		}
		if err != nil || strings.TrimSpace(localSubject) == "" {
			callbackReject(w)
			return
		}
		setCookie(w, stateCookieName, "", -1)
		setCookie(w, browserCookieName, "", -1)
		h.localLogin.Complete(w, r, rawSessionToken, result.Transaction.InteractionDigest, localSubject, upstream)
	})
}

// CombinedCallbackHandler selects the sole valid local session mode before
// delegating to its existing callback handler. Selection never consumes state.
func (h *Handler) CombinedCallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.localLogin == nil || h.linkHooks == nil {
			callbackFailure(w)
			return
		}
		_, _, localErr := h.localLogin.Current(r)
		_, _, _, linkErr := h.linkHooks.Current(r)
		if localErr == nil && linkErr != nil {
			h.LocalCallbackHandler().ServeHTTP(w, r)
			return
		}
		if localErr != nil && linkErr == nil {
			h.LinkCallbackHandler().ServeHTTP(w, r)
			return
		}
		callbackFailure(w)
	})
}

// LinkCallbackHandler completes an explicit link decision for the same
// authenticated account and browser session that initiated it.
func (h *Handler) LinkCallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if h.linkHooks == nil || len(r.URL.RawQuery) > maxQueryLen {
			linkReject(w)
			return
		}
		state, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
		if state == "" || code == "" {
			linkReject(w)
			return
		}
		stateCookie, err := r.Cookie(stateCookieName)
		if err != nil || stateCookie.Value == "" || subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(state)) != 1 {
			linkReject(w)
			return
		}
		providerID := r.PathValue("providerID")
		if providerID == "" {
			providerID = extractProviderID(r.URL.Path)
		}
		localSubject, rawSessionToken, sessionDigest, err := h.linkHooks.Current(r)
		canonical, canonErr := canonicalSessionDigest(rawSessionToken)
		if err != nil || canonErr != nil || !validLinkSubject(localSubject) || rawSessionToken == "" || !validDigest(sessionDigest) || subtle.ConstantTimeCompare([]byte(canonical), []byte(sessionDigest)) != 1 {
			linkReject(w)
			return
		}
		now := h.now()
		result, err := ValidateCallback(r.Context(), h.store, CallbackParams{State: state, Code: code}, sessionDigest, providerID, now)
		if err != nil || result.Transaction.Purpose != PurposeLink || !validLinkSubject(result.Transaction.LinkSubject) || !validDigest(result.Transaction.LinkSessionDigest) ||
			subtle.ConstantTimeCompare([]byte(result.Transaction.LinkSubject), []byte(localSubject)) != 1 ||
			subtle.ConstantTimeCompare([]byte(result.Transaction.LinkSessionDigest), []byte(sessionDigest)) != 1 {
			linkReject(w)
			return
		}
		if cfg, ok := h.configs[providerID]; !ok || checkRuntimeBinding(cfg, result.Transaction) != nil {
			linkReject(w)
			return
		}
		tokenResult, err := h.exchanger.ExchangeCode(r.Context(), providerID, result.Transaction.CallbackURI, result.Code, result.Transaction.PKCEVerifier)
		if err != nil || tokenResult == nil {
			linkReject(w)
			return
		}
		sr, _, _, err := h.resolveSubject(r.Context(), providerID, tokenResult, result.Transaction)
		if err != nil {
			linkReject(w)
			return
		}
		decision, err := h.linkHooks.Link(r.Context(), localSubject, sr, now)
		if err != nil {
			linkReject(w)
			return
		}
		if decision == LinkDecisionConflict {
			linkConflict(w)
			return
		}
		if decision != LinkDecisionLinked {
			linkReject(w)
			return
		}
		setCookie(w, stateCookieName, "", -1)
		w.WriteHeader(http.StatusNoContent)
	})
}

// setCookie is a helper that sets a cookie with standard security attributes.
func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// extractProviderID extracts the provider ID from a URL path of the
// form /upstream/{providerID}/start or /upstream/{providerID}/callback.
func extractProviderID(path string) string {
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) >= 2 && parts[0] == "upstream" {
		return parts[1]
	}
	return ""
}

// generateBrowserSecret creates a random browser session token using the
// given entropy source. The raw value is stored in the cookie; only its
// SHA-256 digest is persisted in the transaction.
func generateBrowserSecret(p *cryptoProvider) (string, error) {
	b, err := p.randomBytes(browserSessionLen)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// TokenExchanger abstracts the OAuth 2.0 authorization code exchange.
// It receives the providerID and the stored transaction CallbackURI
// (never query-controlled data) so multi-provider exchanges can select
// the correct upstream token endpoint.
type TokenExchanger interface {
	ExchangeCode(ctx context.Context, providerID, callbackURI, code, pkceVerifier string) (*TokenExchangeResult, error)
}

// TokenExchangeResult holds the outcome of an authorization code exchange.
type TokenExchangeResult struct {
	IDToken string
	Subject *SubjectResult
}

// checkRuntimeBinding compares the immutable handler config against the
// consumed transaction's source/version and issuer/clientID. For legacy
// flows both sides are empty and the check passes silently. For managed
// flows any mismatch fails closed before any outbound exchanger call.
func checkRuntimeBinding(cfg Config, tx Transaction) error {
	if cfg.ProviderSource != tx.ProviderSource || cfg.RuntimeVersion != tx.RuntimeVersion {
		return errRuntimeBinding
	}
	if cfg.Issuer != tx.Issuer || cfg.ClientID != tx.ClientID {
		return errRuntimeBinding
	}
	return nil
}

// resolveSubject validates the exchanged identity according to the provider
// protocol. OIDC responses carry an ID token; GitHub responses carry a
// provider-scoped subject returned by the userinfo endpoint.
func (h *Handler) resolveSubject(ctx context.Context, providerID string, result *TokenExchangeResult, tx Transaction) (SubjectResult, *OIDCSession, VerifiedIdentity, error) {
	if result == nil {
		return SubjectResult{}, nil, VerifiedIdentity{}, ErrNoSubject
	}
	cfg, ok := h.configs[providerID]
	if !ok {
		return SubjectResult{}, nil, VerifiedIdentity{}, ErrInvalidConfig
	}
	clonedCfg := cloneConfig(cfg)
	switch cfg.NormalizedKind() {
	case ProviderKindOIDC:
		if result.IDToken == "" && result.Subject != nil {
			if err := result.Subject.Validate(); err != nil {
				return SubjectResult{}, nil, VerifiedIdentity{}, err
			}
			sr, err := bindManagedSubject(*result.Subject, tx)
			if err != nil {
				return SubjectResult{}, nil, VerifiedIdentity{}, err
			}
			vi := VerifiedIdentity{Subject: sr, Config: clonedCfg}
			return sr, nil, vi, nil
		}
		if result.IDToken == "" || result.Subject != nil {
			return SubjectResult{}, nil, VerifiedIdentity{}, ErrNoSubject
		}
		claims, err := ValidateIDToken(ctx, h.verifier, result.IDToken, tx, h.now())
		if err != nil {
			return SubjectResult{}, nil, VerifiedIdentity{}, err
		}
		sr := SubjectResult{ProviderID: providerID, Subject: claims.Subject}
		if err := sr.Validate(); err != nil {
			return SubjectResult{}, nil, VerifiedIdentity{}, err
		}
		sr, err = bindManagedSubject(sr, tx)
		if err != nil {
			return SubjectResult{}, nil, VerifiedIdentity{}, err
		}
		vi := VerifiedIdentity{Subject: sr, Config: clonedCfg, IDTokenClaims: cloneIDTokenClaims(claims)}
		return sr, &OIDCSession{Issuer: claims.Issuer, ClientID: tx.ClientID, Subject: claims.Subject, SessionID: claims.SessionID, AuthenticationTime: claims.AuthenticationTime}, vi, nil
	case ProviderKindGitHub:
		if result.IDToken != "" || result.Subject == nil || result.Subject.ProviderID != providerID {
			return SubjectResult{}, nil, VerifiedIdentity{}, ErrNoSubject
		}
		if err := result.Subject.Validate(); err != nil {
			return SubjectResult{}, nil, VerifiedIdentity{}, err
		}
		sr, err := bindManagedSubject(*result.Subject, tx)
		if err != nil {
			return SubjectResult{}, nil, VerifiedIdentity{}, err
		}
		vi := VerifiedIdentity{Subject: sr, Config: clonedCfg}
		return sr, nil, vi, nil
	case ProviderKindOAuthUserInfo:
		// OAuthUserInfo: like GitHub, subject comes from the token exchange
		// (via userinfo endpoint), not from an ID token.
		if result.IDToken != "" || result.Subject == nil || result.Subject.ProviderID != providerID {
			return SubjectResult{}, nil, VerifiedIdentity{}, ErrNoSubject
		}
		if err := result.Subject.Validate(); err != nil {
			return SubjectResult{}, nil, VerifiedIdentity{}, err
		}
		sr, err := bindManagedSubject(*result.Subject, tx)
		if err != nil {
			return SubjectResult{}, nil, VerifiedIdentity{}, err
		}
		vi := VerifiedIdentity{Subject: sr, Config: clonedCfg}
		return sr, nil, vi, nil
	default:
		return SubjectResult{}, nil, VerifiedIdentity{}, ErrInvalidConfig
	}
}
