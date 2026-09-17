// Package login serves the small browser boundary for OAuth authorization.
package login

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/metrics"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/recovery"
	"github.com/mrchypark/goauthy/internal/security"
	"github.com/mrchypark/goauthy/internal/tracing"
	"go.opentelemetry.io/otel/trace"
)

const (
	authorizePath       = "/oidc/authorize"
	interactionLifetime = 5 * time.Minute
	sessionLifetime     = 4 * time.Hour
	formLimit           = 8 << 10
	passkeyStartLimit   = 8 << 10
	passkeyFinishLimit  = 64 << 10
	failureWriteGrace   = 5 * time.Second
)

var loginPage = template.Must(template.New("login").Parse(`<!doctype html><html lang="{{.Language}}"><head><meta charset="utf-8"><link rel="stylesheet" href="/auth/v1/theme/global.css">{{if .ThemeURL}}<link rel="stylesheet" href="{{.ThemeURL}}">{{end}}<title>{{.SignIn}}</title></head><body><main><h1>{{.SignIn}}</h1><p>{{.ContinueTo}} {{.ClientID}}</p><form method="post" action="../auth/login"><input type="hidden" name="interaction" value="{{.Interaction}}"><label>{{.Username}} <input name="username" autocomplete="username" required></label><label>{{.Password}} <input type="password" name="password" autocomplete="current-password" required></label>{{if .CaptchaSiteKey}}<div class="captcha-container" data-sitekey="{{.CaptchaSiteKey}}"></div><input type="hidden" name="captcha_response" id="captcha_response">{{end}}<button type="submit">{{.SignIn}}</button></form>{{if .Providers}}<div style="margin:1.5em 0;text-align:center;border-top:1px solid #ccc;padding-top:1em"><span style="background:#fff;padding:0 0.5em;color:#666;font-size:0.9em">or</span></div>{{range .Providers}}<a href="/upstream/{{.ID}}/start?redirect_uri={{.CallbackURI}}&amp;interaction={{$.Interaction}}" style="display:block;margin:0.5em 0;padding:0.75em;border:1px solid #ccc;border-radius:4px;text-align:center;text-decoration:none;color:#333">{{.Name}}</a>{{end}}{{end}}</main></body></html>`))

const fedCMLandingPayload = "goauthy-fedcm-login/v1"

var fedCMLandingPage = template.Must(template.New("fedcm-login").Parse(`<!doctype html><html lang="{{.Language}}"><head><meta charset="utf-8"><link rel="stylesheet" href="/auth/v1/theme/global.css">{{if .ThemeURL}}<link rel="stylesheet" href="{{.ThemeURL}}">{{end}}<title>{{.SignIn}}</title></head><body><main><h1>{{.SignIn}}</h1><form method="post" action=""><input type="hidden" name="fedcm" value="1"><input type="hidden" name="interaction" value="{{.Interaction}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label>{{.Username}} <input name="username" autocomplete="username" required></label><label>{{.Password}} <input type="password" name="password" autocomplete="current-password" required></label><button type="submit">{{.SignIn}}</button></form></main></body></html>`))

var fedCMSuccessPage = template.Must(template.New("fedcm-success").Parse(`<!doctype html><html lang="{{.Language}}"><head><meta charset="utf-8"><link rel="stylesheet" href="/auth/v1/theme/global.css">{{if .ThemeURL}}<link rel="stylesheet" href="{{.ThemeURL}}">{{end}}<title>{{.SignedIn}}</title></head><body><main><p>{{.SignedIn}}</p></main></body></html>`))

// ErrExternalAuthentication deliberately does not reveal which upstream
// binding check failed.
var (
	ErrExternalAuthentication = errors.New("invalid external authentication")
	ErrAccountLocked          = errors.New("account locked")
)

// UpstreamProvider is a display-oriented description of an upstream identity
// provider available for login.
type UpstreamProvider struct {
	ID          string
	Name        string
	LogoURL     string
	CallbackURI string
}

// Handler wires the concrete state stores to two browser endpoints.
type Handler struct {
	issuer            string
	browser           *browser.Store
	identity          *identity.Store
	oauth             *oauth.Server
	policy            *loginpolicy.Store
	passkeys          *passkey.Service
	otp               *recovery.OTPHandler
	now               func() time.Time
	wait              func(context.Context, time.Duration) error
	deadline          func(http.ResponseWriter, time.Time) error
	onPasswordExpired func(context.Context, string) error
	onLoginLocation   func(*http.Request, string, string, string, string) error
	themeURLResolver  func(context.Context, string) (string, error)
	browserIDPolicy   *browser.BrowserIDPolicy
	trustedProxies    []netip.Prefix
	metrics           *metrics.Registry
	fedcmEnabled      bool
	fedcmForceMFA     bool
	upstreamProviders func(ctx context.Context) ([]UpstreamProvider, error)
	lockdown          *loginpolicy.LockdownStore
	captchaSiteKey    string
}

// SetMetrics attaches a metrics registry for authentication counters.
func (h *Handler) SetMetrics(reg *metrics.Registry) { h.metrics = reg }

// SetThemeURLResolver supplies the versioned stylesheet URL for a login page.
// The resolver owns client fallback and URL construction; an unset resolver
// keeps the legacy page available with only the global stylesheet.
func (h *Handler) SetThemeURLResolver(resolver func(context.Context, string) (string, error)) {
	h.themeURLResolver = resolver
}

func (h *Handler) resolveThemeURL(ctx context.Context, clientID string) (string, error) {
	if h.themeURLResolver == nil {
		return "", nil
	}
	if clientID == "" {
		clientID = "rauthy"
	}
	return h.themeURLResolver(ctx, clientID)
}

// EnableFedCM opts this handler into issuing the separate cross-site session
// cookie after successful authentication. It is HTTPS-only by browser policy.
func (h *Handler) EnableFedCM(enabled bool) error {
	if enabled {
		u, err := url.Parse(h.issuer)
		if err != nil || strings.ToLower(u.Scheme) != "https" {
			return errors.New("FedCM requires an HTTPS issuer")
		}
	}
	h.fedcmEnabled = enabled
	return nil
}

// SetFedCMForceMFA carries the deployment's existing forced-MFA policy to the
// direct landing. A password alone is never upgraded to a FedCM session when
// this policy is active; a future passkey UI can complete the same marker.
func (h *Handler) SetFedCMForceMFA(enabled bool) { h.fedcmForceMFA = enabled }

// SetUpstreamProviderCatalog supplies the function used to discover upstream
// identity providers for the login page.
func (h *Handler) SetUpstreamProviderCatalog(fn func(ctx context.Context) ([]UpstreamProvider, error)) {
	h.upstreamProviders = fn
}

// SetLockdownStore attaches a global lockdown store for emergency login blocking.
func (h *Handler) SetLockdownStore(store *loginpolicy.LockdownStore) {
	h.lockdown = store
}

func (h *Handler) SetCaptchaSiteKey(siteKey string) {
	h.captchaSiteKey = siteKey
}

// SetOTPHandler attaches the OTP handler for email-based 2FA.
func (h *Handler) SetOTPHandler(handler *recovery.OTPHandler) {
	h.otp = handler
}

func New(issuer string, browserStore *browser.Store, identityStore *identity.Store, oauthServer *oauth.Server) (*Handler, error) {
	return NewWithRecovery(issuer, browserStore, identityStore, oauthServer, nil)
}

func NewWithRecovery(issuer string, browserStore *browser.Store, identityStore *identity.Store, oauthServer *oauth.Server, onPasswordExpired func(context.Context, string) error) (*Handler, error) {
	normalizedIssuer, err := oidc.NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	if _, err := browser.CookieName(normalizedIssuer); err != nil {
		return nil, err
	}
	if browserStore == nil || identityStore == nil || oauthServer == nil {
		return nil, errors.New("login handler requires browser, identity, and OAuth stores")
	}
	return &Handler{
		issuer: normalizedIssuer, browser: browserStore, identity: identityStore, oauth: oauthServer,
		now: time.Now, wait: waitContext,
		onPasswordExpired: onPasswordExpired,
		deadline: func(w http.ResponseWriter, deadline time.Time) error {
			return http.NewResponseController(w).SetWriteDeadline(deadline)
		},
	}, nil
}

// NewWithPolicy enables replicated direct-peer login protection. The caller
// owns runtime wiring so tests and embedders can retain the legacy boundary.
func NewWithPolicy(issuer string, browserStore *browser.Store, identityStore *identity.Store, oauthServer *oauth.Server, policy *loginpolicy.Store) (*Handler, error) {
	return NewWithPolicyAndRecovery(issuer, browserStore, identityStore, oauthServer, policy, nil)
}

// NewWithPolicyAndRecovery enables login protection and the password-expiry
// recovery callback. The callback runs before any interaction or session state
// is consumed.
func NewWithPolicyAndRecovery(issuer string, browserStore *browser.Store, identityStore *identity.Store, oauthServer *oauth.Server, policy *loginpolicy.Store, onPasswordExpired func(context.Context, string) error) (*Handler, error) {
	h, err := NewWithRecovery(issuer, browserStore, identityStore, oauthServer, onPasswordExpired)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.New("login handler requires login policy")
	}
	h.policy = policy
	return h, nil
}

// NewWithPolicyRecoveryAndPasskeys enables passwordless WebAuthn login while
// preserving the existing password-login construction boundary.
func NewWithPolicyRecoveryAndPasskeys(issuer string, browserStore *browser.Store, identityStore *identity.Store, oauthServer *oauth.Server, policy *loginpolicy.Store, onPasswordExpired func(context.Context, string) error, passkeys *passkey.Service) (*Handler, error) {
	h, err := NewWithPolicyAndRecovery(issuer, browserStore, identityStore, oauthServer, policy, onPasswordExpired)
	if err != nil {
		return nil, err
	}
	if passkeys == nil {
		return nil, errors.New("login handler requires passkey service")
	}
	h.passkeys = passkeys
	return h, nil
}

// NewWithPolicyRecoveryPasskeysAndTrustedProxies enables passwordless WebAuthn
// login with trusted-proxy peer IP resolution for session IP binding.
func NewWithPolicyRecoveryPasskeysAndTrustedProxies(issuer string, browserStore *browser.Store, identityStore *identity.Store, oauthServer *oauth.Server, policy *loginpolicy.Store, onPasswordExpired func(context.Context, string) error, passkeys *passkey.Service, trustedProxies []netip.Prefix) (*Handler, error) {
	h, err := NewWithPolicyRecoveryAndPasskeys(issuer, browserStore, identityStore, oauthServer, policy, onPasswordExpired, passkeys)
	if err != nil {
		return nil, err
	}
	h.trustedProxies = trustedProxies
	return h, nil
}

// NewWithPolicyAndTrustedProxies enables login protection with trusted-proxy
// peer IP resolution for session IP binding.
func NewWithPolicyAndTrustedProxies(issuer string, browserStore *browser.Store, identityStore *identity.Store, oauthServer *oauth.Server, policy *loginpolicy.Store, onPasswordExpired func(context.Context, string) error, trustedProxies []netip.Prefix) (*Handler, error) {
	h, err := NewWithPolicyAndRecovery(issuer, browserStore, identityStore, oauthServer, policy, onPasswordExpired)
	if err != nil {
		return nil, err
	}
	h.trustedProxies = trustedProxies
	return h, nil
}

// resolvePeerIP returns the canonical peer IP. The middleware resolves this
// once at the HTTP boundary and stores it in context; this method reads the
// context value first. When context is empty (standalone handler use or
// embedding outside cmd/goauthy) it falls back to its own resolution using
// the configured trusted proxies.
func (h *Handler) resolvePeerIP(r *http.Request) (string, bool) {
	if peerIP := browser.PeerIPFromContext(r.Context()); peerIP != "" {
		return peerIP, true
	}
	if len(h.trustedProxies) > 0 {
		return loginpolicy.PeerIPFromRequest(r.RemoteAddr, r.Header, h.trustedProxies)
	}
	return loginpolicy.PeerIP(r.RemoteAddr)
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	request, valid := h.oauth.ValidateAuthorizationRequestForLogin(w, r)
	if !valid {
		return
	}
	var err error
	if session, sessionToken, ok := h.session(r); ok && session.Authenticated() && !reauthenticate(request, session, h.now()) {
		if _, err := h.identity.UserBySubject(r.Context(), session.Subject); err == nil && (!request.ForceMFA || session.AuthenticationMethod == "mfa") {
			// Legacy sessions have no peer binding. They remain usable for the
			// normal browser flow, but must not cross the FedCM credential
			// boundary because FedCM resolution requires a bound peer.
			if session.PeerIP != "" {
				if err := h.setFedCMSessionCookie(w, sessionToken, session.ExpiresAt); err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			}
			h.oauth.CompleteAuthorizationWithSession(w, r, session.Subject, request.RequestedScopes, session.CreatedAt, session.ID, session.AuthenticationMethod)
			return
		}
	}
	if prompted(request.Prompt, "none") {
		h.oauth.WriteLoginRequired(w, r)
		return
	}
	themeURL, err := h.resolveThemeURL(r.Context(), request.ClientID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	var session browser.IssuedSession
	if current, token, ok := h.session(r); ok && !current.Authenticated() {
		session = browser.IssuedSession{Session: current, Token: token}
	} else {
		peerIP, peerOK := h.resolvePeerIP(r)
		if !peerOK {
			http.Error(w, "Invalid login request", http.StatusBadRequest)
			return
		}
		session, err = h.browser.CreateInitSession(r.Context(), h.now().Add(interactionLifetime), peerIP)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
	}
	interaction, err := h.browser.CreateAuthorizationInteraction(r.Context(), session.Token, request.RequestID, []byte(r.URL.RequestURI()), h.now().Add(interactionLifetime))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	cookie, err := browser.SessionCookie(h.issuer, session.Token, session.ExpiresAt)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	if err := h.setBrowserIDCookie(w, r); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	messages := i18n.MessagesFor(strings.Join(r.Header.Values("Accept-Language"), ","))
	localizedHTMLHeaders(w, messages.Language)
	// Chromium applies form-action to the callback redirect after the login
	// POST too. Use only this already-validated request's callback origin.
	w.Header().Set("Content-Security-Policy", authorizationFormCSP(request.RedirectURI))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var providers []UpstreamProvider
	if h.upstreamProviders != nil {
		if list, err := h.upstreamProviders(r.Context()); err == nil {
			providers = list
		}
	}
	if idpHint := r.URL.Query().Get("idp_hint"); idpHint != "" && len(providers) > 0 {
		for _, p := range providers {
			if p.ID == idpHint {
				http.Redirect(w, r, "/upstream/"+p.ID+"/start?redirect_uri="+url.QueryEscape(p.CallbackURI)+"&interaction="+url.QueryEscape(interaction.Token), http.StatusFound)
				return
			}
		}
	}
	if err := loginPage.Execute(w, loginPageData{ClientID: request.ClientID, Interaction: interaction.Token, ThemeURL: themeURL, CaptchaSiteKey: h.captchaSiteKey, Providers: providers, Messages: messages}); err != nil {
		return
	}
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	_, span := tracing.NewTracer("goauthy/login").Start(r.Context(), "login",
		trace.WithSpanKind(trace.SpanKindServer),
	)
	defer span.End()
	securityHeaders(w)
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if crossSite(r.Header.Values("Sec-Fetch-Site")) {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	form, err := parseLoginForm(w, r)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	session, sessionToken, ok := h.session(r)
	if !ok || session.Authenticated() {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	auth, peerIP, started, ok := h.authenticatePassword(w, r, form.username, form.password)
	if !ok {
		return
	}
	// Read the immutable original request before any interaction transition.
	// A force-MFA client must never receive a password-only session or code.
	interaction, err := h.browser.LoadAuthorizationInteractionReadOnly(r.Context(), sessionToken, form.interaction)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	original, err := h.originalAuthorizeRequest(r, interaction.Payload)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	request, err := h.oauth.ValidateAuthorizationRequest(original)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	if request.ForceMFA {
		if h.passkeys != nil {
			user, err := h.identity.UserBySubject(r.Context(), auth.Subject)
			if err != nil {
				http.Error(w, "Invalid login request", http.StatusUnauthorized)
				return
			}
			rcr, code, exp, err := h.passkeys.BeginMFALogin(r.Context(), auth.Subject, user.Username, form.interaction, session.ID)
			if err != nil {
				if errors.Is(err, passkey.ErrNotFound) || errors.Is(err, passkey.ErrInvalid) {
					http.Error(w, "Invalid login request", http.StatusNotAcceptable)
					return
				}
				http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(passkeyStartResponse{Code: code, RCR: rcr, Exp: exp.UTC()})
			return
		}
		if h.otp != nil && h.otp.Enabled() {
			lang := ""
			if langHeader := r.Header.Get("Accept-Language"); langHeader != "" {
				lang = parseAcceptLanguage(langHeader)
			}
			expiresAt := time.Now().UTC().Add(5 * time.Minute)
			if err := h.otp.SendOTP(r.Context(), auth.Subject, lang, expiresAt); err != nil {
				http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
				return
			}
			if err := h.otp.StoreInteraction(session.ID, auth.Subject, form.interaction, expiresAt); err != nil {
				http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(otpStartResponse{ExpiresAt: expiresAt})
			return
		}
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	h.completeAuthentication(w, r, sessionToken, form.interaction, auth.Subject, "pwd", func() error {
		return h.recordSuccessfulAuthentication(r.Context(), peerIP, h.now().Sub(started), nil)
	})
}

// FedCMLanding serves the same password authentication and browser-session
// rotation used by OAuth login, without inventing an OAuth client or redirect.
// The one-time browser interaction is retained as the replay/concurrency claim
// for this direct account-login surface.
func (h *Handler) FedCMLanding(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if !h.fedcmEnabled {
		http.NotFound(w, r)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.fedCMGet(w, r)
	case http.MethodPost:
		h.fedCMPost(w, r)
	default:
		methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
	}
}

func (h *Handler) fedCMGet(w http.ResponseWriter, r *http.Request) {
	if current, token, ok := h.session(r); ok && current.Authenticated() {
		if _, err := h.identity.UserBySubject(r.Context(), current.Subject); current.PeerIP == "" || err != nil || h.fedcmForceMFA && current.AuthenticationMethod != "mfa" {
			http.Error(w, "Invalid login request", http.StatusForbidden)
			return
		}
		if err := h.setFedCMSessionCookie(w, token, current.ExpiresAt); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		h.writeFedCMSuccess(w, r)
		return
	}
	peerIP, ok := h.resolvePeerIP(r)
	if !ok || peerIP == "" {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	var session browser.IssuedSession
	if current, token, ok := h.session(r); ok && !current.Authenticated() && current.PeerIP != "" {
		session = browser.IssuedSession{Session: current, Token: token}
	} else {
		var err error
		session, err = h.browser.CreateInitSession(r.Context(), h.now().Add(interactionLifetime), peerIP)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
	}
	requestID, err := newFedCMRequestID()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	interaction, err := h.browser.CreateAuthorizationInteraction(r.Context(), session.Token, requestID, []byte(fedCMLandingPayload), h.now().Add(interactionLifetime))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	csrf, err := browser.DeriveCSRFToken(session.Token)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	cookie, err := browser.SessionCookie(h.issuer, session.Token, session.ExpiresAt)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	if err := h.setBrowserIDCookie(w, r); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	themeURL, err := h.resolveThemeURL(r.Context(), "rauthy")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	messages := i18n.MessagesFor(strings.Join(r.Header.Values("Accept-Language"), ","))
	localizedHTMLHeaders(w, messages.Language)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := fedCMLandingPage.Execute(w, fedCMLandingPageData{Interaction: interaction.Token, CSRFToken: csrf, ThemeURL: themeURL, Messages: messages}); err != nil {
		return
	}
}

type loginPageData struct {
	ClientID, Interaction, ThemeURL string
	CaptchaSiteKey                  string
	Providers                       []UpstreamProvider
	PasskeyLogin                    bool
	PasskeyNonce                    string
	i18n.Messages
}

type fedCMLandingPageData struct {
	Interaction, CSRFToken, ThemeURL string
	i18n.Messages
}

type fedCMSuccessPageData struct {
	ThemeURL string
	i18n.Messages
}

func newFedCMRequestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "fedcm:" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func (h *Handler) fedCMPost(w http.ResponseWriter, r *http.Request) {
	if crossSite(r.Header.Values("Sec-Fetch-Site")) || !sameIssuerOrigin(r, h.issuer) {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	form, err := parseFedCMLandingForm(w, r)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	session, sessionToken, ok := h.session(r)
	if !ok || session.Authenticated() || session.PeerIP == "" || browser.ValidateCSRFToken(sessionToken, form.csrfToken) != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	auth, peerIP, started, ok := h.authenticatePassword(w, r, form.username, form.password)
	if !ok {
		return
	}
	if h.fedcmForceMFA {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	interaction, err := h.browser.ConsumeAuthorizationInteraction(r.Context(), sessionToken, form.interaction)
	if err != nil || string(interaction.Payload) != fedCMLandingPayload {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	if err := h.recordSuccessfulAuthentication(r.Context(), peerIP, h.now().Sub(started), nil); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if _, err := h.rotateBrowserSession(w, r, sessionToken, auth.Subject, "pwd", peerIP); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	h.writeFedCMSuccess(w, r)
}

func (h *Handler) writeFedCMSuccess(w http.ResponseWriter, r *http.Request) {
	themeURL, err := h.resolveThemeURL(r.Context(), "rauthy")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	messages := i18n.MessagesFor(strings.Join(r.Header.Values("Accept-Language"), ","))
	localizedHTMLHeaders(w, messages.Language)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = fedCMSuccessPage.Execute(w, fedCMSuccessPageData{ThemeURL: themeURL, Messages: messages})
}

type fedCMLandingForm struct{ interaction, username, password, csrfToken string }

func parseFedCMLandingForm(w http.ResponseWriter, r *http.Request) (fedCMLandingForm, error) {
	if len(r.Header.Values("Content-Type")) != 1 {
		return fedCMLandingForm{}, errors.New("invalid content type")
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return fedCMLandingForm{}, errors.New("invalid content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, formLimit)
	if err := r.ParseForm(); err != nil || len(r.PostForm) != 5 {
		return fedCMLandingForm{}, errors.New("invalid form")
	}
	fedCM, ok := r.PostForm["fedcm"]
	if !ok || len(fedCM) != 1 || fedCM[0] != "1" {
		return fedCMLandingForm{}, errors.New("invalid form marker")
	}
	form := fedCMLandingForm{}
	for key, target := range map[string]*string{"interaction": &form.interaction, "username": &form.username, "password": &form.password, "csrf_token": &form.csrfToken} {
		values, ok := r.PostForm[key]
		if !ok || len(values) != 1 || values[0] == "" {
			return fedCMLandingForm{}, errors.New("invalid form field")
		}
		*target = values[0]
	}
	if !utf8.ValidString(form.password) || utf8.RuneCountInString(form.password) > 256 {
		return fedCMLandingForm{}, errors.New("invalid password")
	}
	return form, nil
}

func sameIssuerOrigin(r *http.Request, issuer string) bool {
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 || values[0] == "" {
		return false
	}
	if values[0] == "null" {
		// Native forms under no-referrer suppress Origin. Require browser-owned
		// same-origin Fetch Metadata as well as the caller's existing CSRF guard.
		var protection http.CrossOriginProtection
		return len(r.Header.Values("Sec-Fetch-Site")) == 1 && r.Header.Get("Sec-Fetch-Site") == "same-origin" && protection.Check(r) == nil
	}
	origin, err := url.Parse(values[0])
	if err != nil || origin.Scheme == "" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawPath != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.Opaque != "" {
		return false
	}
	want, err := url.Parse(issuer)
	if err != nil || want.Scheme == "" || want.Host == "" {
		return false
	}
	return strings.EqualFold(origin.Scheme, want.Scheme) && strings.EqualFold(origin.Hostname(), want.Hostname()) && originPort(origin) == originPort(want)
}

func originPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func (h *Handler) authenticatePassword(w http.ResponseWriter, r *http.Request, username, password string) (identity.Authentication, string, time.Time, bool) {
	if h.lockdown != nil {
		locked, reason, until, lockdownErr := h.lockdown.IsLockedDown(r.Context())
		if lockdownErr == nil && locked {
			isAdmin, adminErr := h.lockdown.IsAdminByUsername(r.Context(), username)
			if adminErr == nil && isAdmin {
				goto checkRateLimit
			}
			w.Header().Set("Content-Type", "application/json")
			if !until.IsZero() {
				seconds := int(time.Until(until).Seconds())
				if seconds < 1 {
					seconds = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(seconds))
			}
			if reason == "" {
				reason = "system is in lockdown mode"
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "service_unavailable", "message": reason})
			return identity.Authentication{}, "", time.Time{}, false
		}
	}
checkRateLimit:
	peerIP, valid := h.resolvePeerIP(r)
	if !valid || peerIP == "" {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return identity.Authentication{}, "", time.Time{}, false
	}
	if h.policy != nil {
		status, err := h.policy.Check(r.Context(), peerIP, h.now().UTC())
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return identity.Authentication{}, "", time.Time{}, false
		}
		if !status.BlockedUntil.IsZero() {
			writeBlocked(w, h.now, status.BlockedUntil)
			return identity.Authentication{}, "", time.Time{}, false
		}
		allowed, err := h.policy.Allow(r.Context(), peerIP, h.now().UTC())
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return identity.Authentication{}, "", time.Time{}, false
		}
		if !allowed {
			writeRetryAfter(w, h.now, h.now().Add(loginpolicy.DefaultAttemptWindow))
			return identity.Authentication{}, "", time.Time{}, false
		}
	}
	accountHash := loginpolicy.AccountStuffingDigest(username)
	if h.policy != nil {
		if locked, remaining, lockErr := h.policy.CheckAccountLock(r.Context(), accountHash, h.now().UTC()); lockErr == nil && locked {
			w.Header().Set("Content-Type", "application/json")
			seconds := int(remaining.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "account_locked", "retry_after_seconds": seconds})
			return identity.Authentication{}, "", time.Time{}, false
		}
	}
	started := h.now()
	auth, err := h.identity.Authenticate(r.Context(), username, []byte(password))
	if errors.Is(err, identity.ErrPasswordExpired) {
		if auth.Subject == "" || h.onPasswordExpired == nil || h.onPasswordExpired(r.Context(), auth.Subject) != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return identity.Authentication{}, "", time.Time{}, false
		}
		http.Error(w, "Password reset required", http.StatusForbidden)
		return identity.Authentication{}, "", time.Time{}, false
	}
	if errors.Is(err, identity.ErrInvalidCredentials) {
		if h.metrics != nil {
			h.metrics.AuthFailure()
		}
		if h.policy != nil {
			status, policyErr := h.policy.Failure(r.Context(), peerIP, h.now().UTC())
			if policyErr != nil {
				http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
				return identity.Authentication{}, "", time.Time{}, false
			}
			if !status.BlockedUntil.IsZero() {
				writeBlocked(w, h.now, status.BlockedUntil)
				return identity.Authentication{}, "", time.Time{}, false
			}
			delay := loginpolicy.Delay(status, h.now().Sub(started))
			if delay > 0 {
				if err := h.deadline(w, h.now().Add(delay+failureWriteGrace)); err != nil {
					http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
					return identity.Authentication{}, "", time.Time{}, false
				}
			}
			if err := h.wait(r.Context(), delay); err != nil {
				return identity.Authentication{}, "", time.Time{}, false
			}
		}
		if h.policy != nil {
			h.policy.RecordAccountFailure(r.Context(), accountHash, peerIP, h.now().UTC())
		}
		http.Error(w, "Invalid user credentials", http.StatusUnauthorized)
		return identity.Authentication{}, "", time.Time{}, false
	}
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return identity.Authentication{}, "", time.Time{}, false
	}
	if h.onLoginLocation != nil {
		if !security.ValidHeaderText(r.UserAgent()) {
			http.Error(w, "Invalid User-Agent", http.StatusBadRequest)
			return identity.Authentication{}, "", time.Time{}, false
		}
		// Notify on a correct password even when the later MFA step cannot finish.
		if err := h.recordLoginLocation(w, r, auth.Subject, peerIP); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return identity.Authentication{}, "", time.Time{}, false
		}
	}
	if h.policy != nil {
		h.policy.ClearAccountLock(r.Context(), accountHash)
	}
	return auth, peerIP, started, true
}

// CompleteExternalAuthentication completes an already-verified upstream
// authentication. The adapter supplies the raw init-session token and the
// persisted interaction digest; it cannot choose the authentication method.
func (h *Handler) CompleteExternalAuthentication(w http.ResponseWriter, r *http.Request, sessionToken, interactionDigest, subject string) {
	h.completeExternalAuthentication(w, r, sessionToken, interactionDigest, subject, nil)
}

// CompleteUpstreamAuthentication completes an already-verified upstream
// authentication and atomically binds its replacement browser session to the
// verified upstream session. The binding is stored before a cookie or
// authorization code can be emitted, so later upstream logout can revoke it.
func (h *Handler) CompleteUpstreamAuthentication(w http.ResponseWriter, r *http.Request, sessionToken, interactionDigest, subject string, binding *browser.UpstreamSessionBinding) {
	h.completeExternalAuthentication(w, r, sessionToken, interactionDigest, subject, binding)
}

func (h *Handler) completeExternalAuthentication(w http.ResponseWriter, r *http.Request, sessionToken, interactionDigest, subject string, binding *browser.UpstreamSessionBinding) {
	securityHeaders(w)
	peerIP, peerOK := h.resolvePeerIP(r)
	if !peerOK {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	session, err := h.browser.LoadSessionForPeer(r.Context(), sessionToken, peerIP)
	if err != nil || session.Authenticated() {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	interaction, err := h.browser.LoadAuthorizationInteractionReadOnlyByDigest(r.Context(), sessionToken, interactionDigest)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	original, err := h.originalAuthorizeRequest(r, interaction.Payload)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	request, err := h.oauth.ValidateAuthorizationRequest(original)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	authMethod := "external"
	if request.ForceMFA {
		if binding == nil || !binding.MFAPassed {
			http.Error(w, "Invalid login request", http.StatusForbidden)
			return
		}
		authMethod = "mfa"
	}
	// Preserve verified upstream MFA even when ForceMFA is not set.
	// The session carries the stronger authentication proof regardless
	// of whether the current authorization request demands it.
	if authMethod == "external" && binding != nil && binding.MFAPassed {
		authMethod = "mfa"
	}
	if _, err := h.identity.UserBySubject(r.Context(), subject); err != nil {
		http.Error(w, "Invalid login request", http.StatusUnauthorized)
		return
	}
	consumed, err := h.browser.ConsumeAuthorizationInteractionByDigest(r.Context(), sessionToken, interactionDigest)
	if err != nil || consumed.RequestID != interaction.RequestID || !bytes.Equal(consumed.Payload, interaction.Payload) {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	h.completeConsumedAuthentication(w, r, sessionToken, subject, authMethod, original, request, peerIP, nil, binding)
}

// CurrentExternalInitSession returns the cookie bearer token and its canonical
// persisted digest only for a live, unauthenticated session bound to this peer.
func (h *Handler) CurrentExternalInitSession(r *http.Request) (string, string, error) {
	name, err := browser.CookieName(h.issuer)
	if err != nil {
		return "", "", ErrExternalAuthentication
	}
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return "", "", ErrExternalAuthentication
	}
	peerIP, ok := h.resolvePeerIP(r)
	if !ok {
		return "", "", ErrExternalAuthentication
	}
	session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, peerIP)
	if err != nil || session.Authenticated() {
		return "", "", ErrExternalAuthentication
	}
	return cookie.Value, session.ID, nil
}

// PrepareExternalAuthentication proves that an upstream flow is bound to the
// current live init session without consuming its OAuth interaction.
func (h *Handler) PrepareExternalAuthentication(r *http.Request, rawInteractionToken string) (string, string, string, error) {
	sessionToken, sessionDigest, err := h.CurrentExternalInitSession(r)
	if err != nil {
		return "", "", "", ErrExternalAuthentication
	}
	interaction, err := h.browser.LoadAuthorizationInteractionReadOnly(r.Context(), sessionToken, rawInteractionToken)
	if err != nil {
		return "", "", "", ErrExternalAuthentication
	}
	original, err := h.originalAuthorizeRequest(r, interaction.Payload)
	if err != nil {
		return "", "", "", ErrExternalAuthentication
	}
	_, err = h.oauth.ValidateAuthorizationRequest(original)
	if err != nil {
		return "", "", "", ErrExternalAuthentication
	}
	interactionDigest, err := browser.CanonicalTokenDigest(rawInteractionToken)
	if err != nil {
		return "", "", "", ErrExternalAuthentication
	}
	return sessionToken, sessionDigest, interactionDigest, nil
}

// completeAuthentication is the sole transition from an init browser session
// into an authenticated OAuth browser session. Both password and passkey
// authenticators intentionally use this path.
func (h *Handler) completeAuthentication(w http.ResponseWriter, r *http.Request, sessionToken, interactionToken, subject, authMethod string, onConsumed func() error) {
	peerIP, peerOK := h.resolvePeerIP(r)
	if !peerOK {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	interaction, err := h.browser.ConsumeAuthorizationInteraction(r.Context(), sessionToken, interactionToken)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	original, err := h.originalAuthorizeRequest(r, interaction.Payload)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	request, err := h.oauth.ValidateAuthorizationRequest(original)
	if err != nil || (request.ForceMFA && authMethod != "mfa") {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	h.completeConsumedAuthentication(w, r, sessionToken, subject, authMethod, original, request, peerIP, onConsumed, nil)
}

func (h *Handler) completeConsumedAuthentication(w http.ResponseWriter, r *http.Request, sessionToken, subject, authMethod string, original *http.Request, request oauth.AuthorizationRequest, peerIP string, onConsumed func() error, binding *browser.UpstreamSessionBinding) {
	if _, err := h.identity.UserBySubject(r.Context(), subject); err != nil {
		http.Error(w, "Invalid login request", http.StatusUnauthorized)
		return
	}
	if onConsumed != nil {
		if err := onConsumed(); err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
	}
	// ponytail: a failed code issuance consumes this interaction; restart authorize rather than risking duplicate codes.
	newSession, err := h.rotateBrowserSessionWithBinding(w, r, sessionToken, subject, authMethod, peerIP, binding)
	if err != nil {
		if errors.Is(err, errLoginLocation) {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if errors.Is(err, identity.ErrInvalidUserAgent) {
			http.Error(w, "Invalid User-Agent", http.StatusBadRequest)
			return
		}
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if h.metrics != nil {
		h.metrics.AuthSuccess()
	}
	h.oauth.CompleteAuthorizationWithSession(w, original, subject, request.RequestedScopes, newSession.CreatedAt, newSession.ID, newSession.AuthenticationMethod)
}

// rotateBrowserSession is the common post-authentication browser transition.
// Callers must consume any one-time challenge before invoking it. The caller's
// old session is revoked after the replacement is durably created, matching
// the existing OAuth login behavior and preserving the peer binding.
func (h *Handler) rotateBrowserSession(w http.ResponseWriter, r *http.Request, sessionToken, subject, authMethod, peerIP string) (browser.IssuedSession, error) {
	return h.rotateBrowserSessionWithBinding(w, r, sessionToken, subject, authMethod, peerIP, nil)
}

func (h *Handler) rotateBrowserSessionWithBinding(w http.ResponseWriter, r *http.Request, sessionToken, subject, authMethod, peerIP string, binding *browser.UpstreamSessionBinding) (browser.IssuedSession, error) {
	if h.onLoginLocation != nil && (authMethod == "webauthn" || authMethod == "mfa") && !security.ValidHeaderText(r.UserAgent()) {
		return browser.IssuedSession{}, identity.ErrInvalidUserAgent
	}
	if _, err := h.identity.UserBySubject(r.Context(), subject); err != nil {
		return browser.IssuedSession{}, err
	}
	if authMethod != "pwd" {
		if err := h.recordLoginLocation(w, r, subject, peerIP); err != nil {
			return browser.IssuedSession{}, err
		}
	}
	var (
		newSession browser.IssuedSession
		err        error
	)
	if binding != nil {
		if authMethod != "external" && authMethod != "mfa" {
			return browser.IssuedSession{}, errors.New("upstream binding requires external or mfa authentication")
		}
		newSession, err = h.browser.CreateUpstreamSession(r.Context(), subject, *binding, authMethod, h.now().Add(sessionLifetime), peerIP)
	} else {
		newSession, err = h.browser.CreateSession(r.Context(), subject, authMethod, h.now().Add(sessionLifetime), peerIP)
	}
	if err != nil {
		return browser.IssuedSession{}, err
	}
	if err := h.identity.RecordLoginForSession(r.Context(), subject, newSession.ID); err != nil {
		// The replacement must not become usable if bookkeeping cannot prove
		// that it belongs to the active authenticated session.
		_ = h.browser.RevokeSessionID(r.Context(), newSession.ID)
		return browser.IssuedSession{}, err
	}
	if err := h.browser.RevokeSession(r.Context(), sessionToken); err != nil {
		return browser.IssuedSession{}, err
	}
	cookie, err := browser.SessionCookie(h.issuer, newSession.Token, newSession.ExpiresAt)
	if err != nil {
		return browser.IssuedSession{}, err
	}
	fedcmCookie, err := h.fedCMSessionCookie(newSession.Token, newSession.ExpiresAt)
	if err != nil {
		return browser.IssuedSession{}, err
	}
	http.SetCookie(w, cookie)
	if fedcmCookie != nil {
		http.SetCookie(w, fedcmCookie)
	}
	return newSession, nil
}

func (h *Handler) fedCMSessionCookie(token string, expiresAt time.Time) (*http.Cookie, error) {
	if !h.fedcmEnabled {
		return nil, nil
	}
	return browser.FedCMSessionCookie(h.issuer, token, expiresAt)
}

func (h *Handler) setFedCMSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) error {
	cookie, err := h.fedCMSessionCookie(token, expiresAt)
	if err != nil {
		return err
	}
	if cookie != nil {
		http.SetCookie(w, cookie)
	}
	return nil
}

// WebAuthnStart begins a passkey assertion bound to the current unauthenticated
// browser session and its original OAuth authorization interaction.
//
// Two entry points share this endpoint:
//   - Cookie present: normal passwordless passkey login (subject from cookie).
//   - Cookie absent + Username: passkey-only login (subject from
//     LookupPasskeyOnlySubject).  Absent cookie without username, or a
//     tampered/invalid cookie, is rejected—no fallback.
func (h *Handler) WebAuthnStart(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if crossSite(r.Header.Values("Sec-Fetch-Site")) {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	payload, err := decodePasskeyStart(w, r)
	if err != nil || payload.Purpose.Login == "" {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	if h.passkeys == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	session, sessionToken, ok := h.session(r)
	if !ok || session.Authenticated() {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}

	_, allowed := h.allowPasskeyLogin(w, r)
	if !allowed {
		return
	}

	// Parse/validate the passkey cookie BEFORE interaction validation so that
	// a present-but-invalid cookie always yields 401 (not a different error
	// from interaction or OAuth validation). The DB lookup for the cookie
	// subject is deferred until after interaction validation.
	var (
		cookieSubject string
		fresh         bool
	)
	cookie, cookieErr := r.Cookie(h.passkeyCookieName())
	switch {
	case cookieErr == nil && cookie.Value != "":
		// Cookie present: parse cryptographic cookie. If tampered/invalid,
		// reject 401 immediately—never fall through to username lookup.
		cookieSubject, err = h.passkeys.SubjectFromCookie(cookie.Value)
		if err != nil {
			http.Error(w, "Invalid login request", http.StatusUnauthorized)
			return
		}

	case errors.Is(cookieErr, http.ErrNoCookie):
		// Absent cookie: only permit fresh identity lookup when a username
		// is provided.
		if payload.Username == "" {
			http.Error(w, "Invalid login request", http.StatusUnauthorized)
			return
		}
		fresh = true

	default:
		// Present but empty or unreadable cookie: always reject.
		http.Error(w, "Invalid login request", http.StatusUnauthorized)
		return
	}

	// Validate the live init session against the original OAuth request
	// before issuing any WebAuthn challenge.
	interaction, err := h.browser.LoadAuthorizationInteractionReadOnly(r.Context(), sessionToken, payload.Purpose.Login)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	original, err := h.originalAuthorizeRequest(r, interaction.Payload)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	request, err := h.oauth.ValidateAuthorizationRequest(original)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}

	// Resolve subject and username. The cookie user DB lookup happens here,
	// after interaction and OAuth validation, to prevent a username oracle.
	var (
		subject  string
		username string
	)
	if fresh {
		subject, username, err = h.identity.LookupPasskeyOnlySubject(r.Context(), payload.Username)
		if err != nil {
			http.Error(w, "Invalid login request", http.StatusUnauthorized)
			return
		}
	} else {
		subject = cookieSubject
		user, userErr := h.identity.UserBySubject(r.Context(), subject)
		if userErr != nil {
			if errors.Is(userErr, identity.ErrInactiveSubject) {
				http.Error(w, "Invalid login request", http.StatusUnauthorized)
				return
			}
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		username = user.Username
	}

	// Fresh passkey-only accounts always require user verification (UV).
	// Use BeginMFALogin for fresh OR when the authorization request forces
	// MFA, avoiding a mode race that relied on BeginLogin auto-upgrade.
	if fresh || request.ForceMFA {
		rcr, code, exp, mfaErr := h.passkeys.BeginMFALogin(r.Context(), subject, username, payload.Purpose.Login, session.ID)
		if mfaErr != nil {
			if errors.Is(mfaErr, passkey.ErrNotFound) || errors.Is(mfaErr, passkey.ErrInvalid) {
				http.Error(w, "Invalid login request", http.StatusUnauthorized)
				return
			}
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(passkeyStartResponse{Code: code, RCR: rcr, Exp: exp.UTC()})
		return
	}
	rcr, code, exp, loginErr := h.passkeys.BeginLogin(r.Context(), subject, username, payload.Purpose.Login, session.ID)
	if loginErr != nil {
		if errors.Is(loginErr, passkey.ErrNotFound) || errors.Is(loginErr, passkey.ErrInvalid) {
			http.Error(w, "Invalid login request", http.StatusUnauthorized)
			return
		}
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(passkeyStartResponse{Code: code, RCR: rcr, Exp: exp.UTC()})
}

// WebAuthnFinish validates an assertion then follows the exact same browser
// session rotation and OAuth completion transition as password login.
func (h *Handler) WebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if crossSite(r.Header.Values("Sec-Fetch-Site")) {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	payload, err := decodePasskeyFinish(w, r)
	if err != nil || payload.Code == "" || payload.Data == "" {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	if h.passkeys == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	session, sessionToken, ok := h.session(r)
	if !ok || session.Authenticated() {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	peerIP, allowed := h.allowPasskeyLogin(w, r)
	if !allowed {
		return
	}
	started := h.now()
	assertionRequest := r.Clone(r.Context())
	assertionRequest.Body = io.NopCloser(bytes.NewBufferString(payload.Data))
	assertionRequest.ContentLength = int64(len(payload.Data))
	assertionRequest.Header.Set("Content-Type", "application/json")
	result, err := h.passkeys.FinishLogin(r.Context(), session.ID, payload.Code, assertionRequest)
	if err != nil || result.Subject == "" || result.InteractionToken == "" {
		h.passkeyFailure(w, r, peerIP)
		return
	}
	if _, err := h.identity.UserBySubject(r.Context(), result.Subject); err != nil {
		h.passkeyFailure(w, r, peerIP)
		return
	}
	if refreshed, err := h.passkeys.PasswordlessCookie(result.Subject); err == nil {
		if cookie, err := h.passwordlessCookie(refreshed); err == nil {
			http.SetCookie(w, cookie)
		}
	}
	h.completeAuthentication(w, r, sessionToken, result.InteractionToken, result.Subject, result.AuthenticationMethod, func() error {
		return h.recordSuccessfulAuthentication(r.Context(), peerIP, h.now().Sub(started), nil)
	})
}

type passkeyStartRequest struct {
	Username string `json:"username,omitempty"`
	Purpose  struct {
		Login string `json:"Login"`
	} `json:"purpose"`
}

type passkeyFinishRequest struct {
	Code string `json:"code"`
	Data string `json:"data"`
}

type passkeyStartResponse struct {
	Code string    `json:"code"`
	RCR  any       `json:"rcr"`
	Exp  time.Time `json:"exp"`
}

type otpStartResponse struct {
	ExpiresAt time.Time `json:"expires_at"`
}

type otpVerifyRequest struct {
	Code string `json:"code"`
}

const otpVerifyLimit = 1 << 10

// OTPVerify implements POST /auth/v1/users/otp/verify. It verifies the OTP
// code and completes the login flow if valid.
func (h *Handler) OTPVerify(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if crossSite(r.Header.Values("Sec-Fetch-Site")) {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	if h.otp == nil || !h.otp.Enabled() {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	session, sessionToken, ok := h.session(r)
	if !ok || session.Authenticated() {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	peerIP, allowed := h.allowPasskeyLogin(w, r)
	if !allowed {
		return
	}
	var payload otpVerifyRequest
	if err := decodeStrictJSON(w, r, otpVerifyLimit, &payload); err != nil || payload.Code == "" {
		http.Error(w, "Invalid OTP request", http.StatusBadRequest)
		return
	}
	subject, interactionToken, err := h.otp.ConsumeInteraction(session.ID)
	if err != nil || subject == "" || interactionToken == "" {
		http.Error(w, "Invalid OTP request", http.StatusUnauthorized)
		return
	}
	if _, err := h.identity.UserBySubject(r.Context(), subject); err != nil {
		http.Error(w, "Invalid login request", http.StatusUnauthorized)
		return
	}
	verified, verifyErr := h.otp.VerifyOTPCode(r.Context(), subject, payload.Code)
	if verifyErr != nil || !verified {
		if h.metrics != nil {
			h.metrics.AuthFailure()
		}
		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
		return
	}
	started := h.now()
	h.completeAuthentication(w, r, sessionToken, interactionToken, subject, "otp", func() error {
		return h.recordSuccessfulAuthentication(r.Context(), peerIP, h.now().Sub(started), nil)
	})
}

func decodePasskeyStart(w http.ResponseWriter, r *http.Request) (passkeyStartRequest, error) {
	var payload passkeyStartRequest
	return payload, decodeStrictJSON(w, r, passkeyStartLimit, &payload)
}

func decodePasskeyFinish(w http.ResponseWriter, r *http.Request) (passkeyFinishRequest, error) {
	var payload passkeyFinishRequest
	return payload, decodeStrictJSON(w, r, passkeyFinishLimit, &payload)
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, limit int64, target any) error {
	if len(r.Header.Values("Content-Type")) != 1 {
		return errors.New("invalid content type")
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("invalid content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func (h *Handler) allowPasskeyLogin(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.policy == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return "", false
	}
	peerIP, valid := h.resolvePeerIP(r)
	if !valid {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return "", false
	}
	status, err := h.policy.Check(r.Context(), peerIP, h.now().UTC())
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return "", false
	}
	if !status.BlockedUntil.IsZero() {
		writeBlocked(w, h.now, status.BlockedUntil)
		return "", false
	}
	allowed, err := h.policy.Allow(r.Context(), peerIP, h.now().UTC())
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return "", false
	}
	if !allowed {
		writeRetryAfter(w, h.now, h.now().Add(loginpolicy.DefaultAttemptWindow))
		return "", false
	}
	return peerIP, true
}

func (h *Handler) passkeyFailure(w http.ResponseWriter, r *http.Request, peerIP string) {
	if h.metrics != nil {
		h.metrics.AuthFailure()
	}
	status, err := h.policy.Failure(r.Context(), peerIP, h.now().UTC())
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if !status.BlockedUntil.IsZero() {
		writeBlocked(w, h.now, status.BlockedUntil)
		return
	}
	http.Error(w, "Invalid login request", http.StatusUnauthorized)
}

func (h *Handler) passkeyCookieName() string {
	issuer, err := url.Parse(h.issuer)
	if err == nil && issuer.Scheme == "https" {
		return "__Host-goauthy-passkey"
	}
	return "goauthy-passkey"
}

func (h *Handler) passwordlessCookie(value string) (*http.Cookie, error) {
	issuer, err := url.Parse(h.issuer)
	if err != nil || issuer.Host == "" || (issuer.Scheme != "http" && issuer.Scheme != "https") {
		return nil, errors.New("invalid issuer")
	}
	return &http.Cookie{Name: h.passkeyCookieName(), Value: value, Path: "/", HttpOnly: true, Secure: issuer.Scheme == "https", SameSite: http.SameSiteLaxMode}, nil
}

// recordSuccessfulAuthentication is intentionally a no-op for every
// authentication error: outages and Argon work-limit failures must neither
// erase brute-force state nor influence the durable timing floor.
func (h *Handler) recordSuccessfulAuthentication(ctx context.Context, peerIP string, elapsed time.Duration, authErr error) error {
	if authErr != nil || h.policy == nil {
		return authErr
	}
	return h.policy.Success(ctx, peerIP, elapsed)
}

func waitContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func writeBlocked(w http.ResponseWriter, now func() time.Time, until time.Time) {
	writeRetryAfter(w, now, until)
}

func writeRetryAfter(w http.ResponseWriter, now func() time.Time, until time.Time) {
	seconds := int(until.Sub(now().UTC()).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
}

func (h *Handler) session(r *http.Request) (browser.Session, string, bool) {
	name, err := browser.CookieName(h.issuer)
	if err != nil {
		return browser.Session{}, "", false
	}
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return browser.Session{}, "", false
	}
	peerIP, ok := h.resolvePeerIP(r)
	if !ok {
		return browser.Session{}, "", false
	}
	session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, peerIP)
	if err != nil {
		return browser.Session{}, "", false
	}
	return session, cookie.Value, true
}

func (h *Handler) originalAuthorizeRequest(r *http.Request, payload []byte) (*http.Request, error) {
	raw := string(payload)
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.RawPath != "" || u.Fragment != "" || !strings.HasPrefix(raw, "/") {
		return nil, errors.New("invalid saved authorize request")
	}
	issuer, err := url.Parse(h.issuer)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(issuer.Path, "/")
	path := u.Path
	if base != "" && strings.HasPrefix(path, base+"/") {
		path = strings.TrimPrefix(path, base)
	}
	if path != authorizePath {
		return nil, errors.New("invalid saved authorize request")
	}
	issuer.Path = base + path
	issuer.RawPath = ""
	issuer.RawQuery = u.RawQuery
	return http.NewRequestWithContext(r.Context(), http.MethodGet, issuer.String(), nil)
}

type loginForm struct{ interaction, username, password string }

func parseLoginForm(w http.ResponseWriter, r *http.Request) (loginForm, error) {
	if len(r.Header.Values("Content-Type")) != 1 {
		return loginForm{}, errors.New("invalid content type")
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return loginForm{}, errors.New("invalid content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, formLimit)
	if err := r.ParseForm(); err != nil {
		return loginForm{}, err
	}
	if len(r.PostForm) != 3 {
		return loginForm{}, errors.New("unexpected form fields")
	}
	form := loginForm{}
	for key, target := range map[string]*string{"interaction": &form.interaction, "username": &form.username, "password": &form.password} {
		values, ok := r.PostForm[key]
		if !ok || len(values) != 1 || values[0] == "" {
			return loginForm{}, errors.New("invalid form field")
		}
		*target = values[0]
	}
	if !utf8.ValidString(form.password) || utf8.RuneCountInString(form.password) > 256 {
		return loginForm{}, errors.New("invalid password")
	}
	return form, nil
}

func reauthenticate(request oauth.AuthorizationRequest, session browser.Session, now time.Time) bool {
	if prompted(request.Prompt, "login") || prompted(request.Prompt, "consent") {
		return true
	}
	return request.MaxAgeSeconds != nil && !session.CreatedAt.Add(time.Duration(*request.MaxAgeSeconds)*time.Second).After(now)
}

func prompted(prompt []string, value string) bool {
	for _, item := range prompt {
		if item == value {
			return true
		}
	}
	return false
}

func crossSite(values []string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), "cross-site") {
			return true
		}
	}
	return false
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
}

func localizedHTMLHeaders(w http.ResponseWriter, language string) {
	w.Header().Set("Content-Language", language)
	w.Header().Add("Vary", "Accept-Language")
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

func parseAcceptLanguage(header string) string {
	best := ""
	bestQ := -1.0
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lang := part
		q := 1.0
		if idx := strings.Index(part, ";"); idx >= 0 {
			lang = strings.TrimSpace(part[:idx])
			params := strings.TrimSpace(part[idx+1:])
			if strings.HasPrefix(params, "q=") {
				if val, err := strconv.ParseFloat(params[2:], 64); err == nil {
					q = val
				}
			}
		}
		if q <= bestQ {
			continue
		}
		code := lang
		if idx := strings.IndexByte(lang, '-'); idx >= 0 {
			code = lang[:idx]
		}
		if idx := strings.IndexByte(lang, '_'); idx >= 0 {
			code = lang[:idx]
		}
		switch code {
		case "de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zh":
			if code == "zh" {
				best = "zh_hans"
			} else {
				best = code
			}
			bestQ = q
		}
	}
	return best
}
