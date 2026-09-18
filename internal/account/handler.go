// Package account serves authenticated account-management boundaries.
package account

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
)

const (
	passwordRequestLimit = 4 << 10
	maxPasswordLength    = 256
	passkeyRequestLimit  = 64 << 10
)

// ErrExternalLinkSession is returned when an upstream link callback has no
// authenticated, peer-bound local browser session.
var ErrExternalLinkSession = errors.New("invalid external link session")

// Handler exposes the small authenticated password-change surface.
type Handler struct {
	issuer                  string
	browser                 *browser.Store
	identity                *identity.Store
	rules                   credential.Rules
	passkeys                *passkey.Service
	apiKeys                 *apikey.Store
	isAdmin                 func(context.Context, string) (bool, error)
	selfDeleteEnabled       bool
	adminForceMFA           bool
	externalLinkStart       http.Handler
	externalLinkProviderIDs map[string]struct{}
	dynamicLinkExists       func(context.Context, string) (bool, error)
	now                     func() time.Time
	random                  func([]byte) (int, error)
}

func NewWithPasskeys(issuer string, browserStore *browser.Store, identityStore *identity.Store, rules credential.Rules, passkeys *passkey.Service) (*Handler, error) {
	h, err := New(issuer, browserStore, identityStore, rules)
	if err != nil {
		return nil, err
	}
	if passkeys == nil {
		return nil, errors.New("account handler requires passkey service")
	}
	h.passkeys = passkeys
	return h, nil
}

func (h *Handler) IssueModificationToken(w http.ResponseWriter, r *http.Request) {
	session, ok := h.mutationSession(w, r, http.MethodPost)
	if !ok {
		return
	}
	payload, err := decodeStrictJSON[mfaModificationTokenRequest](w, r, passkeyRequestLimit)
	if err != nil || (payload.Password == nil) == (payload.MFACode == nil) || h.passkeys == nil {
		badRequest(w, "invalid MFA modification request")
		return
	}
	hasCredentials, err := h.passkeys.HasCredentials(r.Context(), session.Subject)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	var id string
	var exp time.Time
	if hasCredentials {
		if payload.MFACode == nil || !validMFAProofCode(*payload.MFACode) {
			badRequest(w, "invalid MFA modification request")
			return
		}
		id, exp, err = h.passkeys.ExchangeModificationProof(r.Context(), session.Subject, session.ID, *payload.MFACode)
	} else {
		if payload.Password == nil || !boundedPassword([]byte(*payload.Password)) {
			badRequest(w, "invalid MFA modification request")
			return
		}
		password := []byte(*payload.Password)
		defer clear(password)
		if err = h.identity.VerifyPassword(r.Context(), session.Subject, password); err == nil {
			id, exp, err = h.passkeys.IssuePasswordModificationToken(r.Context(), session.Subject, session.ID)
		}
	}
	if err != nil {
		badRequest(w, "invalid MFA modification request")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "user_id": session.Subject, "exp": exp.Unix()})
}

// BeginMFAWebAuthn starts an authenticated, account-local WebAuthn proof.
// MfaModToken creates a modification-token proof; PasswordNew authorizes the
// reverse passkey-only to password transition. Neither can cross purposes.
func (h *Handler) BeginMFAWebAuthn(w http.ResponseWriter, r *http.Request) {
	session, ok := h.mutationSession(w, r, http.MethodPost)
	if !ok {
		return
	}
	payload, err := decodeStrictJSON[mfaWebAuthnStartRequest](w, r, passkeyRequestLimit)
	if err != nil || (payload.Purpose != "MfaModToken" && payload.Purpose != "PasswordNew") || h.passkeys == nil {
		badRequest(w, "invalid MFA WebAuthn request")
		return
	}
	user, err := h.identity.UserBySubject(r.Context(), session.Subject)
	if err != nil {
		unauthorized(w)
		return
	}
	var rcr any
	var code string
	var exp time.Time
	if payload.Purpose == "PasswordNew" {
		rcr, code, exp, err = h.passkeys.BeginPasswordNewProof(r.Context(), session.Subject, user.Username, session.ID)
	} else {
		rcr, code, exp, err = h.passkeys.BeginModificationProof(r.Context(), session.Subject, user.Username, session.ID)
	}
	if err != nil {
		badRequest(w, "invalid MFA WebAuthn request")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mfaWebAuthnStartResponse{Code: code, RCR: rcr, Exp: exp.Unix()})
}

// FinishMFAWebAuthn verifies an authenticated account's assertion and returns
// a one-use service proof code. It deliberately does not create a mod token.
func (h *Handler) FinishMFAWebAuthn(w http.ResponseWriter, r *http.Request) {
	session, ok := h.mutationSession(w, r, http.MethodPost)
	if !ok {
		return
	}
	payload, err := decodeStrictJSON[mfaWebAuthnFinishRequest](w, r, passkeyRequestLimit)
	if err != nil || !validMFAProofCode(payload.Code) || len(payload.Data) == 0 || h.passkeys == nil {
		badRequest(w, "invalid MFA WebAuthn request")
		return
	}
	assertion := r.Clone(r.Context())
	assertion.Body = io.NopCloser(bytes.NewReader(payload.Data))
	assertion.ContentLength = int64(len(payload.Data))
	assertion.Header.Set("Content-Type", "application/json")
	code, err := h.passkeys.FinishModificationProof(r.Context(), session.Subject, session.ID, payload.Code, assertion)
	if err != nil {
		badRequest(w, "invalid MFA WebAuthn request")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(mfaWebAuthnFinishResponse{Code: code, UserID: session.Subject})
}

func (h *Handler) ListPasskeys(w http.ResponseWriter, r *http.Request) {
	subject, _, _, key, ok := h.passkeyPrincipal(w, r, http.MethodGet)
	if !ok || h.passkeys == nil {
		return
	}
	if key != nil {
		if err := h.apiKeys.Authorize(r.Context(), *key, "Users", apikey.Read); err != nil {
			forbidden(w)
			return
		}
	}
	items, err := h.passkeys.List(r.Context(), subject)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(passkeyResponses(items))
}

// PasskeyResponse is the public Rauthy-compatible representation. The
// internal passkey model keeps time.Time values; the API intentionally emits
// Unix seconds.
type PasskeyResponse struct {
	Name         string `json:"name"`
	Registered   int64  `json:"registered"`
	LastUsed     int64  `json:"last_used"`
	UserVerified bool   `json:"user_verified,omitempty"`
}

func passkeyResponses(items []passkey.Credential) []PasskeyResponse {
	out := make([]PasskeyResponse, 0, len(items))
	for _, item := range items {
		out = append(out, PasskeyResponse{Name: item.Name, Registered: item.Registered.Unix(), LastUsed: item.LastUsed.Unix(), UserVerified: item.UserVerified})
	}
	return out
}

type modificationRequest struct {
	Token string `json:"mfa_mod_token_id"`
}
type mfaModificationTokenRequest struct {
	Password *string `json:"password"`
	MFACode  *string `json:"mfa_code"`
}
type mfaWebAuthnStartRequest struct {
	Purpose string `json:"purpose"`
}
type mfaWebAuthnFinishRequest struct {
	Code string          `json:"code"`
	Data json.RawMessage `json:"data"`
}
type mfaWebAuthnStartResponse struct {
	Code string `json:"code"`
	RCR  any    `json:"rcr"`
	Exp  int64  `json:"exp"`
}
type mfaWebAuthnFinishResponse struct {
	Code   string `json:"code"`
	UserID string `json:"user_id"`
}
type registrationStartRequest struct {
	Name  string `json:"passkey_name"`
	Token string `json:"mfa_mod_token_id"`
}
type registrationFinishRequest struct {
	Name string          `json:"passkey_name"`
	Data json.RawMessage `json:"data"`
}

func (h *Handler) BeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	session, ok := h.mutationSession(w, r, http.MethodPost)
	if !ok {
		return
	}
	subject := session.Subject
	if h.passkeys == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	payload, err := decodeStrictJSON[registrationStartRequest](w, r, passkeyRequestLimit)
	if err != nil || !validPasskeyName(payload.Name) {
		unauthorized(w)
		return
	}
	if err := h.passkeys.ConsumeModificationToken(r.Context(), subject, session.ID, payload.Token); err != nil {
		unauthorized(w)
		return
	}
	user, err := h.identity.UserBySubject(r.Context(), subject)
	if err != nil {
		unauthorized(w)
		return
	}
	opts, code, exp, err := h.passkeys.BeginRegistration(r.Context(), subject, user.Username, payload.Name, session.ID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, h.registrationCookie(subject, code, exp))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(opts)
}

func (h *Handler) FinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	session, ok := h.mutationSession(w, r, http.MethodPost)
	if !ok {
		return
	}
	subject := session.Subject
	if h.passkeys == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	payload, err := decodeStrictJSON[registrationFinishRequest](w, r, passkeyRequestLimit)
	if err != nil || !validPasskeyName(payload.Name) || len(payload.Data) == 0 {
		unauthorized(w)
		return
	}
	cookie, err := r.Cookie(h.registrationCookieName())
	if err != nil || cookie.Value == "" {
		unauthorized(w)
		return
	}
	clone := r.Clone(r.Context())
	clone.Body = io.NopCloser(bytes.NewReader(payload.Data))
	clone.ContentLength = int64(len(payload.Data))
	if _, err := h.passkeys.FinishRegistration(r.Context(), subject, payload.Name, session.ID, cookie.Value, clone); err != nil {
		unauthorized(w)
		return
	}
	value, err := h.passkeys.PasswordlessCookie(subject)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, h.passwordlessCookie(value))
	http.SetCookie(w, h.clearRegistrationCookie())
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) DeletePasskey(w http.ResponseWriter, r *http.Request) {
	subject, session, _, key, ok := h.passkeyPrincipal(w, r, http.MethodDelete)
	if !ok || h.passkeys == nil {
		return
	}
	if key != nil { // API keys are read-only for this deliberately destructive reset surface.
		forbidden(w)
		return
	}
	// Even an administrator must prove MFA before deleting their own passkey.
	// Only a reset of another subject uses the administrative bypass.
	if subject == session.Subject {
		payload, err := decodeStrictJSON[modificationRequest](w, r, passkeyRequestLimit)
		if err != nil || h.passkeys.ConsumeModificationToken(r.Context(), subject, session.ID, payload.Token) != nil {
			unauthorized(w)
			return
		}
		if err := h.passkeys.Delete(r.Context(), subject, r.PathValue("name")); err != nil {
			unauthorized(w)
			return
		}
	} else if err := requireEmptyBody(w, r); err != nil || h.passkeys.DeleteForAdministrator(r.Context(), session.Subject, subject, r.PathValue("name")) != nil {
		unauthorized(w)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ConfigureSelfDelete enables the Rauthy self-delete capability. It is
// deliberately opt-in because deletion is permanent.
func (h *Handler) ConfigureSelfDelete(enabled bool) { h.selfDeleteEnabled = enabled }

// ConfigureAdminForceMFA applies the bootstrap forced-MFA policy to the
// destructive administrator user-delete endpoint. API keys are unaffected.
func (h *Handler) ConfigureAdminForceMFA(enabled bool) { h.adminForceMFA = enabled }

// DeleteUser handles DELETE /auth/v1/users/{subject}. Only a direct
// rauthy_admin browser session or a Users:delete API key may use this route.
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	target, session, _, key, ok := h.passkeyPrincipal(w, r, http.MethodDelete)
	if !ok {
		return
	}
	if err := requireEmptyBody(w, r); err != nil {
		badRequest(w, "invalid user deletion request")
		return
	}
	if key != nil {
		if err := h.apiKeys.Authorize(r.Context(), *key, "Users", apikey.Delete); err != nil {
			forbidden(w)
			return
		}
		guard, args := h.apiKeys.AuthorizationGuard(*key, "Users", apikey.Delete)
		if err := h.identity.DeleteUserWithGuard(r.Context(), target, guard, args); err != nil {
			if errors.Is(err, identity.ErrDeleteUnauthorized) {
				forbidden(w)
				return
			}
			h.writeUserDeleteError(w, err, http.StatusConflict)
			return
		}
	} else {
		// passkeyPrincipal intentionally permits same-subject account reads;
		// this route always requires the stronger direct-admin check.
		admin, err := h.isAdminResult(r.Context(), session.Subject)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if !admin {
			forbidden(w)
			return
		}
		if h.adminForceMFA && session.AuthenticationMethod != "mfa" {
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}
		guard, args := h.browserDeleteGuard(session, target, false, browser.PeerIPFromContext(r.Context()))
		if err := h.identity.DeleteUserWithGuard(r.Context(), target, guard, args); err != nil {
			if errors.Is(err, identity.ErrDeleteUnauthorized) {
				forbidden(w)
				return
			}
			h.writeUserDeleteError(w, err, http.StatusConflict)
			return
		}
		if target == session.Subject {
			if cookie, err := browser.DeleteSessionCookie(h.issuer); err == nil {
				http.SetCookie(w, cookie)
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) isAdminResult(ctx context.Context, subject string) (bool, error) {
	if h.isAdmin == nil {
		return false, errors.New("administrator authorization unavailable")
	}
	return h.isAdmin(ctx, subject)
}

// SelfDelete handles GET/DELETE /auth/v1/users/{subject}/self/delete.
func (h *Handler) SelfDelete(w http.ResponseWriter, r *http.Request) {
	var session browser.Session
	var ok bool
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		securityHeaders(w)
		methodNotAllowed(w, "GET, DELETE")
		return
	}
	if r.Method == http.MethodGet {
		if _, ok := h.selfDeleteSession(w, r, false); !ok {
			return
		}
	} else {
		session, ok = h.selfDeleteSession(w, r, true)
		if !ok {
			return
		}
		if err := requireEmptyBody(w, r); err != nil {
			badRequest(w, "invalid user deletion request")
			return
		}
	}
	if !h.selfDeleteEnabled {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}
	target := r.PathValue("subject")
	if admin, err := h.isAdminResult(r.Context(), target); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	} else if admin {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	guard, args := h.browserDeleteGuard(session, target, true, browser.PeerIPFromContext(r.Context()))
	if err := h.identity.DeleteUserWithGuard(r.Context(), target, guard, args); err != nil {
		if errors.Is(err, identity.ErrDeleteUnauthorized) {
			if _, _, live := h.session(r); !live {
				unauthorized(w)
			} else {
				w.WriteHeader(http.StatusNotAcceptable)
			}
			return
		}
		h.writeUserDeleteError(w, err, http.StatusNotAcceptable)
		return
	}
	if cookie, err := browser.DeleteSessionCookie(h.issuer); err == nil {
		http.SetCookie(w, cookie)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) selfDeleteSession(w http.ResponseWriter, r *http.Request, mutation bool) (browser.Session, bool) {
	if r.URL.RawQuery != "" {
		securityHeaders(w)
		forbidden(w)
		return browser.Session{}, false
	}
	if mutation {
		// mutationSession is intentionally browser-only; reject any attempted
		// API-key authorization before it can be mistaken for cookie authority.
		if apikey.HasAuthorization(r) {
			securityHeaders(w)
			unauthorized(w)
			return browser.Session{}, false
		}
		session, ok := h.mutationSession(w, r, http.MethodDelete)
		if !ok {
			return browser.Session{}, false
		}
		if h.identity.ValidateSubject(r.Context(), session.Subject) != nil {
			unauthorized(w)
			return browser.Session{}, false
		}
		return session, true
	}
	method := http.MethodGet
	if !h.security(w, r, method) {
		return browser.Session{}, false
	}
	if apikey.HasAuthorization(r) {
		unauthorized(w)
		return browser.Session{}, false
	}
	session, token, ok := h.session(r)
	if !ok {
		unauthorized(w)
		return browser.Session{}, false
	}
	if subject := r.PathValue("subject"); subject == "" || subject != session.Subject {
		forbidden(w)
		return browser.Session{}, false
	}
	if h.identity.ValidateSubject(r.Context(), session.Subject) != nil {
		unauthorized(w)
		return browser.Session{}, false
	}
	if mutation && browser.ValidateCSRFToken(token, r.Header.Get("X-CSRF-Token")) != nil {
		forbidden(w)
		return browser.Session{}, false
	}
	return session, true
}

func (h *Handler) browserDeleteGuard(session browser.Session, target string, self bool, peerIP string) (string, []any) {
	sessionGuard, sessionArgs := h.browser.SessionAuthorizationGuard(session, peerIP)
	guard := sessionGuard + ` AND EXISTS (SELECT 1 FROM identity_users u WHERE u.subject=? AND u.disabled=0)`
	args := append(sessionArgs, session.Subject)
	if self {
		guard += ` AND NOT EXISTS (SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id WHERE u.subject=? AND u.disabled=0 AND r.name='rauthy_admin')`
		args = append(args, target)
	} else {
		guard += ` AND EXISTS (SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id WHERE u.subject=? AND u.disabled=0 AND r.name='rauthy_admin')`
		args = append(args, session.Subject)
	}
	return guard, args
}

func (h *Handler) writeUserDeleteError(w http.ResponseWriter, err error, finalStatus int) {
	switch {
	case errors.Is(err, identity.ErrInactiveSubject), errors.Is(err, identity.ErrInvalidSubject):
		w.WriteHeader(http.StatusNotFound)
	case errors.Is(err, identity.ErrFinalAdmin):
		w.WriteHeader(finalStatus)
	default:
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	}
}

// ConfigurePasskeyAdministrators enables the two explicit administrator paths.
// Without both dependencies the handler fails closed rather than treating a
// browser session as an administrator.
func (h *Handler) ConfigurePasskeyAdministrators(keys *apikey.Store, isAdmin func(context.Context, string) (bool, error)) {
	h.apiKeys, h.isAdmin = keys, isAdmin
}

// ConfigureExternalLinks enables account-scoped upstream identity linking.
// It is intended for startup, before the handler begins serving requests.
func (h *Handler) ConfigureExternalLinks(start http.Handler, allowedProviderIDs []string) error {
	if start == nil || len(allowedProviderIDs) == 0 {
		return errors.New("external links require start handler and providers")
	}
	providers := make(map[string]struct{}, len(allowedProviderIDs))
	for _, providerID := range allowedProviderIDs {
		if upstreamprovider.NormalizeProviderID(providerID) != providerID {
			return errors.New("external links require canonical provider IDs")
		}
		if _, exists := providers[providerID]; exists {
			return errors.New("external links require unique provider IDs")
		}
		providers[providerID] = struct{}{}
	}
	h.externalLinkStart, h.externalLinkProviderIDs = start, providers
	return nil
}

// ConfigureDynamicExternalLinks enables runtime-resolved upstream identity
// linking. The exists function is called with the exact, non-lowercased
// provider ID from the request path. Errors from exists are returned to the
// caller as 503 without side effects.
func (h *Handler) ConfigureDynamicExternalLinks(start http.Handler, exists func(context.Context, string) (bool, error)) error {
	if start == nil || exists == nil {
		return errors.New("dynamic external links require start handler and resolver")
	}
	h.externalLinkStart = start
	h.dynamicLinkExists = exists
	return nil
}

// StartExternalLink authorizes an account-bound upstream link transaction.
func (h *Handler) StartExternalLink(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.externalLinkSession(w, r, http.MethodPost); !ok {
		return
	}
	if err := requireEmptyBody(w, r); err != nil {
		badRequest(w, "invalid external link request")
		return
	}
	ok, err := h.resolveExternalLinkProvider(r.Context(), r.PathValue("providerID"))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	h.externalLinkStart.ServeHTTP(w, r)
}

// UnlinkExternal removes an account's provider-scoped external identity link.
func (h *Handler) UnlinkExternal(w http.ResponseWriter, r *http.Request) {
	session, ok := h.externalLinkSession(w, r, http.MethodDelete)
	if !ok {
		return
	}
	if err := requireEmptyBody(w, r); err != nil {
		badRequest(w, "invalid external unlink request")
		return
	}
	providerID := r.PathValue("providerID")
	ok, err := h.resolveExternalLinkProvider(r.Context(), providerID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err = h.identity.ValidateSubject(r.Context(), session.Subject); err != nil {
		unauthorized(w)
		return
	}
	if _, err := h.identity.IsPasskeyOnly(r.Context(), session.Subject); err != nil {
		badRequest(w, "invalid external unlink request")
		return
	}
	var random [16]byte
	if n, err := h.random(random[:]); err != nil || n != len(random) {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if err := h.identity.UnlinkExternal(r.Context(), session.Subject, providerID, h.now(), base64.RawURLEncoding.EncodeToString(random[:])); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resolveExternalLinkProvider checks whether the given provider ID is allowed.
// Static providers (from ConfigureExternalLinks) are checked first via exact
// map lookup without a context call. Dynamic providers are resolved via the
// injected exists function. Errors are returned to the caller; callers must
// fail closed (503) on error.
func (h *Handler) resolveExternalLinkProvider(ctx context.Context, providerID string) (bool, error) {
	if providerID == "" || h.externalLinkStart == nil {
		return false, nil
	}
	if _, ok := h.externalLinkProviderIDs[providerID]; ok {
		return true, nil
	}
	if h.dynamicLinkExists != nil {
		return h.dynamicLinkExists(ctx, providerID)
	}
	return false, nil
}

// CurrentExternalLinkSession returns the local browser authority required by
// an upstream link callback. The callback's upstream state validation is its
// CSRF protection, so this deliberately writes no HTTP response or CSRF check.
func (h *Handler) CurrentExternalLinkSession(r *http.Request) (subject, token, digest string, err error) {
	session, token, ok := h.session(r)
	if !ok || !session.Authenticated() || session.Subject == "" || token == "" || session.ID == "" {
		return "", "", "", ErrExternalLinkSession
	}
	return session.Subject, token, session.ID, nil
}

// passkeyPrincipal separates API-key authentication from browser authority.
// A supplied Authorization header never falls back to a cookie session.
func (h *Handler) passkeyPrincipal(w http.ResponseWriter, r *http.Request, method string) (string, browser.Session, string, *apikey.Principal, bool) {
	securityHeaders(w)
	if r.Method != method {
		methodNotAllowed(w, method)
		return "", browser.Session{}, "", nil, false
	}
	if r.URL.RawQuery != "" || crossSite(r) {
		forbidden(w)
		return "", browser.Session{}, "", nil, false
	}
	subject := r.PathValue("subject")
	if subject == "" {
		unauthorized(w)
		return "", browser.Session{}, "", nil, false
	}
	if apikey.HasAuthorization(r) {
		header, valid := apikey.Authorization(r)
		if !valid || h.apiKeys == nil {
			unauthorized(w)
			return "", browser.Session{}, "", nil, false
		}
		key, err := h.apiKeys.Authenticate(r.Context(), header)
		if err != nil {
			unauthorized(w)
			return "", browser.Session{}, "", nil, false
		}
		return subject, browser.Session{}, "", &key, true
	}
	session, raw, ok := h.session(r)
	if !ok {
		unauthorized(w)
		return "", browser.Session{}, "", nil, false
	}
	if h.identity.ValidateSubject(r.Context(), session.Subject) != nil {
		unauthorized(w)
		return "", browser.Session{}, "", nil, false
	}
	admin := false
	if subject != session.Subject {
		if h.isAdmin == nil {
			forbidden(w)
			return "", browser.Session{}, "", nil, false
		}
		var err error
		admin, err = h.isAdmin(r.Context(), session.Subject)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return "", browser.Session{}, "", nil, false
		}
		if !admin {
			forbidden(w)
			return "", browser.Session{}, "", nil, false
		}
	}
	if method != http.MethodGet && browser.ValidateCSRFToken(raw, r.Header.Get("X-CSRF-Token")) != nil {
		forbidden(w)
		return "", browser.Session{}, "", nil, false
	}
	return subject, session, raw, nil, true
}

// New constructs the account handler with the same password rules enforced by
// its identity store.
func New(issuer string, browserStore *browser.Store, identityStore *identity.Store, rules credential.Rules) (*Handler, error) {
	if _, err := browser.CookieName(issuer); err != nil {
		return nil, err
	}
	if browserStore == nil || identityStore == nil {
		return nil, errors.New("account handler requires browser and identity stores")
	}
	if err := rules.Validate(); err != nil {
		return nil, err
	}
	return &Handler{issuer: issuer, browser: browserStore, identity: identityStore, rules: rules, now: time.Now, random: rand.Read}, nil
}

// GetPassword returns the authenticated session's derived CSRF token and the
// password policy. The raw bearer cookie is never included in the response.
func (h *Handler) GetPassword(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if crossSite(r) {
		forbidden(w)
		return
	}
	_, token, ok := h.session(r)
	if !ok {
		unauthorized(w)
		return
	}
	csrf, err := browser.DeriveCSRFToken(token)
	if err != nil {
		unauthorized(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(passwordResponse{CSRFToken: csrf, PasswordPolicy: policyResponse(h.rules)})
}

// PutSelfPassword changes only the authenticated subject's local password.
func (h *Handler) PutSelfPassword(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPut {
		methodNotAllowed(w, http.MethodPut)
		return
	}
	if crossSite(r) {
		forbidden(w)
		return
	}
	session, token, ok := h.session(r)
	if !ok {
		unauthorized(w)
		return
	}
	if subject := r.PathValue("subject"); subject == "" || subject != session.Subject {
		forbidden(w)
		return
	}
	if err := browser.ValidateCSRFToken(token, r.Header.Get("X-CSRF-Token")); err != nil {
		forbidden(w)
		return
	}
	payload, err := decodePasswordChange(w, r)
	if err != nil {
		badRequest(w, "invalid password change request")
		return
	}
	if payload.Next == nil || (payload.Current == nil && payload.MFACode == nil) || (payload.Current != nil && payload.MFACode != nil) {
		badRequest(w, "invalid password change request")
		return
	}
	next := []byte(*payload.Next)
	defer clear(next)
	if !boundedPassword(next) || (payload.Current != nil && *payload.Current == "") || (payload.MFACode != nil && *payload.MFACode == "") {
		badRequest(w, "invalid password change request")
		return
	}
	passkeyOnly, err := h.identity.IsPasskeyOnly(r.Context(), session.Subject)
	if err != nil {
		unauthorized(w)
		return
	}
	if passkeyOnly != (payload.MFACode != nil) {
		badRequest(w, "invalid password change request")
		return
	}
	if !passkeyOnly {
		current := []byte(*payload.Current)
		defer clear(current)
		if !boundedPassword(current) {
			badRequest(w, "invalid password change request")
			return
		}
		err = h.identity.ChangePassword(r.Context(), session.Subject, current, next)
	} else {
		err = h.identity.SetPasswordWithWebAuthnProof(r.Context(), session.Subject, session.ID, *payload.MFACode, next)
	}
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrPasswordRejected), errors.Is(err, identity.ErrPasswordReuse):
			badRequest(w, "password rejected")
		case passkeyOnly:
			badRequest(w, "invalid password change request")
		case errors.Is(err, identity.ErrInvalidCredentials), errors.Is(err, identity.ErrInactiveSubject), errors.Is(err, identity.ErrPasswordChangeConflict), errors.Is(err, identity.ErrPasswordAuthenticationDisabled):
			unauthorized(w)
		default:
			unauthorized(w)
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// ConvertSelfPasskey removes the password sign-in method only after identity
// has confirmed that the authenticated account has a user-verified passkey.
func (h *Handler) ConvertSelfPasskey(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if crossSite(r) {
		forbidden(w)
		return
	}
	session, token, ok := h.session(r)
	if !ok {
		unauthorized(w)
		return
	}
	if subject := r.PathValue("subject"); subject == "" || subject != session.Subject {
		forbidden(w)
		return
	}
	// Passwordless conversion is a security-sensitive admission change. The
	// current browser session must prove fresh user verification and carry the
	// request's peer binding; legacy password/empty-peer sessions are not enough.
	if session.AuthenticationMethod != "mfa" || session.PeerIP == "" {
		unauthorized(w)
		return
	}
	if err := browser.ValidateCSRFToken(token, r.Header.Get("X-CSRF-Token")); err != nil {
		unauthorized(w)
		return
	}
	if err := requireEmptyBody(w, r); err != nil {
		badRequest(w, "invalid passkey conversion request")
		return
	}
	if err := h.identity.ConvertToPasskeyOnly(r.Context(), session.Subject); err != nil {
		badRequest(w, "invalid passkey conversion request")
		return
	}
	w.WriteHeader(http.StatusOK)
}

type passwordChangeRequest struct {
	Current *string `json:"password_current"`
	MFACode *string `json:"mfa_code"`
	Next    *string `json:"password_new"`
}

type passwordResponse struct {
	CSRFToken      string         `json:"csrf_token"`
	PasswordPolicy passwordPolicy `json:"password_policy"`
}

type passwordPolicy struct {
	LengthMin int `json:"length_min"`
	LengthMax int `json:"length_max"`
	LowerCase int `json:"lower_case"`
	UpperCase int `json:"upper_case"`
	Digits    int `json:"digits"`
	Special   int `json:"special"`
	History   int `json:"history"`
	ValidDays int `json:"valid_days"`
}

func policyResponse(rules credential.Rules) passwordPolicy {
	return passwordPolicy{LengthMin: rules.LengthMin, LengthMax: rules.LengthMax, LowerCase: rules.LowerCase, UpperCase: rules.UpperCase, Digits: rules.Digits, Special: rules.Special, History: rules.History, ValidDays: rules.ValidDays}
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
	session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, browser.PeerIPFromContext(r.Context()))
	if err != nil || !session.Authenticated() {
		return browser.Session{}, "", false
	}
	return session, cookie.Value, true
}

func (h *Handler) mutationSession(w http.ResponseWriter, r *http.Request, method string) (browser.Session, bool) {
	session, ok := h.authenticatedSession(w, r, method)
	if !ok {
		return browser.Session{}, false
	}
	if subject := r.PathValue("subject"); subject == "" || subject != session.Subject {
		forbidden(w)
		return browser.Session{}, false
	}
	return session, true
}

func (h *Handler) externalLinkSession(w http.ResponseWriter, r *http.Request, method string) (browser.Session, bool) {
	return h.authenticatedSession(w, r, method)
}

func (h *Handler) authenticatedSession(w http.ResponseWriter, r *http.Request, method string) (browser.Session, bool) {
	if !h.security(w, r, method) {
		return browser.Session{}, false
	}
	session, token, ok := h.session(r)
	if !ok {
		unauthorized(w)
		return browser.Session{}, false
	}
	if err := browser.ValidateCSRFToken(token, r.Header.Get("X-CSRF-Token")); err != nil {
		forbidden(w)
		return browser.Session{}, false
	}
	return session, true
}

func decodePasswordChange(w http.ResponseWriter, r *http.Request) (passwordChangeRequest, error) {
	return decodeStrictJSON[passwordChangeRequest](w, r, passwordRequestLimit)
}

func requireEmptyBody(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1)
	var one [1]byte
	n, err := r.Body.Read(one[:])
	if n != 0 || (err != nil && err != io.EOF) {
		return errors.New("request body")
	}
	return nil
}

func boundedPassword(value []byte) bool {
	return len(value) <= maxPasswordLength && utf8.Valid(value) && utf8.RuneCount(value) <= maxPasswordLength
}

func crossSite(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site")
}

func methodNotAllowed(w http.ResponseWriter, method string) {
	w.Header().Set("Allow", method)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func unauthorized(w http.ResponseWriter) { http.Error(w, "Unauthorized", http.StatusUnauthorized) }
func forbidden(w http.ResponseWriter)    { http.Error(w, "Forbidden", http.StatusForbidden) }
func badRequest(w http.ResponseWriter, message string) {
	http.Error(w, message, http.StatusBadRequest)
}

func (h *Handler) security(w http.ResponseWriter, r *http.Request, method string) bool {
	securityHeaders(w)
	if r.Method != method {
		methodNotAllowed(w, method)
		return false
	}
	if crossSite(r) {
		forbidden(w)
		return false
	}
	return true
}

func decodeStrictJSON[T any](w http.ResponseWriter, r *http.Request, limit int64) (T, error) {
	var value T
	if len(r.Header.Values("Content-Type")) != 1 {
		return value, errors.New("content type")
	}
	if media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || media != "application/json" {
		return value, errors.New("content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil || rejectDuplicateJSONFields(body) != nil {
		return value, errors.New("json")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return value, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return value, errors.New("trailing JSON")
	}
	return value, nil
}

// rejectDuplicateJSONFields walks every object before encoding/json decodes it,
// since the decoder otherwise silently retains the final duplicate key.
func rejectDuplicateJSONFields(body []byte) error {
	d := json.NewDecoder(bytes.NewReader(body))
	if err := walkJSONValue(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func walkJSONValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("object key")
			}
			if _, duplicate := seen[name]; duplicate {
				return errors.New("duplicate JSON key")
			}
			seen[name] = struct{}{}
			if err := walkJSONValue(d); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case '[':
		for d.More() {
			if err := walkJSONValue(d); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func validPasskeyName(value string) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 32 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '\u00c0' && r <= '\u024f' || r == '-' || r == '\'' || unicode.IsSpace(r)) {
			return false
		}
	}
	return true
}

func validMFAProofCode(value string) bool {
	if len(value) != 48 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}

func (h *Handler) registrationCookieName() string {
	if strings.HasPrefix(h.issuer, "https://") {
		return "__Host-goauthy_passkey_registration"
	}
	return "goauthy_passkey_registration"
}
func (h *Handler) registrationCookie(subject, code string, expires time.Time) *http.Cookie {
	return &http.Cookie{Name: h.registrationCookieName(), Value: code, Path: "/", Expires: expires.UTC(), MaxAge: 300, HttpOnly: true, Secure: strings.HasPrefix(h.issuer, "https://"), SameSite: http.SameSiteStrictMode}
}
func (h *Handler) clearRegistrationCookie() *http.Cookie {
	c := h.registrationCookie("", "", time.Unix(1, 0))
	c.MaxAge = -1
	return c
}
func (h *Handler) passwordlessCookie(value string) *http.Cookie {
	name := "goauthy-passkey"
	secure := strings.HasPrefix(h.issuer, "https://")
	if secure {
		name = "__Host-goauthy-passkey"
	}
	return &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: 2160 * 3600, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode}
}
