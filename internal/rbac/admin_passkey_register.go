package rbac

import (
	"encoding/json"
	"net/http"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
)

// AdminRegisterPasskey initiates passkey registration for an admin-provisioned
// user. It requires an admin session and returns WebAuthn credential creation
// options that the client must forward to the user's authenticator.
func (h *Handler) AdminRegisterPasskey(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.methodNotAllowed(w)
		return
	}
	if h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if h.passkeyService == nil {
		h.error(w, http.StatusServiceUnavailable, "Service Unavailable")
		return
	}
	subject := r.PathValue("subject")
	if !validSubjectID(subject) {
		h.notFound(w)
		return
	}
	actor, key, ok := h.principalFor(w, r, true, "Users", apikey.Update, true)
	if !ok {
		return
	}
	_ = actor
	_ = key
	name, _ := browser.CookieName(h.issuer)
	cookie, err := r.Cookie(name)
	if err != nil {
		h.genericUnauthorized(w)
		return
	}
	peer := browser.PeerIPFromContext(r.Context())
	session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, peer)
	if err != nil || !session.Authenticated() || h.identity.ValidateSubject(r.Context(), session.Subject) != nil {
		h.genericUnauthorized(w)
		return
	}
	admin, err := h.store.IsAdmin(r.Context(), session.Subject)
	if err != nil {
		h.unavailable(w)
		return
	}
	if !admin {
		h.genericUnauthorized(w)
		return
	}
	if browser.ValidateCSRFToken(cookie.Value, r.Header.Get("X-CSRF-Token")) != nil {
		h.genericUnauthorized(w)
		return
	}
	user, err := h.identity.UserBySubject(r.Context(), subject)
	if err != nil {
		h.notFound(w)
		return
	}
	credOpts, _, _, err := h.passkeyService.BeginRegistration(r.Context(), subject, user.Username, "admin-provisioned", "")
	if err != nil {
		h.error(w, http.StatusServiceUnavailable, "Service Unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(credOpts)
}
