package rbac

import (
	"errors"
	"io"
	"net/http"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
)

// DeleteSessionByID handles DELETE /auth/v1/sessions/id/{session_id}.
// Unlike per-user logout, delegated administrators may not invoke this route.
func (h *Handler) DeleteSessionByID(w http.ResponseWriter, r *http.Request) {
	h.deleteSessions(w, r, false)
}

// LogoutAllSessions handles DELETE /auth/v1/sessions with the same direct-admin
// boundary as single-session deletion, not the delegated per-user boundary.
func (h *Handler) LogoutAllSessions(w http.ResponseWriter, r *http.Request) {
	h.deleteSessions(w, r, true)
}

func (h *Handler) deleteSessions(w http.ResponseWriter, r *http.Request, all bool) {
	h.securityHeaders(w)
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		h.methodNotAllowed(w)
		return
	}
	if h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	actor, key, ok := h.principalFor(w, r, true, "Sessions", apikey.Delete, false)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		h.badRequest(w)
		return
	}
	if r.Body != nil {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
		if err != nil || len(body) != 0 {
			h.badRequest(w)
			return
		}
	}
	sid := r.PathValue("session_id")
	// A SID has the same canonical 32-byte base64url representation as a
	// browser token. Reuse validation; do not use the returned digest as SID.
	if !all {
		if _, err := browser.CanonicalTokenDigest(sid); err != nil {
			h.notFound(w)
			return
		}
	}
	var guard string
	var args []any
	if key != nil {
		guard, args = h.store.apiKeys.AuthorizationGuard(*key, "Sessions", apikey.Delete)
	} else {
		name, err := browser.CookieName(h.issuer)
		if err != nil {
			h.unavailable(w)
			return
		}
		cookie, err := r.Cookie(name)
		if err != nil {
			h.genericUnauthorized(w)
			return
		}
		peer := browser.PeerIPFromContext(r.Context())
		session, err := h.browser.LoadSessionReadOnlyForPeer(r.Context(), cookie.Value, peer)
		if err != nil || !session.Authenticated() || session.Subject != actor {
			h.genericUnauthorized(w)
			return
		}
		sessionGuard, sessionArgs := h.browser.SessionAuthorizationGuard(session, peer)
		guard, args = "("+adminGuard()+") AND "+sessionGuard, append([]any{actor}, sessionArgs...)
	}
	nonce, err := h.store.randomID()
	if err != nil {
		h.unavailable(w)
		return
	}
	if all {
		err = h.store.LogoutAllSessions(r.Context(), requestID("sessions-logout-all", nonce), guard, args...)
	} else {
		err = h.store.DeleteSession(r.Context(), requestID("session-delete", nonce), sid, guard, args...)
	}
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			h.error(w, http.StatusForbidden, "Forbidden")
		} else {
			h.writeStoreError(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
}
