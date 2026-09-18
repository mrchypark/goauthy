package rbac

import (
	"encoding/json"
	"net/http"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
)

func (h *Handler) User(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		h.methodNotAllowed(w)
		return
	}
	if h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if r.URL.RawQuery != "" {
		h.badRequest(w)
		return
	}
	var actor, guard string
	var args []any
	api := apikey.HasAuthorization(r)
	if api {
		_, key, ok := h.principalFor(w, r, false, "Users", apikey.Read, false)
		if !ok {
			return
		}
		guard, args = h.store.apiKeys.AuthorizationGuard(*key, "Users", apikey.Read)
	} else {
		name, _ := browser.CookieName(h.issuer)
		cookie, err := r.Cookie(name)
		if err != nil {
			h.genericUnauthorized(w)
			return
		}
		peer := browser.PeerIPFromContext(r.Context())
		session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, peer)
		if err != nil || !session.Authenticated() {
			h.genericUnauthorized(w)
			return
		}
		actor = session.Subject
		guard, args = h.browser.SessionAuthorizationGuard(session, peer)
		guard += ` AND EXISTS(SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)`
		args = append(args, actor)
	}
	if h.beforeUserDetailRead != nil {
		h.beforeUserDetailRead()
	}
	user, changed, status, err := h.store.detailUser(r.Context(), actor, r.PathValue("subject"), guard, args, api)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if status != http.StatusOK {
		h.error(w, status, http.StatusText(status))
		return
	}
	user.PasswordExpires = h.identity.PasswordExpiresAt(changed)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(user)
}
