package rbac

import (
	"errors"
	"io"
	"net/http"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/rhiza"
)

// ForceLogoutUser handles DELETE /auth/v1/sessions/{subject}.
func (h *Handler) ForceLogoutUser(w http.ResponseWriter, r *http.Request) {
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
	actor, key, ok := h.principalFor(w, r, true, "Sessions", apikey.Delete, true)
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
	target := r.PathValue("subject")
	if !validSubjectID(target) {
		h.notFound(w)
		return
	}
	guard, args := "", []any(nil)
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
		delegated, delegatedArgs := delegatedMembershipGuard(actor, target, nil, false, false)
		delegated += ` AND EXISTS (SELECT 1 FROM rbac_user_groups tm JOIN rbac_groups tg ON tg.id=tm.group_id JOIN rbac_user_roles am ON am.subject=? JOIN rbac_roles ar ON ar.id=am.role_id WHERE tm.subject=? AND substr(ar.name,1,13)='rauthy_admin:' AND (ar.name='rauthy_admin:*' OR (substr(ar.name,-1)='*' AND substr(tg.name,1,length(ar.name)-14)=substr(ar.name,14,length(ar.name)-14)) OR (substr(ar.name,-1)<>'*' AND substr(ar.name,14)=tg.name)))`
		guard = `(` + adminGuard() + ` OR (` + delegated + `)) AND ` + sessionGuard
		args = append([]any{actor}, delegatedArgs...)
		args = append(args, actor, target)
		args = append(args, sessionArgs...)
	}
	// Classification is advisory only; ForceLogout repeats the exact predicate
	// as its transactional commit barrier.
	decision, err := h.store.db.Query(r.Context(), rhiza.QueryRequest{SQL: `SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM identity_users WHERE subject=?) THEN 404 WHEN NOT (` + guard + `) THEN 403 ELSE 200 END`, Args: append([]any{target}, args...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(decision.Rows) != 1 || len(decision.Rows[0]) != 1 {
		h.unavailable(w)
		return
	}
	status, ok := decision.Rows[0][0].(int64)
	if !ok {
		h.unavailable(w)
		return
	}
	if status != http.StatusOK {
		h.error(w, int(status), http.StatusText(int(status)))
		return
	}
	nonce, err := h.store.randomID()
	if err != nil {
		h.unavailable(w)
		return
	}
	operationID := requestID("forced-logout", nonce)
	if err := h.store.ForceLogout(r.Context(), operationID, target, guard, args...); err != nil {
		if errors.Is(err, ErrUnauthorized) {
			h.error(w, http.StatusForbidden, "Forbidden")
			return
		}
		h.unavailable(w)
		return
	}
	w.WriteHeader(http.StatusOK)
}
