package rbac

import (
	"io"
	"net/http"
	"net/netip"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// EventsTest creates one server-defined event. Events:read/group administration
// does not confer this mutation right, and browser mutations require CSRF.
func (h *Handler) EventsTest(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	actor, key, ok := h.principal(w, r, true, "Events", apikey.Create)
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
	ip := browser.PeerIPFromContext(r.Context())
	if ip == "" {
		ip, _ = loginpolicy.PeerIP(r.RemoteAddr)
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		h.badRequest(w)
		return
	}
	var guard func() (string, []any)
	if key != nil {
		guard = func() (string, []any) { return h.store.apiKeys.AuthorizationGuard(*key, "Events", apikey.Create) }
	} else {
		name, _ := browser.CookieName(h.issuer)
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
		guard = func() (string, []any) {
			condition, args := h.browser.SessionAuthorizationGuard(session, peer)
			return adminGuard() + " AND " + condition, append([]any{actor}, args...)
		}
	}
	nonce, err := h.store.randomID()
	if err != nil {
		h.unavailable(w)
		return
	}
	if h.beforeEventCreate != nil {
		h.beforeEventCreate()
	}
	operationID := requestID("event-test", nonce)
	event := eventlog.TestEvent(operationID, addr.Unmap().String(), h.store.now())
	condition, args := guard()
	statement, err := event.Statement(condition, args...)
	if err != nil {
		h.unavailable(w)
		return
	}
	result, err := storage.Execute(r.Context(), h.store.db, rhiza.ExecuteRequest{RequestID: operationID, SQL: statement.SQL, Args: statement.Args})
	if err != nil {
		h.unavailable(w)
		return
	}
	if result.RowsAffected != 1 {
		h.error(w, http.StatusForbidden, "Forbidden")
		return
	}
	w.WriteHeader(http.StatusOK)
}
