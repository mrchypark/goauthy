package rbac

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
)

func (h *Handler) Sessions(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.methodNotAllowed(w)
		return
	}
	if h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	actor, key, ok := h.principalFor(w, r, false, "Sessions", apikey.Read, true)
	if !ok {
		return
	}
	if r.Body != nil {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
		if err != nil || len(body) != 0 {
			h.badRequest(w)
			return
		}
	}
	o, err := parseSessionListOptions(r.URL.RawQuery)
	if err != nil {
		h.badRequest(w)
		return
	}
	guard, args := "", []any(nil)
	if key != nil {
		guard, args = h.store.apiKeys.AuthorizationGuard(*key, "Sessions", apikey.Read)
	} else {
		name, _ := browser.CookieName(h.issuer)
		c, e := r.Cookie(name)
		if e != nil {
			h.genericUnauthorized(w)
			return
		}
		p := browser.PeerIPFromContext(r.Context())
		ss, e := h.browser.LoadSessionReadOnlyForPeer(r.Context(), c.Value, p)
		if e != nil || !ss.Authenticated() || ss.Subject != actor {
			h.genericUnauthorized(w)
			return
		}
		g, a := h.browser.SessionAuthorizationGuard(ss, p)
		guard = "(" + adminGuard() + " OR " + delegatedAdminGuard() + ") AND " + g
		args = append([]any{actor, actor}, a...)
	}
	items, count, token, err := h.store.listSessions(r.Context(), guard, args, o, h.userListThreshold)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	pageSize := o.PageSize
	if pageSize == 0 {
		pageSize = 20
	}
	if pageSize < h.userListThreshold {
		pageSize = h.userListThreshold
	}
	w.Header().Set("Content-Type", "application/json")
	if count >= int64(h.userListThreshold) {
		w.Header().Set("X-Page-Size", strconv.FormatUint(uint64(pageSize), 10))
		w.Header().Set("X-Page-Count", strconv.FormatInt((count+int64(pageSize)-1)/int64(pageSize), 10))
		if token != "" {
			w.Header().Set("X-Continuation-Token", token)
		}
		w.WriteHeader(http.StatusPartialContent)
	}
	_ = json.NewEncoder(w).Encode(items)
}
func parseSessionListOptions(raw string) (SessionListOptions, error) {
	p, err := parseUserListOptions(raw)
	if err != nil {
		return SessionListOptions{}, ErrInvalid
	}
	if p.Cursor != "" {
		if _, err := decodeSessionCursor(p.Cursor); err != nil {
			return SessionListOptions{}, err
		}
	}
	values, _ := url.ParseQuery(raw) // Already validated by the shared parser.
	state := values.Get("session_state")
	if state == "" {
		state = "Auth"
	}
	return SessionListOptions{PageSize: p.PageSize, Offset: p.Offset, Backwards: p.Backwards, Cursor: p.Cursor, State: state}, nil
}
