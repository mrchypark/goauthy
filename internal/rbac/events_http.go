package rbac

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
)

type eventQueryJSON struct {
	From  *int64          `json:"from"`
	Until *int64          `json:"until"`
	Level *eventlog.Level `json:"level"`
	Type  *eventlog.Type  `json:"typ"`
}

// EventsQuery returns the public lifecycle event slice under an API-key or
// current browser-admin authorization snapshot.
func (h *Handler) EventsQuery(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	actor, key, ok := h.principalFor(w, r, false, "Events", apikey.Read, true)
	if !ok {
		return
	}
	if len(r.Header.Values("Content-Type")) != 1 {
		h.badRequest(w)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		h.badRequest(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 || !utf8.Valid(body) || rejectDuplicateJSONFields(body) != nil {
		h.badRequest(w)
		return
	}
	// encoding/json matches struct field names case-insensitively. Reject
	// alternate spellings before decoding so aliases cannot override a field.
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		h.badRequest(w)
		return
	}
	for name := range fields {
		if name != "from" && name != "until" && name != "level" && name != "typ" {
			h.badRequest(w)
			return
		}
	}
	var input eventQueryJSON
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input.From == nil || input.Level == nil {
		h.badRequest(w)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		h.badRequest(w)
		return
	}
	query := eventlog.Query{From: *input.From, Until: input.Until, Level: *input.Level, Type: input.Type}
	if err := query.Validate(); err != nil {
		h.badRequest(w)
		return
	}
	guard, args := "", []any(nil)
	if key != nil {
		guard, args = h.store.apiKeys.AuthorizationGuard(*key, "Events", apikey.Read)
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
		session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, peer)
		if err != nil || !session.Authenticated() || session.Subject != actor {
			h.genericUnauthorized(w)
			return
		}
		sessionGuard, sessionArgs := h.browser.SessionAuthorizationGuard(session, peer)
		guard = "(" + adminGuard() + " OR " + delegatedAdminGuard() + ") AND " + sessionGuard
		args = append([]any{actor, actor}, sessionArgs...)
	}
	if h.beforeEventRead != nil {
		h.beforeEventRead()
	}
	store, err := eventlog.NewStore(h.store.db)
	if err != nil {
		h.unavailable(w)
		return
	}
	events, authorized, err := store.ListGuarded(r.Context(), query, h.store.now(), guard, args...)
	if err != nil {
		h.unavailable(w)
		return
	}
	if !authorized {
		h.error(w, http.StatusForbidden, "Forbidden")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}
