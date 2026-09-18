package rbac

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
)

const DefaultUserListThreshold uint16 = 1000

// SetUserListThreshold is startup-only, like the handler's other configuration.
func (h *Handler) SetUserListThreshold(threshold uint16) error {
	if threshold == 0 {
		return ErrInvalid
	}
	h.userListThreshold = threshold
	return nil
}

// Users returns only the minified list; list visibility never grants mutation.
func (h *Handler) Users(w http.ResponseWriter, r *http.Request) {
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
	actor, key, ok := h.principalFor(w, r, false, "Users", apikey.Read, true)
	if !ok {
		return
	}
	options, err := parseUserListOptions(r.URL.RawQuery)
	if err != nil {
		h.badRequest(w)
		return
	}
	var guard string
	var args []any
	if key != nil {
		guard, args = h.store.apiKeys.AuthorizationGuard(*key, "Users", apikey.Read)
	} else {
		// Retain the established browser preflight, then bind the query to this
		// exact session as well as the current direct/delegated role.
		name, _ := browser.CookieName(h.issuer)
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
	if h.beforeUserListRead != nil {
		h.beforeUserListRead()
	}
	page, err := h.store.listUsers(r.Context(), guard, args, options, h.userListThreshold)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-User-Count", strconv.FormatInt(page.Count, 10))
	status := http.StatusOK
	if page.Paginated {
		status = http.StatusPartialContent
		w.Header().Set("X-Page-Size", strconv.FormatUint(uint64(page.PageSize), 10))
		w.Header().Set("X-Page-Count", strconv.FormatInt((page.Count+int64(page.PageSize)-1)/int64(page.PageSize), 10))
		if page.ContinuationToken != "" {
			w.Header().Set("X-Continuation-Token", page.ContinuationToken)
		}
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(page.Users)
}

func parseUserListOptions(raw string) (UserListOptions, error) {
	if len(raw) > 2048 {
		return UserListOptions{}, ErrInvalid
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return UserListOptions{}, ErrInvalid
	}
	var options UserListOptions
	for name, items := range values {
		if len(items) != 1 {
			return UserListOptions{}, ErrInvalid
		}
		value := items[0]
		switch name {
		case "page_size", "offset":
			n, err := strconv.ParseUint(value, 10, 16)
			if err != nil || value == "" || value[0] == '+' || (name == "page_size" && n == 0) {
				return UserListOptions{}, ErrInvalid
			}
			if name == "page_size" {
				options.PageSize = uint16(n)
			} else {
				options.Offset = uint16(n)
			}
		case "backwards":
			if value != "true" && value != "false" {
				return UserListOptions{}, ErrInvalid
			}
			options.Backwards = value == "true"
		case "continuation_token":
			if len(value) > 700 || value == "" {
				return UserListOptions{}, ErrInvalid
			}
			options.Cursor = value
		case "session_state":
			switch value {
			case "Init", "Auth", "LoggedOut", "Unknown":
			default:
				return UserListOptions{}, ErrInvalid
			}
		default:
			return UserListOptions{}, ErrInvalid
		}
	}
	return options, nil
}
