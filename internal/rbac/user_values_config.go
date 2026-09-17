package rbac

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/rhiza"
)

// UserValuesConfigHandler binds the actual registration setting at startup.
// Open registration intentionally makes this configuration public, even when
// the request carries an invalid credential. The private path never falls back
// from a supplied API key to ambient browser authority.
func (h *Handler) UserValuesConfigHandler(openRegistration bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.securityHeaders(w)
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			h.methodNotAllowed(w)
			return
		}
		if r.URL.RawQuery != "" {
			h.badRequest(w)
			return
		}
		if r.Body != nil {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(body) != 0 {
				h.badRequest(w)
				return
			}
		}
		if !openRegistration {
			if h.crossSite(r) {
				h.genericUnauthorized(w)
				return
			}
			actor, key, ok := h.principalFor(w, r, false, "Users", apikey.Read, true)
			if !ok {
				return
			}
			var guard string
			var args []any
			if key != nil {
				guard, args = h.store.apiKeys.AuthorizationGuard(*key, "Users", apikey.Read)
			} else {
				guard, args = h.userUpdateSessionGuard(r, actor)
				guard = "(" + guard + ") AND (" + adminGuard() + " OR " + delegatedAdminGuard() + ")"
				args = append(args, actor, actor)
			}
			if h.beforeUserValuesConfigRead != nil {
				h.beforeUserValuesConfigRead()
			}
			result, err := h.store.db.Query(r.Context(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: args, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil {
				h.unavailable(w)
				return
			}
			if len(result.Rows) == 0 {
				h.genericUnauthorized(w)
				return
			}
			if len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != int64(1) {
				h.unavailable(w)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.userValuesPolicy.ConfigResponse())
	})
}
