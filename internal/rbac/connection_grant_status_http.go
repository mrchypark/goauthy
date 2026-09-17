package rbac

import (
	"encoding/json"
	"net/http"
)

// UserResourceConnectionUseGrant exposes no credentials and grants no use authority.
func (h *Handler) UserResourceConnectionUseGrant(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if h.saasCredentials == nil || h.connectionUseResource == "" || h.connectionResourceAuthorizer == nil || h.authCollections == nil {
		h.unavailable(w)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.methodNotAllowed(w)
		return
	}
	owner, guard, ok := h.connectionResourceBoundary(w, r, "goauthy.connections.read", false)
	if !ok {
		return
	}
	if !emptyBody(r) || len(r.Header.Values("If-Match")) != 0 {
		h.badRequest(w)
		return
	}
	collection, connection, id := r.PathValue("collection_id"), r.PathValue("connection_id"), r.PathValue("grant_id")
	if collection == "" || connection == "" || id == "" {
		h.badRequest(w)
		return
	}
	status, err := h.saasCredentials.GetUseGrantStatus(r.Context(), owner, collection, connection, id, h.connectionUseResource, guard)
	if err != nil {
		h.writeUseGrantError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
