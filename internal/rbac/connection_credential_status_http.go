package rbac

import (
	"encoding/json"
	"net/http"
)

// ConnectionCredentialStatus reports the current OAuth credential state for a
// consented delivery grant without refreshing or otherwise mutating it.
func (h *Handler) ConnectionCredentialStatus(w http.ResponseWriter, r *http.Request) {
	owner, consumer, authority, ok := h.authorizeConnectionUseBoundary(w, r, http.MethodGet, false, false, true)
	if !ok {
		return
	}
	status, err := h.saasCredentials.OAuth2UseGrantStatus(r.Context(), owner, consumer, r.PathValue("grant_id"), h.connectionUseResource, authority)
	if err != nil {
		h.writeInvokeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
