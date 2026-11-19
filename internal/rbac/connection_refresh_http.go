package rbac

import (
	"encoding/json"
	"net/http"
)

// RefreshConnectionCredential refreshes an OAuth credential only when the
// consented grant explicitly delegates refresh-token use.
func (h *Handler) RefreshConnectionCredential(w http.ResponseWriter, r *http.Request) {
	owner, consumer, authority, ok := h.authorizeConnectionUseBoundary(w, r, http.MethodPost, false, true, false)
	if !ok {
		return
	}
	var in struct {
		CredentialVersion int64 `json:"credential_version"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	if err := decodeJSON(r, &in, map[string]bool{"credential_version": true}, []string{"credential_version"}, nil); err != nil || in.CredentialVersion <= 0 || in.CredentialVersion == 1<<63-1 {
		h.badRequest(w)
		return
	}
	status, err := h.saasCredentials.RefreshOAuth2UseGrant(r.Context(), h.saasProviderStore, owner, consumer, r.PathValue("grant_id"), h.connectionUseResource, in.CredentialVersion, authority)
	if err != nil {
		h.writeInvokeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
