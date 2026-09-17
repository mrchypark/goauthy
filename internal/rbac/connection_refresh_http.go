package rbac

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// RefreshConnectionCredential refreshes an OAuth credential only when the
// consented grant explicitly delegates refresh-token use.
func (h *Handler) RefreshConnectionCredential(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	issuer, err := url.Parse(h.issuer)
	if err != nil || issuer.Scheme != "https" || h.saasCredentials == nil || h.saasProviderStore == nil || h.connectionUseAuthorizer == nil || h.connectionUseResource == "" {
		h.unavailable(w)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Sec-Fetch-Site")) != 0 || len(r.Header.Values("Authorization")) != 1 {
		h.genericUnauthorized(w)
		return
	}
	if len(r.Header.Values("If-Match")) != 0 || len(r.Header.Values("X-CSRF-Token")) != 0 {
		h.badRequest(w)
		return
	}
	owner, consumer, authority, err := h.connectionUseAuthorizer(r)
	if err != nil || authority == nil {
		h.genericUnauthorized(w)
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
