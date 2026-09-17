package rbac

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// ConnectionCredentialStatus reports the current OAuth credential state for a
// consented delivery grant without refreshing or otherwise mutating it.
func (h *Handler) ConnectionCredentialStatus(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	issuer, err := url.Parse(h.issuer)
	if err != nil || issuer.Scheme != "https" || h.saasCredentials == nil || h.connectionUseAuthorizer == nil || h.connectionUseResource == "" {
		h.unavailable(w)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Sec-Fetch-Site")) != 0 || len(r.Header.Values("Authorization")) != 1 {
		h.genericUnauthorized(w)
		return
	}
	if len(r.Header.Values("If-Match")) != 0 || len(r.Header.Values("X-CSRF-Token")) != 0 || !emptyBody(r) {
		h.badRequest(w)
		return
	}
	owner, consumer, authority, err := h.connectionUseAuthorizer(r)
	if err != nil || authority == nil {
		h.genericUnauthorized(w)
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
