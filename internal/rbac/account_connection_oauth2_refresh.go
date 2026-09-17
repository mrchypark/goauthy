package rbac

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// AccountConnectionOAuth2Refresh refreshes an owner's stored OAuth2
// connection and returns metadata only; credentials are never serialized.
func (h *Handler) AccountConnectionOAuth2Refresh(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	issuer, err := url.Parse(h.issuer)
	if err != nil || issuer.Scheme != "https" {
		h.unavailable(w)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || h.crossSite(r) || len(r.Header.Values("If-Match")) != 0 {
		h.badRequest(w)
		return
	}
	if h.saasProviderStore == nil || h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	version, err := apiKeyVersion(r)
	if err != nil {
		h.badRequest(w)
		return
	}
	status, err := h.saasCredentials.RefreshOAuth2(r.Context(), h.saasProviderStore, owner, r.PathValue("collection_id"), r.PathValue("connection_id"), version, authority)
	if err != nil {
		h.oauth2ConnectionError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
