package rbac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/mrchypark/goauthy/internal/saas"
)

type oauth2RefreshFunc func(context.Context, *saas.ProviderStore, string, string, string, int64, func() (string, []any)) (saas.OAuth2Status, error)

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
	if h.saasProviderStore == nil || h.saasCredentials == nil || h.oauth2Refresh == nil {
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
	status, err := h.oauth2Refresh(r.Context(), h.saasProviderStore, owner, r.PathValue("collection_id"), r.PathValue("connection_id"), version, authority)
	if err != nil {
		h.oauth2ConnectionError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
