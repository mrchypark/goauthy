package rbac

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/mrchypark/goauthy/internal/saas"
)

// DeliverConnectionCredential returns a consented credential to an
// authenticated server-side consumer. The request carries no caller data.
func (h *Handler) DeliverConnectionCredential(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	issuer, err := url.Parse(h.issuer)
	if err != nil || issuer.Scheme != "https" {
		h.unavailable(w)
		return
	}
	if h.saasCredentials == nil || h.connectionUseAuthorizer == nil || h.connectionUseResource == "" {
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
	if len(r.Header.Values("If-Match")) != 0 || len(r.Header.Values("X-CSRF-Token")) != 0 || !emptyBody(r) {
		h.badRequest(w)
		return
	}
	owner, consumer, authority, err := h.connectionUseAuthorizer(r)
	if err != nil || authority == nil {
		h.genericUnauthorized(w)
		return
	}
	grant, _, err := h.saasCredentials.AuthorizeUseGrant(r.Context(), owner, consumer, r.PathValue("grant_id"), h.connectionUseResource, "credential_delivery", authority)
	if err != nil {
		if errors.Is(err, saas.ErrUseGrantInvalid) {
			h.badRequest(w)
			return
		}
		h.writeInvokeError(w, err)
		return
	}
	var delivery any
	if grant.ConnectorDigest == "" {
		delivery, err = h.saasCredentials.DeliverOAuth2(r.Context(), owner, consumer, r.PathValue("grant_id"), h.connectionUseResource, authority)
	} else {
		delivery, err = h.saasCredentials.DeliverAPIKey(r.Context(), owner, consumer, r.PathValue("grant_id"), h.connectionUseResource, authority)
	}
	if err != nil {
		if errors.Is(err, saas.ErrUseGrantInvalid) {
			h.badRequest(w)
			return
		}
		h.writeInvokeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(delivery)
}
