package rbac

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/saas"
)

// BindConnectionHandoffAuthorizer wires the OAuth resource-server adapter
// used by the connection-handoff proposal boundary.
func (h *Handler) BindConnectionHandoffAuthorizer(authorizer func(*http.Request) (string, string, func() (string, []any), error)) error {
	if h == nil || authorizer == nil {
		return errors.New("connection handoff authorizer required")
	}
	h.connectionHandoffAuthorizer = authorizer
	return nil
}

// CreateConnectionHandoff creates a pending, browser-reviewed handoff.
func (h *Handler) CreateConnectionHandoff(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if h.saasCredentials == nil || h.connectionUseResource == "" || h.connectionHandoffAuthorizer == nil {
		h.unavailable(w)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || h.crossSite(r) || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Authorization")) != 1 {
		h.genericUnauthorized(w)
		return
	}
	if len(r.Header.Values("If-Match")) != 0 {
		h.badRequest(w)
		return
	}
	owner, requester, authority, err := h.connectionHandoffAuthorizer(r)
	if err != nil || authority == nil {
		h.genericUnauthorized(w)
		return
	}
	var in saas.UseHandoffInput
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	fields := map[string]bool{
		"collection_id": true, "connection_id": true, "consumer_client_id": true,
		"mode": true, "purpose": true, "expires_at_unix_ms": true,
		"return_uri": true, "state": true, "allow_refresh": true,
	}
	if err := decodeJSON(r, &in, fields, []string{"collection_id", "connection_id", "consumer_client_id", "mode", "purpose", "expires_at_unix_ms", "return_uri", "state"}, nil); err != nil {
		h.badRequest(w)
		return
	}
	id, review, err := h.saasCredentials.CreateUseHandoff(r.Context(), owner, requester, h.connectionUseResource, in, authority)
	if err != nil {
		h.writeHandoffError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		ID        string                `json:"id"`
		ReviewURI string                `json:"review_uri"`
		Review    saas.UseHandoffReview `json:"review"`
	}{id, h.issuer + "/account/connection-handoffs/" + id, review})
}

// OwnerConnectionHandoff reviews or completes a handoff using the owner's
// browser session. Approval never redirects and never returns a secret.
func (h *Handler) OwnerConnectionHandoff(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if len(r.Header.Values("If-Match")) != 0 {
		h.badRequest(w)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		h.methodNotAllowed(w)
		return
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	id := r.PathValue("handoff_id")
	if id == "" {
		h.notFound(w)
		return
	}
	if r.Method == http.MethodGet {
		if !emptyBody(r) {
			h.badRequest(w)
			return
		}
		review, err := h.saasCredentials.ReviewUseHandoff(r.Context(), owner, id, authority)
		if err != nil {
			h.writeHandoffError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(review)
		return
	}
	var in struct {
		Approve         bool    `json:"approve"`
		ReviewDigest    *string `json:"review_digest"`
		ConnectorDigest *string `json:"connector_digest"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	if err := decodeJSON(r, &in, map[string]bool{"approve": true, "review_digest": true, "connector_digest": true}, []string{"approve"}, nil); err != nil {
		h.badRequest(w)
		return
	}
	if in.Approve && ((in.ReviewDigest != nil && in.ConnectorDigest != nil) || (in.ReviewDigest == nil && in.ConnectorDigest == nil) || in.ReviewDigest != nil && *in.ReviewDigest == "" || in.ConnectorDigest != nil && *in.ConnectorDigest == "") || !in.Approve && (in.ReviewDigest != nil || in.ConnectorDigest != nil) {
		h.badRequest(w)
		return
	}
	digest := ""
	if in.ReviewDigest != nil {
		digest = *in.ReviewDigest
	} else if in.ConnectorDigest != nil {
		digest = *in.ConnectorDigest
	}
	returnURI, err := h.saasCredentials.CompleteUseHandoff(r.Context(), owner, id, in.Approve, digest, authority)
	if err != nil {
		h.writeHandoffError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		ReturnURI string `json:"return_uri"`
	}{returnURI})
}

func (h *Handler) writeHandoffError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, saas.ErrUseGrantInvalid):
		h.badRequest(w)
	case errors.Is(err, saas.ErrUseGrantNotFound), errors.Is(err, saas.ErrCredentialNotFound), errors.Is(err, clients.ErrNotFound):
		h.notFound(w)
	case errors.Is(err, saas.ErrUseGrantConflict):
		h.error(w, http.StatusConflict, "Conflict")
	case errors.Is(err, saas.ErrCredentialUnauthorized), errors.Is(err, clients.ErrUnauthorized):
		h.genericUnauthorized(w)
	default:
		h.unavailable(w)
	}
}
