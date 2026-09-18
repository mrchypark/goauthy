package rbac

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/mrchypark/goauthy/internal/saas"
)

func (h *Handler) AccountConnectionUseGrants(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	if r.URL.RawQuery != "" || h.crossSite(r) || (r.Method != http.MethodGet && r.Method != http.MethodPost) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			h.methodNotAllowed(w)
		} else {
			h.genericUnauthorized(w)
		}
		return
	}
	if len(r.Header.Values("If-Match")) != 0 {
		h.badRequest(w)
		return
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	collectionID, connectionID := r.PathValue("collection_id"), r.PathValue("connection_id")
	if collectionID == "" || connectionID == "" {
		h.notFound(w)
		return
	}
	if r.Method == http.MethodGet {
		if !emptyBody(r) {
			h.badRequest(w)
			return
		}
		items, err := h.saasCredentials.ListUseGrants(r.Context(), owner, collectionID, connectionID, authority)
		if err != nil {
			h.writeUseGrantError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(items)
		return
	}
	if h.connectionUseResource == "" {
		h.unavailable(w)
		return
	}
	var in saas.UseGrantInput
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	if err := decodeJSON(r, &in, map[string]bool{"consumer_client_id": true, "mode": true, "purpose": true, "expires_at_unix_ms": true, "connector_digest": true, "credential_version": true, "allow_refresh": true}, []string{"consumer_client_id", "mode", "purpose", "expires_at_unix_ms"}, nil); err != nil {
		h.badRequest(w)
		return
	}
	item, err := h.saasCredentials.CreateUseGrant(r.Context(), owner, collectionID, connectionID, h.connectionUseResource, in, authority)
	if err != nil {
		h.writeUseGrantError(w, err)
		return
	}
	h.writeUseGrant(w, item, http.StatusCreated)
}

func (h *Handler) AccountConnectionUseGrant(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		h.methodNotAllowed(w)
		return
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	if !emptyBody(r) {
		h.badRequest(w)
		return
	}
	revision, err := clientRevision(r)
	if err != nil {
		h.error(w, http.StatusPreconditionRequired, "If-Match revision required")
		return
	}
	collectionID, connectionID, grantID := r.PathValue("collection_id"), r.PathValue("connection_id"), r.PathValue("grant_id")
	if collectionID == "" || connectionID == "" || grantID == "" {
		h.notFound(w)
		return
	}
	if err := h.saasCredentials.RevokeUseGrant(r.Context(), owner, collectionID, connectionID, grantID, revision, authority); err != nil {
		h.writeUseGrantError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writeUseGrant(w http.ResponseWriter, item saas.UseGrant, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", `"`+strconv.FormatInt(item.Revision, 10)+`"`)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(item)
}

func (h *Handler) writeUseGrantError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, saas.ErrUseGrantInvalid):
		h.badRequest(w)
	case errors.Is(err, saas.ErrUseGrantNotFound):
		h.notFound(w)
	case errors.Is(err, saas.ErrUseGrantConflict):
		h.error(w, http.StatusConflict, "Conflict")
	case errors.Is(err, saas.ErrCredentialUnauthorized):
		h.genericUnauthorized(w)
	default:
		h.unavailable(w)
	}
}
