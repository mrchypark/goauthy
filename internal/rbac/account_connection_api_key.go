package rbac

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mrchypark/goauthy/internal/saas"
)

type accountConnectionAPIKeyResponse struct {
	Registered bool  `json:"registered"`
	Version    int64 `json:"version"`
}

func (h *Handler) BindSaaSCredentials(store *saas.CredentialStore) error {
	if h == nil || store == nil {
		return errors.New("SaaS credential store required")
	}
	h.saasCredentials = store
	return nil
}

func (h *Handler) AccountConnectionAPIKey(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, PUT, DELETE")
		h.methodNotAllowed(w)
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
	switch r.Method {
	case http.MethodGet:
		if !emptyBody(r) {
			h.badRequest(w)
			return
		}
		status, err := h.saasCredentials.APIKeyStatus(r.Context(), owner, collectionID, connectionID, authority)
		if err != nil {
			h.writeAPIKeyError(w, err)
			return
		}
		h.writeAPIKeyStatus(w, status)
	case http.MethodPut:
		var in struct {
			APIKey          string  `json:"api_key"`
			Version         int64   `json:"version"`
			ConnectorDigest *string `json:"connector_digest"`
		}
		if err := decodeJSON(r, &in, map[string]bool{"api_key": true, "version": true, "connector_digest": true}, []string{"api_key", "version"}, nil); err != nil || in.Version < 0 || in.APIKey == "" {
			h.badRequest(w)
			return
		}
		var status saas.APIKeyStatus
		var err error
		if in.ConnectorDigest == nil {
			status, err = h.saasCredentials.PutAPIKey(r.Context(), owner, collectionID, connectionID, in.Version, in.APIKey, authority)
		} else {
			connector, loadErr := h.saasCredentials.APIKeyConnector(r.Context(), owner, collectionID, connectionID, authority)
			if loadErr != nil {
				h.writeAPIKeyError(w, loadErr)
				return
			}
			status, err = h.saasCredentials.PutBoundAPIKey(r.Context(), owner, collectionID, connectionID, in.Version, in.APIKey, connector, *in.ConnectorDigest, authority)
		}
		if err != nil {
			h.writeAPIKeyError(w, err)
			return
		}
		h.writeAPIKeyStatus(w, status)
	case http.MethodDelete:
		if len(r.Header.Values("If-Match")) != 0 {
			h.badRequest(w)
			return
		}
		version, err := apiKeyVersion(r)
		if err != nil {
			h.badRequest(w)
			return
		}
		if err := h.saasCredentials.RevokeAPIKey(r.Context(), owner, collectionID, connectionID, version, authority); err != nil {
			h.writeAPIKeyError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *Handler) AccountConnectionAPIKeyConnector(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if !emptyBody(r) || len(r.Header.Values("If-Match")) != 0 {
		h.badRequest(w)
		return
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	collection, connection := r.PathValue("collection_id"), r.PathValue("connection_id")
	if collection == "" || connection == "" {
		h.notFound(w)
		return
	}
	connector, err := h.saasCredentials.APIKeyConnector(r.Context(), owner, collection, connection, authority)
	if err != nil {
		h.writeAPIKeyError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(connector.Info())
}

func apiKeyVersion(r *http.Request) (int64, error) {
	var in struct {
		Version int64 `json:"version"`
	}
	if err := decodeJSON(r, &in, map[string]bool{"version": true}, []string{"version"}, nil); err != nil || in.Version < 1 {
		return 0, errors.New("version")
	}
	return in.Version, nil
}

func (h *Handler) writeAPIKeyStatus(w http.ResponseWriter, status saas.APIKeyStatus) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(accountConnectionAPIKeyResponse{Registered: status.Registered, Version: status.Version})
}

func (h *Handler) writeAPIKeyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, saas.ErrCredentialNotFound):
		h.notFound(w)
	case errors.Is(err, saas.ErrCredentialConflict):
		h.error(w, http.StatusConflict, "Conflict")
	case errors.Is(err, saas.ErrCredentialUnauthorized):
		h.genericUnauthorized(w)
	case errors.Is(err, saas.ErrInvalidAPIKey):
		h.badRequest(w)
	default:
		h.unavailable(w)
	}
}
