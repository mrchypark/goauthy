package upstreamprovider

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/branding"
)

// ProviderMinimalResponse is the pinned rauthy v0.36.2
// AuthProviderTemplate fields for the public /providers/minimal endpoint.
// Updated is 0 when no logo is present; the field is always included
// to match the upstream response shape exactly.
type ProviderMinimalResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Updated int64  `json:"updated"`
}

// RegistryHandler serves the read-side HTTP API for upstream auth
// providers. It wraps an existing RegistryStore with apikey and browser
// admin authorization conventions matching branding/logo_http.go.
type RegistryHandler struct {
	store        *RegistryStore
	keys         *apikey.Store
	logos        *branding.ProviderLogoStore
	browserAdmin branding.BrowserAdministrator
}

// NewRegistryHandler constructs a RegistryHandler. Both store and keys
// are required; browserAdmin may be nil when no browser session boundary
// is configured. The logo store is created internally from the store's
// database handle for provider updated-at lookups.
func NewRegistryHandler(
	store *RegistryStore,
	keys    *apikey.Store,
	browserAdmin branding.BrowserAdministrator,
) (*RegistryHandler, error) {
	if store == nil || keys == nil {
		return nil, errors.New("registry handler requires store and API-key guard")
	}
	var logos *branding.ProviderLogoStore
	if store.db != nil {
		logos, _ = branding.NewProviderLogoStore(store.db)
	}
	return &RegistryHandler{
		store:        store,
		keys:         keys,
		logos:        logos,
		browserAdmin: browserAdmin,
	}, nil
}

// authorize checks either an API-Key header or the browser admin session.
// The right parameter selects the apikey permission checked on the
// API-key path. For the browser path, read requests skip CSRF (false)
// and mutations require CSRF (true), matching the theme_http.go
// read-versus-CSRF convention.
func (h *RegistryHandler) authorize(w http.ResponseWriter, r *http.Request, right apikey.Right) (*apikey.Principal, bool) {
	if apikey.HasAuthorization(r) {
		header, valid := apikey.Authorization(r)
		if !valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil, false
		}
		key, err := h.keys.Authenticate(r.Context(), header)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil, false
		}
		if err := h.keys.Authorize(r.Context(), key, authProvidersGroup, right); err != nil {
			if errors.Is(err, apikey.ErrForbidden) {
				http.Error(w, "Forbidden", http.StatusForbidden)
			} else {
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			}
			return nil, false
		}
		return &key, true
	}
	if h.browserAdmin == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	return nil, h.browserAdmin(w, r, right != apikey.Read)
}

// PostProviders handles POST /auth/v1/providers. It returns every
// persisted provider with the decrypted client_secret for admin read.
func (h *RegistryHandler) PostProviders(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, apikey.Read); !ok {
		return
	}
	providers, err := h.store.List(r.Context())
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	resp := make([]ProviderResponse, 0, len(providers))
	for _, doc := range providers {
		secret, err := h.store.SecretCleartext(doc)
		if err != nil {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		resp = append(resp, doc.Response(secret))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// GetProvidersMinimal handles GET /auth/v1/providers/minimal. It is
// public (no authorization required) and returns only enabled providers
// with the exact pinned template fields: id, name, updated.
func (h *RegistryHandler) GetProvidersMinimal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	providers, err := h.store.List(r.Context())
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	resp := make([]ProviderMinimalResponse, 0)
	for _, doc := range providers {
		if !doc.Enabled {
			continue
		}
		updated := int64(0)
		if h.logos != nil {
			logo, err := h.logos.Find(r.Context(), doc.ID, "small")
			if err == nil {
				updated = logo.Updated
			}
		}
		resp = append(resp, ProviderMinimalResponse{ID: doc.ID, Name: doc.Name, Updated: updated})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// GetProviderDeleteSafe handles GET /auth/v1/providers/{id}/delete_safe.
// It returns 200 with an empty array if the provider has no linked users,
// or 406 with the linked user array (including disabled users) otherwise.
func (h *RegistryHandler) GetProviderDeleteSafe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if _, ok := h.authorize(w, r, apikey.Read); !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	linked, err := h.store.LinkedUsers(r.Context(), id)
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if len(linked) == 0 {
		_ = json.NewEncoder(w).Encode(linked)
		return
	}
	w.WriteHeader(http.StatusNotAcceptable)
	_ = json.NewEncoder(w).Encode(linked)
}
