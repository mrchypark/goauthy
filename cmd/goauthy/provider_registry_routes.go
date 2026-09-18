package main

import (
	"net/http"

	"github.com/mrchypark/goauthy/internal/upstreamprovider"
)

// mountProviderRegistryRoutes registers the provider registry
// CRUD routes on the given mux. All methods are unconditional.
func mountProviderRegistryRoutes(mux *http.ServeMux, h *upstreamprovider.RegistryHandler) {
	// Read routes.
	mux.HandleFunc("POST /auth/v1/providers", h.PostProviders)
	mux.HandleFunc("GET /auth/v1/providers/minimal", h.GetProvidersMinimal)
	mux.HandleFunc("GET /auth/v1/providers/{id}/delete_safe", h.GetProviderDeleteSafe)
	// Write routes.
	mux.HandleFunc("POST /auth/v1/providers/create", h.CreateProvider)
	mux.HandleFunc("PUT /auth/v1/providers/{id}", h.UpdateProvider)
	mux.HandleFunc("DELETE /auth/v1/providers/{id}", h.DeleteProvider)
}

