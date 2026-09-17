package main

import (
	"net/http"

	"github.com/mrchypark/goauthy/internal/branding"
)

// mountProviderLogoRoutes registers the provider logo CRUD routes on the
// given mux. All methods are unconditional; /img and /link are distinct
// routes that never conflict.
func mountProviderLogoRoutes(mux *http.ServeMux, h *branding.ProviderLogoHandler) {
	mux.HandleFunc("GET /auth/v1/providers/{id}/img", h.Logo)
	mux.HandleFunc("PUT /auth/v1/providers/{id}/img", h.Logo)
	mux.HandleFunc("DELETE /auth/v1/providers/{id}/img", h.Logo)
}
