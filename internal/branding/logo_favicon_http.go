package branding

import (
	"errors"
	"net/http"
	"strconv"
)

// Favicon handles the public client favicon and its Clients.Update-protected
// mutations at /auth/v1/clients/{id}/favicon.
func (h *ClientLogoHandler) Favicon(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	id := r.PathValue("id")
	switch r.Method {
	case http.MethodGet:
		h.getFavicon(w, r, id)
	case http.MethodPut:
		h.putFavicon(w, r, id)
	case http.MethodDelete:
		h.deleteFavicon(w, r, id)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *ClientLogoHandler) getFavicon(w http.ResponseWriter, r *http.Request, id string) {
	_, cached, err := clientLogoUpdated(r)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Favicon lookup is deliberately exact. Unlike /logo, it has no client or
	// global fallback.
	favicon, err := h.store.Find(r.Context(), id, "favicon")
	if errors.Is(err, ErrLogoNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	writeClientImage(w, favicon, cached)
}

func (h *ClientLogoHandler) putFavicon(w http.ResponseWriter, r *http.Request, id string) {
	principal, ok := h.authorize(w, r)
	if !ok {
		return
	}
	if r.ContentLength < 0 || r.ContentLength > clientLogoUploadLimit {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	assets, err := decodeClientLogoMultipart(w, r, true)
	if err != nil || len(assets) != 1 {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if err := h.store.ReplaceFaviconAuthorized(r.Context(), id, assets[0], h.apiKeys, principal); err != nil {
		h.logoMutationError(w, err)
		return
	}

	w.Header().Set("Clear-Site-Data", `"cache"`)
	w.WriteHeader(http.StatusOK)
}

func (h *ClientLogoHandler) deleteFavicon(w http.ResponseWriter, r *http.Request, id string) {
	principal, ok := h.authorize(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteFaviconAuthorized(r.Context(), id, h.apiKeys, principal); err != nil {
		h.logoMutationError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func writeClientImage(w http.ResponseWriter, logo StoredLogo, cached bool) {
	w.Header().Set("Content-Type", logo.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(logo.Data)))
	w.Header().Set("Content-Security-Policy", clientLogoCSP)
	if cached {
		w.Header().Set("Cache-Control", "max-age=31104000, stale-while-revalidate=2592000, public")
	}
	_, _ = w.Write(logo.Data)
}
