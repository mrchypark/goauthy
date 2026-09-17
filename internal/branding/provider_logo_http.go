package branding

import (
	"errors"
	"mime"
	"net/http"
	"strconv"

	"github.com/mrchypark/goauthy/internal/apikey"
)

const providerLogoUploadLimit int64 = 10 << 20

// ProviderLogoHandler serves the public provider logo and the
// AuthProviders.Update mutation boundary. The store owns durable
// resolution storage and SVG fallback.
type ProviderLogoHandler struct {
	store        *ProviderLogoStore
	apiKeys      *apikey.Store
	browserAdmin BrowserAdministrator
}

func NewProviderLogoHandler(store *ProviderLogoStore, apiKeys *apikey.Store, browserAdmin BrowserAdministrator) (*ProviderLogoHandler, error) {
	if store == nil || apiKeys == nil {
		return nil, errors.New("provider logo handler requires store and API-key guard")
	}
	return &ProviderLogoHandler{store: store, apiKeys: apiKeys, browserAdmin: browserAdmin}, nil
}

// Logo handles GET, PUT, and DELETE at /auth/v1/providers/{id}/img.
func (h *ProviderLogoHandler) Logo(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	switch r.Method {
	case http.MethodGet:
		h.get(w, r, id)
	case http.MethodPut:
		h.put(w, r, id)
	case http.MethodDelete:
		h.delete(w, r, id)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *ProviderLogoHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	_, cached, err := clientLogoUpdated(r)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	logo, err := h.store.Find(r.Context(), id, "small")
	if errors.Is(err, ErrLogoNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", logo.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(logo.Data)))
	if cached {
		w.Header().Set("Cache-Control", "max-age=31104000, stale-while-revalidate=2592000, public")
	}
	_, _ = w.Write(logo.Data)
}

func (h *ProviderLogoHandler) put(w http.ResponseWriter, r *http.Request, id string) {
	principal, ok := h.authorize(w, r)
	if !ok {
		return
	}
	if r.ContentLength < 0 || r.ContentLength > providerLogoUploadLimit {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	assets, err := decodeProviderLogoMultipart(w, r)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if err := h.store.ReplaceAuthorized(r.Context(), id, assets, h.apiKeys, principal); err != nil {
		h.logoMutationError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *ProviderLogoHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	principal, ok := h.authorize(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteAuthorized(r.Context(), id, h.apiKeys, principal); err != nil {
		h.logoMutationError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *ProviderLogoHandler) authorize(w http.ResponseWriter, r *http.Request) (*apikey.Principal, bool) {
	if apikey.HasAuthorization(r) {
		header, valid := apikey.Authorization(r)
		if !valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil, false
		}
		key, err := h.apiKeys.Authenticate(r.Context(), header)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil, false
		}
		if err := h.apiKeys.Authorize(r.Context(), key, "AuthProviders", apikey.Update); err != nil {
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
	return nil, h.browserAdmin(w, r, true)
}

func (h *ProviderLogoHandler) logoMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, apikey.ErrForbidden):
		http.Error(w, "Forbidden", http.StatusForbidden)
	case errors.Is(err, ErrInvalidLogo), errors.Is(err, ErrInvalidRasterLogo), errors.Is(err, ErrInvalidLogoSVG), errors.Is(err, ErrRasterLogoTooLarge):
		http.Error(w, "Bad Request", http.StatusBadRequest)
	case errors.Is(err, ErrProviderNotFound), errors.Is(err, ErrLogoNotFound):
		http.NotFound(w, nil)
	default:
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}
}

func decodeProviderLogoMultipart(w http.ResponseWriter, r *http.Request) ([]LogoAsset, error) {
	if len(r.Header.Values("Content-Type")) != 1 {
		return nil, errors.New("content type")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "multipart/form-data" {
		return nil, errors.New("content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, providerLogoUploadLimit)
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, errors.New("multipart form")
	}
	part, err := reader.NextPart()
	if err != nil {
		return nil, errors.New("multipart payload is empty")
	}
	contentType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
	if err != nil {
		return nil, errors.New("content type is missing")
	}
	data, err := ioReadAllLimit(part, providerLogoUploadLimit)
	part.Close()
	if err != nil {
		return nil, err
	}
	switch contentType {
	case "image/png", "image/jpeg":
		return ProcessRasterLogo(data, logoProviderSmallSize, false)
	case "image/svg+xml":
		clean, err := SanitizedLogoSVG(data)
		if err != nil {
			return nil, err
		}
		return []LogoAsset{{Resolution: "svg", ContentType: "image/svg+xml", Data: clean}}, nil
	default:
		return nil, errors.New("unsupported logo content type")
	}
}
