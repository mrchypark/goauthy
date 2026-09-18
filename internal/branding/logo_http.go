package branding

import (
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
)

const (
	clientLogoUploadLimit int64 = 10 << 20
	clientLogoCSP               = "connect-src 'none'; script-src 'none'; frame-ancestors 'none'; object-src 'none';"
)

// ClientLogoHandler serves the public client logo and the Clients.Update
// mutation boundary. The store owns durable fallback and favicon preservation.
type ClientLogoHandler struct {
	store        *ClientLogoStore
	apiKeys      *apikey.Store
	browserAdmin BrowserAdministrator
}

func NewClientLogoHandler(store *ClientLogoStore, apiKeys *apikey.Store, browserAdmin BrowserAdministrator) (*ClientLogoHandler, error) {
	if store == nil || apiKeys == nil {
		return nil, errors.New("client logo handler requires store and API-key guard")
	}
	return &ClientLogoHandler{store: store, apiKeys: apiKeys, browserAdmin: browserAdmin}, nil
}

// Logo handles GET, PUT, and DELETE at /auth/v1/clients/{id}/logo.
func (h *ClientLogoHandler) Logo(w http.ResponseWriter, r *http.Request) {
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

func (h *ClientLogoHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	_, cached, err := clientLogoUpdated(r)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	logo, err := h.store.GetFallback(r.Context(), id)
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
	w.Header().Set("Content-Security-Policy", clientLogoCSP)
	if cached {
		w.Header().Set("Cache-Control", "max-age=31104000, stale-while-revalidate=2592000, public")
	}
	_, _ = w.Write(logo.Data)
}

func (h *ClientLogoHandler) put(w http.ResponseWriter, r *http.Request, id string) {
	principal, ok := h.authorize(w, r)
	if !ok {
		return
	}
	if r.ContentLength < 0 || r.ContentLength > clientLogoUploadLimit {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	assets, err := decodeClientLogoMultipart(w, r, false)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if err := h.store.ReplaceAuthorized(r.Context(), id, assets, h.apiKeys, principal); err != nil {
		h.logoMutationError(w, err)
		return
	}
	w.Header().Set("Clear-Site-Data", `"cache"`)
	w.WriteHeader(http.StatusOK)
}

func (h *ClientLogoHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
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

func (h *ClientLogoHandler) authorize(w http.ResponseWriter, r *http.Request) (*apikey.Principal, bool) {
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
		if err := h.apiKeys.Authorize(r.Context(), key, "Clients", apikey.Update); err != nil {
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

func (h *ClientLogoHandler) logoMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, apikey.ErrForbidden):
		http.Error(w, "Forbidden", http.StatusForbidden)
	case errors.Is(err, ErrInvalidLogo), errors.Is(err, ErrInvalidRasterLogo), errors.Is(err, ErrInvalidLogoSVG), errors.Is(err, ErrRasterLogoTooLarge):
		http.Error(w, "Bad Request", http.StatusBadRequest)
	case errors.Is(err, clients.ErrNotFound), errors.Is(err, ErrLogoNotFound):
		http.NotFound(w, nil)
	default:
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}
}

func clientLogoUpdated(r *http.Request) (int64, bool, error) {
	values, present := r.URL.Query()["updated"]
	if !present {
		return 0, false, nil
	}
	if len(values) != 1 || values[0] == "" {
		return 0, true, errors.New("invalid updated parameter")
	}
	updated, err := strconv.ParseInt(values[0], 10, 64)
	return updated, true, err
}

func decodeClientLogoMultipart(w http.ResponseWriter, r *http.Request, favicon bool) ([]LogoAsset, error) {
	if len(r.Header.Values("Content-Type")) != 1 {
		return nil, errors.New("content type")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "multipart/form-data" {
		return nil, errors.New("content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, clientLogoUploadLimit)
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
	data, err := ioReadAllLimit(part, clientLogoUploadLimit)
	part.Close()
	if err != nil {
		return nil, err
	}
	switch contentType {
	case "image/png", "image/jpeg":
		return ProcessRasterLogo(data, logoClientSmallSize, favicon)
	case "image/svg+xml":
		clean, err := SanitizedLogoSVG(data)
		if err != nil {
			return nil, err
		}
		resolution := "svg"
		if favicon {
			resolution = "favicon"
		}
		return []LogoAsset{{Resolution: resolution, ContentType: "image/svg+xml", Data: clean}}, nil
	default:
		return nil, errors.New("unsupported logo content type")
	}
}

func ioReadAllLimit(part *multipart.Part, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(part, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("logo exceeds upload limit")
	}
	return data, nil
}
