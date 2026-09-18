package branding

import (
	"context"
	"errors"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/mrchypark/goauthy/internal/apikey"
)

const clientFaviconMultipartLimit int64 = maxFaviconBytes + 64<<10

// BrowserAdministrator is the existing same-origin browser-admin/CSRF
// boundary supplied by cmd/goauthy. API-key authorization is handled here so
// PUT and DELETE share the Clients.Update permission contract.
type BrowserAdministrator func(http.ResponseWriter, *http.Request, bool) bool

type ClientFaviconHandler struct {
	store        *ClientFaviconStore
	clients      map[string]struct{}
	apiKeys      *apikey.Store
	browserAdmin BrowserAdministrator
}

func NewClientFaviconHandler(store *ClientFaviconStore, apiKeys *apikey.Store, browserAdmin BrowserAdministrator, clientIDs ...string) (*ClientFaviconHandler, error) {
	if store == nil || apiKeys == nil {
		return nil, errors.New("client favicon handler requires store and API-key guard")
	}
	clients := make(map[string]struct{}, len(clientIDs))
	for _, id := range clientIDs {
		if !validClientID(id) {
			return nil, errors.New("invalid client favicon client ID")
		}
		clients[id] = struct{}{}
	}
	return &ClientFaviconHandler{store: store, clients: clients, apiKeys: apiKeys, browserAdmin: browserAdmin}, nil
}

// Favicon handles public GET and Clients.Update-protected PUT/DELETE at
// /auth/v1/clients/{id}/favicon. Only configured static client IDs are
// addressable; dynamic and arbitrary path IDs cannot enumerate the store.
func (h *ClientFaviconHandler) Favicon(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	if _, ok := h.clients[id]; !ok {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		asset, err := h.store.Get(r.Context(), id)
		if errors.Is(err, ErrClientFaviconNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		NewHandler(asset).ServeHTTP(w, r)
	case http.MethodPut:
		principal, ok := h.authorize(w, r)
		if !ok {
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "Invalid favicon", http.StatusBadRequest)
			return
		}
		asset, err := decodeMultipartFavicon(w, r)
		if err != nil {
			http.Error(w, "Invalid favicon", http.StatusBadRequest)
			return
		}
		expected, err := h.putExpected(r.Context(), id, r.Header.Get("If-Match"), r.Header.Get("If-None-Match"))
		if err != nil {
			h.faviconMutationError(w, err)
			return
		}
		if err := h.store.PutConditional(r.Context(), id, asset, expected, h.apiKeys, principal); err != nil {
			h.faviconMutationError(w, err)
			return
		}
		w.Header().Set("Clear-Site-Data", `"cache"`)
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		principal, ok := h.authorize(w, r)
		if !ok {
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "Invalid favicon", http.StatusBadRequest)
			return
		}
		expected, err := h.deleteExpected(r.Context(), id, r.Header.Get("If-Match"))
		if err != nil {
			h.faviconMutationError(w, err)
			return
		}
		if err := h.store.DeleteConditional(r.Context(), id, expected, h.apiKeys, principal); err != nil {
			h.faviconMutationError(w, err)
			return
		}
		w.Header().Set("Clear-Site-Data", `"cache"`)
		w.WriteHeader(http.StatusOK)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *ClientFaviconHandler) authorize(w http.ResponseWriter, r *http.Request) (*apikey.Principal, bool) {
	if apikey.HasAuthorization(r) {
		header, valid := apikey.Authorization(r)
		if !valid || h.apiKeys == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil, false
		}
		key, err := h.apiKeys.Authenticate(r.Context(), header)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil, false
		}
		if err := h.apiKeys.Authorize(r.Context(), key, "Clients", apikey.Update); err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
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

func (h *ClientFaviconHandler) putExpected(ctx context.Context, id, ifMatch, ifNoneMatch string) (*Asset, error) {
	current, err := h.store.Get(ctx, id)
	if errors.Is(err, ErrClientFaviconNotFound) {
		if ifNoneMatch == "*" && ifMatch == "" {
			return nil, nil
		}
		return nil, ErrClientFaviconPrecondition
	}
	if err != nil {
		return nil, err
	}
	if ifNoneMatch != "" || !strongETagMatch(ifMatch, current.etag) {
		return nil, ErrClientFaviconPrecondition
	}
	return current, nil
}

func (h *ClientFaviconHandler) deleteExpected(ctx context.Context, id, ifMatch string) (*Asset, error) {
	current, err := h.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !strongETagMatch(ifMatch, current.etag) {
		return nil, ErrClientFaviconPrecondition
	}
	return current, nil
}

func strongETagMatch(value, etag string) bool {
	if value == "" || etag == "" {
		return false
	}
	for _, candidate := range strings.Split(value, ",") {
		candidate = strings.TrimSpace(candidate)
		if !strings.HasPrefix(candidate, "W/") && candidate == etag {
			return true
		}
	}
	return false
}

func (h *ClientFaviconHandler) faviconMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrClientFaviconForbidden):
		http.Error(w, "Forbidden", http.StatusForbidden)
	case errors.Is(err, ErrClientFaviconPrecondition):
		http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
	case errors.Is(err, ErrClientFaviconNotFound):
		http.NotFound(w, nil)
	default:
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}
}

func decodeMultipartFavicon(w http.ResponseWriter, r *http.Request) (*Asset, error) {
	if len(r.Header.Values("Content-Type")) != 1 {
		return nil, errors.New("content type")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "multipart/form-data" {
		return nil, errors.New("content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, clientFaviconMultipartLimit)
	if err := r.ParseMultipartForm(clientFaviconMultipartLimit); err != nil || r.MultipartForm == nil {
		return nil, errors.New("multipart form")
	}
	defer r.MultipartForm.RemoveAll()
	if len(r.MultipartForm.File) != 1 {
		return nil, errors.New("exactly one file")
	}
	var fileHeader *multipart.FileHeader
	for _, headers := range r.MultipartForm.File {
		if len(headers) != 1 {
			return nil, errors.New("exactly one file")
		}
		fileHeader = headers[0]
	}
	if fileHeader == nil {
		return nil, errors.New("missing file")
	}
	file, err := fileHeader.Open()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readClientFavicon(file)
}
