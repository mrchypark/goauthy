package branding

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/security"
)

const maxThemeRequestBytes = 1 << 20

// ThemeClientExists checks that a managed client exists. The callback lets
// the parent keep client lookup behind its existing guarded client store.
type ThemeClientExists func(context.Context, string) error

type ThemeHandler struct {
	store        *ThemeStore
	apiKeys      *apikey.Store
	browserAdmin BrowserAdministrator
	clientExists ThemeClientExists
}

// NewThemeHandler creates the pinned theme HTTP contract handler. The parent
// should pass a client lookup that includes disabled managed clients.
func NewThemeHandler(store *ThemeStore, apiKeys *apikey.Store, browserAdmin BrowserAdministrator, clientExists ThemeClientExists) (*ThemeHandler, error) {
	if store == nil || apiKeys == nil || clientExists == nil {
		return nil, errors.New("theme handler requires store, API-key guard, and client lookup")
	}
	return &ThemeHandler{store: store, apiKeys: apiKeys, browserAdmin: browserAdmin, clientExists: clientExists}, nil
}

// Theme serves /auth/v1/theme/{client_id} and
// /auth/v1/theme/{client_id}/{timestamp}.
func (h *ThemeHandler) Theme(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	clientID := r.PathValue("client_id")
	if clientID == "" {
		clientID = r.PathValue("id")
	}
	if clientID == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.get(w, r, clientID, false)
	case http.MethodPost:
		h.post(w, r, clientID, false)
	case http.MethodPut:
		h.put(w, r, clientID, false)
	case http.MethodDelete:
		h.delete(w, r, clientID, false)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST, PUT, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// GlobalTheme handles the common theme independently of every client ID.
func (h *ThemeHandler) GlobalTheme(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.get(w, r, GlobalBrandID, true)
	case http.MethodPost:
		h.post(w, r, GlobalBrandID, true)
	case http.MethodPut:
		h.put(w, r, GlobalBrandID, true)
	case http.MethodDelete:
		h.delete(w, r, GlobalBrandID, true)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST, PUT, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *ThemeHandler) get(w http.ResponseWriter, r *http.Request, clientID string, global bool) {
	if !validThemeTimestamp(r.PathValue("timestamp")) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	var theme Theme
	var err error
	if global {
		theme, err = h.store.GetGlobal(r.Context())
	} else {
		theme, err = h.store.GetFallback(r.Context(), clientID)
	}
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	acceptEncoding := r.Header.Get("Accept-Encoding")
	if !security.ValidHeaderText(acceptEncoding) {
		acceptEncoding = ""
	}
	body, encoding, err := encodeThemeCSS(theme.CSS(), acceptEncoding)
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/css")
	if encoding != "" {
		w.Header().Set("Content-Encoding", encoding)
	}
	// The representation depends on Accept-Encoding, so a shared cache must key
	// on it before serving an encoded or identity copy to another client.
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("Cache-Control", "max-age=31104000, public")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func (h *ThemeHandler) post(w http.ResponseWriter, r *http.Request, clientID string, global bool) {
	if _, ok := h.authorize(w, r, apikey.Read); !ok {
		return
	}
	if !global {
		if err := h.clientExists(r.Context(), clientID); err != nil {
			h.themeMutationError(w, err)
			return
		}
	}
	var theme Theme
	var err error
	if global {
		theme, err = h.store.GetGlobal(r.Context())
	} else {
		theme, err = h.store.GetDefault(r.Context(), clientID)
	}
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	writeThemeJSON(w, theme)
}

func (h *ThemeHandler) put(w http.ResponseWriter, r *http.Request, clientID string, global bool) {
	principal, ok := h.authorize(w, r, apikey.Update)
	if !ok {
		return
	}
	theme, err := decodeTheme(w, r)
	if err != nil || theme.ClientID != clientID {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !global {
		if err := h.clientExists(r.Context(), clientID); err != nil {
			h.themeMutationError(w, err)
			return
		}
	}
	if global {
		err = h.store.PutGlobalAuthorized(r.Context(), theme, h.apiKeys, principal)
	} else if r.Header.Get("If-None-Match") == "*" {
		err = h.store.PutIfAbsentAuthorized(r.Context(), theme, h.apiKeys, principal)
	} else {
		err = h.store.PutAuthorized(r.Context(), theme, h.apiKeys, principal)
	}
	if err != nil {
		h.themeMutationError(w, err)
		return
	}
	w.Header().Set("Clear-Site-Data", `"cache"`)
	w.WriteHeader(http.StatusOK)
}

func (h *ThemeHandler) delete(w http.ResponseWriter, r *http.Request, clientID string, global bool) {
	principal, ok := h.authorize(w, r, apikey.Delete)
	if !ok {
		return
	}
	if !global {
		if err := h.clientExists(r.Context(), clientID); err != nil {
			h.themeMutationError(w, err)
			return
		}
	}
	var err error
	if global {
		err = h.store.DeleteGlobalAuthorized(r.Context(), h.apiKeys, principal)
	} else {
		err = h.store.DeleteAuthorized(r.Context(), clientID, h.apiKeys, principal)
	}
	if err != nil {
		h.themeMutationError(w, err)
		return
	}
	w.Header().Set("Clear-Site-Data", `"cache"`)
	w.WriteHeader(http.StatusOK)
}

func (h *ThemeHandler) authorize(w http.ResponseWriter, r *http.Request, right apikey.Right) (*apikey.Principal, bool) {
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
		if err := h.apiKeys.Authorize(r.Context(), key, "Clients", right); err != nil {
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

func (h *ThemeHandler) themeMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, apikey.ErrForbidden):
		http.Error(w, "Forbidden", http.StatusForbidden)
	case errors.Is(err, ErrInvalidTheme):
		http.Error(w, "Bad Request", http.StatusBadRequest)
	case errors.Is(err, ErrThemeConflict):
		http.Error(w, "Theme changed; reload before saving", http.StatusPreconditionFailed)
	case errors.Is(err, clients.ErrNotFound):
		http.Error(w, "Not Found", http.StatusNotFound)
	default:
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}
}

func decodeTheme(w http.ResponseWriter, r *http.Request) (Theme, error) {
	var theme Theme
	if len(r.Header.Values("Content-Type")) != 1 {
		return theme, ErrInvalidTheme
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return theme, ErrInvalidTheme
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxThemeRequestBytes)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&theme); err != nil {
		return theme, ErrInvalidTheme
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return theme, ErrInvalidTheme
	}
	if err := theme.Validate(); err != nil {
		return theme, err
	}
	return theme, nil
}

func writeThemeJSON(w http.ResponseWriter, theme Theme) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(theme)
}

func validThemeTimestamp(value string) bool {
	if value == "" {
		return false
	}
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}

func encodeThemeCSS(css, acceptEncoding string) ([]byte, string, error) {
	// The pinned preference is br, then gzip. The pinned Rust helper uses
	// Brotli's default parameters, whose quality is 11. An empty encoding is
	// identity, which carries no Content-Encoding header.
	encoding := themeEncoding(acceptEncoding)
	if encoding == "" {
		return []byte(css), "", nil
	}
	var body bytes.Buffer
	var writer io.WriteCloser
	if encoding == "br" {
		writer = brotli.NewWriterLevel(&body, brotli.BestCompression)
	} else {
		writer = gzip.NewWriter(&body)
	}
	if _, err := io.WriteString(writer, css); err != nil {
		return nil, "", err
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return body.Bytes(), encoding, nil
}

// themeEncoding returns the best acceptable coding, or "" for identity.
// A coding is unacceptable when the header gives it q=0, and a coding the
// header never mentions is unacceptable unless a wildcard covers it; identity
// stays acceptable by default but loses to a coding of equal quality.
func themeEncoding(acceptEncoding string) string {
	quality := make(map[string]float64, 4)
	wildcard, hasWildcard := 0.0, false
	for _, part := range strings.Split(acceptEncoding, ",") {
		coding, params, _ := strings.Cut(part, ";")
		coding = strings.ToLower(strings.TrimSpace(coding))
		if coding == "" {
			continue
		}
		q := 1.0
		for _, param := range strings.Split(params, ";") {
			name, value, ok := strings.Cut(param, "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || parsed < 0 || parsed > 1 {
				parsed = 0
			}
			q = parsed
		}
		if coding == "*" {
			wildcard, hasWildcard = q, true
		} else if previous, ok := quality[coding]; !ok || q > previous {
			quality[coding] = q
		}
	}
	best, bestQuality := "", 0.0
	for _, coding := range []string{"br", "gzip", "identity"} {
		q, listed := quality[coding]
		if !listed && hasWildcard {
			q = wildcard
		} else if !listed && coding == "identity" {
			q = 1
		} else if !listed {
			q = 0
		}
		if q > bestQuality {
			best, bestQuality = coding, q
		}
	}
	if best == "identity" {
		return ""
	}
	return best
}
