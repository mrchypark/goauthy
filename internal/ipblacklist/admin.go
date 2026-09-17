package ipblacklist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
)

const adminPath = "/auth/v1/blacklist"

type AdminHandler struct {
	store        *Store
	keys         *apikey.Store
	browserAdmin func(http.ResponseWriter, *http.Request, bool) bool
	now          func() time.Time
}

func NewAdminHandler(store *Store, keys *apikey.Store, browserAdmin func(http.ResponseWriter, *http.Request, bool) bool) *AdminHandler {
	return &AdminHandler{store: store, keys: keys, browserAdmin: browserAdmin, now: time.Now}
}

type adminRequest struct {
	IP  string `json:"ip"`
	Exp int64  `json:"exp"`
}

type adminResponse struct {
	IP  string `json:"ip"`
	Exp int64  `json:"exp"`
}

func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.headers(w, r)
	if h == nil || h.store == nil || r == nil || r.URL == nil || r.URL.RawQuery != "" || ambiguousPath(r.URL) {
		h.fail(w, r, http.StatusUnauthorized)
		return
	}
	if r.URL.Path == adminPath {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r)
		case http.MethodPost:
			h.add(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			h.fail(w, r, http.StatusMethodNotAllowed)
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, adminPath+"/") && r.URL.Path != adminPath+"/" {
		prefix := strings.TrimPrefix(r.URL.Path, adminPath+"/")
		canonical, err := CanonicalPrefix(prefix)
		if err != nil || canonical.String() != prefix {
			h.fail(w, r, http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			h.get(w, r, prefix)
		case http.MethodPut:
			h.update(w, r, prefix)
		case http.MethodDelete:
			h.delete(w, r, prefix)
		default:
			w.Header().Set("Allow", "GET, PUT, DELETE")
			h.fail(w, r, http.StatusMethodNotAllowed)
		}
		return
	}
	h.fail(w, r, http.StatusNotFound)
}

func (h *AdminHandler) principal(w http.ResponseWriter, r *http.Request, mutation bool, right apikey.Right) bool {
	if apikey.HasAuthorization(r) {
		if h.keys == nil {
			h.fail(w, r, http.StatusUnauthorized)
			return false
		}
		auth, ok := apikey.Authorization(r)
		if !ok || !strings.HasPrefix(auth, "API-Key ") {
			h.fail(w, r, http.StatusUnauthorized)
			return false
		}
		p, err := h.keys.Authenticate(r.Context(), auth)
		if err != nil || h.keys.Authorize(r.Context(), p, "Blacklist", right) != nil {
			h.fail(w, r, http.StatusUnauthorized)
			return false
		}
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		h.fail(w, r, http.StatusForbidden)
		return false
	}
	if h.browserAdmin == nil || !h.browserAdmin(w, r, mutation) {
		return false
	}
	return true
}

func ambiguousPath(u *url.URL) bool {
	return u.RawPath != "" && u.RawPath != u.Path
}

func (h *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	if !h.principal(w, r, false, apikey.Read) {
		return
	}
	entries, err := h.store.List(r.Context())
	if err != nil {
		h.fail(w, r, http.StatusServiceUnavailable)
		return
	}
	out := make([]adminResponse, 0, len(entries))
	for _, e := range entries {
		out = append(out, adminResponse{IP: e.Prefix, Exp: expirySeconds(e.ExpiresAtUnixMs)})
	}
	h.json(w, map[string]any{"ips": out})
}

func (h *AdminHandler) get(w http.ResponseWriter, r *http.Request, prefix string) {
	if !h.principal(w, r, false, apikey.Read) {
		return
	}
	e, err := h.store.Get(r.Context(), prefix)
	if err != nil {
		h.fail(w, r, statusFor(err))
		return
	}
	h.json(w, adminResponse{IP: e.Prefix, Exp: expirySeconds(e.ExpiresAtUnixMs)})
}

func (h *AdminHandler) add(w http.ResponseWriter, r *http.Request) {
	if !h.principal(w, r, true, apikey.Create) {
		return
	}
	v, ok := decodeAdmin(w, r)
	if !ok || v.Exp <= h.now().Unix() {
		h.fail(w, r, http.StatusBadRequest)
		return
	}
	canonical, err := CanonicalPrefix(v.IP)
	if err != nil || canonical.String() != v.IP {
		h.fail(w, r, http.StatusBadRequest)
		return
	}
	e, err := h.store.Add(r.Context(), v.IP, "", timePtr(v.Exp), requestID(r, v.IP, strconv.FormatInt(v.Exp, 10)))
	if err != nil {
		h.fail(w, r, statusFor(err))
		return
	}
	h.json(w, adminResponse{IP: e.Prefix, Exp: expirySeconds(e.ExpiresAtUnixMs)})
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request, prefix string) {
	if !h.principal(w, r, true, apikey.Update) {
		return
	}
	v, ok := decodeAdmin(w, r)
	if !ok || v.IP == "" || v.Exp <= h.now().Unix() {
		h.fail(w, r, http.StatusBadRequest)
		return
	}
	if p, err := CanonicalPrefix(prefix); err != nil || p.String() != v.IP {
		h.fail(w, r, http.StatusBadRequest)
		return
	}
	e, err := h.store.Update(r.Context(), prefix, "", timePtr(v.Exp), requestID(r, prefix, strconv.FormatInt(v.Exp, 10)))
	if err != nil {
		h.fail(w, r, statusFor(err))
		return
	}
	h.json(w, adminResponse{IP: e.Prefix, Exp: expirySeconds(e.ExpiresAtUnixMs)})
}

func (h *AdminHandler) delete(w http.ResponseWriter, r *http.Request, prefix string) {
	if !h.principal(w, r, true, apikey.Delete) {
		return
	}
	if _, err := CanonicalPrefix(prefix); err != nil {
		h.fail(w, r, http.StatusBadRequest)
		return
	}
	if err := h.store.Delete(r.Context(), prefix, requestID(r, prefix)); err != nil {
		h.fail(w, r, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func decodeAdmin(w http.ResponseWriter, r *http.Request) (adminRequest, bool) {
	if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" {
		return adminRequest{}, false
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	if err != nil || rejectDuplicateJSON(b) != nil {
		return adminRequest{}, false
	}
	var v adminRequest
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(&struct{}{}) == nil || v.IP == "" || v.Exp <= 0 {
		return adminRequest{}, false
	}
	return v, true
}

func rejectDuplicateJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := walkJSON(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing json")
	}
	return nil
}

func walkJSON(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := k.(string)
				if !ok || seen[name] {
					return errors.New("duplicate field")
				}
				seen[name] = true
				if err := walkJSON(d); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("object")
			}
		case '[':
			for d.More() {
				if err := walkJSON(d); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("array")
			}
		default:
			return errors.New("delimiter")
		}
	}
	return nil
}

func (h *AdminHandler) headers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	if id := requestID(r); id != "" {
		w.Header().Set("X-Request-ID", id)
	}
}
func (h *AdminHandler) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (h *AdminHandler) fail(w http.ResponseWriter, r *http.Request, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"request denied"}`)
}
func statusFor(err error) int {
	if errors.Is(err, ErrInvalid) {
		return http.StatusBadRequest
	}
	if errors.Is(err, ErrNotFound) {
		return http.StatusNotFound
	}
	return http.StatusServiceUnavailable
}
func timePtr(sec int64) *time.Time { t := time.Unix(sec, 0).UTC(); return &t }
func expirySeconds(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v / 1000
}
func requestID(r *http.Request, mutation ...string) string {
	if r == nil || r.URL == nil {
		return ""
	}
	v := r.Header.Get("X-Request-ID")
	if len(mutation) == 0 && validRequestID(v) {
		return v
	}
	parts := append([]string{r.Method, r.URL.Path, r.URL.RawQuery}, mutation...)
	if validRequestID(v) {
		parts = append(parts, v)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func validRequestID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.ContainsRune("-_.:", c)) {
			return false
		}
	}
	return true
}
