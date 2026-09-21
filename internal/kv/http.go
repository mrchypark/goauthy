package kv

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const bodyLimit int64 = 64 << 10

type Handler struct {
	store *Store
	admin func(http.ResponseWriter, *http.Request, bool) bool
}

func NewHandler(s *Store, a func(http.ResponseWriter, *http.Request, bool) bool) *Handler {
	return &Handler{s, a}
}
func (h *Handler) Routes(m *http.ServeMux) {
	p := "/auth/v1/kv"
	// Keep trust-boundary checks identical on every KV endpoint, including
	// errors and empty mutation responses. ServeMux dispatch remains stdlib.
	mount := func(method, path string, body, query bool, fn http.HandlerFunc) {
		m.HandleFunc(method+" "+p+path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cache-Control", "no-store")
			if r.Method != method {
				allow(w, method)
				return
			}
			if h == nil || h.store == nil {
				errw(w, ErrCorrupt)
				return
			}
			if !query && (r.URL.RawQuery != "" || r.URL.ForceQuery) {
				errw(w, ErrBadRequest)
				return
			}
			if !body && r.Body != nil {
				b, err := io.ReadAll(io.LimitReader(r.Body, 1))
				if err != nil || len(b) != 0 {
					errw(w, ErrBadRequest)
					return
				}
			}
			fn(w, r)
		})
	}
	mount("GET", "/ns", false, true, h.namespaces)
	mount("POST", "/ns", true, false, h.namespaces)
	mount("PUT", "/ns/{ns}", true, false, h.namespace)
	mount("DELETE", "/ns/{ns}", false, false, h.namespace)
	mount("GET", "/ns/{ns}/access", false, true, h.accesses)
	mount("POST", "/ns/{ns}/access", true, false, h.accesses)
	mount("PUT", "/ns/{ns}/access/{id}", true, false, h.access)
	mount("DELETE", "/ns/{ns}/access/{id}", false, false, h.access)
	mount("POST", "/ns/{ns}/access/{id}/secret", false, false, h.rotate)
	mount("GET", "/ns/{ns}/values", false, true, h.adminValues)
	mount("POST", "/ns/{ns}/values", true, false, h.adminValue)
	mount("PUT", "/ns/{ns}/values", true, false, h.adminValue)
	mount("DELETE", "/ns/{ns}/values/{key}", false, false, h.adminValue)
	mount("GET", "/pub/{ns}/{key}", false, false, h.public)
	mount("GET", "/keys", false, true, h.keys)
	mount("PUT", "/keys", true, false, h.values)
	mount("GET", "/keys/{key}", false, false, h.key)
	mount("DELETE", "/keys/{key}", false, false, h.key)
	mount("GET", "/values", false, true, h.values)
	mount("GET", "/test", false, false, h.test)
}
func (h *Handler) adminOK(w http.ResponseWriter, r *http.Request, mut bool) bool {
	if len(r.Header.Values("Authorization")) > 0 {
		w.WriteHeader(401)
		return false
	}
	if h.admin == nil || h.store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return false
	}
	return h.admin(w, r, mut)
}
func clean(r *http.Request) *http.Request {
	q := r.Clone(r.Context())
	u := *r.URL
	u.RawQuery = ""
	q.URL = &u
	return q
}
func decode(r *http.Request, v any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return ErrBadRequest
	}
	b, e := io.ReadAll(http.MaxBytesReader(nil, r.Body, bodyLimit))
	if e != nil {
		return ErrBadRequest
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(v); e != nil || d.Decode(&struct{}{}) != io.EOF {
		return ErrBadRequest
	}
	return nil
}
func jsonw(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// jsonPage writes a list response. A listing that continues on a following page
// stays 200 and carries the token that resumes exactly after this page; 206
// would require a Content-Range that a keyset cursor does not produce.
func jsonPage(w http.ResponseWriter, v any, next string) {
	if next != "" {
		w.Header().Set("X-Continuation-Token", next)
	}
	jsonw(w, v)
}
func errw(w http.ResponseWriter, e error) {
	if e == nil {
		w.WriteHeader(200)
		return
	}
	c := 503
	switch {
	case errors.Is(e, ErrUnauthorized):
		c = 401
	case errors.Is(e, ErrForbidden):
		c = 403
	case errors.Is(e, ErrNotFound):
		c = 404
	case errors.Is(e, ErrConflict):
		c = 409
	case errors.Is(e, ErrCorrupt):
		c = 503
	case errors.Is(e, ErrBadRequest):
		c = 400
	}
	w.WriteHeader(c)
}
func allow(w http.ResponseWriter, a string) { w.Header().Set("Allow", a); w.WriteHeader(405) }
func q(r *http.Request) (int, string, string, error) {
	vals, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, "", "", ErrBadRequest
	}
	for k := range vals {
		if k != "limit" && k != "search" && k != "cursor" {
			return 0, "", "", ErrBadRequest
		}
	}
	if len(vals["limit"]) > 1 || len(vals["search"]) > 1 || len(vals["cursor"]) > 1 {
		return 0, "", "", ErrBadRequest
	}
	n := 0
	if x := vals.Get("limit"); x != "" {
		var e error
		n, e = strconv.Atoi(x)
		if e != nil || n < 0 || n > 1000 {
			return 0, "", "", ErrBadRequest
		}
	}
	s := vals.Get("search")
	if len(s) > 64 {
		return 0, "", "", ErrBadRequest
	}
	return n, s, vals.Get("cursor"), nil
}
func (h *Handler) namespaces(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		n, s, cursor, e := q(r)
		if e != nil {
			errw(w, e)
			return
		}
		// GA80-KV-001: this listing has no search filter, so a nonempty term is
		// rejected instead of answered with an unfiltered page.
		if s != "" {
			errw(w, ErrBadRequest)
			return
		}
		if !h.adminOK(w, clean(r), false) {
			return
		}
		v, next, e := h.store.ListNamespaces(r.Context(), n, cursor)
		if e != nil {
			errw(w, e)
			return
		}
		jsonPage(w, v, next)
		return
	}
	if r.Method != "POST" {
		allow(w, "GET, POST")
		return
	}
	if !h.adminOK(w, r, true) {
		return
	}
	var p struct {
		Name   string `json:"name"`
		Public *bool  `json:"public"`
	}
	if decode(r, &p) != nil {
		errw(w, ErrBadRequest)
		return
	}
	public := false
	if p.Public != nil {
		public = *p.Public
	}
	errw(w, h.store.PutNamespace(r.Context(), "", p.Name, public, true))
}
func (h *Handler) namespace(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(w, r, true) {
		return
	}
	n := r.PathValue("ns")
	if r.Method == "DELETE" {
		errw(w, h.store.DeleteNamespace(r.Context(), n))
		return
	}
	if r.Method != "PUT" {
		allow(w, "PUT, DELETE")
		return
	}
	var p struct {
		Name   string `json:"name"`
		Public *bool  `json:"public"`
	}
	if decode(r, &p) != nil {
		errw(w, ErrBadRequest)
		return
	}
	public := false
	if p.Public != nil {
		public = *p.Public
	}
	errw(w, h.store.PutNamespace(r.Context(), n, p.Name, public, false))
}
func (h *Handler) accesses(w http.ResponseWriter, r *http.Request) {
	n := r.PathValue("ns")
	if r.Method == "GET" {
		n2, s, cursor, e := q(r)
		if e != nil {
			errw(w, e)
			return
		}
		// GA80-KV-001: this listing has no search filter, so a nonempty term is
		// rejected instead of answered with an unfiltered page.
		if s != "" {
			errw(w, ErrBadRequest)
			return
		}
		// The admin gate rejects any query string, so the validated listing
		// parameters are stripped before the session check.
		if !h.adminOK(w, clean(r), false) {
			return
		}
		v, next, e := h.store.Accesses(r.Context(), n, n2, cursor)
		if e != nil {
			errw(w, e)
			return
		}
		jsonPage(w, v, next)
		return
	}
	if !h.adminOK(w, r, true) {
		return
	}
	if r.Method != "POST" {
		allow(w, "GET, POST")
		return
	}
	var p struct {
		Enabled *bool   `json:"enabled"`
		Name    *string `json:"name"`
	}
	if decode(r, &p) != nil || p.Enabled == nil {
		errw(w, ErrBadRequest)
		return
	}
	v, e := h.store.CreateAccess(r.Context(), n, *p.Enabled, p.Name)
	if e != nil {
		errw(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(v)
}
func (h *Handler) access(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(w, r, true) {
		return
	}
	n, id := r.PathValue("ns"), r.PathValue("id")
	if r.Method == "DELETE" {
		errw(w, h.store.DeleteAccess(r.Context(), n, id))
		return
	}
	if r.Method != "PUT" {
		allow(w, "PUT, DELETE")
		return
	}
	var p struct {
		Enabled *bool   `json:"enabled"`
		Name    *string `json:"name"`
	}
	if decode(r, &p) != nil || p.Enabled == nil {
		errw(w, ErrBadRequest)
		return
	}
	errw(w, h.store.UpdateAccess(r.Context(), n, id, *p.Enabled, p.Name))
}
func (h *Handler) rotate(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(w, r, true) {
		return
	}
	v, e := h.store.RotateAccess(r.Context(), r.PathValue("ns"), r.PathValue("id"))
	if e != nil {
		errw(w, e)
		return
	}
	jsonw(w, v)
}
func (h *Handler) adminValues(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		allow(w, "GET")
		return
	}
	n, s, cursor, e := q(r)
	if e != nil {
		errw(w, e)
		return
	}
	if !h.adminOK(w, clean(r), false) {
		return
	}
	v, next, e := h.store.Values(r.Context(), Access{Namespace: r.PathValue("ns")}, n, s, cursor)
	if e != nil {
		errw(w, e)
		return
	}
	jsonPage(w, v, next)
}
func (h *Handler) adminValue(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(w, r, r.Method != "GET") {
		return
	}
	a := Access{Namespace: r.PathValue("ns")}
	switch r.Method {
	case "DELETE":
		errw(w, h.store.Delete(r.Context(), a, r.PathValue("key")))
	case "POST", "PUT":
		var v Value
		if decode(r, &v) != nil {
			errw(w, ErrBadRequest)
			return
		}
		errw(w, h.store.Set(r.Context(), a, v))
	default:
		allow(w, "POST, PUT, DELETE")
	}
}
func (h *Handler) public(w http.ResponseWriter, r *http.Request) {
	v, e := h.store.PublicGet(r.Context(), r.PathValue("ns"), r.PathValue("key"))
	if e != nil {
		errw(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(v)
}
func (h *Handler) bearer(r *http.Request) (Access, error) {
	if len(r.Header.Values("Authorization")) != 1 {
		return Access{}, ErrUnauthorized
	}
	return h.store.Authenticate(r.Context(), r.Header.Get("Authorization"))
}
func (h *Handler) keys(w http.ResponseWriter, r *http.Request) {
	a, e := h.bearer(r)
	if e != nil {
		errw(w, e)
		return
	}
	n, s, cursor, e := q(r)
	if e != nil {
		errw(w, e)
		return
	}
	v, next, e := h.store.Keys(r.Context(), a, n, s, cursor)
	if e != nil {
		errw(w, e)
		return
	}
	jsonPage(w, v, next)
}
func (h *Handler) values(w http.ResponseWriter, r *http.Request) {
	a, e := h.bearer(r)
	if e != nil {
		errw(w, e)
		return
	}
	if r.Method == "PUT" {
		var v Value
		if decode(r, &v) != nil {
			errw(w, ErrBadRequest)
			return
		}
		errw(w, h.store.Set(r.Context(), a, v))
		return
	}
	if r.Method != "GET" {
		allow(w, "GET, PUT")
		return
	}
	n, s, cursor, e := q(r)
	if e != nil {
		errw(w, e)
		return
	}
	v, next, e := h.store.Values(r.Context(), a, n, s, cursor)
	if e != nil {
		errw(w, e)
		return
	}
	jsonPage(w, v, next)
}
func (h *Handler) key(w http.ResponseWriter, r *http.Request) {
	a, e := h.bearer(r)
	if e != nil {
		errw(w, e)
		return
	}
	switch r.Method {
	case "GET":
		v, e := h.store.Get(r.Context(), a, r.PathValue("key"))
		if e != nil {
			errw(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(v)
	case "DELETE":
		errw(w, h.store.Delete(r.Context(), a, r.PathValue("key")))
	default:
		allow(w, "GET, DELETE")
	}
}
func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	a, e := h.bearer(r)
	if e != nil {
		errw(w, e)
		return
	}
	jsonw(w, map[string]any{"id": a.ID, "ns": a.Namespace, "name": a.Name})
}
