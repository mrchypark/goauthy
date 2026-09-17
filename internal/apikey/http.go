package apikey

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/mrchypark/goauthy/internal/audit"
)

// Handler serves /auth/v1/api_keys. BrowserAdmin must validate the existing
// browser session and CSRF token for mutations. API keys cannot manage keys;
// their self-test is the only API-key operation on this surface.
type Handler struct {
	store        *Store
	browserAdmin func(http.ResponseWriter, *http.Request, bool) bool
}

func NewHandler(store *Store, browserAdmin func(http.ResponseWriter, *http.Request, bool) bool) *Handler {
	return &Handler{store: store, browserAdmin: browserAdmin}
}
func (h *Handler) Keys(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	switch r.Method {
	case http.MethodGet:
		p, ok, wrote := h.principal(w, r, false, Read)
		if !ok {
			if !wrote {
				h.deny(w, r)
			}
			return
		}
		v, e := h.store.List(r.Context(), p)
		if e != nil {
			h.error(w, e)
			return
		}
		h.json(w, map[string]any{"keys": v})
	case http.MethodPost:
		p, ok, wrote := h.principal(w, r, true, Create)
		if !ok {
			if !wrote {
				h.deny(w, r)
			}
			return
		}
		var v Request
		if !decode(w, r, &v) {
			return
		}
		_, secret, e := h.store.Create(r.Context(), p, v)
		if e != nil {
			h.error(w, e)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(secret))
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
func (h *Handler) Key(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	name := r.PathValue("name")
	if r.Method == http.MethodPut {
		p, ok, wrote := h.principal(w, r, true, Update)
		if !ok {
			if !wrote {
				h.deny(w, r)
			}
			return
		}
		var v Request
		if !decode(w, r, &v) {
			return
		}
		k, e := h.store.Update(r.Context(), p, name, v)
		if e != nil {
			h.error(w, e)
			return
		}
		h.json(w, k)
		return
	}
	if r.Method == http.MethodDelete {
		p, ok, wrote := h.principal(w, r, true, Delete)
		if !ok {
			if !wrote {
				h.deny(w, r)
			}
			return
		}
		if e := h.store.Delete(r.Context(), p, name); e != nil {
			h.error(w, e)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Allow", "PUT, DELETE")
	w.WriteHeader(http.StatusMethodNotAllowed)
}
func (h *Handler) Secret(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "PUT")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	p, ok, wrote := h.principal(w, r, true, Update)
	if !ok {
		if !wrote {
			h.deny(w, r)
		}
		return
	}
	v, e := h.store.Rotate(r.Context(), p, r.PathValue("name"))
	if e != nil {
		h.error(w, e)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(v))
}
func (h *Handler) Test(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	authorization, ok := Authorization(r)
	if !ok {
		h.deny(w, r)
		return
	}
	p, e := h.store.Authenticate(r.Context(), authorization)
	if e != nil || p.Name != r.PathValue("name") {
		h.deny(w, r)
		return
	}
	k, e := h.store.Get(r.Context(), p)
	if e != nil {
		h.error(w, e)
		return
	}
	h.json(w, k)
}

// Events serves the durable audit slice to an explicit Events:read API key.
// It deliberately does not use browserAdmin or any bearer-token fallback.
func (h *Handler) Events(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	limit, cursor, err := auditQuery(r.URL)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if h == nil || h.store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	authorization, ok := Authorization(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	principal, err := h.store.Authenticate(r.Context(), authorization)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	events, next, err := h.store.ListAuditEvents(r.Context(), principal, cursor, limit)
	if errors.Is(err, ErrForbidden) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	response := auditEventsResponse{Events: make([]auditEventResponse, 0, len(events))}
	for _, event := range events {
		response.Events = append(response.Events, auditEventResponse{ID: event.ID, OccurredAtUnixMilli: event.OccurredAtUnixMilli, Type: event.Type, Action: event.Action, Outcome: event.Outcome, ActorKind: event.ActorKind, ActorHash: event.ActorHash, TargetHash: event.TargetHash})
	}
	if next != nil {
		response.NextCursor = &auditCursorResponse{Sequence: next.Sequence}
	}
	h.json(w, response)
}

type auditEventResponse struct {
	ID                  string `json:"id"`
	OccurredAtUnixMilli int64  `json:"occurred_at_unix_ms"`
	Type                string `json:"type"`
	Action              string `json:"action"`
	Outcome             string `json:"outcome"`
	ActorKind           string `json:"actor_kind"`
	ActorHash           string `json:"actor_hash,omitempty"`
	TargetHash          string `json:"target_hash"`
}

type auditCursorResponse struct {
	Sequence int64 `json:"sequence"`
}

type auditEventsResponse struct {
	Events     []auditEventResponse `json:"events"`
	NextCursor *auditCursorResponse `json:"next_cursor,omitempty"`
}

func auditQuery(u *url.URL) (int, *audit.Cursor, error) {
	if u == nil {
		return 0, nil, errors.New("query")
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return 0, nil, err
	}
	for name, value := range values {
		if (name != "limit" && name != "sequence") || len(value) != 1 {
			return 0, nil, errors.New("query")
		}
	}
	limit := 32
	if raw, exists := values["limit"]; exists {
		parsed, err := strconv.Atoi(raw[0])
		if err != nil || strconv.Itoa(parsed) != raw[0] || parsed < 1 || parsed > 32 {
			return 0, nil, errors.New("limit")
		}
		limit = parsed
	}
	sequence, hasSequence := values["sequence"]
	if !hasSequence {
		return limit, nil, nil
	}
	parsed, err := strconv.ParseInt(sequence[0], 10, 64)
	if err != nil || parsed < 1 || strconv.FormatInt(parsed, 10) != sequence[0] {
		return 0, nil, errors.New("cursor")
	}
	return limit, &audit.Cursor{Sequence: parsed}, nil
}
func (h *Handler) principal(w http.ResponseWriter, r *http.Request, mutation bool, right Right) (*Principal, bool, bool) {
	if HasAuthorization(r) {
		// Rauthy does not allow API keys to manage API keys. Keep this
		// boundary closed even when the presented key has ApiKeys rights.
		return nil, false, false
	}
	if h.browserAdmin != nil {
		if h.browserAdmin(w, r, mutation) {
			return nil, true, false
		}
		return nil, false, true
	}
	return nil, false, false
}
func decode(w http.ResponseWriter, r *http.Request, v *Request) bool {
	if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil || rejectDuplicateFields(body) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) == nil {
		w.WriteHeader(http.StatusBadRequest)
		return false
	}
	return true
}
func rejectDuplicateFields(body []byte) error {
	d := json.NewDecoder(bytes.NewReader(body))
	if err := walkJSON(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing json")
	}
	return nil
}

func walkJSON(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("key")
			}
			if _, duplicate := seen[name]; duplicate {
				return errors.New("duplicate field")
			}
			seen[name] = struct{}{}
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
	return nil
}
func (h *Handler) headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
func (h *Handler) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (h *Handler) deny(w http.ResponseWriter, r *http.Request) {
	if authorization, ok := Authorization(r); ok {
		if _, err := h.store.Authenticate(r.Context(), authorization); err == nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
}

// HasAuthorization reports any Authorization attempt, including malformed or
// repeated headers. Such attempts must never inherit browser cookie authority.
func HasAuthorization(r *http.Request) bool { return len(r.Header.Values("Authorization")) != 0 }

// Authorization returns the sole non-empty Authorization value. Multiple
// header fields are ambiguous and are rejected at every API-key boundary.
func Authorization(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	return r.Header.Get("Authorization"), len(values) == 1 && values[0] != ""
}
func (h *Handler) error(w http.ResponseWriter, e error) {
	if e == ErrForbidden {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if e == ErrNotFound {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusBadRequest)
}
