package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
)

func (h *Handler) Clients(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if h.clients == nil {
		h.unavailable(w)
		return
	}
	switch r.Method {
	case http.MethodGet:
		actor, key, ok := h.principalFor(w, r, false, "Clients", apikey.Read, false)
		if !ok {
			return
		}
		v, err := h.clients.ListWithGuard(r.Context(), h.clientAuthority(r, actor, key, "Clients", apikey.Read))
		if err != nil {
			h.writeClientError(w, err)
			return
		}
		h.writeClients(w, v)
	case http.MethodPost:
		actor, key, ok := h.principalFor(w, r, true, "Clients", apikey.Create, false)
		if !ok {
			return
		}
		in, err := decodeManagedClient(r)
		if err != nil {
			h.badRequest(w)
			return
		}
		c, err := h.clients.CreateWithGuard(r.Context(), in, h.clientAuthority(r, actor, key, "Clients", apikey.Create))
		if err != nil {
			h.writeClientError(w, err)
			return
		}
		h.writeClient(w, c, http.StatusCreated)
	default:
		w.Header().Set("Allow", "GET, POST")
		h.methodNotAllowed(w)
	}
}

func (h *Handler) Client(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if h.clients == nil {
		h.unavailable(w)
		return
	}
	right := apikey.Read
	if r.Method == http.MethodPut {
		right = apikey.Update
	} else if r.Method == http.MethodDelete {
		right = apikey.Delete
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, PUT, DELETE")
		h.methodNotAllowed(w)
		return
	}
	actor, key, ok := h.principalFor(w, r, r.Method != http.MethodGet, "Clients", right, false)
	if !ok {
		return
	}
	auth := h.clientAuthority(r, actor, key, "Clients", right)
	if r.Method == http.MethodGet {
		c, err := h.clients.GetWithGuard(r.Context(), r.PathValue("id"), auth)
		if err != nil {
			h.writeClientError(w, err)
			return
		}
		h.writeClient(w, c, http.StatusOK)
		return
	}
	if r.Method == http.MethodDelete {
		if !emptyBody(r) {
			h.badRequest(w)
			return
		}
		rev, err := clientRevision(r)
		if err != nil {
			h.error(w, http.StatusPreconditionRequired, "If-Match revision required")
			return
		}
		if err = h.clients.DeleteWithGuard(r.Context(), r.PathValue("id"), rev, auth); err != nil {
			h.writeClientError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rev, err := clientRevision(r)
	if err != nil {
		h.error(w, http.StatusPreconditionRequired, "If-Match revision required")
		return
	}
	in, err := decodeManagedUpdate(r)
	if err != nil {
		h.badRequest(w)
		return
	}
	c, err := h.clients.UpdateWithGuard(r.Context(), r.PathValue("id"), rev, in, auth)
	if err != nil {
		h.writeClientError(w, err)
		return
	}
	h.writeClient(w, c, http.StatusOK)
}

func (h *Handler) ClientSecret(w http.ResponseWriter, r *http.Request) { h.clientSecret(w, r, false) }
func (h *Handler) RotateClientSecret(w http.ResponseWriter, r *http.Request) {
	h.clientSecret(w, r, true)
}
func (h *Handler) clientSecret(w http.ResponseWriter, r *http.Request, rotate bool) {
	h.securityHeaders(w)
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if h.clients == nil {
		h.unavailable(w)
		return
	}
	want, right := http.MethodPost, apikey.Read
	if rotate {
		want, right = http.MethodPut, apikey.Update
	}
	if r.Method != want {
		w.Header().Set("Allow", want)
		h.methodNotAllowed(w)
		return
	}
	actor, key, ok := h.principalFor(w, r, true, "Secrets", right, false)
	if !ok {
		return
	}
	if !emptyBody(r) {
		h.badRequest(w)
		return
	}
	auth := h.clientAuthority(r, actor, key, "Secrets", right)
	if !rotate {
		secret, err := h.clients.ReadSecretWithGuard(r.Context(), r.PathValue("id"), auth)
		if err != nil {
			h.writeClientError(w, err)
			return
		}
		h.writeSecret(w, secret, "")
		return
	}
	rev, err := clientRevision(r)
	if err != nil {
		h.error(w, http.StatusPreconditionRequired, "If-Match revision required")
		return
	}
	c, err := h.clients.RotateSecretWithGuard(r.Context(), r.PathValue("id"), rev, auth)
	if err != nil {
		h.writeClientError(w, err)
		return
	}
	secret, err := h.clients.ReadSecretWithRevisionWithGuard(r.Context(), r.PathValue("id"), c.Revision, auth)
	if err != nil {
		h.writeClientError(w, err)
		return
	}
	h.writeSecret(w, secret, strconv.FormatInt(c.Revision, 10))
}

func decodeManagedClient(r *http.Request) (clients.NewRequest, error) {
	var v clients.NewRequest
	return v, decodeJSON(r, &v, map[string]bool{"backchannel_logout_uri": true, "restrict_group_prefix": true, "id": true, "name": true, "confidential": true, "redirect_uris": true, "scopes": true, "default_scopes": true, "enabled_flows": true, "audience": true, "default_aud": true, "force_mfa": true}, []string{"id", "confidential", "redirect_uris"}, map[string]bool{"name": true, "backchannel_logout_uri": true, "restrict_group_prefix": true})
}
func decodeManagedUpdate(r *http.Request) (clients.UpdateRequest, error) {
	var v clients.UpdateRequest
	return v, decodeJSON(r, &v, map[string]bool{"backchannel_logout_uri": true, "restrict_group_prefix": true, "name": true, "confidential": true, "redirect_uris": true, "enabled": true, "scopes": true, "default_scopes": true, "enabled_flows": true, "audience": true, "default_aud": true, "force_mfa": true}, []string{"confidential", "redirect_uris", "enabled", "scopes", "default_scopes", "enabled_flows"}, map[string]bool{"name": true, "backchannel_logout_uri": true, "restrict_group_prefix": true})
}
func decodeJSON(r *http.Request, v any, fields map[string]bool, required []string, nullable map[string]bool) error {
	if r.Body == nil || len(r.Header.Values("Content-Type")) != 1 {
		return errors.New("body")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return errors.New("content type")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, adminRequestLimit+1))
	if err != nil || len(body) == 0 || int64(len(body)) > adminRequestLimit || !utf8.Valid(body) || rejectDuplicateJSONFields(body) != nil {
		return errors.New("json")
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &raw) != nil || raw == nil || bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return errors.New("json")
	}
	for _, key := range required {
		if _, ok := raw[key]; !ok {
			return errors.New("json")
		}
	}
	for key, value := range raw {
		if !fields[key] || (bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !nullable[key]) {
			return errors.New("json")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func emptyBody(r *http.Request) bool {
	if r.Body == nil {
		return true
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 1))
	return err == nil && len(b) == 0
}
func clientRevision(r *http.Request) (int64, error) {
	values := r.Header.Values("If-Match")
	if len(values) != 1 {
		return 0, errors.New("revision")
	}
	v := values[0]
	if len(v) < 3 || v[0] != '"' || v[len(v)-1] != '"' {
		return 0, errors.New("revision")
	}
	n, err := strconv.ParseInt(v[1:len(v)-1], 10, 64)
	if err != nil || n <= 0 {
		return 0, errors.New("revision")
	}
	return n, nil
}
func (h *Handler) clientAuthority(r *http.Request, actor string, key *apikey.Principal, group string, right apikey.Right) func() (string, []any) {
	if key != nil {
		return func() (string, []any) { return h.store.apiKeys.AuthorizationGuard(*key, group, right) }
	}
	return func() (string, []any) {
		session, args := h.userUpdateSessionGuard(r, actor)
		if session == "0" {
			return "0", nil
		}
		return session + " AND " + adminGuard(), append(args, actor)
	}
}
func (h *Handler) writeClients(w http.ResponseWriter, v []clients.Client) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (h *Handler) writeClient(w http.ResponseWriter, c clients.Client, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", `"`+strconv.FormatInt(c.Revision, 10)+`"`)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(c)
}
func (h *Handler) writeSecret(w http.ResponseWriter, secret, revision string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if revision != "" {
		w.Header().Set("ETag", `"`+revision+`"`)
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"secret": secret})
}
func (h *Handler) writeClientError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, clients.ErrUnauthorized):
		h.genericUnauthorized(w)
	case errors.Is(err, clients.ErrConflict):
		h.error(w, http.StatusConflict, "Conflict")
	case errors.Is(err, clients.ErrInvalid), errors.Is(err, clients.ErrReserved):
		h.badRequest(w)
	case errors.Is(err, clients.ErrNotFound):
		h.notFound(w)
	default:
		h.unavailable(w)
	}
}
