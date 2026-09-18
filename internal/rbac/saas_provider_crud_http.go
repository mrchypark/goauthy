package rbac

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/saas"
)

func (h *Handler) BindSaaSProviderStore(store *saas.ProviderStore) error {
	if h == nil || store == nil {
		return errors.New("SaaS provider store required")
	}
	h.saasProviderStore = store
	return nil
}

func (h *Handler) BindProviderResourceAuthorizer(authorizer func(*http.Request, string) (string, func() (string, []any), error)) error {
	if h == nil || authorizer == nil {
		return errors.New("provider resource authorizer required")
	}
	h.providerResourceAuthorizer = authorizer
	return nil
}

func (h *Handler) providerBoundary(w http.ResponseWriter, r *http.Request) (func() (string, []any), bool) {
	h.securityHeaders(w)
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return nil, false
	}
	if apikey.HasAuthorization(r) {
		return h.providerBearerBoundary(w, r)
	}
	if r.Method != http.MethodGet && len(r.Header.Values("X-CSRF-Token")) != 1 {
		h.genericUnauthorized(w)
		return nil, false
	}
	actor, ok := h.actor(w, r, r.Method != http.MethodGet)
	if !ok {
		return nil, false
	}
	if h.saasProviderStore == nil {
		h.unavailable(w)
		return nil, false
	}
	return h.clientAuthority(r, actor, nil, "", apikey.Read), true
}

func (h *Handler) providerBearerBoundary(w http.ResponseWriter, r *http.Request) (func() (string, []any), bool) {
	if h.saasProviderStore == nil || h.providerResourceAuthorizer == nil || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("Cookie")) != 0 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		h.genericUnauthorized(w)
		return nil, false
	}
	scope := "goauthy.providers.read"
	if r.Method != http.MethodGet {
		scope = "goauthy.providers.write"
	}
	subject, authority, err := h.providerResourceAuthorizer(r, scope)
	if err != nil || subject == "" || authority == nil {
		h.genericUnauthorized(w)
		return nil, false
	}
	admin, err := h.store.IsAdmin(r.Context(), subject)
	if err != nil {
		h.unavailable(w)
		return nil, false
	}
	if !admin {
		h.genericUnauthorized(w)
		return nil, false
	}
	return func() (string, []any) {
		guard, args := authority()
		if strings.TrimSpace(guard) == "" {
			return "0", nil
		}
		return "(" + guard + ") AND " + adminGuard(), append(append([]any(nil), args...), subject)
	}, true
}

func (h *Handler) managedSaaSProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		h.methodNotAllowed(w)
		return
	}
	guard, ok := h.providerBoundary(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		providers, err := h.saasProviderStore.List(r.Context(), guard)
		if err != nil {
			h.providerResponse(w, nil, 0, 0, err)
			return
		}
		items := make([]any, 0, len(providers)+len(h.saasProviders))
		for _, p := range h.saasProviders {
			items = append(items, p)
		}
		for _, p := range providers {
			items = append(items, p)
		}
		h.providerResponse(w, items, 0, http.StatusOK, nil)
		return
	}
	in, err := decodeProvider(r, true)
	if err != nil {
		h.badRequest(w)
		return
	}
	if h.staticProvider(in.ID) {
		h.providerResponse(w, nil, 0, 0, saas.ErrProviderConflict)
		return
	}
	item, err := h.saasProviderStore.Create(r.Context(), in, guard)
	h.providerResponse(w, item, item.Revision, http.StatusCreated, err)
}

func (h *Handler) SaaSProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, PUT, DELETE")
		h.methodNotAllowed(w)
		return
	}
	guard, ok := h.providerBoundary(w, r)
	if !ok {
		return
	}
	id := r.PathValue("provider_id")
	if h.staticProvider(id) {
		h.providerResponse(w, nil, 0, 0, saas.ErrProviderConflict)
		return
	}
	if r.Method == http.MethodGet {
		item, err := h.saasProviderStore.Get(r.Context(), id, guard)
		h.providerResponse(w, item, item.Revision, http.StatusOK, err)
		return
	}
	revision, err := clientRevision(r)
	if err != nil {
		h.error(w, http.StatusPreconditionRequired, "If-Match revision required")
		return
	}
	if r.Method == http.MethodDelete {
		if !emptyBody(r) {
			h.badRequest(w)
			return
		}
		err = h.saasProviderStore.Delete(r.Context(), id, revision, guard)
		h.providerResponse(w, nil, 0, http.StatusNoContent, err)
		return
	}
	in, err := decodeProvider(r, false)
	if err != nil {
		h.badRequest(w)
		return
	}
	in.ID = id
	item, err := h.saasProviderStore.Update(r.Context(), id, revision, in, guard)
	h.providerResponse(w, item, item.Revision, http.StatusOK, err)
}

func (h *Handler) staticProvider(id string) bool {
	for _, p := range h.saasProviders {
		if p.ID == id {
			return true
		}
	}
	return false
}

func decodeProvider(r *http.Request, create bool) (saas.ProviderInput, error) {
	var in saas.ProviderInput
	fields := map[string]bool{"name": true, "kind": true, "enabled": true, "client_id": true, "client_secret": true, "callback_uri": true, "auth_endpoint": true, "token_endpoint": true, "scopes": true, "auth_style": true, "identity_endpoint": true, "subject_field": true, "connector": true}
	required := []string{"name", "kind", "enabled"}
	if create {
		fields["id"] = true
		required = append(required, "id")
	}
	err := decodeJSON(r, &in, fields, required, nil)
	return in, err
}

func (h *Handler) providerResponse(w http.ResponseWriter, value any, revision int64, status int, err error) {
	if err != nil {
		switch {
		case errors.Is(err, saas.ErrProviderInvalid):
			h.badRequest(w)
		case errors.Is(err, saas.ErrProviderUnauthorized):
			h.genericUnauthorized(w)
		case errors.Is(err, saas.ErrProviderNotFound):
			h.error(w, http.StatusNotFound, "provider not found")
		case errors.Is(err, saas.ErrProviderConflict), errors.Is(err, saas.ErrProviderInUse):
			h.error(w, http.StatusConflict, "provider revision or references conflict")
		default:
			h.unavailable(w)
		}
		return
	}
	if revision > 0 {
		w.Header().Set("ETag", `"`+strconv.FormatInt(revision, 10)+`"`)
	}
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
