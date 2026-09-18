package rbac

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/authcollection"
	"github.com/mrchypark/goauthy/internal/browser"
)

func (h *Handler) BindAuthCollections(store *authcollection.Store) error {
	if h == nil || store == nil {
		return errors.New("auth collection store required")
	}
	h.authCollections = store
	return nil
}

func (h *Handler) authCollectionBoundary(w http.ResponseWriter, r *http.Request) bool {
	h.securityHeaders(w)
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return false
	}
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) && len(r.Header.Values("X-CSRF-Token")) != 1 {
		h.genericUnauthorized(w)
		return false
	}
	if h.authCollections == nil {
		h.unavailable(w)
		return false
	}
	return true
}

// Definitions are administrator-owned. Existing OAuth-client API keys do not
// implicitly gain access to this separate product boundary.
func (h *Handler) AuthCollections(w http.ResponseWriter, r *http.Request) {
	if !h.authCollectionBoundary(w, r) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		h.methodNotAllowed(w)
		return
	}
	actor, ok := h.actor(w, r, r.Method == http.MethodPost)
	if !ok {
		return
	}
	guard := h.clientAuthority(r, actor, nil, "", apikey.Read)
	if r.Method == http.MethodGet {
		items, err := h.authCollections.ListDefinitions(r.Context(), guard)
		h.authCollectionResponse(w, items, 0, http.StatusOK, err)
		return
	}
	in, err := decodeAuthCollection(r, true)
	if err != nil {
		h.badRequest(w)
		return
	}
	guard, ok = h.collectionProviderAuthority(r, in.AuthMethod, in.ProviderIDs, guard)
	if !ok {
		h.badRequest(w)
		return
	}
	item, err := h.authCollections.CreateDefinition(r.Context(), in, guard)
	h.authCollectionResponse(w, item, item.Revision, http.StatusCreated, err)
}

func (h *Handler) AuthCollection(w http.ResponseWriter, r *http.Request) {
	if !h.authCollectionBoundary(w, r) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, PUT, DELETE")
		h.methodNotAllowed(w)
		return
	}
	actor, ok := h.actor(w, r, r.Method != http.MethodGet)
	if !ok {
		return
	}
	guard := h.clientAuthority(r, actor, nil, "", apikey.Read)
	id := r.PathValue("collection_id")
	if r.Method == http.MethodGet {
		item, err := h.authCollections.GetDefinition(r.Context(), id, guard)
		h.authCollectionResponse(w, item, item.Revision, http.StatusOK, err)
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
		err := h.authCollections.DeleteDefinition(r.Context(), id, revision, guard)
		h.authCollectionResponse(w, nil, 0, http.StatusNoContent, err)
		return
	}
	in, err := decodeAuthCollection(r, false)
	if err != nil {
		h.badRequest(w)
		return
	}
	guard, ok = h.collectionProviderAuthority(r, in.AuthMethod, in.ProviderIDs, guard)
	if !ok {
		h.badRequest(w)
		return
	}
	in.ID = id
	item, err := h.authCollections.UpdateDefinition(r.Context(), id, revision, in, guard)
	h.authCollectionResponse(w, item, item.Revision, http.StatusOK, err)
}

// authConnectionSubject does not accept a caller-supplied owner or API-key
// fallback. The returned predicate is evaluated again inside the DB operation.
func (h *Handler) authConnectionSubject(w http.ResponseWriter, r *http.Request) (string, func() (string, []any), bool) {
	if apikey.HasAuthorization(r) {
		h.genericUnauthorized(w)
		return "", nil, false
	}
	name, _ := browser.CookieName(h.issuer)
	cookies := r.CookiesNamed(name)
	if len(cookies) != 1 || cookies[0].Value == "" {
		h.genericUnauthorized(w)
		return "", nil, false
	}
	cookie := cookies[0]
	session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, browser.PeerIPFromContext(r.Context()))
	if err != nil || !session.Authenticated() || h.identity.ValidateSubject(r.Context(), session.Subject) != nil {
		h.genericUnauthorized(w)
		return "", nil, false
	}
	if r.Method != http.MethodGet && (len(r.Header.Values("X-CSRF-Token")) != 1 || browser.ValidateCSRFToken(cookie.Value, r.Header.Get("X-CSRF-Token")) != nil) {
		h.genericUnauthorized(w)
		return "", nil, false
	}
	return session.Subject, func() (string, []any) { return h.userUpdateSessionGuard(r, session.Subject) }, true
}

func (h *Handler) AccountAuthCollections(w http.ResponseWriter, r *http.Request) {
	if !h.authCollectionBoundary(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		h.methodNotAllowed(w)
		return
	}
	_, guard, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	items, err := h.authCollections.ListDefinitions(r.Context(), guard)
	h.authCollectionResponse(w, items, 0, http.StatusOK, err)
}

func (h *Handler) AccountConnections(w http.ResponseWriter, r *http.Request) {
	if !h.authCollectionBoundary(w, r) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		h.methodNotAllowed(w)
		return
	}
	owner, guard, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	id := r.PathValue("collection_id")
	if r.Method == http.MethodGet {
		items, err := h.authCollections.ListConnections(r.Context(), owner, id, guard)
		h.authCollectionResponse(w, items, 0, http.StatusOK, err)
		return
	}
	in, err := decodeAuthConnection(r)
	if err != nil {
		h.badRequest(w)
		return
	}
	item, err := h.authCollections.CreateConnection(r.Context(), owner, id, in.DefinitionRevision, in.Metadata, guard)
	h.authCollectionResponse(w, item, item.Revision, http.StatusCreated, err)
}

func (h *Handler) AccountConnection(w http.ResponseWriter, r *http.Request) {
	if !h.authCollectionBoundary(w, r) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, PUT, DELETE")
		h.methodNotAllowed(w)
		return
	}
	owner, guard, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	collectionID, id := r.PathValue("collection_id"), r.PathValue("connection_id")
	if r.Method == http.MethodGet {
		item, err := h.authCollections.GetConnection(r.Context(), owner, collectionID, id, guard)
		h.authCollectionResponse(w, item, item.Revision, http.StatusOK, err)
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
		err := h.authCollections.DeleteConnection(r.Context(), owner, collectionID, id, revision, guard)
		h.authCollectionResponse(w, nil, 0, http.StatusNoContent, err)
		return
	}
	in, err := decodeAuthConnection(r)
	if err != nil {
		h.badRequest(w)
		return
	}
	item, err := h.authCollections.UpdateConnection(r.Context(), owner, collectionID, id, revision, in.DefinitionRevision, in.Metadata, guard)
	h.authCollectionResponse(w, item, item.Revision, http.StatusOK, err)
}

func decodeAuthCollection(r *http.Request, create bool) (authcollection.DefinitionInput, error) {
	var in authcollection.DefinitionInput
	fields := map[string]bool{"name": true, "auth_method": true, "enabled": true, "fields": true, "provider_ids": true}
	required := []string{"name", "auth_method", "enabled", "fields"}
	if create {
		fields["id"] = true
		required = append(required, "id")
	}
	err := decodeJSON(r, &in, fields, required, nil)
	return in, err
}

func (h *Handler) collectionProviderAuthority(r *http.Request, authMethod string, ids []string, authority func() (string, []any)) (func() (string, []any), bool) {
	if authMethod == "device_flow" && len(ids) != 0 || authMethod == "api_key" && len(ids) > 1 || authMethod != "oauth2" && authMethod != "api_key" && authMethod != "device_flow" {
		return nil, false
	}
	var dynamicIDs []string
	for _, id := range ids {
		if h.staticProvider(id) {
			if authMethod != "oauth2" {
				return nil, false
			}
			continue
		}
		if h.saasProviderStore == nil {
			return nil, false
		}
		provider, err := h.saasProviderStore.Get(r.Context(), id, authority)
		wantKind := authMethod
		if err != nil || !provider.Enabled || provider.Kind != wantKind {
			return nil, false
		}
		dynamicIDs = append(dynamicIDs, id)
	}
	return func() (string, []any) {
		guard, args := authority()
		guard = "(" + guard + ")"
		args = append([]any(nil), args...)
		for _, id := range dynamicIDs {
			guard += " AND EXISTS (SELECT 1 FROM saas_providers WHERE id=? AND deleted=0 AND enabled=1 AND kind=?)"
			args = append(args, id, authMethod)
		}
		return guard, args
	}, true
}

type authConnectionInput struct {
	DefinitionRevision int64           `json:"definition_revision"`
	Metadata           json.RawMessage `json:"metadata"`
}

func decodeAuthConnection(r *http.Request) (authConnectionInput, error) {
	var in authConnectionInput
	err := decodeJSON(r, &in, map[string]bool{"definition_revision": true, "metadata": true}, []string{"definition_revision", "metadata"}, nil)
	return in, err
}

func (h *Handler) authCollectionResponse(w http.ResponseWriter, value any, revision int64, status int, err error) {
	if err != nil {
		switch {
		case errors.Is(err, authcollection.ErrUnauthorized):
			h.genericUnauthorized(w)
		case errors.Is(err, authcollection.ErrNotFound):
			h.error(w, http.StatusNotFound, "Not found")
		case errors.Is(err, authcollection.ErrConflict):
			h.error(w, http.StatusConflict, "Revision or state conflict")
		case errors.Is(err, authcollection.ErrInvalid):
			h.badRequest(w)
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
