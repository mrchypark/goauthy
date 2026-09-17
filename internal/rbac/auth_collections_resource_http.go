package rbac

import (
	"errors"
	"net/http"
	"strings"
)

// BindConnectionResourceAuthorizer wires the OAuth resource-server adapter.
// The adapter owns bearer verification and returns the subject plus the SQL
// authority predicate used by the auth-collection store.
func (h *Handler) BindConnectionResourceAuthorizer(authorizer func(*http.Request, string) (string, func() (string, []any), error)) error {
	if h == nil || authorizer == nil {
		return errors.New("connection resource authorizer required")
	}
	h.connectionResourceAuthorizer = authorizer
	return nil
}

func (h *Handler) connectionResourceBoundary(w http.ResponseWriter, r *http.Request, scope string, mutation bool) (string, func() (string, []any), bool) {
	h.securityHeaders(w)
	if r.URL.RawQuery != "" || r.URL.ForceQuery || h.crossSite(r) || h.authCollections == nil || h.connectionResourceAuthorizer == nil {
		h.genericUnauthorized(w)
		return "", nil, false
	}
	// Resource routes are bearer-only. Cookie fallback and mixed credentials
	// would make ownership ambiguous, and CSRF is not part of this boundary.
	if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) == "" || len(r.Header.Values("Cookie")) != 0 {
		h.genericUnauthorized(w)
		return "", nil, false
	}
	owner, guard, err := h.connectionResourceAuthorizer(r, scope)
	if err != nil || owner == "" || guard == nil {
		h.genericUnauthorized(w)
		return "", nil, false
	}
	return owner, guard, true
}

func (h *Handler) UserResourceAuthCollections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.methodNotAllowed(w)
		return
	}
	_, guard, ok := h.connectionResourceBoundary(w, r, "goauthy.connections.read", false)
	if !ok {
		return
	}
	items, err := h.authCollections.ListDefinitions(r.Context(), guard)
	h.authCollectionResponse(w, items, 0, http.StatusOK, err)
}

func (h *Handler) UserResourceConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		h.methodNotAllowed(w)
		return
	}
	owner, guard, ok := h.connectionResourceBoundary(w, r, map[bool]string{true: "goauthy.connections.write", false: "goauthy.connections.read"}[r.Method == http.MethodPost], r.Method == http.MethodPost)
	if !ok {
		return
	}
	collectionID := r.PathValue("collection_id")
	if r.Method == http.MethodGet {
		items, err := h.authCollections.ListConnections(r.Context(), owner, collectionID, guard)
		h.authCollectionResponse(w, items, 0, http.StatusOK, err)
		return
	}
	in, err := decodeAuthConnection(r)
	if err != nil {
		h.badRequest(w)
		return
	}
	item, err := h.authCollections.CreateConnection(r.Context(), owner, collectionID, in.DefinitionRevision, in.Metadata, guard)
	h.authCollectionResponse(w, item, item.Revision, http.StatusCreated, err)
}

func (h *Handler) UserResourceConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, PUT, DELETE")
		h.methodNotAllowed(w)
		return
	}
	owner, guard, ok := h.connectionResourceBoundary(w, r, map[bool]string{true: "goauthy.connections.write", false: "goauthy.connections.read"}[r.Method != http.MethodGet], r.Method != http.MethodGet)
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
