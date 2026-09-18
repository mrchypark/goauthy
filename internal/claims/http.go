// Package claims exposes the browser-admin boundary for custom claims.
package claims

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"sort"
	"strings"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
)

const requestLimit int64 = 8 << 10

// Handler serves only browser-authenticated rauthy_admin requests. API keys
// deliberately remain out of this first claims slice.
type Handler struct {
	store            *Store
	browser          *browser.Store
	identity         *identity.Store
	issuer           string
	bootstrapClients map[string]struct{}
}

func NewHandler(store *Store, browserStore *browser.Store, identityStore *identity.Store, issuer string, bootstrapClientIDs ...string) (*Handler, error) {
	if store == nil || browserStore == nil || identityStore == nil {
		return nil, errors.New("claims handler requires stores")
	}
	if _, err := browser.CookieName(issuer); err != nil {
		return nil, err
	}
	clients := make(map[string]struct{}, len(bootstrapClientIDs))
	for _, id := range bootstrapClientIDs {
		if !validBootstrapClientID(id) {
			return nil, errors.New("invalid bootstrap client ID")
		}
		clients[id] = struct{}{}
	}
	return &Handler{store: store, browser: browserStore, identity: identityStore, issuer: issuer, bootstrapClients: clients}, nil
}

// Scopes handles GET and POST /auth/v1/scopes.
func (h *Handler) Scopes(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if !h.safeRequest(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		actor, key, ok := h.actorOrKey(w, r, false, "Scopes", apikey.Read)
		if !ok {
			return
		}
		var items []Scope
		var err error
		if key != nil {
			items, err = h.store.ListScopesAPIKey(r.Context(), *key)
		} else {
			items, err = h.store.ListScopes(r.Context(), actor)
		}
		if err != nil {
			h.storeError(w, err)
			return
		}
		h.json(w, scopeResponses(items))
	case http.MethodPost:
		h.createScope(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		h.methodNotAllowed(w)
	}
}

// Scope handles PUT and DELETE /auth/v1/scopes/{id}.
func (h *Handler) Scope(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if !h.safeRequest(w, r) {
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "PUT, DELETE")
		h.methodNotAllowed(w)
		return
	}
	actor, key, ok := h.actorOrKey(w, r, true, "Scopes", map[bool]apikey.Right{true: apikey.Update, false: apikey.Delete}[r.Method == http.MethodPut])
	if !ok {
		return
	}
	name := r.PathValue("id")
	if !validScopeName(name) {
		h.notFound(w)
		return
	}
	catalog, err := h.store.CatalogRevision(r.Context())
	if err != nil {
		h.unavailable(w)
		return
	}
	if r.Method == http.MethodDelete {
		var err error
		if key != nil {
			err = h.store.DeleteScopeAPIKey(r.Context(), *key, name, catalog)
		} else {
			err = h.store.DeleteScope(r.Context(), actor, name, catalog)
		}
		if err != nil {
			h.storeError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	value, err := decodeScope(w, r)
	if err != nil {
		h.badRequest(w)
		return
	}
	var updated Scope
	if key != nil {
		updated, err = h.store.UpdateScopeAPIKey(r.Context(), *key, name, catalog, value)
	} else {
		updated, err = h.store.UpdateScope(r.Context(), actor, name, catalog, value)
	}
	if err != nil {
		h.storeError(w, err)
		return
	}
	h.json(w, scopeResponse(updated))
}

func (h *Handler) createScope(w http.ResponseWriter, r *http.Request) {
	actor, key, ok := h.actorOrKey(w, r, true, "Scopes", apikey.Create)
	if !ok {
		return
	}
	value, err := decodeScope(w, r)
	if err != nil {
		h.badRequest(w)
		return
	}
	catalog, err := h.store.CatalogRevision(r.Context())
	if err != nil {
		h.unavailable(w)
		return
	}
	var created Scope
	if key != nil {
		created, err = h.store.CreateScopeAPIKey(r.Context(), *key, catalog, value)
	} else {
		created, err = h.store.CreateScope(r.Context(), actor, catalog, value)
	}
	if err != nil {
		h.storeError(w, err)
		return
	}
	h.json(w, scopeResponse(created))
}

// Attributes handles GET and POST /auth/v1/users/attr.
func (h *Handler) Attributes(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if !h.safeRequest(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		actor, key, ok := h.actorOrKey(w, r, false, "UserAttributes", apikey.Read)
		if !ok {
			return
		}
		var items []Attribute
		var err error
		if key != nil {
			items, err = h.store.ListAttributesAPIKey(r.Context(), *key)
		} else {
			items, err = h.store.ListAttributes(r.Context(), actor)
		}
		if err != nil {
			h.storeError(w, err)
			return
		}
		h.json(w, map[string]any{"values": attributeResponses(items)})
	case http.MethodPost:
		h.createAttribute(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		h.methodNotAllowed(w)
	}
}

// Attribute handles PUT and DELETE /auth/v1/users/attr/{name}.
func (h *Handler) Attribute(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if !h.safeRequest(w, r) {
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "PUT, DELETE")
		h.methodNotAllowed(w)
		return
	}
	actor, key, ok := h.actorOrKey(w, r, true, "UserAttributes", map[bool]apikey.Right{true: apikey.Update, false: apikey.Delete}[r.Method == http.MethodPut])
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !validAttributeName(name) {
		h.notFound(w)
		return
	}
	catalog, err := h.store.CatalogRevision(r.Context())
	if err != nil {
		h.unavailable(w)
		return
	}
	if r.Method == http.MethodDelete {
		var err error
		if key != nil {
			err = h.store.DeleteAttributeAPIKey(r.Context(), *key, name, catalog)
		} else {
			err = h.store.DeleteAttribute(r.Context(), actor, name, catalog)
		}
		if err != nil {
			h.storeError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	value, err := decodeAttribute(w, r)
	if err != nil {
		h.badRequest(w)
		return
	}
	var updated Attribute
	if key != nil {
		updated, err = h.store.UpdateAttributeAPIKey(r.Context(), *key, name, catalog, value)
	} else {
		updated, err = h.store.UpdateAttribute(r.Context(), actor, name, catalog, value)
	}
	if err != nil {
		h.storeError(w, err)
		return
	}
	h.json(w, attributeResponse(updated))
}

func (h *Handler) createAttribute(w http.ResponseWriter, r *http.Request) {
	actor, key, ok := h.actorOrKey(w, r, true, "UserAttributes", apikey.Create)
	if !ok {
		return
	}
	value, err := decodeAttribute(w, r)
	if err != nil {
		h.badRequest(w)
		return
	}
	catalog, err := h.store.CatalogRevision(r.Context())
	if err != nil {
		h.unavailable(w)
		return
	}
	var created Attribute
	if key != nil {
		created, err = h.store.CreateAttributeAPIKey(r.Context(), *key, catalog, value)
	} else {
		created, err = h.store.CreateAttribute(r.Context(), actor, catalog, value)
	}
	if err != nil {
		h.storeError(w, err)
		return
	}
	h.json(w, attributeResponse(created))
}

// UserAttributePut disambiguates the two upstream three-segment PUT routes
// that net/http correctly rejects as overlapping ServeMux patterns.
func (h *Handler) UserAttributePut(w http.ResponseWriter, r *http.Request) {
	first, second := r.PathValue("first"), r.PathValue("second")
	switch {
	case first == "attr" && validAttributeName(second):
		r.SetPathValue("name", second)
		h.Attribute(w, r)
	case second == "attr" && validSubject(first):
		r.SetPathValue("subject", first)
		h.UserAttributes(w, r)
	default:
		h.headers(w)
		h.notFound(w)
	}
}

// UserAttributes handles GET and PUT /auth/v1/users/{subject}/attr.
func (h *Handler) UserAttributes(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if !h.safeRequest(w, r) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		h.methodNotAllowed(w)
		return
	}
	if apikey.HasAuthorization(r) {
		_, key, ok := h.actorOrKey(w, r, false, "Users", map[bool]apikey.Right{true: apikey.Update, false: apikey.Read}[r.Method == http.MethodPut])
		if !ok {
			return
		}
		subject := r.PathValue("subject")
		if !validSubject(subject) {
			h.notFound(w)
			return
		}
		values, revision, err := h.store.GetUserValuesAPIKey(r.Context(), *key, subject)
		if err != nil {
			h.storeError(w, err)
			return
		}
		if r.Method == http.MethodGet {
			h.json(w, userValuesResponse(values))
			return
		}
		put, err := decodeUserValues(w, r)
		if err != nil {
			h.badRequest(w)
			return
		}
		if _, err = h.store.PutUserValuesAPIKey(r.Context(), *key, subject, revision, put); err != nil {
			h.storeError(w, err)
			return
		}
		values, _, err = h.store.GetUserValuesAPIKey(r.Context(), *key, subject)
		if err != nil {
			h.storeError(w, err)
			return
		}
		h.json(w, userValuesResponse(values))
		return
	}
	actor, ok := h.actor(w, r, r.Method == http.MethodPut)
	if !ok {
		return
	}
	subject := r.PathValue("subject")
	if !validSubject(subject) {
		h.notFound(w)
		return
	}
	admin := h.store.admin(r.Context(), actor) == nil
	if !admin {
		if actor != subject {
			h.forbidden(w)
			return
		}
		if r.Method != http.MethodPut {
			h.unauthorized(w)
			return
		}
	}
	var (
		values   map[string]json.RawMessage
		revision int64
		err      error
	)
	if admin {
		values, revision, err = h.store.GetUserValues(r.Context(), actor, subject)
	} else {
		values, revision, err = h.store.selfUserValues(r.Context(), actor, subject)
	}
	if err != nil {
		h.storeError(w, err)
		return
	}
	if r.Method == http.MethodGet {
		h.json(w, userValuesResponse(values))
		return
	}
	put, err := decodeUserValues(w, r)
	if err != nil {
		h.badRequest(w)
		return
	}
	if admin {
		_, err = h.store.PutUserValues(r.Context(), actor, subject, revision, put)
	} else {
		_, err = h.store.PutSelfUserValues(r.Context(), actor, subject, revision, put)
	}
	if err != nil {
		h.storeError(w, err)
		return
	}
	var updated map[string]json.RawMessage
	if admin {
		updated, _, err = h.store.GetUserValues(r.Context(), actor, subject)
	} else {
		updated, _, err = h.store.selfUserValues(r.Context(), actor, subject)
	}
	if err != nil {
		h.storeError(w, err)
		return
	}
	h.json(w, userValuesResponse(updated))
}

// EditableUserAttributes handles GET /auth/v1/users/{subject}/attr/editable.
// It is intentionally session-self-only, including for administrators.
func (h *Handler) EditableUserAttributes(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if !h.safeRequest(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		h.methodNotAllowed(w)
		return
	}
	actor, ok := h.actor(w, r, false)
	if !ok {
		return
	}
	subject := r.PathValue("subject")
	if !validSubject(subject) {
		h.notFound(w)
		return
	}
	if actor != subject {
		h.forbidden(w)
		return
	}
	items, err := h.store.EditableUserAttributes(r.Context(), subject)
	if err != nil {
		h.storeError(w, err)
		return
	}
	h.json(w, editableAttributesResponse(items))
}

// BootstrapClientScopes handles GET and PUT /auth/v1/clients/{id}/scopes.
// This is intentionally not a general client-management endpoint.
func (h *Handler) BootstrapClientScopes(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if !h.safeRequest(w, r) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		h.methodNotAllowed(w)
		return
	}
	actor, key, ok := h.actorOrKey(w, r, r.Method == http.MethodPut, "Clients", map[bool]apikey.Right{true: apikey.Update, false: apikey.Read}[r.Method == http.MethodPut])
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, allowed := h.bootstrapClients[id]; !allowed {
		h.notFound(w)
		return
	}
	var policy ClientScopes
	var err error
	if key != nil {
		policy, err = h.store.GetBootstrapClientScopesAPIKey(r.Context(), *key, id)
	} else {
		policy, err = h.store.GetBootstrapClientScopes(r.Context(), actor, id)
	}
	if err != nil {
		h.storeError(w, err)
		return
	}
	if r.Method == http.MethodGet {
		h.json(w, clientScopesResponse(policy))
		return
	}
	allowed, defaults, err := decodeClientScopes(w, r)
	if err != nil {
		h.badRequest(w)
		return
	}
	var updated ClientScopes
	if key != nil {
		updated, err = h.store.UpdateBootstrapClientScopesAPIKey(r.Context(), *key, id, policy.Revision, allowed, defaults)
	} else {
		updated, err = h.store.UpdateBootstrapClientScopes(r.Context(), actor, id, policy.Revision, allowed, defaults)
	}
	if err != nil {
		h.storeError(w, err)
		return
	}
	h.json(w, clientScopesResponse(updated))
}

// BootstrapClientCredentialsClaims handles GET and PUT
// /auth/v1/clients/{id}/claims for configured client_credentials clients.
func (h *Handler) BootstrapClientCredentialsClaims(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if !h.safeRequest(w, r) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		h.methodNotAllowed(w)
		return
	}
	actor, key, ok := h.actorOrKey(w, r, r.Method == http.MethodPut, "Clients", map[bool]apikey.Right{true: apikey.Update, false: apikey.Read}[r.Method == http.MethodPut])
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, allowed := h.bootstrapClients[id]; !allowed {
		h.notFound(w)
		return
	}
	var policy ClientCredentialsClaims
	var err error
	if key != nil {
		policy, err = h.store.GetBootstrapClientCredentialsClaimsAPIKey(r.Context(), *key, id)
	} else {
		policy, err = h.store.GetBootstrapClientCredentialsClaims(r.Context(), actor, id)
	}
	if err != nil {
		h.storeError(w, err)
		return
	}
	if r.Method == http.MethodGet {
		h.json(w, clientCredentialsClaimsResponse(policy))
		return
	}
	values, atRoot, revision, err := decodeClientCredentialsClaims(w, r)
	if err != nil {
		h.badRequest(w)
		return
	}
	if key != nil {
		policy, err = h.store.UpdateBootstrapClientCredentialsClaimsAPIKey(r.Context(), *key, id, revision, values, atRoot)
	} else {
		policy, err = h.store.UpdateBootstrapClientCredentialsClaims(r.Context(), actor, id, revision, values, atRoot)
	}
	if err != nil {
		h.storeError(w, err)
		return
	}
	h.json(w, clientCredentialsClaimsResponse(policy))
}

func (h *Handler) safeRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" || strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		h.unauthorized(w)
		return false
	}
	return true
}

func (h *Handler) actor(w http.ResponseWriter, r *http.Request, mutation bool) (string, bool) {
	if apikey.HasAuthorization(r) {
		h.unauthorized(w)
		return "", false
	}
	name, err := browser.CookieName(h.issuer)
	if err != nil {
		h.unavailable(w)
		return "", false
	}
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		h.unauthorized(w)
		return "", false
	}
	session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, browser.PeerIPFromContext(r.Context()))
	if err != nil || !session.Authenticated() || h.identity.ValidateSubject(r.Context(), session.Subject) != nil {
		h.unauthorized(w)
		return "", false
	}
	if mutation && browser.ValidateCSRFToken(cookie.Value, r.Header.Get("X-CSRF-Token")) != nil {
		h.unauthorized(w)
		return "", false
	}
	return session.Subject, true
}

// actorOrKey keeps API-key authentication disjoint from browser cookies: a
// malformed API-Key header never falls back to a privileged browser session.
func (h *Handler) actorOrKey(w http.ResponseWriter, r *http.Request, mutation bool, group string, right apikey.Right) (string, *apikey.Principal, bool) {
	if apikey.HasAuthorization(r) {
		header, valid := apikey.Authorization(r)
		if !valid {
			h.unauthorized(w)
			return "", nil, false
		}
		key, err := h.store.AuthenticateAPIKey(r.Context(), header)
		if err != nil {
			h.unauthorized(w)
			return "", nil, false
		}
		if err := h.store.AuthorizeAPIKey(r.Context(), key, group, right); err != nil {
			h.forbidden(w)
			return "", nil, false
		}
		return "", &key, true
	}
	actor, ok := h.actor(w, r, mutation)
	return actor, nil, ok
}

func decodeScope(w http.ResponseWriter, r *http.Request) (Scope, error) {
	var wire struct {
		Name   *string   `json:"scope"`
		Access *[]string `json:"attr_include_access"`
		ID     *[]string `json:"attr_include_id"`
		Root   *bool     `json:"claims_at_root"`
	}
	if err := strictJSON(w, r, &wire); err != nil || wire.Name == nil || !validScopeName(*wire.Name) {
		return Scope{}, errors.New("invalid scope")
	}
	value := Scope{Name: *wire.Name}
	if wire.Access != nil {
		value.AttributeIncludeAccess = append([]string(nil), (*wire.Access)...)
	}
	if wire.ID != nil {
		value.AttributeIncludeID = append([]string(nil), (*wire.ID)...)
	}
	if wire.Root != nil {
		value.ClaimsAtRoot = *wire.Root
	}
	if !validAttributeNames(value.AttributeIncludeAccess) || !validAttributeNames(value.AttributeIncludeID) {
		return Scope{}, errors.New("invalid scope attributes")
	}
	return value, nil
}

func decodeAttribute(w http.ResponseWriter, r *http.Request) (Attribute, error) {
	var wire struct {
		Name         *string         `json:"name"`
		Description  *string         `json:"desc"`
		Default      json.RawMessage `json:"default_value"`
		Type         *string         `json:"typ"`
		UserEditable *bool           `json:"user_editable"`
	}
	if err := strictJSON(w, r, &wire); err != nil || wire.Name == nil || !validAttributeName(*wire.Name) {
		return Attribute{}, errors.New("invalid attribute")
	}
	value := Attribute{Name: *wire.Name}
	if wire.Description != nil {
		value.Description = *wire.Description
	}
	if len(value.Description) > 128 || (wire.Type != nil && *wire.Type != "email") || (len(wire.Default) != 0 && !json.Valid(wire.Default)) {
		return Attribute{}, errors.New("invalid attribute")
	}
	if bytes.Equal(wire.Default, []byte("null")) {
		wire.Default = nil
	}
	value.Default = append(json.RawMessage(nil), wire.Default...)
	if wire.Type != nil {
		value.Type = *wire.Type
	}
	if wire.UserEditable != nil {
		value.UserEditable = *wire.UserEditable
	}
	return value, nil
}

func decodeUserValues(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, error) {
	var wire struct {
		Values *[]struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		} `json:"values"`
	}
	if err := strictJSON(w, r, &wire); err != nil || wire.Values == nil {
		return nil, errors.New("invalid attribute values")
	}
	values := make(map[string]json.RawMessage, len(*wire.Values))
	for _, item := range *wire.Values {
		if !validAttributeName(item.Key) || len(item.Value) == 0 || !json.Valid(item.Value) {
			return nil, errors.New("invalid attribute value")
		}
		if _, duplicate := values[item.Key]; duplicate {
			return nil, errors.New("duplicate attribute value")
		}
		if bytes.Equal(item.Value, []byte("null")) || bytes.Equal(item.Value, []byte(`""`)) {
			values[item.Key] = json.RawMessage("null")
			continue
		}
		values[item.Key] = append(json.RawMessage(nil), item.Value...)
	}
	return values, nil
}

func decodeClientScopes(w http.ResponseWriter, r *http.Request) ([]string, []string, error) {
	var wire struct {
		Allowed *[]string `json:"allowed_scopes"`
		Default *[]string `json:"default_scopes"`
	}
	if err := strictJSON(w, r, &wire); err != nil || wire.Allowed == nil || wire.Default == nil || !validScopeNames(*wire.Allowed) || !validScopeNames(*wire.Default) {
		return nil, nil, errors.New("invalid client scopes")
	}
	allowed, defaults := append([]string(nil), (*wire.Allowed)...), append([]string(nil), (*wire.Default)...)
	for _, name := range defaults {
		if !contains(allowed, name) {
			return nil, nil, errors.New("default not allowed")
		}
	}
	return allowed, defaults, nil
}

func decodeClientCredentialsClaims(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, bool, int64, error) {
	var wire struct {
		Claims   json.RawMessage `json:"claims"`
		AtRoot   *bool           `json:"claims_at_root"`
		Revision *int64          `json:"revision"`
	}
	if err := strictJSON(w, r, &wire); err != nil || len(wire.Claims) == 0 || wire.AtRoot == nil || wire.Revision == nil || *wire.Revision < 0 {
		return nil, false, 0, ErrInvalid
	}
	if bytes.Equal(wire.Claims, []byte("null")) {
		return nil, *wire.AtRoot, *wire.Revision, nil
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(wire.Claims, &values) != nil || values == nil {
		return nil, false, 0, ErrInvalid
	}
	if _, err := canonicalClientCredentialsClaims(values); err != nil {
		return nil, false, 0, err
	}
	return values, *wire.AtRoot, *wire.Revision, nil
}

func strictJSON(w http.ResponseWriter, r *http.Request, value any) error {
	if len(r.Header.Values("Content-Type")) != 1 {
		return errors.New("content type")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return errors.New("content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, requestLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 || rejectDuplicateFields(body) != nil {
		return errors.New("json")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("json")
	}
	return nil
}

func rejectDuplicateFields(body []byte) error {
	d := json.NewDecoder(bytes.NewReader(body))
	if err := walkJSON(d); err != nil {
		return err
	}
	_, err := d.Token()
	if err != io.EOF {
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
			if _, dup := seen[name]; dup {
				return errors.New("duplicate")
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

type scopeWire struct {
	Scope             string   `json:"scope"`
	AttrIncludeAccess []string `json:"attr_include_access,omitempty"`
	AttrIncludeID     []string `json:"attr_include_id,omitempty"`
	ClaimsAtRoot      bool     `json:"claims_at_root"`
}

func scopeResponse(v Scope) scopeWire {
	return scopeWire{v.Name, v.AttributeIncludeAccess, v.AttributeIncludeID, v.ClaimsAtRoot}
}
func scopeResponses(items []Scope) []scopeWire {
	out := make([]scopeWire, len(items))
	for i := range items {
		out[i] = scopeResponse(items[i])
	}
	return out
}

type attributeWire struct {
	Name         string          `json:"name"`
	Description  string          `json:"desc,omitempty"`
	Default      json.RawMessage `json:"default_value,omitempty"`
	Type         string          `json:"typ,omitempty"`
	UserEditable bool            `json:"user_editable"`
}

func attributeResponse(v Attribute) attributeWire {
	return attributeWire{v.Name, v.Description, v.Default, v.Type, v.UserEditable}
}
func attributeResponses(items []Attribute) []attributeWire {
	out := make([]attributeWire, len(items))
	for i := range items {
		out[i] = attributeResponse(items[i])
	}
	return out
}

type editableAttributeWire struct {
	Name        string          `json:"name"`
	Description string          `json:"desc,omitempty"`
	Default     json.RawMessage `json:"default_value,omitempty"`
	Type        string          `json:"typ,omitempty"`
	Value       json.RawMessage `json:"value,omitempty"`
}

func editableAttributesResponse(items []EditableAttribute) map[string]any {
	values := make([]editableAttributeWire, len(items))
	for i, item := range items {
		values[i] = editableAttributeWire{item.Name, item.Description, item.Default, item.Type, item.Value}
	}
	return map[string]any{"values": values}
}
func userValuesResponse(values map[string]json.RawMessage) map[string]any {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]map[string]json.RawMessage, 0, len(keys))
	for _, key := range keys {
		items = append(items, map[string]json.RawMessage{"key": json.RawMessage(strconvQuote(key)), "value": values[key]})
	}
	return map[string]any{"values": items}
}
func strconvQuote(value string) []byte { encoded, _ := json.Marshal(value); return encoded }
func clientScopesResponse(v ClientScopes) map[string]any {
	allowed, defaults := v.Allowed, v.Default
	if allowed == nil {
		allowed = []string{}
	}
	if defaults == nil {
		defaults = []string{}
	}
	return map[string]any{"client_id": v.ClientID, "allowed_scopes": allowed, "default_scopes": defaults}
}
func clientCredentialsClaimsResponse(v ClientCredentialsClaims) map[string]any {
	return map[string]any{"claims": v.Values, "claims_at_root": v.AtRoot, "revision": v.Revision}
}

func validScopeNames(values []string) bool {
	seen := map[string]struct{}{}
	for _, v := range values {
		if !validScopeName(v) {
			return false
		}
		if _, dup := seen[v]; dup {
			return false
		}
		seen[v] = struct{}{}
	}
	return true
}
func validAttributeNames(values []string) bool {
	if len(values) == 0 {
		return true
	}
	seen := map[string]struct{}{}
	for _, v := range values {
		if !validAttributeName(v) {
			return false
		}
		if _, dup := seen[v]; dup {
			return false
		}
		seen[v] = struct{}{}
	}
	return true
}
func validBootstrapClientID(v string) bool {
	return len(v) > 0 && len(v) <= 64 && !strings.ContainsAny(v, "/\\\r\n")
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (h *Handler) headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
}
func (h *Handler) json(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func (h *Handler) storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnauthorized):
		h.unauthorized(w)
	case errors.Is(err, ErrConflict):
		h.error(w, http.StatusConflict, "Conflict")
	case errors.Is(err, ErrNotFound):
		h.notFound(w)
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrReserved), errors.Is(err, ErrInactiveSubject):
		h.badRequest(w)
	default:
		log.Printf("claims store unavailable: %v", err)
		h.unavailable(w)
	}
}
func (h *Handler) unauthorized(w http.ResponseWriter) {
	h.error(w, http.StatusUnauthorized, "Unauthorized")
}
func (h *Handler) forbidden(w http.ResponseWriter) { h.error(w, http.StatusForbidden, "Forbidden") }
func (h *Handler) notFound(w http.ResponseWriter)  { h.error(w, http.StatusNotFound, "Not Found") }
func (h *Handler) badRequest(w http.ResponseWriter) {
	h.error(w, http.StatusBadRequest, "Invalid request")
}
func (h *Handler) unavailable(w http.ResponseWriter) {
	h.error(w, http.StatusServiceUnavailable, "Service Unavailable")
}
func (h *Handler) methodNotAllowed(w http.ResponseWriter) {
	h.error(w, http.StatusMethodNotAllowed, "Method Not Allowed")
}
func (h *Handler) error(w http.ResponseWriter, status int, message string) {
	http.Error(w, message, status)
}
