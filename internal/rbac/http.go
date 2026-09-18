// Package rbac exposes the browser-admin boundary for roles, groups, and
// their adjacent authorization metadata.
package rbac

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/authcollection"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/recovery"
	"github.com/mrchypark/goauthy/internal/saas"
)

const adminRequestLimit int64 = 8 << 10

// Handler authorizes every request from the current browser session. Request
// bodies deliberately never carry an actor or a privilege-bearing subject.
type Handler struct {
	store                         *Store
	clients                       *clients.Store
	deviceSessions                *device.Store
	authCollections               *authcollection.Store
	connectionResourceAuthorizer  func(*http.Request, string) (string, func() (string, []any), error)
	browser                       *browser.Store
	identity                      *identity.Store
	passkeyService                *passkey.Service
	issuer                        string
	bootstrapClients              map[string]struct{}
	userListThreshold             uint16
	beforeUserListRead            func()
	beforeUserDetailRead          func()
	beforeUserCreate              func()
	beforeUserUpdate              func()
	beforePreferredUsernameUpdate func()
	beforeUserValuesConfigRead    func()
	userValuesPolicy              identity.UserValuesPolicy
	// OnUserUpdated runs after a successful commit and before the response.
	OnUserUpdated               func(context.Context, identity.UserUpdateResult)
	beforeEventRead             func()
	beforeEventCreate           func()
	eventStreams                atomic.Int32
	userCreation                *recovery.Service
	passwordNewTTL              time.Duration
	saasProviders               []SaaSProviderInfo
	saasProviderStore           *saas.ProviderStore
	providerResourceAuthorizer  func(*http.Request, string) (string, func() (string, []any), error)
	saasCredentials             *saas.CredentialStore
	connectionUseResource       string
	connectionUseAuthorizer     func(*http.Request) (string, string, func() (string, []any), error)
	connectionHandoffAuthorizer func(*http.Request) (string, string, func() (string, []any), error)
}

func (h *Handler) BindConnectionUseResource(resource string) error {
	if h == nil {
		return errors.New("RBAC handler required")
	}
	u, err := url.Parse(resource)
	if err != nil || len(resource) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.Contains(resource, "#") || strings.ContainsFunc(resource, unicode.IsSpace) {
		return errors.New("invalid connection use resource")
	}
	h.connectionUseResource = resource
	return nil
}

// BindClients enables the managed OAuth-client administration boundary.
func (h *Handler) BindClients(store *clients.Store) error {
	if h == nil || store == nil {
		return errors.New("managed clients store required")
	}
	h.clients = store
	return nil
}

// SetPasskeyService enables admin-provisioned passkey-only user creation.
func (h *Handler) SetPasskeyService(service *passkey.Service) {
	if h != nil {
		h.passkeyService = service
	}
}

func NewHandler(store *Store, browserStore *browser.Store, identityStore *identity.Store, issuer string, bootstrapClientIDs ...string) (*Handler, error) {
	if store == nil || browserStore == nil || identityStore == nil {
		return nil, errors.New("RBAC handler requires stores")
	}
	if _, err := browser.CookieName(issuer); err != nil {
		return nil, err
	}
	clients := make(map[string]struct{}, len(bootstrapClientIDs))
	for _, clientID := range bootstrapClientIDs {
		if !bootstrapClientIDPattern.MatchString(clientID) {
			return nil, errors.New("invalid bootstrap client ID")
		}
		clients[clientID] = struct{}{}
	}
	return &Handler{store: store, browser: browserStore, identity: identityStore, issuer: issuer, bootstrapClients: clients, userListThreshold: DefaultUserListThreshold}, nil
}

// Roles handles GET and POST /auth/v1/roles.
func (h *Handler) Roles(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	switch r.Method {
	case http.MethodGet:
		actor, key, ok := h.principal(w, r, false, "Roles", apikey.Read)
		if !ok {
			return
		}
		var items []Entity
		var err error
		if key != nil {
			items, err = h.store.ListRolesAPIKey(r.Context(), *key)
		} else {
			items, err = h.store.ListRolesForAdmin(r.Context(), actor)
		}
		if err != nil {
			h.writeStoreError(w, err)
			return
		}
		h.writeEntities(w, items)
	case http.MethodPost:
		h.create(w, r, true)
	default:
		w.Header().Set("Allow", "GET, POST")
		h.methodNotAllowed(w)
	}
}

// Groups handles GET and POST /auth/v1/groups.
func (h *Handler) Groups(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	switch r.Method {
	case http.MethodGet:
		actor, key, ok := h.principal(w, r, false, "Groups", apikey.Read)
		if !ok {
			return
		}
		var items []Entity
		var err error
		if key != nil {
			items, err = h.store.ListGroupsAPIKey(r.Context(), *key)
		} else {
			items, err = h.store.ListGroupsForAdmin(r.Context(), actor)
		}
		if err != nil {
			h.writeStoreError(w, err)
			return
		}
		h.writeEntities(w, items)
	case http.MethodPost:
		h.create(w, r, false)
	default:
		w.Header().Set("Allow", "GET, POST")
		h.methodNotAllowed(w)
	}
}

// Role handles PUT and DELETE /auth/v1/roles/{id}.
func (h *Handler) Role(w http.ResponseWriter, r *http.Request) { h.entity(w, r, true) }

// Group handles PUT and DELETE /auth/v1/groups/{id}.
func (h *Handler) Group(w http.ResponseWriter, r *http.Request) { h.entity(w, r, false) }

// LoginRestriction handles GET/PUT /auth/v1/clients/{id}/login-restriction.
// Only bootstrap client IDs explicitly configured at construction are exposed.
func (h *Handler) LoginRestriction(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		h.methodNotAllowed(w)
		return
	}
	right := apikey.Read
	if r.Method == http.MethodPut {
		right = apikey.Update
	}
	actor, key, ok := h.principal(w, r, r.Method == http.MethodPut, "Clients", right)
	if !ok {
		return
	}
	clientID := r.PathValue("id")
	if _, allowed := h.bootstrapClients[clientID]; !allowed {
		h.notFound(w)
		return
	}
	if r.Method == http.MethodGet {
		policy, err := h.store.GetBootstrapClientLoginRestrictionForAdmin(r.Context(), actor, clientID)
		if key != nil {
			policy, err = h.store.GetBootstrapClientLoginRestriction(r.Context(), clientID)
		}
		if err != nil {
			h.writeStoreError(w, err)
			return
		}
		h.writeLoginRestriction(w, policy)
		return
	}
	request, err := decodeLoginRestriction(w, r)
	if err != nil {
		h.badRequest(w)
		return
	}
	var policy BootstrapClientLoginRestriction
	if key != nil {
		policy, err = h.store.UpdateBootstrapClientLoginRestrictionAPIKey(r.Context(), *key, clientID, request.Revision, request.RestrictGroupPrefix)
	} else {
		policy, err = h.store.UpdateBootstrapClientLoginRestriction(r.Context(), actor, clientID, request.Revision, request.RestrictGroupPrefix)
	}
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	h.writeLoginRestriction(w, policy)
}

// PatchUserMembership handles the role/group-only subset of Rauthy's PATCH
// /auth/v1/users/{id}. It intentionally does not claim to implement the full
// UserResponse or arbitrary user-field PatchOp surface.
func (h *Handler) PatchUserMembership(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodPatch {
		w.Header().Set("Allow", http.MethodPatch)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	actor, key, ok := h.principalFor(w, r, true, "Users", apikey.Update, true)
	if !ok {
		return
	}
	target := r.PathValue("subject")
	if !validSubjectID(target) {
		h.notFound(w)
		return
	}
	patch, err := decodeMembershipPatch(w, r)
	if err != nil {
		h.badRequest(w)
		return
	}
	var principal Principal
	if key != nil {
		principal, err = h.store.PatchPrincipalAPIKey(r.Context(), *key, target, patch.Roles, patch.Groups, patch.ReplaceRoles, patch.ReplaceGroups)
	} else {
		principal, err = h.store.PatchPrincipal(r.Context(), actor, target, patch.Roles, patch.Groups, patch.ReplaceRoles, patch.ReplaceGroups)
	}
	if err != nil {
		if errors.Is(err, ErrInactiveSubject) || errors.Is(err, ErrNotFound) {
			h.notFound(w)
			return
		}
		h.writeStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(membershipResponse(target, principal))
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request, role bool) {
	group := "Groups"
	if role {
		group = "Roles"
	}
	actor, key, ok := h.principal(w, r, true, group, apikey.Create)
	if !ok {
		return
	}
	request, err := decodeRequest(w, r, role)
	if err != nil {
		h.badRequest(w)
		return
	}
	var entity Entity
	if role {
		if key != nil {
			entity, err = h.store.CreateRoleAPIKey(r.Context(), *key, request.Name, request.Meta)
		} else {
			entity, err = h.store.CreateRole(r.Context(), actor, request.Name, request.Meta)
		}
	} else {
		if key != nil {
			entity, err = h.store.CreateGroupAPIKey(r.Context(), *key, request.Name, request.Meta)
		} else {
			entity, err = h.store.CreateGroup(r.Context(), actor, request.Name, request.Meta)
		}
	}
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	h.writeEntity(w, entity)
}

func (h *Handler) entity(w http.ResponseWriter, r *http.Request, role bool) {
	h.securityHeaders(w)
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "PUT, DELETE")
		h.methodNotAllowed(w)
		return
	}
	resource := "Groups"
	if role {
		resource = "Roles"
	}
	right := apikey.Update
	if r.Method == http.MethodDelete {
		right = apikey.Delete
	}
	actor, key, ok := h.principal(w, r, true, resource, right)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !validID(id) {
		h.notFound(w)
		return
	}
	var current Entity
	var err error
	if role {
		if key != nil {
			current, err = h.store.GetRoleAPIKey(r.Context(), *key, id)
		} else {
			current, err = h.store.GetRoleForAdmin(r.Context(), actor, id)
		}
	} else {
		if key != nil {
			current, err = h.store.GetGroupAPIKey(r.Context(), *key, id)
		} else {
			current, err = h.store.GetGroupForAdmin(r.Context(), actor, id)
		}
	}
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			h.genericUnauthorized(w)
		} else {
			h.writeLookupError(w, err)
		}
		return
	}
	if r.Method == http.MethodDelete {
		if key != nil {
			if role {
				err = h.store.DeleteRoleAPIKey(r.Context(), *key, current.ID, current.Revision)
			} else {
				err = h.store.DeleteGroupAPIKey(r.Context(), *key, current.ID, current.Revision)
			}
		} else {
			err = h.delete(r, actor, role, current)
		}
		if err != nil {
			h.writeStoreError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	request, err := decodeRequest(w, r, role)
	if err != nil {
		h.badRequest(w)
		return
	}
	if role {
		if key != nil {
			current, err = h.store.UpdateRoleAPIKey(r.Context(), *key, id, current.Revision, request.Name, request.Meta)
		} else {
			current, err = h.store.UpdateRole(r.Context(), actor, id, current.Revision, request.Name, request.Meta)
		}
	} else {
		if key != nil {
			current, err = h.store.UpdateGroupAPIKey(r.Context(), *key, id, current.Revision, request.Name, request.Meta)
		} else {
			current, err = h.store.UpdateGroup(r.Context(), actor, id, current.Revision, request.Name, request.Meta)
		}
	}
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	h.writeEntity(w, current)
}

func (h *Handler) delete(r *http.Request, actor string, role bool, current Entity) error {
	if role {
		return h.store.DeleteRole(r.Context(), actor, current.ID, current.Revision)
	}
	return h.store.DeleteGroup(r.Context(), actor, current.ID, current.Revision)
}

// actor intentionally makes authorization decisions before any resource
// lookup, preventing a non-admin from using these endpoints for enumeration.
func (h *Handler) actor(w http.ResponseWriter, r *http.Request, mutation bool) (string, bool) {
	return h.actorFor(w, r, mutation, false)
}

func (h *Handler) actorFor(w http.ResponseWriter, r *http.Request, mutation, allowDelegated bool) (string, bool) {
	if apikey.HasAuthorization(r) {
		h.genericUnauthorized(w)
		return "", false
	}
	name, err := browser.CookieName(h.issuer)
	if err != nil {
		h.unavailable(w)
		return "", false
	}
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		h.genericUnauthorized(w)
		return "", false
	}
	session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, browser.PeerIPFromContext(r.Context()))
	if err != nil || !session.Authenticated() || h.identity.ValidateSubject(r.Context(), session.Subject) != nil {
		h.genericUnauthorized(w)
		return "", false
	}
	admin, err := h.store.IsAdmin(r.Context(), session.Subject)
	if err != nil {
		h.unavailable(w)
		return "", false
	}
	if !admin && allowDelegated {
		delegated, err := h.store.isDelegatedAdmin(r.Context(), session.Subject)
		if err != nil {
			h.unavailable(w)
			return "", false
		}
		admin = delegated
	}
	if !admin {
		h.genericUnauthorized(w)
		return "", false
	}
	if mutation && browser.ValidateCSRFToken(cookie.Value, r.Header.Get("X-CSRF-Token")) != nil {
		h.genericUnauthorized(w)
		return "", false
	}
	return session.Subject, true
}

// principal never falls back to a browser session when Authorization is
// supplied. This makes a malformed or revoked API key fail closed instead of
// accidentally inheriting ambient browser authority.
func (h *Handler) principal(w http.ResponseWriter, r *http.Request, mutation bool, group string, right apikey.Right) (string, *apikey.Principal, bool) {
	return h.principalFor(w, r, mutation, group, right, false)
}

func (h *Handler) principalFor(w http.ResponseWriter, r *http.Request, mutation bool, group string, right apikey.Right, allowDelegated bool) (string, *apikey.Principal, bool) {
	if apikey.HasAuthorization(r) {
		header, valid := apikey.Authorization(r)
		if !valid {
			h.genericUnauthorized(w)
			return "", nil, false
		}
		if h.store.apiKeys == nil {
			h.genericUnauthorized(w)
			return "", nil, false
		}
		key, err := h.store.apiKeys.Authenticate(r.Context(), header)
		if err != nil {
			h.genericUnauthorized(w)
			return "", nil, false
		}
		if err := h.store.apiKeys.Authorize(r.Context(), key, group, right); err != nil {
			h.error(w, http.StatusForbidden, "Forbidden")
			return "", nil, false
		}
		return "", &key, true
	}
	actor, ok := h.actorFor(w, r, mutation, allowDelegated)
	return actor, nil, ok
}

type entityRequest struct {
	Name string
	Meta json.RawMessage
}

type loginRestrictionRequest struct {
	RestrictGroupPrefix *string
	Revision            int64
}

func decodeLoginRestriction(w http.ResponseWriter, r *http.Request) (loginRestrictionRequest, error) {
	if len(r.Header.Values("Content-Type")) != 1 {
		return loginRestrictionRequest{}, errors.New("content type")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return loginRestrictionRequest{}, errors.New("content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 || rejectDuplicateJSONFields(body) != nil {
		return loginRestrictionRequest{}, errors.New("invalid JSON")
	}
	var wire struct {
		RestrictGroupPrefix json.RawMessage `json:"restrict_group_prefix"`
		Revision            *int64          `json:"revision"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Revision == nil || len(wire.RestrictGroupPrefix) == 0 || *wire.Revision < 0 {
		return loginRestrictionRequest{}, errors.New("invalid login restriction")
	}
	if bytes.Equal(wire.RestrictGroupPrefix, []byte("null")) {
		return loginRestrictionRequest{Revision: *wire.Revision}, nil
	}
	var prefix string
	if json.Unmarshal(wire.RestrictGroupPrefix, &prefix) != nil || ValidateGroupPrefix(prefix) != nil {
		return loginRestrictionRequest{}, errors.New("invalid group prefix")
	}
	return loginRestrictionRequest{RestrictGroupPrefix: &prefix, Revision: *wire.Revision}, nil
}

type membershipPatch struct {
	Roles, Groups               []string
	ReplaceRoles, ReplaceGroups bool
}

// decodeMembershipPatch accepts Rauthy's PatchOp envelope but deliberately
// limits keys to roles/groups until the rest of admin user management exists.
func decodeMembershipPatch(w http.ResponseWriter, r *http.Request) (membershipPatch, error) {
	if len(r.Header.Values("Content-Type")) != 1 {
		return membershipPatch{}, errors.New("content type")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return membershipPatch{}, errors.New("content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 || rejectDuplicateJSONFields(body) != nil {
		return membershipPatch{}, errors.New("invalid JSON")
	}
	var wire struct {
		Put *[]struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		} `json:"put"`
		Del *[]string `json:"del"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Put == nil || wire.Del == nil {
		return membershipPatch{}, errors.New("invalid JSON")
	}
	patch := membershipPatch{}
	seen := map[string]struct{}{}
	for _, put := range *wire.Put {
		if put.Key != "roles" && put.Key != "groups" {
			return membershipPatch{}, errors.New("unsupported patch key")
		}
		if _, exists := seen[put.Key]; exists || !json.Valid(put.Value) {
			return membershipPatch{}, errors.New("duplicate patch key")
		}
		seen[put.Key] = struct{}{}
		values, err := patchNames(put.Value, put.Key == "groups")
		if err != nil {
			return membershipPatch{}, err
		}
		if put.Key == "roles" {
			patch.Roles, patch.ReplaceRoles = values, true
		} else {
			patch.Groups, patch.ReplaceGroups = values, true
		}
	}
	for _, key := range *wire.Del {
		if key != "roles" && key != "groups" {
			return membershipPatch{}, errors.New("unsupported patch key")
		}
		if _, exists := seen[key]; exists {
			return membershipPatch{}, errors.New("duplicate patch key")
		}
		seen[key] = struct{}{}
		if key == "roles" {
			patch.Roles, patch.ReplaceRoles = []string{}, true
		} else {
			patch.Groups, patch.ReplaceGroups = []string{}, true
		}
	}
	return patch, nil
}

func patchNames(raw json.RawMessage, group bool) ([]string, error) {
	var values []string
	if json.Unmarshal(raw, &values) != nil || len(values) > maxMemberships {
		return nil, errors.New("invalid membership values")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if (group && ValidateGroupName(value) != nil) || (!group && ValidateRoleName(value) != nil) {
			return nil, errors.New("invalid membership name")
		}
		if _, exists := seen[value]; exists {
			return nil, errors.New("duplicate membership name")
		}
		seen[value] = struct{}{}
	}
	return values, nil
}

// rejectDuplicateJSONFields walks nested structures because encoding/json
// otherwise silently accepts duplicate key/value pairs.
func rejectDuplicateJSONFields(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, exists := seen[name]; exists {
				return errors.New("duplicate JSON key")
			}
			seen[name] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func decodeRequest(w http.ResponseWriter, r *http.Request, role bool) (entityRequest, error) {
	if len(r.Header.Values("Content-Type")) != 1 {
		return entityRequest{}, errors.New("content type")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return entityRequest{}, errors.New("content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 || duplicateFields(body) != nil {
		return entityRequest{}, errors.New("invalid JSON")
	}
	var wire struct {
		Role  *string         `json:"role"`
		Group *string         `json:"group"`
		Meta  json.RawMessage `json:"meta"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return entityRequest{}, errors.New("invalid JSON")
	}
	if role && (wire.Role == nil || wire.Group != nil) || !role && (wire.Group == nil || wire.Role != nil) {
		return entityRequest{}, errors.New("invalid request")
	}
	name := ""
	if role {
		name = *wire.Role
	} else {
		name = *wire.Group
	}
	if len(wire.Meta) != 0 && !json.Valid(wire.Meta) {
		return entityRequest{}, errors.New("invalid metadata")
	}
	if bytes.Equal(wire.Meta, []byte("null")) {
		wire.Meta = nil
	}
	return entityRequest{Name: name, Meta: wire.Meta}, nil
}

func duplicateFields(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("object required")
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("invalid key")
		}
		if _, exists := seen[key]; exists {
			return errors.New("duplicate key")
		}
		seen[key] = struct{}{}
		var discard json.RawMessage
		if err := decoder.Decode(&discard); err != nil {
			return err
		}
	}
	token, err = decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return errors.New("object required")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func validID(id string) bool {
	return len(id) > 0 && len(id) <= 64 && !strings.ContainsAny(id, "/\\\r\n")
}

func validSubjectID(subject string) bool {
	return len(subject) > 0 && len(subject) <= 512 && strings.TrimSpace(subject) == subject
}

func (h *Handler) crossSite(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site")
}

func (h *Handler) securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
}

func (h *Handler) writeEntities(w http.ResponseWriter, entities []Entity) {
	w.Header().Set("Content-Type", "application/json")
	response := make([]entityResponse, len(entities))
	for i, entity := range entities {
		response[i] = responseEntity(entity)
	}
	_ = json.NewEncoder(w).Encode(response)
}

func (h *Handler) writeEntity(w http.ResponseWriter, entity Entity) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(responseEntity(entity))
}

func (h *Handler) writeLoginRestriction(w http.ResponseWriter, policy BootstrapClientLoginRestriction) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		ClientID            string  `json:"client_id"`
		RestrictGroupPrefix *string `json:"restrict_group_prefix"`
		Revision            int64   `json:"revision"`
	}{policy.ClientID, policy.RestrictGroupPrefix, policy.Revision})
}

// entityResponse deliberately omits revision: Rauthy's public role/group
// representation has only the stable ID, name, and optional metadata.
type entityResponse struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Meta json.RawMessage `json:"meta,omitempty"`
}

// membershipDocument is deliberately only the membership-compatible subset of
// Rauthy's UserResponse while admin profile lifecycle is still unimplemented.
type membershipDocument struct {
	ID     string   `json:"id"`
	Roles  []string `json:"roles"`
	Groups []string `json:"groups"`
}

func membershipResponse(id string, principal Principal) membershipDocument {
	roles := make([]string, len(principal.Roles))
	for i, role := range principal.Roles {
		roles[i] = role.Name
	}
	groups := make([]string, len(principal.Groups))
	for i, group := range principal.Groups {
		groups[i] = group.Name
	}
	return membershipDocument{ID: id, Roles: roles, Groups: groups}
}

func responseEntity(entity Entity) entityResponse {
	return entityResponse{ID: entity.ID, Name: entity.Name, Meta: entity.Meta}
}

func (h *Handler) writeLookupError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		h.notFound(w)
		return
	}
	h.unavailable(w)
}

func (h *Handler) writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnauthorized):
		h.genericUnauthorized(w)
	case errors.Is(err, ErrConflict):
		h.error(w, http.StatusConflict, "Conflict")
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrReserved), errors.Is(err, ErrInactiveSubject):
		h.badRequest(w)
	case errors.Is(err, ErrNotFound):
		h.notFound(w)
	default:
		h.unavailable(w)
	}
}

func (h *Handler) genericUnauthorized(w http.ResponseWriter) {
	h.error(w, http.StatusUnauthorized, "Unauthorized")
}
func (h *Handler) notFound(w http.ResponseWriter) { h.error(w, http.StatusNotFound, "Not Found") }
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
