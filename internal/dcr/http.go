// Package dcr implements the narrow RFC 7591 registration boundary.
package dcr

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/redirecturi"
)

const registrationBodyLimit = 16 << 10

const registrationPath = "/oidc/register"

// deviceGrantType is kept local because importing internal/oauth would create
// a package cycle. Keep the wire value identical to oauth.DeviceGrantType.
const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// LoadRegistrationToken loads the mounted global DCR bearer token without
// exposing its value in errors.
func LoadRegistrationToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("read DCR registration token")
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || len(token) > 256 || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return "", errors.New("invalid DCR registration token")
	}
	return token, nil
}

// Handler exposes registration creation and read-only self-management.
type Handler struct {
	store               *Store
	issuer              string
	globalToken         string
	allowAnonymous      bool
	anonymousRateWindow time.Duration
	statementPolicy     *softwareStatementPolicy
	allowedResources    map[string]struct{}
}

// HandlerConfig controls registration methods that do not use a global bearer.
type HandlerConfig struct {
	Anonymous                bool
	AnonymousRateLimitWindow time.Duration
	SoftwareStatements       SoftwareStatementConfig
	AllowedResources         []string
}

// NewHandler returns a disabled (404) handler when neither globalBearer nor
// anonymous registration is configured.
func NewHandler(store *Store, issuer, globalBearer string, configs ...HandlerConfig) (http.Handler, error) {
	issuer, err := oidc.NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("DCR handler requires store")
	}
	config := HandlerConfig{}
	if len(configs) > 0 {
		config = configs[0]
	}
	if config.Anonymous && config.AnonymousRateLimitWindow <= 0 {
		return nil, errors.New("DCR anonymous rate limit window must be positive")
	}
	if (globalBearer != "" || config.Anonymous) && store.keyring == nil {
		return nil, errors.New("DCR handler requires envelope keyring")
	}
	statementPolicy, err := newSoftwareStatementPolicy(config.SoftwareStatements)
	if err != nil {
		return nil, err
	}
	allowedResources := make(map[string]struct{}, len(config.AllowedResources))
	for _, resource := range config.AllowedResources {
		if !validMetadataURI(resource) {
			return nil, errors.New("DCR handler requires valid HTTPS allowed resources")
		}
		if _, exists := allowedResources[resource]; exists {
			return nil, errors.New("DCR handler allowed resources must be unique")
		}
		allowedResources[resource] = struct{}{}
	}
	return &Handler{store: store, issuer: issuer, globalToken: globalBearer, allowAnonymous: config.Anonymous, anonymousRateWindow: config.AnonymousRateLimitWindow, statementPolicy: statementPolicy, allowedResources: allowedResources}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.globalToken == "" && !h.allowAnonymous {
		writeNotFound(w)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == registrationPath {
		h.create(w, r)
		return
	}
	if r.Method == http.MethodGet {
		if id, ok := registrationID(r.URL.Path); ok {
			h.get(w, r, id)
			return
		}
	}
	if r.Method == http.MethodPut {
		if id, ok := registrationID(r.URL.Path); ok {
			h.update(w, r, id)
			return
		}
	}
	if r.Method == http.MethodDelete {
		if id, ok := deleteRegistrationID(r); ok {
			h.delete(w, r, id)
			return
		}
	}
	writeNotFound(w)
}

func registrationID(path string) (string, bool) {
	const prefix = registrationPath + "/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	id := strings.TrimPrefix(path, prefix)
	return id, id != "" && !strings.Contains(id, "/")
}

// deleteRegistrationID accepts only the canonical URI emitted in a DCR
// response. Dynamic client IDs contain no escapable characters, so accepting
// an escaped path would create a second interpretation at a proxy boundary.
func deleteRegistrationID(r *http.Request) (string, bool) {
	if r.URL.RawPath != "" {
		return "", false
	}
	return registrationID(r.URL.Path)
}

type registrationRequest struct {
	ClientID                     *string   `json:"client_id"`
	RedirectURIs                 []string  `json:"redirect_uris"`
	GrantTypes                   []string  `json:"grant_types"`
	ResponseTypes                []string  `json:"response_types"`
	TokenEndpointAuthMethod      string    `json:"token_endpoint_auth_method"`
	ClientName                   string    `json:"client_name"`
	ClientURI                    *string   `json:"client_uri"`
	LogoURI                      *string   `json:"logo_uri"`
	TOSURI                       *string   `json:"tos_uri"`
	PolicyURI                    *string   `json:"policy_uri"`
	Contacts                     *[]string `json:"contacts"`
	SoftwareStatement            *string   `json:"software_statement"`
	DPoPBoundAccessTokens        *bool     `json:"dpop_bound_access_tokens"`
	BackchannelLogoutURI         *string   `json:"backchannel_logout_uri"`
	Audiences                    *[]string `json:"audience"`
	clientIDPresent              bool
	clientURIPresent             bool
	logoURIPresent               bool
	tosURIPresent                bool
	policyURIPresent             bool
	contactsPresent              bool
	softwareStatementPresent     bool
	dpopBoundAccessTokensPresent bool
	audiencePresent              bool
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	TOSURI                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	SoftwareStatement       string   `json:"software_statement,omitempty"`
	DPoPBoundAccessTokens   bool     `json:"dpop_bound_access_tokens"`
	BackchannelLogoutURI    string   `json:"backchannel_logout_uri,omitempty"`
	Audiences               []string `json:"audience,omitempty"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	anonymous := h.globalToken == "" && h.allowAnonymous
	if anonymous {
		if len(r.Header.Values("Authorization")) != 0 {
			writeUnauthorized(w)
			return
		}
	} else if !sameBearer(r, h.globalToken) {
		writeUnauthorized(w)
		return
	}
	key, ok := idempotencyKey(r)
	if !ok {
		writeError(w, http.StatusBadRequest)
		return
	}
	if r.URL.RawQuery != "" || !jsonContentType(r) {
		writeError(w, http.StatusBadRequest)
		return
	}
	request, err := decodeRegistrationRequest(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	if request.softwareStatementPresent {
		if request.SoftwareStatement == nil {
			writeRegistrationError(w, "invalid_software_statement")
			return
		}
		request, _, err = h.statementPolicy.merge(*request.SoftwareStatement, request)
		if err != nil {
			writeRegistrationError(w, softwareStatementErrorCode(err))
			return
		}
	}
	if anonymous && request.audiencePresent {
		writeError(w, http.StatusBadRequest)
		return
	}
	if anonymous && (request.clientURIPresent || request.logoURIPresent || request.tosURIPresent || request.policyURIPresent) {
		writeError(w, http.StatusBadRequest)
		return
	}
	if request.clientIDPresent || (request.clientURIPresent && request.ClientURI == nil) || (request.logoURIPresent && request.LogoURI == nil) || (request.tosURIPresent && request.TOSURI == nil) || (request.policyURIPresent && request.PolicyURI == nil) || (request.contactsPresent && request.Contacts == nil) {
		writeError(w, http.StatusBadRequest)
		return
	}
	policy, err := h.store.ScopePolicy()
	if err != nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	create, err := request.createRequest(h.store.allowLoopback, policy)
	if err != nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	if !h.allowed(create.Audiences) {
		writeError(w, http.StatusBadRequest)
		return
	}
	digest, err := effectiveCreateDigest(create)
	if err != nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	buildResponse := func(registration Registration) ([]byte, error) {
		return registrationResponseBody(h.issuer, registration, true)
	}
	var result idempotentRegistration
	if anonymous {
		peerIP, peerErr := netip.ParseAddr(browser.PeerIPFromContext(r.Context()))
		if peerErr != nil || !peerIP.IsValid() || peerIP.IsUnspecified() {
			writeError(w, http.StatusBadRequest)
			return
		}
		result, err = h.store.CreateAnonymousIdempotent(r.Context(), create, key, peerIP, digest, h.anonymousRateWindow, buildResponse)
	} else {
		result, err = h.store.CreateIdempotent(r.Context(), create, key, h.globalToken, digest, buildResponse)
	}
	if err != nil {
		switch {
		case errors.Is(err, ErrRateLimited):
			var limited *RateLimitError
			if errors.As(err, &limited) {
				writeRateLimited(w, limited.RetryNotBefore)
				return
			}
			writeRateLimited(w, time.Time{})
		case errors.Is(err, ErrIdempotencyMismatch):
			writeError(w, http.StatusUnprocessableEntity)
		default:
			writeError(w, http.StatusBadRequest)
		}
		return
	}
	writeRawJSON(w, http.StatusCreated, result.response)
}

func writeRateLimited(w http.ResponseWriter, retryNotBefore time.Time) {
	if !retryNotBefore.IsZero() {
		w.Header().Set("X-Retry-Not-Before", strconv.FormatInt(retryNotBefore.Unix(), 10))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request, id string) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest)
		return
	}
	token, ok := bearer(r)
	if !ok {
		writeUnauthorized(w)
		return
	}
	registration, err := h.store.GetRegistration(r.Context(), id, token)
	if err != nil {
		writeUnauthorized(w)
		return
	}
	writeRegistration(w, http.StatusOK, h.issuer, registration, false)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request, id string) {
	if r.URL.RawQuery != "" || !jsonContentType(r) {
		writeError(w, http.StatusBadRequest)
		return
	}
	token, ok := bearer(r)
	if !ok {
		writeUnauthorized(w)
		return
	}
	request, err := decodeRegistrationRequest(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	existing, _, authErr := h.store.authenticateRegistration(r.Context(), id, token)
	if authErr != nil {
		writeUpdateError(w, authErr)
		return
	}
	if request.softwareStatementPresent {
		if request.SoftwareStatement == nil {
			writeRegistrationError(w, "invalid_software_statement")
			return
		}
		request, _, err = h.statementPolicy.merge(*request.SoftwareStatement, request)
		if err != nil {
			writeRegistrationError(w, softwareStatementErrorCode(err))
			return
		}
	}
	if existing.Anonymous && (request.clientURIPresent || request.logoURIPresent || request.tosURIPresent || request.policyURIPresent || request.audiencePresent) {
		writeError(w, http.StatusBadRequest)
		return
	}
	if !request.clientIDPresent || request.ClientID == nil || *request.ClientID == "" || subtle.ConstantTimeCompare([]byte(*request.ClientID), []byte(id)) != 1 {
		writeError(w, http.StatusBadRequest)
		return
	}
	policy, err := h.store.ScopePolicy()
	if err != nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	update, err := request.createRequest(h.store.allowLoopback, policy)
	if err != nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	if !h.allowed(update.Audiences) {
		writeError(w, http.StatusBadRequest)
		return
	}
	registration, err := h.store.Update(r.Context(), id, token, update)
	if err != nil {
		writeUpdateError(w, err)
		return
	}
	writeRegistration(w, http.StatusOK, h.issuer, registration, true)
}

func (h *Handler) allowed(audiences []string) bool {
	for _, audience := range audiences {
		if _, ok := h.allowedResources[audience]; !ok {
			return false
		}
	}
	return true
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request, id string) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || !emptyBody(r) {
		writeError(w, http.StatusBadRequest)
		return
	}
	token, ok := bearer(r)
	if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(h.globalToken)) == 1 {
		writeUnauthorized(w)
		return
	}
	if err := h.store.DeleteRegistration(r.Context(), id, token); err != nil {
		if errors.Is(err, ErrUnauthorized) {
			writeUnauthorized(w)
			return
		}
		writeError(w, http.StatusBadRequest)
		return
	}
	writeNoContent(w)
}

func emptyBody(r *http.Request) bool {
	if r.Body == nil {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1))
	return err == nil && len(body) == 0
}

func writeUpdateError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrUnauthorized) {
		writeUnauthorized(w)
		return
	}
	if errors.Is(err, ErrConflict) {
		writeError(w, http.StatusConflict)
		return
	}
	writeError(w, http.StatusBadRequest)
}

func decodeRegistrationRequest(w http.ResponseWriter, r *http.Request) (registrationRequest, error) {
	r.Body = http.MaxBytesReader(w, r.Body, registrationBodyLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return registrationRequest{}, err
	}
	if err := rejectDuplicateTopLevelFields(body); err != nil {
		return registrationRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var request registrationRequest
	if err := decoder.Decode(&request); err != nil {
		return registrationRequest{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return registrationRequest{}, err
	}
	_, request.clientIDPresent = fields["client_id"]
	_, request.clientURIPresent = fields["client_uri"]
	_, request.logoURIPresent = fields["logo_uri"]
	_, request.tosURIPresent = fields["tos_uri"]
	_, request.policyURIPresent = fields["policy_uri"]
	_, request.contactsPresent = fields["contacts"]
	_, request.softwareStatementPresent = fields["software_statement"]
	_, request.dpopBoundAccessTokensPresent = fields["dpop_bound_access_tokens"]
	_, request.audiencePresent = fields["audience"]
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return registrationRequest{}, errors.New("multiple JSON values")
	}
	return request, nil
}

func rejectDuplicateTopLevelFields(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("registration body must be an object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("invalid registration field")
		}
		if _, exists := seen[name]; exists {
			return errors.New("duplicate registration field")
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	token, err = decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return errors.New("registration body must be an object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func (r registrationRequest) createRequest(allowLoopback bool, policy ScopePolicy) (CreateRequest, error) {
	if r.audiencePresent && r.Audiences == nil {
		return CreateRequest{}, errors.New("invalid registration metadata")
	}
	if r.dpopBoundAccessTokensPresent && r.DPoPBoundAccessTokens == nil {
		return CreateRequest{}, errors.New("invalid registration metadata")
	}
	clientURI := ""
	if r.ClientURI != nil {
		clientURI = *r.ClientURI
		if clientURI == "" {
			return CreateRequest{}, errors.New("invalid registration metadata")
		}
	}
	logoURI := ""
	if r.LogoURI != nil {
		logoURI = *r.LogoURI
		if logoURI == "" {
			return CreateRequest{}, errors.New("invalid registration metadata")
		}
	}
	tosURI := ""
	if r.TOSURI != nil {
		tosURI = *r.TOSURI
		if tosURI == "" {
			return CreateRequest{}, errors.New("invalid registration metadata")
		}
	}
	policyURI := ""
	if r.PolicyURI != nil {
		policyURI = *r.PolicyURI
		if policyURI == "" {
			return CreateRequest{}, errors.New("invalid registration metadata")
		}
	}
	var contacts []string
	if r.Contacts != nil {
		contacts = canonicalContacts(*r.Contacts)
	}
	if len(r.GrantTypes) == 0 {
		return CreateRequest{}, errors.New("invalid registration metadata")
	}
	for _, grant := range r.GrantTypes {
		if !validGrant(grant) {
			return CreateRequest{}, errors.New("invalid registration metadata")
		}
	}
	method := r.TokenEndpointAuthMethod
	if method == "" {
		method = "client_secret_basic"
	}
	if method != "none" && method != "client_secret_basic" && method != "client_secret_post" {
		return CreateRequest{}, errors.New("invalid token endpoint auth method")
	}
	hasCode := contains(r.GrantTypes, "authorization_code")
	hasDevice := contains(r.GrantTypes, deviceGrantType)
	hasPassword := contains(r.GrantTypes, "password")
	hasClientCredentials := contains(r.GrantTypes, "client_credentials")
	if !hasCode && !hasDevice && !hasClientCredentials && !hasPassword {
		return CreateRequest{}, errors.New("invalid registration metadata")
	}
	if contains(r.GrantTypes, "refresh_token") && !hasCode && !hasDevice && !hasPassword {
		return CreateRequest{}, errors.New("invalid registration metadata")
	}
	if hasClientCredentials && method == "none" {
		return CreateRequest{}, errors.New("invalid registration metadata")
	}
	if hasCode {
		if !validURIList(r.RedirectURIs, allowLoopback && r.TokenEndpointAuthMethod == "none") || !exactly(r.ResponseTypes, "code") {
			return CreateRequest{}, errors.New("invalid registration metadata")
		}
	} else if len(r.RedirectURIs) != 0 || len(r.ResponseTypes) != 0 {
		return CreateRequest{}, errors.New("invalid registration metadata")
	}
	if _, err := NewScopePolicy(policy.Allowed, policy.Default); err != nil || !validName(r.ClientName) {
		return CreateRequest{}, errors.New("invalid registration metadata")
	}
	statement := ""
	if r.SoftwareStatement != nil {
		statement = *r.SoftwareStatement
	}
	audiences := clone(nil)
	if r.Audiences != nil {
		audiences = clone(*r.Audiences)
	}
	dpopBound := false
	if r.DPoPBoundAccessTokens != nil {
		dpopBound = *r.DPoPBoundAccessTokens
	}
	backchannelLogout := ""
	if r.BackchannelLogoutURI != nil {
		if !backchannelURIPattern.MatchString(*r.BackchannelLogoutURI) {
			return CreateRequest{}, errors.New("invalid backchannel logout URI")
		}
		backchannelLogout = *r.BackchannelLogoutURI
	}
	return CreateRequest{ClientURI: clientURI, LogoURI: logoURI, TOSURI: tosURI, PolicyURI: policyURI, Contacts: contacts, RedirectURIs: r.RedirectURIs, Scopes: clone(policy.Allowed), DefaultScopes: clone(policy.Default), GrantTypes: r.GrantTypes, ResponseTypes: r.ResponseTypes, Audiences: audiences, TokenEndpointAuthMethod: method, Name: r.ClientName, SoftwareStatement: statement, DPoPBoundAccessTokens: dpopBound, BackchannelLogoutURI: backchannelLogout}, nil
}

func validURIList(uris []string, allowLoopback bool) bool {
	if len(uris) < 1 || len(uris) > 8 {
		return false
	}
	seen := make(map[string]struct{}, len(uris))
	for _, raw := range uris {
		if allowLoopback && redirecturi.IsLoopbackTemplate(raw) {
			if _, exists := seen[raw]; exists {
				return false
			}
			seen[raw] = struct{}{}
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.String() != raw || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host != strings.ToLower(parsed.Host) {
			return false
		}
		if _, exists := seen[raw]; exists {
			return false
		}
		seen[raw] = struct{}{}
	}
	return true
}

func exactly(values []string, want string) bool { return len(values) == 1 && values[0] == want }

func validName(name string) bool {
	if name == "" || len(name) > 128 || !utf8.ValidString(name) || strings.TrimSpace(name) != name {
		return false
	}
	return strings.IndexFunc(name, unicode.IsControl) < 0
}

func jsonContentType(r *http.Request) bool {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	return err == nil && mediaType == "application/json"
}

func sameBearer(r *http.Request, expected string) bool {
	token, ok := bearer(r)
	return ok && subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// Idempotency-Key is a single HTTP token, 1-128 ASCII bytes. Structured
// values are intentionally not accepted so proxies cannot reinterpret it.
func idempotencyKey(r *http.Request) (string, bool) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 128 {
		return "", false
	}
	for _, char := range values[0] {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			continue
		}
		return "", false
	}
	return values[0], true
}

func effectiveCreateDigest(request CreateRequest) (string, error) {
	method := request.TokenEndpointAuthMethod
	if method == "" {
		method = TokenEndpointAuthClientBasic
	}
	canonical := struct {
		ClientID                string   `json:"client_id"`
		RedirectURIs            []string `json:"redirect_uris"`
		Scopes                  []string `json:"scopes"`
		DefaultScopes           []string `json:"default_scopes"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		Audiences               []string `json:"audiences"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		Name                    string   `json:"name"`
		ClientURI               string   `json:"client_uri"`
		LogoURI                 string   `json:"logo_uri"`
		TOSURI                  string   `json:"tos_uri"`
		PolicyURI               string   `json:"policy_uri"`
		Contacts                []string `json:"contacts"`
		ForceMFA                bool     `json:"force_mfa"`
		SoftwareStatement       string   `json:"software_statement"`
		DPoPBoundAccessTokens   bool     `json:"dpop_bound_access_tokens"`
		BackchannelLogoutURI    string   `json:"backchannel_logout_uri"`
	}{request.ClientID, canonicalList(request.RedirectURIs), canonicalList(request.Scopes), canonicalList(request.DefaultScopes), canonicalList(request.GrantTypes), canonicalList(request.ResponseTypes), canonicalList(request.Audiences), method, request.Name, request.ClientURI, request.LogoURI, request.TOSURI, request.PolicyURI, canonicalContacts(request.Contacts), false, request.SoftwareStatement, request.DPoPBoundAccessTokens, request.BackchannelLogoutURI}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return digestString(string(encoded)), nil
}

func canonicalList(values []string) []string {
	cloned := append([]string(nil), values...)
	if cloned == nil {
		cloned = []string{}
	}
	sort.Strings(cloned)
	return cloned
}

func bearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	return token, token != "" && !strings.ContainsAny(token, " \t\r\n")
}

func writeRegistration(w http.ResponseWriter, status int, issuer string, registration Registration, includeCredentials bool) {
	body, err := registrationResponseBody(issuer, registration, includeCredentials)
	if err != nil {
		writeError(w, http.StatusInternalServerError)
		return
	}
	writeRawJSON(w, status, body)
}

func registrationResponseBody(issuer string, registration Registration, includeCredentials bool) ([]byte, error) {
	response := registrationResponse{ClientID: registration.ClientID, ClientSecretExpiresAt: 0, ClientURI: registration.ClientURI, LogoURI: registration.LogoURI, TOSURI: registration.TOSURI, PolicyURI: registration.PolicyURI, Contacts: canonicalContacts(registration.Contacts), RedirectURIs: registration.RedirectURIs, GrantTypes: registration.GrantTypes, ResponseTypes: registration.ResponseTypes, Audiences: registration.Audiences, TokenEndpointAuthMethod: registration.TokenEndpointAuthMethod, Scope: strings.Join(registration.Scopes, " "), ClientName: registration.Name, SoftwareStatement: registration.SoftwareStatement, DPoPBoundAccessTokens: registration.DPoPBoundAccessTokens, BackchannelLogoutURI: registration.BackchannelLogoutURI}
	if includeCredentials {
		response.ClientSecret = registration.ClientSecret
		response.RegistrationAccessToken = registration.RegistrationAccessToken
		response.RegistrationClientURI = issuer + "/oidc/register/" + registration.ClientID
	}
	body, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	writeError(w, http.StatusUnauthorized)
}

func writeNotFound(w http.ResponseWriter) { writeError(w, http.StatusNotFound) }

func writeError(w http.ResponseWriter, status int) {
	writeJSON(w, status, map[string]string{"error": "invalid_request"})
}

func writeRegistrationError(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

func softwareStatementErrorCode(err error) string {
	if errors.Is(err, errUnapprovedSoftwareStatement) {
		return "unapproved_software_statement"
	}
	return "invalid_software_statement"
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		return
	}
	writeRawJSON(w, status, append(body, '\n'))
}

func writeRawJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeNoContent(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNoContent)
}
