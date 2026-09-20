// Package fedcm implements the small, opt-in HTTP surface required by the
// Federated Credential Management API. It intentionally does not own account
// or session storage; callers inject those decisions at the trust boundary.
package fedcm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
)

const (
	manifestPath       = "/.well-known/web-identity"
	configPath         = "/auth/v1/fed_cm/config"
	accountsPath       = "/auth/v1/fed_cm/accounts"
	clientMetadataPath = "/auth/v1/fed_cm/client_meta"
	assertionPath      = "/auth/v1/fed_cm/token"
	statusPath         = "/auth/v1/fed_cm/status"
	maxQueryValue      = 256
	maxBodyBytes       = 8 << 10
	assertionLifetime  = 5 * time.Minute
)

const (
	ManifestPath       = manifestPath
	ConfigPath         = configPath
	AccountsPath       = accountsPath
	ClientMetadataPath = clientMetadataPath
	AssertionPath      = assertionPath
	StatusPath         = statusPath
)

var errUnavailable = errors.New("FedCM unavailable")

// Account is the public account projection returned to the browser. ID is
// also the subject bound into the signed assertion.
type Account struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Email           string   `json:"email"`
	Picture         string   `json:"picture,omitempty"`
	GivenName       string   `json:"given_name,omitempty"`
	ApprovedClients []string `json:"approved_clients,omitempty"`
	LoginHints      []string `json:"login_hints,omitempty"`
	DomainHints     []string `json:"domain_hints,omitempty"`
	// AuthTime is the authentication event this projection was resolved from.
	// The assertion signs it as auth_time and it is never sent to the browser.
	AuthTime time.Time `json:"-"`
}

// ClientMetadata is the privacy-policy projection for a relying party.
type ClientMetadata struct {
	PrivacyPolicyURL  string `json:"privacy_policy_url"`
	TermsOfServiceURL string `json:"terms_of_service_url"`
}

type ManifestDocument struct {
	ProviderURLs []string `json:"provider_urls"`
}

type ProviderConfig struct {
	AccountsEndpoint       string `json:"accounts_endpoint"`
	ClientMetadataEndpoint string `json:"client_metadata_endpoint"`
	IDAssertionEndpoint    string `json:"id_assertion_endpoint"`
	LoginURL               string `json:"login_url"`
}

type AccountsResponse struct {
	Accounts []Account `json:"accounts"`
}

type AssertionResponse struct {
	Token string `json:"token"`
}

// Config contains policy and resolver hooks for Handler. Enabled is an
// explicit opt-in; a zero Config never advertises or serves FedCM.
type Config struct {
	Issuer              string
	Enabled             bool
	ClientOrigin        string
	ClientID            string
	ProviderURL         string
	LoginURL            string
	PrivacyPolicyURL    string
	TermsOfServiceURL   string
	ClientOrigins       map[string]string
	ResolveAccounts     func(context.Context, *http.Request) ([]Account, error)
	ResolveCurrent      func(context.Context, *http.Request) (Account, error)
	ResolveAccount      func(context.Context, string) (Account, error)
	ResolveClient       func(context.Context, string) (ClientMetadata, error)
	ResolveClientOrigin func(context.Context, string) (string, error)
	LoadSigningKey      func(context.Context) (oidc.SigningKey, error)
	SigningKey          *oidc.SigningKey
	Now                 func() time.Time
}

// Handler serves the six FedCM endpoints below the configured issuer.
type Handler struct {
	issuer              string
	origin              string
	clientID            string
	providerURL         string
	loginURL            string
	enabled             bool
	accounts            func(context.Context, *http.Request) ([]Account, error)
	current             func(context.Context, *http.Request) (Account, error)
	account             func(context.Context, string) (Account, error)
	client              func(context.Context, string) (ClientMetadata, error)
	loadKey             func(context.Context) (oidc.SigningKey, error)
	now                 func() time.Time
	metadata            ClientMetadata
	clientOrigins       map[string]string
	resolveClientOrigin func(context.Context, string) (string, error)
}

// NewHandler validates the issuer and exact registered client Origin.
func NewHandler(cfg Config) (*Handler, error) {
	issuer, err := oidc.NormalizeIssuer(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	static := cfg.ClientID != "" || cfg.ClientOrigin != ""
	perClient := cfg.ResolveClientOrigin != nil || len(cfg.ClientOrigins) != 0
	if cfg.ResolveClientOrigin != nil && len(cfg.ClientOrigins) != 0 {
		return nil, errors.New("FedCM client binding modes are ambiguous")
	}
	if static && (cfg.ClientID == "" || cfg.ClientOrigin == "") || static && perClient || !static && !perClient {
		return nil, errors.New("FedCM requires one complete client binding mode")
	}
	if cfg.ClientID != "" && !validClientID(cfg.ClientID) {
		return nil, errors.New("invalid FedCM client ID")
	}
	origin := cfg.ClientOrigin
	if origin != "" {
		origin, err = exactOrigin(origin)
		if err != nil {
			return nil, errors.New("invalid FedCM client origin")
		}
	}
	for clientID, clientOrigin := range cfg.ClientOrigins {
		if !validClientID(clientID) {
			return nil, errors.New("invalid FedCM client ID")
		}
		if _, err := exactOrigin(clientOrigin); err != nil {
			return nil, errors.New("invalid FedCM client origin")
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	provider := cfg.ProviderURL
	if provider == "" {
		provider = issuer + configPath
	}
	if err := absoluteURL(provider); err != nil {
		return nil, errors.New("invalid FedCM provider URL")
	}
	login := cfg.LoginURL
	if login == "" {
		login = "/auth/v1/account"
	}
	if err := relativeLoginURL(login); err != nil {
		return nil, errors.New("invalid FedCM login URL")
	}
	var clientOrigins map[string]string
	if len(cfg.ClientOrigins) != 0 {
		clientOrigins = make(map[string]string, len(cfg.ClientOrigins))
		for key, value := range cfg.ClientOrigins {
			clientOrigins[key] = value
		}
	}
	h := &Handler{
		issuer: issuer, origin: origin, clientID: cfg.ClientID, providerURL: provider, loginURL: login,
		enabled: cfg.Enabled, accounts: cfg.ResolveAccounts, current: cfg.ResolveCurrent,
		account: cfg.ResolveAccount, client: cfg.ResolveClient, now: cfg.Now,
		metadata:      ClientMetadata{PrivacyPolicyURL: cfg.PrivacyPolicyURL, TermsOfServiceURL: cfg.TermsOfServiceURL},
		clientOrigins: clientOrigins, resolveClientOrigin: cfg.ResolveClientOrigin,
	}
	if cfg.LoadSigningKey != nil {
		h.loadKey = cfg.LoadSigningKey
	} else if cfg.SigningKey != nil {
		key := *cfg.SigningKey
		h.loadKey = func(context.Context) (oidc.SigningKey, error) { return key, nil }
	}
	return h, nil
}

// ServeHTTP dispatches exact paths and rejects all unrecognized methods and
// routes. Parent muxes may mount this handler at the issuer root.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.prepare(w, r)
	if !h.enabled {
		writeError(w, http.StatusNotFound)
		return
	}
	switch r.URL.Path {
	case manifestPath:
		h.Manifest(w, r)
	case configPath:
		h.Config(w, r)
	case accountsPath:
		h.Accounts(w, r)
	case clientMetadataPath:
		h.ClientMetadata(w, r)
	case assertionPath:
		h.Assertion(w, r)
	case statusPath:
		h.Status(w, r)
	default:
		writeError(w, http.StatusNotFound)
	}
}

// Manifest serves /.well-known/web-identity.
func (h *Handler) Manifest(w http.ResponseWriter, r *http.Request) {
	h.prepare(w, r)
	if !h.guard(w, r, http.MethodGet, false, false) || r.URL.RawQuery != "" {
		return
	}
	writeJSON(w, http.StatusOK, ManifestDocument{ProviderURLs: []string{h.providerURL}})
}

// Config serves the FedCM provider configuration document.
func (h *Handler) Config(w http.ResponseWriter, r *http.Request) {
	h.prepare(w, r)
	if !h.guard(w, r, http.MethodGet, false, false) || r.URL.RawQuery != "" {
		return
	}
	writeJSON(w, http.StatusOK, ProviderConfig{
		AccountsEndpoint: accountsPath, ClientMetadataEndpoint: clientMetadataPath,
		IDAssertionEndpoint: assertionPath, LoginURL: h.loginURL,
	})
}

// Accounts returns only the currently authenticated account. A missing
// resolver fails closed rather than exposing a synthetic account list.
func (h *Handler) Accounts(w http.ResponseWriter, r *http.Request) {
	h.prepare(w, r)
	if !h.guard(w, r, http.MethodGet, false, false) {
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest)
		return
	}
	if h.accounts == nil {
		if h.current == nil {
			setLogin(w, "logged-out")
			writeJSON(w, http.StatusUnauthorized, AccountsResponse{Accounts: []Account{}})
			return
		}
		account, err := h.current(r.Context(), r)
		if err != nil || !validAccount(account) {
			setLogin(w, "logged-out")
			writeJSON(w, http.StatusUnauthorized, AccountsResponse{Accounts: []Account{}})
			return
		}
		setLogin(w, "logged-in")
		writeJSON(w, http.StatusOK, AccountsResponse{Accounts: []Account{account}})
		return
	}
	accounts, err := h.accounts(r.Context(), r)
	if err != nil {
		setLogin(w, "logged-out")
		writeJSON(w, http.StatusUnauthorized, AccountsResponse{Accounts: []Account{}})
		return
	}
	if !validAccounts(accounts) {
		setLogin(w, "logged-out")
		writeJSON(w, http.StatusUnauthorized, AccountsResponse{Accounts: []Account{}})
		return
	}
	if len(accounts) == 0 {
		setLogin(w, "logged-out")
		writeJSON(w, http.StatusUnauthorized, AccountsResponse{Accounts: accounts})
		return
	}
	setLogin(w, "logged-in")
	writeJSON(w, http.StatusOK, AccountsResponse{Accounts: accounts})
}

// ClientMetadata returns policy links for the exact requested client ID.
func (h *Handler) ClientMetadata(w http.ResponseWriter, r *http.Request) {
	h.prepare(w, r)
	if !h.guard(w, r, http.MethodGet, true, true) {
		return
	}
	clientID, ok := clientIDQuery(r)
	if !ok {
		writeError(w, http.StatusBadRequest)
		return
	}
	if !validRequestOrigin(r.Header.Get("Origin")) || !h.allowClientOrigin(r.Context(), clientID, r.Header.Get("Origin")) {
		writeError(w, http.StatusForbidden)
		return
	}
	setCORS(w, r.Header.Get("Origin"))
	metadata := h.metadata
	if h.client != nil {
		var err error
		metadata, err = h.client(r.Context(), clientID)
		if err != nil {
			writeError(w, http.StatusBadRequest)
			return
		}
	}
	if !validMetadata(metadata) {
		writeError(w, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, metadata)
}

// Assertion issues an EdDSA JWT whose issuer, audience, subject and nonce are
// all request-bound. The current-account resolver is checked again here.
func (h *Handler) Assertion(w http.ResponseWriter, r *http.Request) {
	h.prepare(w, r)
	if !h.guard(w, r, http.MethodPost, true, false) {
		return
	}
	if h.current == nil || h.loadKey == nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	in, ok := parseAssertionForm(w, r)
	if !ok {
		return
	}
	if !validRequestOrigin(r.Header.Get("Origin")) || !h.allowClientOrigin(r.Context(), in.ClientID, r.Header.Get("Origin")) {
		writeError(w, http.StatusForbidden)
		return
	}
	setCORS(w, r.Header.Get("Origin"))
	current, err := h.current(r.Context(), r)
	if err != nil || !validAccount(current) || current.ID != in.AccountID {
		setLogin(w, "logged-out")
		writeError(w, http.StatusUnauthorized)
		return
	}
	// The live session is the only source of authentication time. Resolving the
	// account again by subject must not turn an old session into a fresh login.
	authTime := current.AuthTime
	if h.account != nil {
		resolved, resolveErr := h.account(r.Context(), in.AccountID)
		if resolveErr != nil || !validAccount(resolved) || resolved.ID != current.ID {
			writeError(w, http.StatusUnauthorized)
			return
		}
		current = resolved
	}
	key, err := h.loadKey(r.Context())
	if err != nil {
		setLogin(w, "logged-out")
		writeError(w, http.StatusServiceUnavailable)
		return
	}
	now := h.now().UTC()
	if authTime.After(now) {
		// A session clock ahead of the signing clock is not a freshness claim
		// this provider can support, so omit auth_time rather than sign a future
		// authentication event.
		authTime = time.Time{}
	}
	token, err := oidc.SignIDToken(key, oidc.IDTokenClaims{
		Issuer: h.issuer, Subject: current.ID, Audience: []string{in.ClientID},
		IssuedAt: now, ExpiresAt: now.Add(assertionLifetime), NotBefore: now,
		Nonce: in.Nonce, AuthTime: authTime,
		Roles: []string{},
	})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, AssertionResponse{Token: token})
}

// Status reports the login status of the current browser account.
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	h.prepare(w, r)
	if !h.guard(w, r, http.MethodGet, false, false) {
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest)
		return
	}
	status := "logged-out"
	if h.current != nil {
		if account, err := h.current(r.Context(), r); err == nil && validAccount(account) {
			status = "logged-in"
		}
	}
	setLogin(w, status)
	if status == "logged-out" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Disconnect and onboarding are intentionally unsupported in this minimal
// core; they are never advertised by the provider configuration.
func (h *Handler) Disconnect(w http.ResponseWriter, r *http.Request) {
	h.prepare(w, r)
	writeError(w, http.StatusNotFound)
}

func (h *Handler) Onboarding(w http.ResponseWriter, r *http.Request) {
	h.prepare(w, r)
	writeError(w, http.StatusNotFound)
}

type IdentityAssertionRequest struct {
	AccountID           string `json:"account_id" form:"account_id"`
	ClientID            string `json:"client_id" form:"client_id"`
	Nonce               string `json:"nonce" form:"nonce"`
	DisclosureTextShown bool   `json:"disclosure_text_shown" form:"disclosure_text_shown"`
}

type assertionRequest = IdentityAssertionRequest

func (h *Handler) prepare(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (h *Handler) guard(w http.ResponseWriter, r *http.Request, method string, origin, query bool) bool {
	if !h.enabled {
		writeError(w, http.StatusNotFound)
		return false
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeError(w, http.StatusMethodNotAllowed)
		return false
	}
	dest, ok := oneHeader(r, "Sec-Fetch-Dest")
	if !ok || dest != "webidentity" {
		writeError(w, http.StatusForbidden)
		return false
	}
	originValues := headerValues(r, "Origin")
	if origin && (len(originValues) != 1 || originValues[0] == "") || !origin && len(originValues) != 0 {
		writeError(w, http.StatusForbidden)
		return false
	}
	if !query && r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest)
		return false
	}
	return true
}

func clientIDQuery(r *http.Request) (string, bool) {
	values := r.URL.Query()
	if len(values) != 1 || len(values["client_id"]) != 1 {
		return "", false
	}
	value := values["client_id"][0]
	return value, validClientID(value)
}

func parseAssertionForm(w http.ResponseWriter, r *http.Request) (assertionRequest, bool) {
	if r.URL.RawQuery != "" || !validFormContentType(r) {
		writeError(w, http.StatusBadRequest)
		return assertionRequest{}, false
	}
	reader := io.LimitReader(r.Body, maxBodyBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil || len(data) == 0 || len(data) > maxBodyBytes {
		writeError(w, http.StatusBadRequest)
		return assertionRequest{}, false
	}
	values, err := url.ParseQuery(string(data))
	if err != nil || len(values) < 3 || len(values) > 8 {
		writeError(w, http.StatusBadRequest)
		return assertionRequest{}, false
	}
	for key, value := range values {
		switch key {
		case "account_id", "client_id", "nonce", "disclosure_text_shown", "is_auto_selected", "mode", "fields", "disclosure_shown_for":
		default:
			writeError(w, http.StatusBadRequest)
			return assertionRequest{}, false
		}
		if len(value) != 1 || value[0] == "" || len(value[0]) > maxQueryValue || strings.TrimSpace(value[0]) != value[0] {
			writeError(w, http.StatusBadRequest)
			return assertionRequest{}, false
		}
	}
	in := assertionRequest{AccountID: values.Get("account_id"), ClientID: values.Get("client_id"), Nonce: values.Get("nonce")}
	if _, ok := values["disclosure_text_shown"]; !ok || len(values["disclosure_text_shown"]) != 1 {
		writeError(w, http.StatusBadRequest)
		return assertionRequest{}, false
	}
	disclosure, err := strconv.ParseBool(values.Get("disclosure_text_shown"))
	if err != nil {
		writeError(w, http.StatusBadRequest)
		return assertionRequest{}, false
	}
	in.DisclosureTextShown = disclosure
	if !validAssertionRequest(in) {
		writeError(w, http.StatusBadRequest)
		return assertionRequest{}, false
	}
	return in, true
}

func validFormContentType(r *http.Request) bool {
	raw, ok := oneHeader(r, "Content-Type")
	if !ok {
		return false
	}
	mediaType, params, err := mime.ParseMediaType(raw)
	if err != nil || mediaType != "application/x-www-form-urlencoded" || len(params) > 4 {
		return false
	}
	for key, value := range params {
		if len(key) > 64 || len(value) > 256 {
			return false
		}
	}
	return true
}

func oneHeader(r *http.Request, name string) (string, bool) {
	values := headerValues(r, name)
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func headerValues(r *http.Request, name string) []string {
	var values []string
	for key, entries := range r.Header {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	return values
}

func (h *Handler) allowClientOrigin(ctx context.Context, clientID, origin string) bool {
	if h.clientID != "" && h.clientID != clientID {
		return false
	}
	expected := h.origin
	if h.resolveClientOrigin != nil {
		value, err := h.resolveClientOrigin(ctx, clientID)
		if err != nil {
			return false
		}
		expected = value
	} else if h.clientOrigins != nil {
		var ok bool
		expected, ok = h.clientOrigins[clientID]
		if !ok {
			return false
		}
	}
	return validRequestOrigin(expected) && expected == origin
}

func validRequestOrigin(origin string) bool {
	_, err := exactOrigin(origin)
	return err == nil
}

func validAssertionRequest(in assertionRequest) bool {
	return validAccountID(in.AccountID) && validClientID(in.ClientID) && (in.Nonce == "" || validNonce(in.Nonce))
}

// validAccountID is the bounded opaque-subject contract shared by the account
// projection and assertion parsing. Subjects are native unpadded base64url
// values, so '-' and '_' are valid; anything the projection can advertise must
// parse, and equality to the authenticated account stays exact.
func validAccountID(value string) bool {
	if value == "" || len(value) > maxQueryValue || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsAny(value, "\r\n")
}

func validClientID(value string) bool {
	if len(value) < 2 || len(value) > maxQueryValue || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.:/_-&?=~#!$'()*+%", c) {
			return false
		}
	}
	return true
}

func validNonce(value string) bool {
	if len(value) > maxQueryValue || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.:/_-&?=~#!$'()*+%@", c) {
			return false
		}
	}
	return true
}

func validAccount(a Account) bool {
	return validAccountID(a.ID) && a.Name != "" && len(a.Name) <= maxQueryValue && a.Email != "" && len(a.Email) <= maxQueryValue
}

func validAccounts(accounts []Account) bool {
	if len(accounts) > 16 {
		return false
	}
	for _, account := range accounts {
		if !validAccount(account) {
			return false
		}
	}
	return true
}

func validMetadata(metadata ClientMetadata) bool {
	return validOptionalURL(metadata.PrivacyPolicyURL) && validOptionalURL(metadata.TermsOfServiceURL)
}

func validOptionalURL(raw string) bool {
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

func exactOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errUnavailable
	}
	return raw, nil
}

func absoluteURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errUnavailable
	}
	return nil
}

func relativeLoginURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.User != nil || u.RawQuery != "" || u.RawPath != "" || raw == "" {
		return errUnavailable
	}
	if u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		return errUnavailable
	}
	for _, segment := range strings.Split(u.Path[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errUnavailable
		}
	}
	return nil
}

func issuerEndpoint(issuer, path string) string { return issuer + path }

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int) {
	writeJSON(w, status, map[string]string{"error": "invalid_request"})
}

func setLogin(w http.ResponseWriter, status string) { w.Header().Set("Set-Login", status) }

func setCORS(w http.ResponseWriter, origin string) {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}
