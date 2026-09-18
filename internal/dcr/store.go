// Package dcr persists the narrow, security-sensitive portion of OAuth dynamic
// client registration. HTTP request parsing and RFC response shaping live above
// this package; this package still validates its persisted invariants.
package dcr

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/redirecturi"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

const (
	TokenEndpointAuthNone        = "none"
	TokenEndpointAuthClientBasic = "client_secret_basic"
	TokenEndpointAuthClientPost  = "client_secret_post"

	maxClientIDLength   = 64
	maxNameLength       = 256
	maxListEntries      = 32
	maxValueLength      = 2048
	maxContactLength    = 48
	createAttempts      = 4
	idempotencyTTL      = 24 * time.Hour
	idempotencyPurpose  = "dcr-registration-response"
	anonymousRateDomain = "goauthy/dcr/anonymous-rate/v1\x00"
)

var (
	ErrIdempotencyMismatch    = errors.New("dynamic client registration idempotency mismatch")
	ErrIdempotencyUnavailable = errors.New("dynamic client registration idempotency unavailable")
	ErrRateLimited            = errors.New("dynamic client registration rate limited")
	backchannelURIPattern     = regexp.MustCompile(`^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%@]+$`)
	clientIDPattern           = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	scopePattern              = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	contactPattern            = regexp.MustCompile(`^[A-Za-z0-9+.@/:-]{1,48}$`)

	ErrClientExists = errors.New("dynamic OAuth client already exists")
	// ErrReservedClientID prevents a dynamic row from shadowing a managed
	// client selected by the OAuth client resolver.
	ErrReservedClientID = errors.New("dynamic OAuth client ID is reserved")
	ErrUnauthorized     = errors.New("dynamic OAuth client registration unauthorized")
	ErrConflict         = errors.New("dynamic OAuth client registration conflict")
	ErrInvalid          = errors.New("invalid dynamic OAuth client registration")
)

// CreateRequest contains the validated DCR metadata. ClientID is optional; an
// empty value asks the store to generate one. The store always generates the
// confidential client secret and registration access token itself.
type CreateRequest struct {
	ClientID                string
	ClientURI               string
	LogoURI                 string
	TOSURI                  string
	PolicyURI               string
	Contacts                []string
	RedirectURIs            []string
	Scopes                  []string
	DefaultScopes           []string
	GrantTypes              []string
	ResponseTypes           []string
	Audiences               []string
	TokenEndpointAuthMethod string
	Name                    string
	ForceMFA                bool
	SoftwareStatement       string
	DPoPBoundAccessTokens   bool
	BackchannelLogoutURI    string
}

// Registration is returned after creation. ClientSecret and
// RegistrationAccessToken are populated only by Create and must be shown only
// once; GetRegistration always returns both as empty strings.
type Registration struct {
	ClientID                string     `json:"client_id"`
	ClientURI               string     `json:"client_uri,omitempty"`
	LogoURI                 string     `json:"logo_uri,omitempty"`
	TOSURI                  string     `json:"tos_uri,omitempty"`
	PolicyURI               string     `json:"policy_uri,omitempty"`
	Contacts                []string   `json:"contacts,omitempty"`
	ClientSecret            string     `json:"client_secret,omitempty"`
	RegistrationAccessToken string     `json:"registration_access_token,omitempty"`
	RedirectURIs            []string   `json:"redirect_uris"`
	Scopes                  []string   `json:"scope"`
	DefaultScopes           []string   `json:"-"`
	GrantTypes              []string   `json:"grant_types"`
	ResponseTypes           []string   `json:"response_types"`
	Audiences               []string   `json:"audience"`
	TokenEndpointAuthMethod string     `json:"token_endpoint_auth_method"`
	Name                    string     `json:"client_name"`
	ForceMFA                bool       `json:"force_mfa"`
	CreatedAt               time.Time  `json:"client_id_issued_at"`
	LastUsedAt              *time.Time `json:"last_used_at,omitempty"`
	Anonymous               bool       `json:"-"`
	SoftwareStatement       string     `json:"software_statement,omitempty"`
	DPoPBoundAccessTokens   bool       `json:"dpop_bound_access_tokens"`
	BackchannelLogoutURI    string     `json:"backchannel_logout_uri,omitempty"`
}

type Config struct {
	AllowRFC8252LoopbackRedirects bool
	ScopePolicy                   ScopePolicy
	// ReservedClientIDs cannot be chosen by dynamic registration. They are
	// configured by the managed OAuth-client owner, not supplied by callers.
	ReservedClientIDs []string
	Keyring           EnvelopeKeyring
	// Now is injectable for deterministic expiry and rate-limit tests.
	Now func() time.Time
}

// RateLimitError reports when another anonymous registration may be accepted.
type RateLimitError struct{ RetryNotBefore time.Time }

func (e *RateLimitError) Error() string { return ErrRateLimited.Error() }
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

// EnvelopeKeyring provides purpose-bound authenticated encryption without
// exposing master keys to the DCR package.
type EnvelopeKeyring interface {
	SealEnvelope(purpose string, plaintext []byte) ([]byte, error)
	OpenEnvelope(purpose string, envelope []byte) ([]byte, error)
	PurposeEnvelopeKeyID(purpose string, envelope []byte) (string, error)
	RewrapEnvelope(purpose string, envelope []byte) ([]byte, error)
	ActiveMasterKeyID() (string, error)
}

// ScopePolicy is the operator-controlled scope set for dynamic registrations.
// It is deliberately independent of the request body.
type ScopePolicy struct {
	Allowed []string
	Default []string
}

func NewScopePolicy(allowed, defaults []string) (ScopePolicy, error) {
	policy := ScopePolicy{Allowed: clone(allowed), Default: clone(defaults)}
	if len(policy.Allowed) == 0 {
		return ScopePolicy{}, fmt.Errorf("%w: allowed scopes", ErrInvalid)
	}
	if err := validateUnique(policy.Allowed, func(value string) bool { return scopePattern.MatchString(value) }); err != nil {
		return ScopePolicy{}, fmt.Errorf("%w: allowed scopes", err)
	}
	if err := validateUnique(policy.Default, func(value string) bool { return scopePattern.MatchString(value) }); err != nil {
		return ScopePolicy{}, fmt.Errorf("%w: default scopes", err)
	}
	for _, scope := range policy.Default {
		if !contains(policy.Allowed, scope) {
			return ScopePolicy{}, fmt.Errorf("%w: default scope is not allowed", ErrInvalid)
		}
	}
	return policy, nil
}

type Store struct {
	db            *rhiza.DB
	allowLoopback bool
	scopePolicy   ScopePolicy
	reservedIDs   map[string]struct{}
	keyring       EnvelopeKeyring
	now           func() time.Time
	// Test-only interposition point used to prove auth keeps one query snapshot.
	afterRegistrationSnapshot func()
}

func NewStore(db *rhiza.DB, configs ...Config) *Store {
	config := Config{}
	if len(configs) != 0 {
		config = configs[0]
	}
	policy := config.ScopePolicy
	if len(policy.Allowed) == 0 && len(policy.Default) == 0 {
		policy, _ = NewScopePolicy([]string{"openid", "profile", "email", "groups"}, []string{"openid"})
	}
	reservedIDs := make(map[string]struct{}, len(config.ReservedClientIDs))
	for _, id := range config.ReservedClientIDs {
		if id != "" {
			reservedIDs[id] = struct{}{}
		}
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Store{db: db, allowLoopback: config.AllowRFC8252LoopbackRedirects, scopePolicy: policy, reservedIDs: reservedIDs, keyring: config.Keyring, now: now}
}

func (s *Store) nowUTC() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func (s *Store) ScopePolicy() (ScopePolicy, error) {
	if s == nil {
		return ScopePolicy{}, fmt.Errorf("%w: store is not configured", ErrInvalid)
	}
	return NewScopePolicy(s.scopePolicy.Allowed, s.scopePolicy.Default)
}

// Create inserts a public or confidential dynamic client. It never writes a
// plaintext client secret or registration token to Rhiza.
func (s *Store) Create(ctx context.Context, request CreateRequest) (Registration, error) {
	if s == nil || s.db == nil {
		return Registration{}, fmt.Errorf("%w: store is not configured", ErrInvalid)
	}
	if err := s.validateCreateRequest(request); err != nil {
		return Registration{}, err
	}
	if request.ClientID != "" && s.reserved(request.ClientID) {
		return Registration{}, ErrReservedClientID
	}
	for attempt := 0; attempt < createAttempts; attempt++ {
		clientID := request.ClientID
		if clientID == "" {
			var err error
			clientID, err = randomValue(24)
			if err != nil {
				return Registration{}, err
			}
		}
		if s.reserved(clientID) {
			continue
		}
		registrationToken, err := randomValue(32)
		if err != nil {
			return Registration{}, err
		}
		registrationDigest := sha256.Sum256([]byte(registrationToken))
		registrationDigestEncoded := base64.RawURLEncoding.EncodeToString(registrationDigest[:])
		var clientSecret string
		var secretHash any
		if request.TokenEndpointAuthMethod != TokenEndpointAuthNone {
			clientSecret, err = randomValue(32)
			if err != nil {
				return Registration{}, err
			}
			hash, hashErr := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
			if hashErr != nil {
				return Registration{}, fmt.Errorf("hash dynamic client secret: %w", hashErr)
			}
			secretHash = string(hash)
		} else {
			secretHash = nil
		}
		registration, err := s.newRegistration(clientID, request, s.nowUTC())
		if err != nil {
			return Registration{}, err
		}
		registration.ClientSecret = clientSecret
		registration.RegistrationAccessToken = registrationToken
		insertErr := s.insert(ctx, registration, secretHash, registrationDigestEncoded)
		if insertErr == nil {
			return registration, nil
		}
		recovered, ok, reconcileErr := s.reconcileCreate(ctx, clientID, registrationDigestEncoded)
		if reconcileErr != nil {
			if errors.Is(reconcileErr, ErrClientExists) && request.ClientID == "" {
				continue
			}
			return Registration{}, reconcileErr
		}
		if ok {
			recovered.ClientSecret = clientSecret
			recovered.RegistrationAccessToken = registrationToken
			return recovered, nil
		}
		return Registration{}, insertErr
	}
	return Registration{}, fmt.Errorf("%w: generated client ID collisions exceeded retry limit", ErrClientExists)
}

type idempotentRegistration struct {
	registration Registration
	response     []byte
	replay       bool
}

// CreateIdempotent atomically persists a dynamic client and its encrypted
// response. key and principal are never persisted; only SHA-256 digests are.
func (s *Store) CreateIdempotent(ctx context.Context, request CreateRequest, key, principal, requestDigest string, buildResponse func(Registration) ([]byte, error)) (idempotentRegistration, error) {
	if s == nil || s.db == nil {
		return idempotentRegistration{}, fmt.Errorf("%w: store is not configured", ErrInvalid)
	}
	if s.keyring == nil {
		return idempotentRegistration{}, ErrIdempotencyUnavailable
	}
	if key == "" || principal == "" || requestDigest == "" || buildResponse == nil {
		return idempotentRegistration{}, fmt.Errorf("%w: idempotency inputs", ErrInvalid)
	}
	if err := s.validateCreateRequest(request); err != nil {
		return idempotentRegistration{}, err
	}
	if request.ClientID != "" && s.reserved(request.ClientID) {
		return idempotentRegistration{}, ErrReservedClientID
	}
	keyDigest := digestString(key)
	principalDigest := digestString(principal)
	createdAt := s.nowUTC().Truncate(time.Millisecond)
	if result, found, err := s.loadDurableIdempotency(ctx, principalDigest, keyDigest, requestDigest, createdAt); err != nil || found {
		return result, err
	}
	activeKeyID, err := s.keyring.ActiveMasterKeyID()
	if err != nil {
		return idempotentRegistration{}, fmt.Errorf("%w: active master key: %v", ErrIdempotencyUnavailable, err)
	}

	for attempt := 0; attempt < createAttempts; attempt++ {
		clientID := request.ClientID
		if clientID == "" {
			var err error
			clientID, err = randomValue(24)
			if err != nil {
				return idempotentRegistration{}, err
			}
		}
		if s.reserved(clientID) {
			continue
		}
		registrationToken, err := randomValue(32)
		if err != nil {
			return idempotentRegistration{}, err
		}
		registrationDigest := sha256.Sum256([]byte(registrationToken))
		registrationDigestEncoded := base64.RawURLEncoding.EncodeToString(registrationDigest[:])
		var clientSecret string
		var secretHash any
		if request.TokenEndpointAuthMethod != TokenEndpointAuthNone {
			clientSecret, err = randomValue(32)
			if err != nil {
				return idempotentRegistration{}, err
			}
			hash, hashErr := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
			if hashErr != nil {
				return idempotentRegistration{}, fmt.Errorf("hash dynamic client secret: %w", hashErr)
			}
			secretHash = string(hash)
		}
		registration, err := s.newRegistration(clientID, request, createdAt)
		if err != nil {
			return idempotentRegistration{}, err
		}
		registration.ClientSecret = clientSecret
		registration.RegistrationAccessToken = registrationToken
		body, err := buildResponse(registration)
		if err != nil {
			return idempotentRegistration{}, err
		}
		envelope, err := s.keyring.SealEnvelope(idempotencyPurpose, body)
		if err != nil {
			return idempotentRegistration{}, err
		}
		redirects, scopes, defaults, grants, responses, audiences, err := registrationJSON(registration)
		if err != nil {
			return idempotentRegistration{}, err
		}
		expires := createdAt.Add(idempotencyTTL).UnixMilli()
		requestID, err := randomValue(18)
		if err != nil {
			return idempotentRegistration{}, err
		}
		_, executeErr := storage.ExecuteEnvelope(ctx, s.db, activeKeyID, rhiza.ExecuteRequest{RequestID: "dcr-idempotency/" + requestID, Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM dcr_registration_idempotency WHERE principal_digest = ? AND key_digest = ? AND expires_at_unix_ms <= ?`, Args: []any{principalDigest, keyDigest, createdAt.UnixMilli()}},
			{SQL: `DELETE FROM dcr_registration_idempotency WHERE rowid IN (SELECT rowid FROM dcr_registration_idempotency WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms, key_digest LIMIT 64)`, Args: []any{createdAt.UnixMilli()}},
			{SQL: `INSERT INTO dynamic_oauth_clients
				(client_id, secret_hash, registration_token_digest, redirect_uris_json, scopes_json, default_scopes_json, grant_types_json, response_types_json, audiences_json, token_endpoint_auth_method, name, force_mfa, created_at_unix_ms, last_used_at_unix_ms, client_uri, contacts_json, logo_uri, tos_uri, policy_uri, software_statement, dpop_bound_access_tokens, backchannel_logout_uri)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{
				registration.ClientID, secretHash, registrationDigestEncoded, redirects, scopes, defaults, grants, responses, audiences,
				registration.TokenEndpointAuthMethod, registration.Name, forceMFAValue(registration.ForceMFA), registration.CreatedAt.UnixMilli(), nullableClientURI(registration.ClientURI), nullableContactsJSON(registration.Contacts), nullableClientURI(registration.LogoURI), nullableClientURI(registration.TOSURI), nullableClientURI(registration.PolicyURI), nullableClientURI(registration.SoftwareStatement), forceMFAValue(registration.DPoPBoundAccessTokens), nullableClientURI(registration.BackchannelLogoutURI),
			}},
			{SQL: `INSERT INTO dcr_registration_idempotency
				(principal_digest, key_digest, request_digest, client_id, response_envelope, expires_at_unix_ms, created_at_unix_ms)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, Args: []any{principalDigest, keyDigest, requestDigest, registration.ClientID, base64.RawURLEncoding.EncodeToString(envelope), expires, createdAt.UnixMilli()}},
		}})
		if executeErr == nil {
			return idempotentRegistration{registration: registration, response: body}, nil
		}
		if errors.Is(executeErr, rhiza.ErrCommitUnknown) {
			return idempotentRegistration{}, executeErr
		}
		if result, found, lookupErr := s.loadDurableIdempotency(ctx, principalDigest, keyDigest, requestDigest, createdAt); lookupErr != nil {
			return idempotentRegistration{}, lookupErr
		} else if found {
			return result, nil
		}
		if request.ClientID == "" {
			continue
		}
		return idempotentRegistration{}, executeErr
	}
	return idempotentRegistration{}, fmt.Errorf("%w: generated client ID collisions exceeded retry limit", ErrClientExists)
}

// CreateAnonymousIdempotent creates an anonymous registration after reserving
// its canonical peer IP's fixed window. A replay is resolved before reserving
// the window, so retries do not consume another registration.
func (s *Store) CreateAnonymousIdempotent(ctx context.Context, request CreateRequest, key string, peerIP netip.Addr, requestDigest string, window time.Duration, buildResponse func(Registration) ([]byte, error)) (idempotentRegistration, error) {
	if s == nil || s.db == nil {
		return idempotentRegistration{}, fmt.Errorf("%w: store is not configured", ErrInvalid)
	}
	if s.keyring == nil {
		return idempotentRegistration{}, ErrIdempotencyUnavailable
	}
	if key == "" || requestDigest == "" || buildResponse == nil || !validAnonymousWindow(window) {
		return idempotentRegistration{}, fmt.Errorf("%w: anonymous registration inputs", ErrInvalid)
	}
	peerIP = peerIP.Unmap()
	if !peerIP.IsValid() || peerIP.IsUnspecified() {
		return idempotentRegistration{}, fmt.Errorf("%w: anonymous peer IP", ErrInvalid)
	}
	if err := s.validateCreateRequest(request); err != nil {
		return idempotentRegistration{}, err
	}
	if request.ClientID != "" && s.reserved(request.ClientID) {
		return idempotentRegistration{}, ErrReservedClientID
	}
	principal := "anonymous/" + peerIP.String()
	keyDigest, principalDigest := digestString(key), digestString(principal)
	createdAt := s.nowUTC().Truncate(time.Millisecond)
	if createdAt.UnixMilli() < 0 {
		return idempotentRegistration{}, fmt.Errorf("%w: anonymous clock", ErrInvalid)
	}
	if result, found, err := s.loadDurableIdempotency(ctx, principalDigest, keyDigest, requestDigest, createdAt); err != nil || found {
		return result, err
	}
	activeKeyID, err := s.keyring.ActiveMasterKeyID()
	if err != nil {
		return idempotentRegistration{}, fmt.Errorf("%w: active master key: %v", ErrIdempotencyUnavailable, err)
	}
	windowStart := createdAt.UnixMilli()
	windowEnd := createdAt.Add(window).UnixMilli()
	if windowEnd <= windowStart {
		return idempotentRegistration{}, fmt.Errorf("%w: anonymous window", ErrInvalid)
	}
	rateKey := digestString(anonymousRateDomain + peerIP.String())

	for attempt := 0; attempt < createAttempts; attempt++ {
		clientID := request.ClientID
		if clientID == "" {
			var err error
			clientID, err = randomValue(24)
			if err != nil {
				return idempotentRegistration{}, err
			}
		}
		if s.reserved(clientID) {
			continue
		}
		registrationToken, err := randomValue(32)
		if err != nil {
			return idempotentRegistration{}, err
		}
		registrationDigest := sha256.Sum256([]byte(registrationToken))
		registrationDigestEncoded := base64.RawURLEncoding.EncodeToString(registrationDigest[:])
		var clientSecret string
		var secretHash any
		if request.TokenEndpointAuthMethod != TokenEndpointAuthNone {
			clientSecret, err = randomValue(32)
			if err != nil {
				return idempotentRegistration{}, err
			}
			hash, hashErr := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
			if hashErr != nil {
				return idempotentRegistration{}, fmt.Errorf("hash dynamic client secret: %w", hashErr)
			}
			secretHash = string(hash)
		}
		registration, err := s.newRegistration(clientID, request, createdAt)
		if err != nil {
			return idempotentRegistration{}, err
		}
		registration.ClientSecret, registration.RegistrationAccessToken = clientSecret, registrationToken
		body, err := buildResponse(registration)
		if err != nil {
			return idempotentRegistration{}, err
		}
		envelope, err := s.keyring.SealEnvelope(idempotencyPurpose, body)
		if err != nil {
			return idempotentRegistration{}, err
		}
		redirects, scopes, defaults, grants, responses, audiences, err := registrationJSON(registration)
		if err != nil {
			return idempotentRegistration{}, err
		}
		requestID, err := randomValue(18)
		if err != nil {
			return idempotentRegistration{}, err
		}
		response, executeErr := storage.ExecuteEnvelope(ctx, s.db, activeKeyID, rhiza.ExecuteRequest{RequestID: "dcr-anonymous/" + requestID, Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM dcr_registration_idempotency WHERE principal_digest = ? AND key_digest = ? AND expires_at_unix_ms <= ?`, Args: []any{principalDigest, keyDigest, createdAt.UnixMilli()}},
			{SQL: `DELETE FROM dcr_registration_idempotency WHERE rowid IN (SELECT rowid FROM dcr_registration_idempotency WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms, key_digest LIMIT 64)`, Args: []any{createdAt.UnixMilli()}},
			{SQL: `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 0, ?, ?) ON CONFLICT(key_digest) DO UPDATE SET window_start_unix_ms=excluded.window_start_unix_ms, count=0, expires_at_unix_ms=excluded.expires_at_unix_ms, last_window_at_unix_ms=excluded.last_window_at_unix_ms WHERE oauth_rate_limits.expires_at_unix_ms <= excluded.last_window_at_unix_ms`, Args: []any{rateKey, windowStart, windowEnd, windowStart}},
			{SQL: `SELECT count, expires_at_unix_ms FROM oauth_rate_limits WHERE key_digest = ?`, Args: []any{rateKey}, WantRows: true},
			{SQL: `INSERT INTO dynamic_oauth_clients (client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,default_scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,force_mfa,anonymous,created_at_unix_ms,last_used_at_unix_ms,client_uri,contacts_json,logo_uri,tos_uri,policy_uri,software_statement,dpop_bound_access_tokens,backchannel_logout_uri) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM oauth_rate_limits WHERE key_digest = ? AND count = 0)`, Args: []any{registration.ClientID, secretHash, registrationDigestEncoded, redirects, scopes, defaults, grants, responses, audiences, registration.TokenEndpointAuthMethod, registration.Name, forceMFAValue(registration.ForceMFA), int64(1), registration.CreatedAt.UnixMilli(), nullableClientURI(registration.ClientURI), nullableContactsJSON(registration.Contacts), nullableClientURI(registration.LogoURI), nullableClientURI(registration.TOSURI), nullableClientURI(registration.PolicyURI), nullableClientURI(registration.SoftwareStatement), forceMFAValue(registration.DPoPBoundAccessTokens), nullableClientURI(registration.BackchannelLogoutURI), rateKey}},
			{SQL: `INSERT INTO dcr_registration_idempotency (principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) SELECT ?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM oauth_rate_limits WHERE key_digest = ? AND count = 0)`, Args: []any{principalDigest, keyDigest, requestDigest, registration.ClientID, base64.RawURLEncoding.EncodeToString(envelope), createdAt.Add(idempotencyTTL).UnixMilli(), createdAt.UnixMilli(), rateKey}},
			{SQL: `UPDATE oauth_rate_limits SET count = 1 WHERE key_digest = ? AND count = 0 AND EXISTS (SELECT 1 FROM dcr_registration_idempotency WHERE principal_digest = ? AND key_digest = ? AND client_id = ?)`, Args: []any{rateKey, principalDigest, keyDigest, registration.ClientID}},
		}})
		if executeErr == nil {
			if len(response.Statements) <= 3 || len(response.Statements[3].Rows) != 1 || len(response.Statements[3].Rows[0]) != 2 {
				return idempotentRegistration{}, errors.New("invalid anonymous rate-limit result")
			}
			count, ok := response.Statements[3].Rows[0][0].(int64)
			retryAt, retryOK := response.Statements[3].Rows[0][1].(int64)
			if !ok || !retryOK || retryAt <= createdAt.UnixMilli() {
				return idempotentRegistration{}, errors.New("invalid anonymous rate-limit count")
			}
			if count != 0 {
				if result, found, lookupErr := s.loadDurableIdempotency(ctx, principalDigest, keyDigest, requestDigest, createdAt); lookupErr != nil {
					return idempotentRegistration{}, lookupErr
				} else if found {
					return result, nil
				}
				return idempotentRegistration{}, &RateLimitError{RetryNotBefore: time.UnixMilli(retryAt).UTC()}
			}
			return idempotentRegistration{registration: registration, response: body}, nil
		}
		if errors.Is(executeErr, rhiza.ErrCommitUnknown) {
			return idempotentRegistration{}, executeErr
		}
		if result, found, lookupErr := s.loadDurableIdempotency(ctx, principalDigest, keyDigest, requestDigest, createdAt); lookupErr != nil {
			return idempotentRegistration{}, lookupErr
		} else if found {
			return result, nil
		}
		if request.ClientID == "" {
			continue
		}
		return idempotentRegistration{}, executeErr
	}
	return idempotentRegistration{}, fmt.Errorf("%w: generated client ID collisions exceeded retry limit", ErrClientExists)
}

func validAnonymousWindow(window time.Duration) bool {
	return window >= time.Second && window <= 24*time.Hour && window%time.Millisecond == 0
}

// loadDurableIdempotency confirms that a replay remains durable before
// returning its one-time credentials. A local read alone cannot establish
// before-ack durability after a prior commit-unknown response.
func (s *Store) loadDurableIdempotency(ctx context.Context, principalDigest, keyDigest, requestDigest string, now time.Time) (idempotentRegistration, bool, error) {
	result, found, err := s.loadIdempotency(ctx, principalDigest, keyDigest, requestDigest, now)
	if err != nil || !found {
		return result, found, err
	}
	activeKeyID, err := s.keyring.ActiveMasterKeyID()
	if err != nil {
		return idempotentRegistration{}, false, fmt.Errorf("%w: active master key: %v", ErrIdempotencyUnavailable, err)
	}
	_, err = storage.ExecuteEnvelope(ctx, s.db, activeKeyID, rhiza.ExecuteRequest{
		RequestID: idempotencyReplayRequestID(activeKeyID, principalDigest, keyDigest, requestDigest, result.response),
		SQL: `UPDATE dcr_registration_idempotency SET created_at_unix_ms = created_at_unix_ms
			WHERE principal_digest = ? AND key_digest = ? AND request_digest = ?`,
		Args: []any{principalDigest, keyDigest, requestDigest},
	})
	if err != nil {
		return idempotentRegistration{}, false, err
	}
	return result, true, nil
}

func idempotencyReplayRequestID(activeKeyID, principalDigest, keyDigest, requestDigest string, response []byte) string {
	hash := sha256.New()
	for _, value := range []string{activeKeyID, principalDigest, keyDigest, requestDigest} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	_, _ = hash.Write(response)
	return "dcr-idempotency-replay/" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil)[:24])
}

func (s *Store) loadIdempotency(ctx context.Context, principalDigest, keyDigest, requestDigest string, now time.Time) (idempotentRegistration, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT request_digest, client_id, response_envelope, expires_at_unix_ms FROM dcr_registration_idempotency WHERE principal_digest = ? AND key_digest = ?`, Args: []any{principalDigest, keyDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return idempotentRegistration{}, false, err
	}
	if len(result.Rows) == 0 {
		return idempotentRegistration{}, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return idempotentRegistration{}, false, errors.New("invalid DCR idempotency row")
	}
	row := result.Rows[0]
	storedDigest, ok := row[0].(string)
	if !ok {
		return idempotentRegistration{}, false, errors.New("invalid DCR idempotency request digest")
	}
	expires, ok := row[3].(int64)
	if !ok {
		return idempotentRegistration{}, false, errors.New("invalid DCR idempotency expiry")
	}
	if expires <= now.UnixMilli() {
		return idempotentRegistration{}, false, nil
	}
	if len(storedDigest) != len(requestDigest) || subtle.ConstantTimeCompare([]byte(storedDigest), []byte(requestDigest)) != 1 {
		return idempotentRegistration{}, false, ErrIdempotencyMismatch
	}
	encoded, ok := row[2].(string)
	if !ok {
		return idempotentRegistration{}, false, errors.New("invalid DCR idempotency envelope")
	}
	envelope, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return idempotentRegistration{}, false, errors.New("invalid DCR idempotency envelope")
	}
	body, err := s.keyring.OpenEnvelope(idempotencyPurpose, envelope)
	if err != nil {
		return idempotentRegistration{}, false, err
	}
	return idempotentRegistration{response: append([]byte(nil), body...), replay: true}, true, nil
}

const maxIdempotencyRewrapBatch = 32

type idempotencyRewrapCandidate struct {
	principalDigest string
	keyDigest       string
	requestDigest   string
	oldEnvelope     string
	expiresAt       int64
	newEnvelope     string
}

// RewrapIdempotencyBatch rewrites at most 32 live idempotency envelopes that
// are sealed by a non-active master key. cursor is opaque; an empty cursor
// starts at the first primary-key tuple. Rows are authenticated before any
// mutation is submitted, and each rewrite is fenced by its exact old row.
func (s *Store) RewrapIdempotencyBatch(ctx context.Context, cursor string) (string, int, error) {
	if s == nil || s.db == nil || ctx == nil || s.keyring == nil {
		return "", 0, ErrIdempotencyUnavailable
	}
	now := s.nowUTC().Truncate(time.Millisecond)
	nowMS := now.UnixMilli()
	activeID, err := s.keyring.ActiveMasterKeyID()
	if err != nil {
		return "", 0, fmt.Errorf("%w: active master key: %v", ErrIdempotencyUnavailable, err)
	}
	principalCursor, keyCursor, err := decodeIdempotencyRewrapCursor(cursor)
	if err != nil {
		return "", 0, fmt.Errorf("%w: rewrap cursor", ErrInvalid)
	}
	query := `SELECT principal_digest,key_digest,request_digest,response_envelope,expires_at_unix_ms
		FROM dcr_registration_idempotency WHERE expires_at_unix_ms > ?`
	args := []any{nowMS}
	if principalCursor != "" {
		query += ` AND (principal_digest > ? OR (principal_digest = ? AND key_digest > ?))`
		args = append(args, principalCursor, principalCursor, keyCursor)
	}
	query += ` ORDER BY principal_digest,key_digest LIMIT ?`
	args = append(args, int64(maxIdempotencyRewrapBatch))
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: query, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return "", 0, err
	}
	if len(result.Rows) > maxIdempotencyRewrapBatch {
		return "", 0, ErrIdempotencyUnavailable
	}
	if len(result.Rows) == 0 {
		return "", 0, nil
	}
	candidates := make([]idempotencyRewrapCandidate, 0, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) != 5 {
			return "", 0, errors.New("invalid DCR idempotency rewrap row")
		}
		principalDigest, principalOK := row[0].(string)
		keyDigest, keyOK := row[1].(string)
		requestDigest, requestOK := row[2].(string)
		oldEnvelope, envelopeOK := row[3].(string)
		expiresAt, expiresOK := row[4].(int64)
		if !principalOK || !keyOK || !requestOK || !envelopeOK || !expiresOK || !validIdempotencyDigest(principalDigest) || !validIdempotencyDigest(keyDigest) || !validIdempotencyDigest(requestDigest) || oldEnvelope == "" || expiresAt <= nowMS {
			return "", 0, errors.New("invalid DCR idempotency rewrap row")
		}
		envelope, err := base64.RawURLEncoding.DecodeString(oldEnvelope)
		if err != nil || len(envelope) == 0 || base64.RawURLEncoding.EncodeToString(envelope) != oldEnvelope {
			return "", 0, errors.New("invalid DCR idempotency rewrap envelope")
		}
		keyID, err := s.keyring.PurposeEnvelopeKeyID(idempotencyPurpose, envelope)
		if err != nil {
			return "", 0, fmt.Errorf("open DCR idempotency envelope: %w", err)
		}
		candidate := idempotencyRewrapCandidate{principalDigest: principalDigest, keyDigest: keyDigest, requestDigest: requestDigest, oldEnvelope: oldEnvelope, expiresAt: expiresAt}
		if keyID != activeID {
			rewrapped, err := s.keyring.RewrapEnvelope(idempotencyPurpose, envelope)
			if err != nil {
				return "", 0, fmt.Errorf("rewrap DCR idempotency envelope: %w", err)
			}
			candidate.newEnvelope = base64.RawURLEncoding.EncodeToString(rewrapped)
			candidates = append(candidates, candidate)
		}
	}
	nextCursor := encodeIdempotencyRewrapCursor(result.Rows[len(result.Rows)-1][0].(string), result.Rows[len(result.Rows)-1][1].(string))
	if len(result.Rows) < maxIdempotencyRewrapBatch {
		nextCursor = ""
	}
	if len(candidates) == 0 {
		return nextCursor, 0, nil
	}
	requestID, sql, args := idempotencyRewrapMutation(nowMS, candidates)
	response, err := storage.ExecuteEnvelope(ctx, s.db, activeID, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql, Args: args})
	if err != nil {
		return cursor, 0, err
	}
	if response.RowsAffected != 0 && response.RowsAffected != int64(len(candidates)) {
		return cursor, 0, fmt.Errorf("DCR idempotency rewrap CAS changed %d rows, want %d", response.RowsAffected, len(candidates))
	}
	if response.RowsAffected == 0 {
		// A concurrent worker may have changed one candidate while leaving the
		// others old. Keep the batch boundary so the untouched rows are retried.
		return cursor, 0, nil
	}
	return nextCursor, int(response.MutationReceipt.RowsAffected), nil
}

func validIdempotencyDigest(value string) bool {
	return len(value) == 43 && strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == ""
}

func encodeIdempotencyRewrapCursor(principalDigest, keyDigest string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(principalDigest + "\x00" + keyDigest))
}

func decodeIdempotencyRewrapCursor(cursor string) (string, string, error) {
	if cursor == "" {
		return "", "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) != 2 || !validIdempotencyDigest(parts[0]) || !validIdempotencyDigest(parts[1]) {
		return "", "", errors.New("invalid cursor")
	}
	return parts[0], parts[1], nil
}

func idempotencyRewrapMutation(nowMS int64, candidates []idempotencyRewrapCandidate) (string, string, []any) {
	// One guarded UPDATE makes the batch all-or-zero. The count predicate is
	// evaluated against every exact old row, so a concurrent change cannot
	// commit a partial batch and advance the cursor past an untouched row.
	var sql strings.Builder
	sql.WriteString("UPDATE dcr_registration_idempotency SET response_envelope = CASE ")
	args := make([]any, 0, len(candidates)*11+1)
	for _, candidate := range candidates {
		sql.WriteString("WHEN principal_digest=? AND key_digest=? THEN ? ")
		args = append(args, candidate.principalDigest, candidate.keyDigest, candidate.newEnvelope)
	}
	sql.WriteString("ELSE response_envelope END WHERE (principal_digest=? AND key_digest=?")
	args = append(args, candidates[0].principalDigest, candidates[0].keyDigest)
	for _, candidate := range candidates[1:] {
		sql.WriteString(" OR (principal_digest=? AND key_digest=?)")
		args = append(args, candidate.principalDigest, candidate.keyDigest)
	}
	sql.WriteString(") AND (SELECT COUNT(*) FROM dcr_registration_idempotency WHERE ")
	for index, candidate := range candidates {
		if index > 0 {
			sql.WriteString(" OR ")
		}
		sql.WriteString("(principal_digest=? AND key_digest=? AND request_digest=? AND response_envelope=? AND expires_at_unix_ms=? AND expires_at_unix_ms>?)")
		args = append(args, candidate.principalDigest, candidate.keyDigest, candidate.requestDigest, candidate.oldEnvelope, candidate.expiresAt, nowMS)
	}
	sql.WriteString(") = ?")
	args = append(args, int64(len(candidates)))
	statement := rhiza.SQLStatement{SQL: sql.String(), Args: args}
	return idempotencyRewrapRequestID([]rhiza.SQLStatement{statement}), statement.SQL, statement.Args
}

func idempotencyRewrapRequestID(statements []rhiza.SQLStatement) string {
	encoded, _ := json.Marshal(statements)
	sum := sha256.Sum256(encoded)
	return "dcr-idempotency-rewrap/" + base64.RawURLEncoding.EncodeToString(sum[:24])
}

func digestString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Store) reserved(clientID string) bool {
	_, ok := s.reservedIDs[clientID]
	return ok
}

func (s *Store) insert(ctx context.Context, registration Registration, secretHash any, registrationDigest string) error {
	redirects, scopes, defaults, grants, responses, audiences, err := registrationJSON(registration)
	if err != nil {
		return err
	}
	requestID := "dcr-create/" + registration.ClientID + "/" + registrationDigest[:16]
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `INSERT INTO dynamic_oauth_clients
		(client_id, secret_hash, registration_token_digest, redirect_uris_json, scopes_json, default_scopes_json, grant_types_json, response_types_json, audiences_json, token_endpoint_auth_method, name, force_mfa, created_at_unix_ms, last_used_at_unix_ms, client_uri, contacts_json, logo_uri, tos_uri, policy_uri, software_statement, dpop_bound_access_tokens, backchannel_logout_uri)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{
		registration.ClientID, secretHash, registrationDigest, redirects, scopes, defaults, grants, responses, audiences,
		registration.TokenEndpointAuthMethod, registration.Name, forceMFAValue(registration.ForceMFA), registration.CreatedAt.UnixMilli(), nullableClientURI(registration.ClientURI), nullableContactsJSON(registration.Contacts), nullableClientURI(registration.LogoURI), nullableClientURI(registration.TOSURI), nullableClientURI(registration.PolicyURI), nullableClientURI(registration.SoftwareStatement), forceMFAValue(registration.DPoPBoundAccessTokens), nullableClientURI(registration.BackchannelLogoutURI),
	}})
	if err == nil {
		return nil
	}
	return err
}

func (s *Store) reconcileCreate(ctx context.Context, clientID, digest string) (Registration, bool, error) {
	registration, stored, exists, err := s.loadSnapshot(ctx, clientID)
	if err != nil || !exists {
		return Registration{}, false, err
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(digest)) != 1 {
		return Registration{}, false, ErrClientExists
	}
	return registration, true, nil
}

type registeredClient struct {
	*fosite.DefaultOpenIDConnectClient
	dpopRequired         bool
	backchannelLogoutURI string
}

func (c *registeredClient) GetBackchannelLogoutURI() string { return c.backchannelLogoutURI }

func (c *registeredClient) DPoPRequired() bool { return c.dpopRequired }

// GetClient returns a Fosite client without exposing registration credentials.
func (s *Store) GetClient(ctx context.Context, clientID string) (fosite.Client, error) {
	registration, exists, err := s.load(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fosite.ErrNotFound
	}
	secretHash, err := s.secretHash(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return &registeredClient{DefaultOpenIDConnectClient: &fosite.DefaultOpenIDConnectClient{DefaultClient: &fosite.DefaultClient{
		ID: registration.ClientID, Secret: secretHash, RedirectURIs: registration.RedirectURIs,
		GrantTypes: registration.GrantTypes, ResponseTypes: registration.ResponseTypes,
		Scopes: registration.Scopes, Audience: registration.Audiences,
		Public: registration.TokenEndpointAuthMethod == TokenEndpointAuthNone,
	}, TokenEndpointAuthMethod: registration.TokenEndpointAuthMethod}, dpopRequired: registration.DPoPBoundAccessTokens, backchannelLogoutURI: registration.BackchannelLogoutURI}, nil
}

// DefaultScopes returns the operator-defined defaults persisted with a dynamic
// registration. The returned slice is safe for callers to modify.
func (s *Store) DefaultScopes(ctx context.Context, clientID string) ([]string, error) {
	registration, exists, err := s.load(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fosite.ErrNotFound
	}
	return clone(registration.DefaultScopes), nil
}

// Update replaces a registered client's metadata after authenticating its
// registration access token. A successful update rotates the registration
// access token and, for confidential clients, the client secret.
func (s *Store) Update(ctx context.Context, clientID, registrationToken string, request CreateRequest) (Registration, error) {
	if s == nil || s.db == nil {
		return Registration{}, fmt.Errorf("%w: store is not configured", ErrInvalid)
	}
	existing, digest, err := s.authenticateRegistration(ctx, clientID, registrationToken)
	if err != nil {
		return Registration{}, err
	}
	if request.ClientID != "" && request.ClientID != clientID {
		return Registration{}, fmt.Errorf("%w: client ID cannot change", ErrInvalid)
	}
	request.ClientID = clientID
	if err := s.validateCreateRequest(request); err != nil {
		return Registration{}, err
	}
	if request.TokenEndpointAuthMethod != existing.TokenEndpointAuthMethod {
		return Registration{}, fmt.Errorf("%w: token endpoint authentication method cannot change", ErrInvalid)
	}
	request.Scopes = clone(existing.Scopes)
	request.DefaultScopes = clone(existing.DefaultScopes)
	desired, err := s.newRegistration(clientID, request, existing.CreatedAt)
	if err != nil {
		return Registration{}, err
	}
	lastUsedAtUnixMilli := s.nowUTC().UnixMilli()
	if existing.LastUsedAt == nil || existing.LastUsedAt.UnixMilli() < lastUsedAtUnixMilli {
		lastUsedAt := time.UnixMilli(lastUsedAtUnixMilli).UTC()
		desired.LastUsedAt = &lastUsedAt
	} else {
		desired.LastUsedAt = existing.LastUsedAt
	}
	rotatedToken, err := randomValue(32)
	if err != nil {
		return Registration{}, err
	}
	rotatedTokenDigest := sha256.Sum256([]byte(rotatedToken))
	rotatedDigest := base64.RawURLEncoding.EncodeToString(rotatedTokenDigest[:])
	var secretHash any
	if desired.TokenEndpointAuthMethod != TokenEndpointAuthNone {
		desired.ClientSecret, err = randomValue(32)
		if err != nil {
			return Registration{}, err
		}
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(desired.ClientSecret), bcrypt.DefaultCost)
		if hashErr != nil {
			return Registration{}, fmt.Errorf("hash rotated dynamic client secret: %w", hashErr)
		}
		secretHash = string(hash)
	}
	desired.RegistrationAccessToken = rotatedToken
	redirects, scopes, defaults, grants, responses, audiences, err := registrationJSON(desired)
	if err != nil {
		return Registration{}, err
	}
	expectedRedirects, expectedScopes, expectedDefaults, expectedGrants, expectedResponses, expectedAudiences, err := registrationJSON(existing)
	if err != nil {
		return Registration{}, err
	}
	metadataHash := sha256.Sum256([]byte(strings.Join([]string{redirects, scopes, defaults, grants, responses, audiences, desired.ClientURI, contactsJSONString(desired.Contacts), desired.LogoURI, desired.TOSURI, desired.PolicyURI, desired.TokenEndpointAuthMethod, desired.Name, fmt.Sprintf("%t", desired.ForceMFA), desired.SoftwareStatement, fmt.Sprintf("%t", desired.DPoPBoundAccessTokens), desired.BackchannelLogoutURI}, "\x00")))
	requestID := updateRequestID(clientID, digest, rotatedDigest, metadataHash)
	one := int64(1)
	statements := []rhiza.SQLStatement{{SQL: `UPDATE dynamic_oauth_clients
		SET secret_hash = ?, registration_token_digest = ?, redirect_uris_json = ?, scopes_json = ?, default_scopes_json = ?, grant_types_json = ?, response_types_json = ?, audiences_json = ?, token_endpoint_auth_method = ?, name = ?, force_mfa = ?, client_uri = ?, contacts_json = ?, logo_uri = ?, tos_uri = ?, policy_uri = ?, software_statement = ?, dpop_bound_access_tokens = ?, backchannel_logout_uri = ?,
			last_used_at_unix_ms = CASE WHEN last_used_at_unix_ms IS NULL OR last_used_at_unix_ms < ? THEN ? ELSE last_used_at_unix_ms END
		WHERE client_id = ? AND registration_token_digest = ? AND token_endpoint_auth_method = ?
		AND redirect_uris_json = ? AND scopes_json = ? AND default_scopes_json = ? AND grant_types_json = ? AND response_types_json = ? AND audiences_json = ? AND name = ? AND force_mfa = ? AND client_uri IS ? AND contacts_json IS ? AND logo_uri IS ? AND tos_uri IS ? AND policy_uri IS ? AND software_statement IS ? AND dpop_bound_access_tokens = ? AND backchannel_logout_uri IS ? RETURNING client_id`, WantRows: true, ExpectedReturnedRows: &one, Args: []any{
		secretHash, rotatedDigest, redirects, scopes, defaults, grants, responses, audiences, desired.TokenEndpointAuthMethod, desired.Name, forceMFAValue(desired.ForceMFA), nullableClientURI(desired.ClientURI), nullableContactsJSON(desired.Contacts), nullableClientURI(desired.LogoURI), nullableClientURI(desired.TOSURI), nullableClientURI(desired.PolicyURI), nullableClientURI(desired.SoftwareStatement), forceMFAValue(desired.DPoPBoundAccessTokens), nullableClientURI(desired.BackchannelLogoutURI),
		lastUsedAtUnixMilli, lastUsedAtUnixMilli,
		clientID, digest, existing.TokenEndpointAuthMethod,
		expectedRedirects, expectedScopes, expectedDefaults, expectedGrants, expectedResponses, expectedAudiences, existing.Name, forceMFAValue(existing.ForceMFA), nullableClientURI(existing.ClientURI),
		nullableContactsJSON(existing.Contacts), nullableClientURI(existing.LogoURI), nullableClientURI(existing.TOSURI), nullableClientURI(existing.PolicyURI), nullableClientURI(existing.SoftwareStatement), forceMFAValue(existing.DPoPBoundAccessTokens), nullableClientURI(existing.BackchannelLogoutURI),
	}}}
	for _, table := range []string{"oidc_user_clients", "oidc_session_clients"} {
		statements = append(statements, rhiza.SQLStatement{SQL: "UPDATE " + table + " SET logout_uri=? WHERE client_id=?", Args: []any{desired.BackchannelLogoutURI, clientID}})
	}
	response, updateErr := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if updateErr == nil && response.Status == "committed" {
		return desired, nil
	}
	if reconciled, ok, reconcileErr := s.reconcileUpdate(ctx, clientID, rotatedDigest, desired); reconcileErr != nil {
		return Registration{}, reconcileErr
	} else if ok {
		reconciled.ClientSecret = desired.ClientSecret
		reconciled.RegistrationAccessToken = desired.RegistrationAccessToken
		return reconciled, nil
	}
	if updateErr == nil || response.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return Registration{}, ErrConflict
	}
	return Registration{}, updateErr
}

func updateRequestID(clientID, digest, rotatedDigest string, metadataHash [sha256.Size]byte) string {
	sum := sha256.Sum256([]byte(clientID + "\x00" + digest + "\x00" + rotatedDigest + "\x00" + base64.RawURLEncoding.EncodeToString(metadataHash[:])))
	return "dcr-update/" + base64.RawURLEncoding.EncodeToString(sum[:24])
}

// DeleteRegistration removes one dynamic registration authenticated by its
// registration access token. The conditional predicate is the authorization
// revalidation at commit time: a concurrent token rotation cannot delete the
// newer registration.
func (s *Store) DeleteRegistration(ctx context.Context, clientID, registrationToken string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: store is not configured", ErrInvalid)
	}
	if !clientIDPattern.MatchString(clientID) || registrationToken == "" {
		return ErrUnauthorized
	}
	digestSum := sha256.Sum256([]byte(registrationToken))
	digest := base64.RawURLEncoding.EncodeToString(digestSum[:])
	requestID, err := deleteRequestID()
	if err != nil {
		return err
	}
	authorized := `EXISTS (SELECT 1 FROM dynamic_oauth_clients WHERE client_id = ? AND registration_token_digest = ?)`
	clientArgs := []any{clientID, clientID, digest}
	accessSignatures := `SELECT signature FROM oauth_access_tokens WHERE client_id = ? AND ` + authorized
	one := int64(1)
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: requestID,
		Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM oauth_refresh_tokens WHERE access_signature IN (` + accessSignatures + `)`, Args: clientArgs},
			{SQL: `DELETE FROM oauth_token_requests WHERE signature IN (` + accessSignatures + `)`, Args: clientArgs},
			{SQL: `DELETE FROM oauth_access_tokens WHERE client_id = ? AND ` + authorized, Args: clientArgs},
			{SQL: `DELETE FROM oauth_device_grants WHERE client_id = ? AND ` + authorized, Args: clientArgs},
			{SQL: `DELETE FROM dpop_nonces WHERE client_id = ? AND ` + authorized, Args: clientArgs},
			{SQL: `DELETE FROM oidc_backchannel_deliveries WHERE client_id = ? AND ` + authorized, Args: clientArgs},
			{SQL: `DELETE FROM oidc_session_clients WHERE client_id = ? AND ` + authorized, Args: clientArgs},
			{SQL: `DELETE FROM oidc_user_clients WHERE client_id = ? AND ` + authorized, Args: clientArgs},
			{SQL: `DELETE FROM client_themes WHERE client_id = ? AND ` + authorized, Args: clientArgs},
			{SQL: `DELETE FROM client_logos WHERE client_id = ? AND ` + authorized, Args: clientArgs},
			{SQL: `DELETE FROM client_favicons WHERE client_id = ? AND ` + authorized, Args: clientArgs},
			{SQL: `DELETE FROM dcr_registration_idempotency WHERE client_id = ? AND ` + authorized, Args: clientArgs},
			{SQL: `DELETE FROM dynamic_oauth_clients WHERE client_id = ? AND registration_token_digest = ? RETURNING client_id`, Args: []any{clientID, digest}, WantRows: true, ExpectedReturnedRows: &one},
		},
	})
	if err != nil {
		if response.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
			return ErrUnauthorized
		}
		return err
	}
	return nil
}

func deleteRequestID() (string, error) {
	// A new opaque ID makes retries re-evaluate the authorization predicate.
	// Reusing a token-derived ID could replay a prior successful DELETE from
	// Rhiza's request cache after the registration is already gone.
	nonce, err := randomValue(18)
	if err != nil {
		return "", err
	}
	return "dcr-delete/" + nonce, nil
}

// GetRegistration authenticates a registration access token and returns the
// persisted metadata. Raw credentials are deliberately never recoverable.
func (s *Store) GetRegistration(ctx context.Context, clientID, registrationToken string) (Registration, error) {
	registration, _, err := s.authenticateRegistration(ctx, clientID, registrationToken)
	return registration, err
}

func (s *Store) authenticateRegistration(ctx context.Context, clientID, registrationToken string) (Registration, string, error) {
	if registrationToken == "" {
		return Registration{}, "", ErrUnauthorized
	}
	registration, stored, exists, err := s.loadSnapshot(ctx, clientID)
	if err != nil || !exists {
		return Registration{}, "", ErrUnauthorized
	}
	digest := sha256.Sum256([]byte(registrationToken))
	wanted := base64.RawURLEncoding.EncodeToString(digest[:])
	if len(stored) != len(wanted) || subtle.ConstantTimeCompare([]byte(stored), []byte(wanted)) != 1 {
		return Registration{}, "", ErrUnauthorized
	}
	return registration, wanted, nil
}

func (s *Store) reconcileUpdate(ctx context.Context, clientID, rotatedDigest string, desired Registration) (Registration, bool, error) {
	recovered, stored, exists, err := s.loadSnapshot(ctx, clientID)
	if err != nil || !exists {
		return Registration{}, false, err
	}
	if len(stored) != len(rotatedDigest) || subtle.ConstantTimeCompare([]byte(stored), []byte(rotatedDigest)) != 1 {
		return Registration{}, false, ErrConflict
	}
	if !sameMetadata(recovered, desired) {
		return Registration{}, false, ErrConflict
	}
	return recovered, true, nil
}

func sameMetadata(left, right Registration) bool {
	return left.ClientID == right.ClientID && left.ClientURI == right.ClientURI && left.LogoURI == right.LogoURI && left.TOSURI == right.TOSURI && left.PolicyURI == right.PolicyURI && left.SoftwareStatement == right.SoftwareStatement && left.DPoPBoundAccessTokens == right.DPoPBoundAccessTokens && left.BackchannelLogoutURI == right.BackchannelLogoutURI && strings.Join(left.Contacts, "\x00") == strings.Join(right.Contacts, "\x00") && left.TokenEndpointAuthMethod == right.TokenEndpointAuthMethod && left.Name == right.Name && left.ForceMFA == right.ForceMFA &&
		strings.Join(left.RedirectURIs, "\x00") == strings.Join(right.RedirectURIs, "\x00") &&
		strings.Join(left.Scopes, "\x00") == strings.Join(right.Scopes, "\x00") &&
		strings.Join(left.DefaultScopes, "\x00") == strings.Join(right.DefaultScopes, "\x00") &&
		strings.Join(left.GrantTypes, "\x00") == strings.Join(right.GrantTypes, "\x00") &&
		strings.Join(left.ResponseTypes, "\x00") == strings.Join(right.ResponseTypes, "\x00") &&
		strings.Join(left.Audiences, "\x00") == strings.Join(right.Audiences, "\x00")
}

func (s *Store) load(ctx context.Context, clientID string) (Registration, bool, error) {
	registration, _, exists, err := s.loadSnapshot(ctx, clientID)
	return registration, exists, err
}

func (s *Store) loadSnapshot(ctx context.Context, clientID string) (Registration, string, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id, secret_hash, registration_token_digest, redirect_uris_json, scopes_json, default_scopes_json, grant_types_json, response_types_json, audiences_json, token_endpoint_auth_method, name, force_mfa, created_at_unix_ms, last_used_at_unix_ms, client_uri, contacts_json, logo_uri, tos_uri, policy_uri, software_statement, anonymous, dpop_bound_access_tokens, backchannel_logout_uri FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Registration{}, "", false, err
	}
	if len(result.Rows) == 0 {
		return Registration{}, "", false, nil
	}
	if s.afterRegistrationSnapshot != nil {
		s.afterRegistrationSnapshot()
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 23 {
		return Registration{}, "", false, fmt.Errorf("invalid dynamic client row")
	}
	row := result.Rows[0]
	secretHash := row[1]
	digest, ok := row[2].(string)
	if !ok || digest == "" {
		return Registration{}, "", false, fmt.Errorf("invalid registration token digest")
	}
	anonymous, ok := row[20].(int64)
	if !ok || anonymous < 0 || anonymous > 1 {
		return Registration{}, "", false, fmt.Errorf("invalid dynamic client anonymous value")
	}
	dpopBound, err := decodeForceMFA(row[21])
	if err != nil {
		return Registration{}, "", false, fmt.Errorf("invalid dynamic client DPoP bound access tokens value")
	}
	text := func(index int) (string, error) {
		value, ok := row[index].(string)
		if !ok {
			return "", fmt.Errorf("invalid dynamic client value")
		}
		return value, nil
	}
	client, err := text(0)
	if err != nil {
		return Registration{}, "", false, err
	}
	redirects, err := decodeStrings(row[3])
	if err != nil {
		return Registration{}, "", false, err
	}
	scopes, err := decodeStrings(row[4])
	if err != nil {
		return Registration{}, "", false, err
	}
	defaults, err := decodeStrings(row[5])
	if err != nil {
		return Registration{}, "", false, err
	}
	grants, err := decodeStrings(row[6])
	if err != nil {
		return Registration{}, "", false, err
	}
	responses, err := decodeStrings(row[7])
	if err != nil {
		return Registration{}, "", false, err
	}
	audiences, err := decodeStrings(row[8])
	if err != nil {
		return Registration{}, "", false, err
	}
	method, err := text(9)
	if err != nil {
		return Registration{}, "", false, err
	}
	if err := validatePersistedSecretHash(method, secretHash); err != nil {
		return Registration{}, "", false, err
	}
	name, err := text(10)
	if err != nil {
		return Registration{}, "", false, err
	}
	forceMFA, err := decodeForceMFA(row[11])
	if err != nil {
		return Registration{}, "", false, fmt.Errorf("invalid dynamic client force MFA value")
	}
	created, ok := row[12].(int64)
	if !ok {
		return Registration{}, "", false, fmt.Errorf("invalid dynamic client timestamp")
	}
	clientURI, err := nullableText(row[14])
	if err != nil {
		return Registration{}, "", false, err
	}
	contacts, err := nullableContacts(row[15])
	if err != nil {
		return Registration{}, "", false, err
	}
	logoURI, err := nullableText(row[16])
	if err != nil {
		return Registration{}, "", false, err
	}
	tosURI, err := nullableText(row[17])
	if err != nil {
		return Registration{}, "", false, err
	}
	policyURI, err := nullableText(row[18])
	if err != nil {
		return Registration{}, "", false, err
	}
	softwareStatement, err := nullableText(row[19])
	if err != nil {
		return Registration{}, "", false, err
	}
	backchannelLogoutURI, err := nullableText(row[22])
	if err != nil {
		return Registration{}, "", false, err
	}
	registration := Registration{ClientID: client, ClientURI: clientURI, LogoURI: logoURI, TOSURI: tosURI, PolicyURI: policyURI, SoftwareStatement: softwareStatement, DPoPBoundAccessTokens: dpopBound, BackchannelLogoutURI: backchannelLogoutURI, Contacts: contacts, RedirectURIs: redirects, Scopes: scopes, DefaultScopes: defaults, GrantTypes: grants, ResponseTypes: responses, Audiences: audiences, TokenEndpointAuthMethod: method, Name: name, ForceMFA: forceMFA, CreatedAt: time.UnixMilli(created).UTC(), Anonymous: anonymous == 1}
	if row[13] != nil {
		used, ok := row[13].(int64)
		if !ok {
			return Registration{}, "", false, fmt.Errorf("invalid dynamic client timestamp")
		}
		value := time.UnixMilli(used).UTC()
		registration.LastUsedAt = &value
	}
	if err := s.validateCreateRequest(CreateRequest{ClientID: registration.ClientID, ClientURI: registration.ClientURI, LogoURI: registration.LogoURI, TOSURI: registration.TOSURI, PolicyURI: registration.PolicyURI, Contacts: registration.Contacts, RedirectURIs: registration.RedirectURIs, Scopes: registration.Scopes, DefaultScopes: registration.DefaultScopes, GrantTypes: registration.GrantTypes, ResponseTypes: registration.ResponseTypes, Audiences: registration.Audiences, TokenEndpointAuthMethod: registration.TokenEndpointAuthMethod, Name: registration.Name, ForceMFA: registration.ForceMFA, SoftwareStatement: registration.SoftwareStatement, DPoPBoundAccessTokens: registration.DPoPBoundAccessTokens, BackchannelLogoutURI: registration.BackchannelLogoutURI}); err != nil {
		return Registration{}, "", false, fmt.Errorf("stored dynamic client violates invariant: %w", err)
	}
	return registration, digest, true, nil
}

// ForceMFA reads the client policy with linearizable consistency so an
// authorization decision never observes a stale registration update.
func (s *Store) ForceMFA(ctx context.Context, clientID string) (bool, error) {
	if s == nil || s.db == nil {
		return false, fmt.Errorf("%w: store is not configured", ErrInvalid)
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	if len(result.Rows) == 0 {
		return false, fosite.ErrNotFound
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return false, fmt.Errorf("invalid dynamic client row")
	}
	// Dynamic registration never controls force_mfa. Keep the legacy column
	// readable for migration compatibility, but do not re-enable its policy.
	return false, nil
}

func forceMFAValue(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func decodeForceMFA(value any) (bool, error) {
	flag, ok := value.(int64)
	if !ok || (flag != 0 && flag != 1) {
		return false, fmt.Errorf("invalid dynamic client force MFA value")
	}
	return flag == 1, nil
}

func validatePersistedSecretHash(method string, value any) error {
	if method == TokenEndpointAuthNone {
		if value != nil {
			return fmt.Errorf("invalid dynamic client secret: public client has a secret hash")
		}
		return nil
	}
	hash, ok := value.(string)
	if !ok || hash == "" {
		return fmt.Errorf("invalid dynamic client secret: confidential client has no hash")
	}
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		return fmt.Errorf("invalid dynamic client secret hash: %w", err)
	}
	return nil
}

func (s *Store) secretHash(ctx context.Context, clientID string) ([]byte, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT secret_hash FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("invalid dynamic client row")
	}
	if result.Rows[0][0] == nil {
		return nil, nil
	}
	value, ok := result.Rows[0][0].(string)
	if !ok || value == "" {
		return nil, fmt.Errorf("invalid dynamic client secret")
	}
	return []byte(value), nil
}

func (s *Store) newRegistration(clientID string, request CreateRequest, now time.Time) (Registration, error) {
	request.ClientID = clientID
	if err := s.validateCreateRequest(request); err != nil {
		return Registration{}, err
	}
	return Registration{ClientID: clientID, ClientURI: request.ClientURI, LogoURI: request.LogoURI, TOSURI: request.TOSURI, PolicyURI: request.PolicyURI, SoftwareStatement: request.SoftwareStatement, DPoPBoundAccessTokens: request.DPoPBoundAccessTokens, BackchannelLogoutURI: request.BackchannelLogoutURI, Contacts: canonicalContacts(request.Contacts), RedirectURIs: clone(request.RedirectURIs), Scopes: clone(request.Scopes), DefaultScopes: clone(request.DefaultScopes), GrantTypes: clone(request.GrantTypes), ResponseTypes: clone(request.ResponseTypes), Audiences: clone(request.Audiences), TokenEndpointAuthMethod: request.TokenEndpointAuthMethod, Name: request.Name, ForceMFA: false, CreatedAt: now.UTC().Truncate(time.Millisecond)}, nil
}

// DPoPBoundAccessTokens returns the persisted DPoP binding policy for a known dynamic client.
func (s *Store) DPoPBoundAccessTokens(ctx context.Context, clientID string) (bool, error) {
	if s == nil || s.db == nil {
		return false, fmt.Errorf("%w: store is not configured", ErrInvalid)
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT dpop_bound_access_tokens FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	if len(result.Rows) == 0 {
		return false, fosite.ErrNotFound
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return false, fmt.Errorf("invalid dynamic client row")
	}
	return decodeForceMFA(result.Rows[0][0])
}

func registrationJSON(registration Registration) (string, string, string, string, string, string, error) {
	values := [][]string{registration.RedirectURIs, registration.Scopes, registration.DefaultScopes, registration.GrantTypes, registration.ResponseTypes, registration.Audiences}
	encoded := make([]string, len(values))
	for i, value := range values {
		if value == nil {
			value = []string{}
		}
		bytes, err := json.Marshal(value)
		if err != nil {
			return "", "", "", "", "", "", err
		}
		encoded[i] = string(bytes)
	}
	return encoded[0], encoded[1], encoded[2], encoded[3], encoded[4], encoded[5], nil
}

func decodeStrings(value any) ([]string, error) {
	raw, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("invalid dynamic client JSON")
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}
	return values, nil
}

func nullableText(value any) (string, error) {
	if value == nil {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid dynamic client value")
	}
	return text, nil
}

func nullableClientURI(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func canonicalContacts(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cloned := append([]string(nil), values...)
	sort.Strings(cloned)
	return cloned
}

func contactsJSONString(values []string) string {
	encoded, _ := json.Marshal(canonicalContacts(values))
	return string(encoded)
}

func nullableContactsJSON(values []string) any {
	if len(values) == 0 {
		return nil
	}
	return contactsJSONString(values)
}

func nullableContacts(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	raw, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("invalid dynamic client contacts")
	}
	var contacts []string
	if err := json.Unmarshal([]byte(raw), &contacts); err != nil {
		return nil, err
	}
	if err := validateContacts(contacts); err != nil {
		return nil, err
	}
	return canonicalContacts(contacts), nil
}

func (s *Store) validateCreateRequest(request CreateRequest) error {
	if len(request.SoftwareStatement) > maxSoftwareStatementLength {
		return fmt.Errorf("%w: software statement", ErrInvalid)
	}
	if request.ClientID != "" && !clientIDPattern.MatchString(request.ClientID) {
		return fmt.Errorf("%w: client ID", ErrInvalid)
	}
	if request.ClientURI != "" && !validClientURI(request.ClientURI) {
		return fmt.Errorf("%w: client URI", ErrInvalid)
	}
	for _, metadata := range []struct {
		name  string
		value string
	}{
		{name: "logo URI", value: request.LogoURI},
		{name: "terms of service URI", value: request.TOSURI},
		{name: "policy URI", value: request.PolicyURI},
	} {
		if metadata.value != "" && !validMetadataURI(metadata.value) {
			return fmt.Errorf("%w: %s", ErrInvalid, metadata.name)
		}
	}
	if request.BackchannelLogoutURI != "" && !backchannelURIPattern.MatchString(request.BackchannelLogoutURI) {
		return fmt.Errorf("%w: backchannel logout URI", ErrInvalid)
	}
	if err := validateContacts(request.Contacts); err != nil {
		return err
	}
	if request.Name == "" || len(request.Name) > maxNameLength || strings.TrimSpace(request.Name) != request.Name {
		return fmt.Errorf("%w: client name", ErrInvalid)
	}
	if !validMethod(request.TokenEndpointAuthMethod) {
		return fmt.Errorf("%w: token endpoint authentication method", ErrInvalid)
	}
	if err := validateUnique(request.GrantTypes, validGrant); err != nil {
		return err
	}
	if err := validateUnique(request.ResponseTypes, func(value string) bool { return value == "code" }); err != nil {
		return err
	}
	if err := validateUnique(request.Scopes, func(value string) bool { return scopePattern.MatchString(value) }); err != nil {
		return err
	}
	if err := validateUnique(request.DefaultScopes, func(value string) bool { return scopePattern.MatchString(value) }); err != nil {
		return err
	}
	for _, scope := range request.DefaultScopes {
		if !contains(request.Scopes, scope) {
			return fmt.Errorf("%w: default scope is not allowed", ErrInvalid)
		}
	}
	hasCode := contains(request.GrantTypes, "authorization_code")
	hasDevice := contains(request.GrantTypes, deviceGrantType)
	hasPassword := contains(request.GrantTypes, "password")
	hasClientCredentials := contains(request.GrantTypes, "client_credentials")
	if !hasCode && !hasDevice && !hasClientCredentials && !hasPassword {
		return fmt.Errorf("%w: grant types", ErrInvalid)
	}
	if contains(request.GrantTypes, "refresh_token") && !hasCode && !hasDevice && !hasPassword {
		return fmt.Errorf("%w: refresh grant", ErrInvalid)
	}
	if hasClientCredentials && request.TokenEndpointAuthMethod == TokenEndpointAuthNone {
		return fmt.Errorf("%w: client credentials authentication", ErrInvalid)
	}
	loopback := s.allowLoopback && request.TokenEndpointAuthMethod == TokenEndpointAuthNone && len(request.GrantTypes) == 1 && hasCode && len(request.ResponseTypes) == 1 && request.ResponseTypes[0] == "code"
	if err := validateRedirectURLs(request.RedirectURIs, loopback); err != nil {
		return err
	}
	if err := validateURLs(request.Audiences); err != nil {
		return err
	}
	if hasCode != contains(request.ResponseTypes, "code") || (hasCode && len(request.RedirectURIs) == 0) {
		return fmt.Errorf("%w: authorization-code metadata", ErrInvalid)
	}
	if !hasCode && len(request.ResponseTypes) != 0 {
		return fmt.Errorf("%w: response types", ErrInvalid)
	}
	return nil
}

func validateContacts(values []string) error {
	if len(values) > maxListEntries {
		return fmt.Errorf("%w: too many contacts", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(value) == 0 || len(value) > maxContactLength || !contactPattern.MatchString(value) {
			return fmt.Errorf("%w: contact value", ErrInvalid)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%w: duplicate contact value", ErrInvalid)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validMethod(value string) bool {
	return value == TokenEndpointAuthNone || value == TokenEndpointAuthClientBasic || value == TokenEndpointAuthClientPost
}
func validGrant(value string) bool {
	return value == "authorization_code" || value == "password" || value == "refresh_token" || value == "client_credentials" || value == deviceGrantType
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func clone(values []string) []string { return append([]string(nil), values...) }
func validateUnique(values []string, valid func(string) bool) error {
	if len(values) > maxListEntries {
		return fmt.Errorf("%w: too many metadata values", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > maxValueLength || !valid(value) {
			return fmt.Errorf("%w: metadata value", ErrInvalid)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%w: duplicate metadata value", ErrInvalid)
		}
		seen[value] = struct{}{}
	}
	return nil
}
func validateURLs(values []string) error {
	return validateUnique(values, func(value string) bool {
		parsed, err := url.Parse(value)
		return err == nil && parsed.IsAbs() && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
	})
}

func validClientURI(value string) bool {
	return validMetadataURI(value)
}

func validMetadataURI(value string) bool {
	if value == "" || len(value) > maxValueLength {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.String() == value && parsed.IsAbs() && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Host == strings.ToLower(parsed.Host)
}

func validateRedirectURLs(values []string, allowLoopback bool) error {
	return validateUnique(values, func(value string) bool {
		if allowLoopback && redirecturi.IsLoopbackTemplate(value) {
			return true
		}
		parsed, err := url.Parse(value)
		return err == nil && parsed.IsAbs() && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
	})
}
func randomValue(bytesLength int) (string, error) {
	bytes := make([]byte, bytesLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("read secure random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
