// Package identity persists local password identities.
package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/scim"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	maxSubjectBytes  = 512
	maxUsernameBytes = 64
)

var (
	ErrInvalidUsername           = errors.New("invalid normalized username")
	ErrInvalidSubject            = errors.New("invalid identity subject")
	ErrInvalidPasswordCredential = errors.New("invalid password credential")
	ErrBootstrapConflict         = errors.New("identity bootstrap conflict")
	ErrInvalidCredentials        = errors.New("invalid credentials")
	ErrInactiveSubject           = errors.New("inactive identity subject")
	ErrPasswordRejected          = errors.New("password rejected")
	ErrPasswordReuse             = errors.New("password has been used recently")
	ErrPasswordChangeConflict    = errors.New("password change conflict")
	ErrPasswordExpired           = errors.New("password expired")
	ErrPasswordResetUnavailable  = errors.New("password reset unavailable")
	ErrInvalidPasswordReset      = errors.New("invalid password reset")
	ErrFinalAdmin                = errors.New("cannot delete the last active direct rauthy_admin")
	ErrLastActiveAdmin           = ErrFinalAdmin
	ErrDeleteUnauthorized        = errors.New("user deletion authorization failed")
	// ErrPasswordAuthenticationDisabled is intentionally internal: HTTP
	// callers map it to their existing generic credential failures.
	ErrPasswordAuthenticationDisabled = errors.New("password authentication disabled")
)

// SchemaStatements is the table contract for the identity migration. username
// is stored only in its canonical ASCII form, so BINARY equality is sufficient.
func SchemaStatements() []rhiza.SQLStatement {
	return []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_users (
		subject TEXT PRIMARY KEY NOT NULL,
		username TEXT NOT NULL UNIQUE,
		password_phc TEXT NOT NULL,
		disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
		created_at_unix_ms INTEGER NOT NULL DEFAULT 0 CHECK (created_at_unix_ms >= 0),
		last_login_at_unix_ms INTEGER CHECK (last_login_at_unix_ms IS NULL OR last_login_at_unix_ms >= 0),
 last_failed_login_at_unix_ms INTEGER CHECK(last_failed_login_at_unix_ms IS NULL OR last_failed_login_at_unix_ms>=0),
 failed_login_attempts INTEGER CHECK(failed_login_attempts IS NULL OR failed_login_attempts>=0),
		user_expires_at_unix_ms INTEGER CHECK (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms >= 0),
		language TEXT CHECK (language IS NULL OR language IN ('de','en','fr','ko','nb','nl','ru','uk','zhhans')),
		password_changed_at_unix_ms INTEGER NOT NULL DEFAULT 0 CHECK (password_changed_at_unix_ms >= 0),
		password_generation INTEGER NOT NULL DEFAULT 1 CHECK (password_generation >= 1)
	) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS rbac_principal_versions (
			subject TEXT PRIMARY KEY NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			revision INTEGER NOT NULL CHECK (revision >= 1),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_password_history (
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			generation INTEGER NOT NULL CHECK (generation >= 1),
			password_phc TEXT NOT NULL CHECK (length(password_phc) BETWEEN 1 AND 512),
			changed_at_unix_ms INTEGER NOT NULL CHECK (changed_at_unix_ms >= 0),
			PRIMARY KEY (subject, generation)
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_password_reset_tokens (
			token_digest TEXT PRIMARY KEY NOT NULL CHECK (length(token_digest) = 43),
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			password_generation INTEGER NOT NULL CHECK (password_generation >= 1),
			issued_at_unix_ms INTEGER NOT NULL CHECK (issued_at_unix_ms >= 0),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > issued_at_unix_ms),
			binding_digest TEXT CHECK (binding_digest IS NULL OR length(binding_digest) = 43),
			bound_at_unix_ms INTEGER CHECK (bound_at_unix_ms IS NULL OR bound_at_unix_ms >= issued_at_unix_ms),
			consumed_attempt TEXT CHECK (consumed_attempt IS NULL OR length(consumed_attempt) = 22),
			consumed_at_unix_ms INTEGER CHECK (consumed_at_unix_ms IS NULL OR consumed_at_unix_ms >= issued_at_unix_ms),
			usage TEXT NOT NULL DEFAULT 'password_reset' CHECK (usage IN ('password_reset', 'password_new')),
			redirect_uri TEXT CHECK (redirect_uri IS NULL OR (length(redirect_uri) BETWEEN 1 AND 2048 AND instr(redirect_uri, char(13)) = 0 AND instr(redirect_uri, char(10)) = 0)),
			CHECK ((binding_digest IS NULL) = (bound_at_unix_ms IS NULL)),
			CHECK ((consumed_attempt IS NULL) = (consumed_at_unix_ms IS NULL))
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_password_reset_tokens_expiry ON identity_password_reset_tokens(expires_at_unix_ms)`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_user_profiles (
			subject TEXT PRIMARY KEY NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			email TEXT NOT NULL UNIQUE CHECK (length(email) BETWEEN 3 AND 254 AND email = lower(email)),
			email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
			preferred_username TEXT CHECK (preferred_username IS NULL OR length(preferred_username) BETWEEN 1 AND 128),
			given_name TEXT CHECK (given_name IS NULL OR length(given_name) BETWEEN 1 AND 32),
			family_name TEXT CHECK (family_name IS NULL OR length(family_name) BETWEEN 1 AND 32),
			user_values_json TEXT CHECK (user_values_json IS NULL OR (length(user_values_json) BETWEEN 2 AND 8192 AND json_valid(user_values_json)))
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_authentication_modes (
			subject TEXT PRIMARY KEY NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			mode TEXT NOT NULL CHECK (mode IN ('password', 'passkey')),
			generation INTEGER NOT NULL CHECK (generation >= 1),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS scim_user_tombstones (
			local_external_id TEXT PRIMARY KEY NOT NULL CHECK (length(local_external_id) BETWEEN 1 AND 512),
			user_name TEXT NOT NULL CHECK (length(user_name) BETWEEN 1 AND 254),
			active INTEGER NOT NULL CHECK (active IN (0, 1)),
			hard_delete INTEGER NOT NULL DEFAULT 0 CHECK (hard_delete IN (0, 1)),
			provider_snapshot_complete INTEGER NOT NULL DEFAULT 0 CHECK (provider_snapshot_complete IN (0, 1)),
			generation TEXT NOT NULL DEFAULT '' CHECK (length(generation) = 0 OR (length(generation) = 22 AND generation NOT GLOB '*[^A-Za-z0-9_-]*')),
			deleted_at_unix_ms INTEGER NOT NULL CHECK (deleted_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS scim_user_tombstones_deleted ON scim_user_tombstones(deleted_at_unix_ms, local_external_id)`},
		{SQL: `CREATE TABLE IF NOT EXISTS scim_user_tombstone_providers (
			local_external_id TEXT NOT NULL CHECK (length(local_external_id) BETWEEN 1 AND 512),
			client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 256),
			delete_policy INTEGER NOT NULL CHECK (delete_policy IN (1, 2)),
			PRIMARY KEY (local_external_id, client_id)
		) STRICT`},
	}
}

type Store struct {
	db                       *rhiza.DB
	hasher                   *credential.Hasher
	rules                    credential.Rules
	now                      func() time.Time
	random                   func([]byte) (int, error)
	resetKey                 []byte
	deleteUserAfterRead      func()
	tombstoneProvidersMu     sync.Mutex
	tombstoneProviders       []SCIMTombstoneProvider
	tombstoneProvidersFrozen bool
}

type User struct {
	Subject  string
	Username string
	Disabled bool
}

// AccountProfile is the narrow, public identity projection used by browser
// federation surfaces. It deliberately excludes credentials, attributes, and
// recovery metadata.
type AccountProfile struct {
	Subject           string
	Username          string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	GivenName         string
	FamilyName        string
}

// Authentication is intentionally returned only after a successful password
// check. NeedsRehash remains for API compatibility; Store performs eligible
// upgrades before returning and therefore always reports false.
// PasswordGeneration and AuthenticationGeneration are captured in the same
// linearizable credential lookup that verified the password. They are zero
// when authentication fails; callers must not use them on error paths.
type Authentication struct {
	Subject                  string
	NeedsRehash              bool
	PasswordGeneration       int64
	AuthenticationGeneration int64
}

// PasswordResetChallenge binds a reset bearer token to one browser before it
// can be consumed. CookieToken is an opaque, canonical base64url value; only
// its keyed digest is persisted.
type PasswordResetChallenge struct {
	CookieToken string
	CSRFToken   string
	ExpiresAt   time.Time
}

// OpenRegistration is the pending, password-first identity created by the
// public registration endpoint. The password is deliberately not accepted
// here: its one-use password_new token completes that separate ceremony.
type OpenRegistration struct {
	Language                string
	Email                   string
	PreferredUsername       string
	PreferredUsernamePolicy *PreferredUsernamePolicy
	GivenName               string
	FamilyName              string
	UserValuesJSON          string
	RedirectURI             string
	TTL                     time.Duration
	SourceIP                string
}

type OpenRegistrationResult struct {
	Subject   string
	Token     string
	ExpiresAt time.Time
	Created   bool
}

func NewStore(db *rhiza.DB) (*Store, error) {
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		return nil, err
	}
	return NewStoreWithPolicies(db, hasher, credential.DefaultRules())
}

// NewStoreWithHasher creates an identity store with the supplied password
// policy. The hasher is shared by authentication and best-effort upgrades.
func NewStoreWithHasher(db *rhiza.DB, hasher *credential.Hasher) (*Store, error) {
	return NewStoreWithPolicies(db, hasher, credential.DefaultRules())
}

// NewStoreWithPolicies creates an identity store with independent hash and
// plaintext-password rules.
func NewStoreWithPolicies(db *rhiza.DB, hasher *credential.Hasher, rules credential.Rules) (*Store, error) {
	if db == nil {
		return nil, errors.New("identity store requires Rhiza DB")
	}
	if hasher == nil {
		return nil, errors.New("identity store requires password hasher")
	}
	if err := rules.Validate(); err != nil {
		return nil, err
	}
	return &Store{db: db, hasher: hasher, rules: rules, now: time.Now, random: rand.Read}, nil
}

// NewStoreWithPasswordReset enables reset issuance using a dedicated 32-byte
// HMAC key. Existing constructors intentionally leave issuance disabled.
func NewStoreWithPasswordReset(db *rhiza.DB, hasher *credential.Hasher, rules credential.Rules, resetKey []byte) (*Store, error) {
	if len(resetKey) != sha256.Size {
		return nil, ErrPasswordResetUnavailable
	}
	store, err := NewStoreWithPolicies(db, hasher, rules)
	if err != nil {
		return nil, err
	}
	store.resetKey = append([]byte(nil), resetKey...)
	return store, nil
}

// CanonicalEmail validates an ASCII mailbox and returns its lower-case storage
// form. Callers which require already-canonical input must compare the result
// with their input rather than silently replacing it.
func CanonicalEmail(value string) (string, error) {
	if value == "" || len(value) > 254 || strings.TrimSpace(value) != value || !ascii(value) {
		return "", ErrInvalidUsername
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Name != "" || parsed.Address != value {
		return "", ErrInvalidUsername
	}
	return strings.ToLower(value), nil
}

// ValidateUsername accepts only an already-normalized ASCII username or email.
// It rejects case-folding, whitespace, and Unicode rather than silently
// changing an ID.
func ValidateUsername(username string) error {
	if email, err := CanonicalEmail(username); err == nil && email == username {
		return nil
	}
	if len(username) == 0 || len(username) > maxUsernameBytes {
		return ErrInvalidUsername
	}
	for i := range len(username) {
		c := username[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (i > 0 && (c == '.' || c == '-' || c == '_'))) {
			return ErrInvalidUsername
		}
	}
	return nil
}

// CleanupExpiredOpenRegistrations removes at most 64 abandoned password-first
// identities. Passing time in keeps scheduler tests deterministic.
func (s *Store) CleanupExpiredOpenRegistrations(ctx context.Context, now time.Time) error {
	unixMillis := now.UTC().Truncate(time.Millisecond).UnixMilli()
	statements, err := s.expiredOpenRegistrationStatements(unixMillis)
	if err != nil {
		return err
	}
	nonce, err := s.randomID(16)
	if err != nil {
		return err
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("password-new-cleanup", strconv.FormatInt(unixMillis, 10), nonce), Statements: statements,
	})
	return err
}

func (s *Store) expiredOpenRegistrationStatements(now int64) ([]rhiza.SQLStatement, error) {
	// Reuse this exact ordered set throughout the atomic batch. Identity rows
	// are deleted last, so all metadata and provider obligations cover the same
	// at-most-64 identities, including concurrent password completion checks.
	const candidates = `SELECT t.subject FROM identity_password_reset_tokens t JOIN identity_users u ON u.subject=t.subject WHERE t.usage='password_new' AND t.consumed_attempt IS NULL AND t.expires_at_unix_ms<=? AND u.password_phc='' AND NOT EXISTS(SELECT 1 FROM identity_webauthn_credentials c WHERE c.subject=u.subject) ORDER BY t.expires_at_unix_ms,t.subject LIMIT 64`
	providers := s.freezeSCIMTombstoneProviders()
	statements := make([]rhiza.SQLStatement, 0, 10+len(providers))
	if len(providers) != 0 {
		generation, err := s.randomID(16)
		if err != nil {
			return nil, ErrSCIMTombstoneGenerationUnavailable
		}
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO scim_user_tombstones(local_external_id,user_name,active,hard_delete,provider_snapshot_complete,generation,deleted_at_unix_ms) SELECT u.subject,u.username,0,1,1,?,? FROM identity_users u WHERE u.subject IN (` + candidates + `) AND NOT EXISTS(SELECT 1 FROM scim_user_tombstones t WHERE t.local_external_id=u.subject)`, Args: []any{generation, now, now}})
		for _, provider := range providers {
			statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO scim_user_tombstone_providers(local_external_id,client_id,delete_policy) SELECT local_external_id,?,? FROM scim_user_tombstones WHERE generation=?`, Args: []any{provider.ID, int64(scim.DeleteRemote), generation}})
		}
	}
	for _, target := range []struct{ table, column string }{{"identity_recovery_emails", "subject"}, {"identity_user_profiles", "subject"}, {"identity_authentication_modes", "subject"}, {"identity_external_links", "local_subject"}, {"rbac_user_roles", "subject"}, {"rbac_user_groups", "subject"}, {"rbac_principal_versions", "subject"}, {"identity_users", "subject"}} {
		statements = append(statements, rhiza.SQLStatement{SQL: `DELETE FROM ` + target.table + ` WHERE ` + target.column + ` IN (` + candidates + `)`, Args: []any{now}})
	}
	statements = append(statements, rhiza.SQLStatement{SQL: `DELETE FROM identity_password_reset_tokens WHERE usage='password_new' AND consumed_attempt IS NULL AND expires_at_unix_ms<=? AND NOT EXISTS(SELECT 1 FROM identity_users u WHERE u.subject=identity_password_reset_tokens.subject)`, Args: []any{now}})
	return statements, nil
}

// RegisterOpenUser creates the password-first pending account and its one-use
// password_new token atomically. A duplicate deliberately converges to its
// existing subject without returning a bearer token.
func (s *Store) RegisterOpenUser(ctx context.Context, input OpenRegistration) (OpenRegistrationResult, error) {
	if input.PreferredUsernamePolicy.ValidateRegistration(optionalPreferredUsername(input.PreferredUsername)) != nil {
		return OpenRegistrationResult{}, ErrInvalidPasswordReset
	}
	if input.Language == "" {
		input.Language = "en"
	}
	if !i18n.ValidUserLanguage(input.Language) {
		return OpenRegistrationResult{}, ErrInvalidPasswordReset
	}
	if len(s.resetKey) != sha256.Size {
		return OpenRegistrationResult{}, ErrPasswordResetUnavailable
	}
	email, err := CanonicalEmail(input.Email)
	if err != nil || input.TTL < time.Minute || input.TTL > 7*24*time.Hour || len(input.RedirectURI) > 2048 || strings.ContainsAny(input.RedirectURI, "\r\n") || len(input.PreferredUsername) > 128 || len(input.GivenName) > 32 || len(input.FamilyName) > 32 || len(input.UserValuesJSON) > 8192 || (input.UserValuesJSON != "" && !json.Valid([]byte(input.UserValuesJSON))) {
		return OpenRegistrationResult{}, ErrInvalidPasswordReset
	}
	var preferred, given, family, values, redirect any
	if input.PreferredUsername != "" {
		preferred = input.PreferredUsername
	}
	if input.GivenName != "" {
		given = input.GivenName
	}
	if input.FamilyName != "" {
		family = input.FamilyName
	}
	if input.UserValuesJSON != "" {
		values = input.UserValuesJSON
	}
	if input.RedirectURI != "" {
		redirect = input.RedirectURI
	}
	subject, err := s.randomID(32)
	if err != nil {
		return OpenRegistrationResult{}, ErrPasswordResetUnavailable
	}
	raw, err := s.randomID(32)
	if err != nil {
		return OpenRegistrationResult{}, ErrPasswordResetUnavailable
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	expires := now.Add(input.TTL)
	digest := s.resetDigest(raw)
	cleanup, err := s.expiredOpenRegistrationStatements(now.UnixMilli())
	if err != nil {
		return OpenRegistrationResult{}, err
	}
	statements := append(cleanup, []rhiza.SQLStatement{
		{SQL: `INSERT OR IGNORE INTO identity_users (subject,username,password_phc,password_changed_at_unix_ms,password_generation,created_at_unix_ms,language) SELECT ?,?, '', ?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM identity_recovery_emails WHERE email = ?) AND NOT EXISTS (SELECT 1 FROM identity_user_profiles WHERE email = ?) AND NOT EXISTS (SELECT 1 FROM identity_user_profiles WHERE preferred_username=?)`, Args: []any{subject, email, now.UnixMilli(), now.UnixMilli(), input.Language, email, email, preferred}},
		{SQL: `INSERT OR IGNORE INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) SELECT ?,1,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND username = ? AND password_phc = '')`, Args: []any{subject, now.UnixMilli(), subject, email}},
		{SQL: `INSERT OR IGNORE INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) SELECT ?, 'password', 1, ? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND username = ? AND password_phc = '')`, Args: []any{subject, now.UnixMilli(), subject, email}},
		{SQL: `INSERT OR IGNORE INTO identity_recovery_emails (subject,email) SELECT ?,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND username = ? AND password_phc = '')`, Args: []any{subject, email, subject, email}},
		{SQL: `INSERT OR IGNORE INTO identity_user_profiles (subject,email,email_verified,preferred_username,given_name,family_name,user_values_json) SELECT ?,?,0,?,?,?,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND username = ? AND password_phc = '')`, Args: []any{subject, email, preferred, given, family, values, subject, email}},
		{SQL: `INSERT OR IGNORE INTO identity_password_reset_tokens (token_digest,subject,password_generation,issued_at_unix_ms,expires_at_unix_ms,usage,redirect_uri) SELECT ?,?,?,?,?,'password_new',? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND username = ? AND password_phc = '') AND EXISTS (SELECT 1 FROM identity_user_profiles WHERE subject = ? AND email = ?)`, Args: []any{digest, subject, int64(1), now.UnixMilli(), expires.UnixMilli(), redirect, subject, email, subject, email}},
	}...)
	event, err := eventlog.Creation(mutationID("password-new-register", subject, digest, strconv.FormatInt(now.UnixMilli(), 10)), email, input.SourceIP, false, now).Statement(`EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND username=? AND password_phc='') AND EXISTS (SELECT 1 FROM identity_user_profiles WHERE subject=? AND email=?) AND EXISTS (SELECT 1 FROM identity_password_reset_tokens WHERE token_digest=? AND subject=? AND usage='password_new' AND consumed_attempt IS NULL)`, subject, email, subject, email, digest, subject)
	if err != nil {
		return OpenRegistrationResult{}, err
	}
	statements = append(statements, event)
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: mutationID("password-new-register", subject, digest, strconv.FormatInt(now.UnixMilli(), 10)), Statements: statements})
	if err != nil {
		return OpenRegistrationResult{}, err
	}
	owner, found, err := s.openRegistrationOwner(ctx, email)
	if err != nil {
		return OpenRegistrationResult{}, err
	}
	if !found {
		return OpenRegistrationResult{}, ErrInvalidPasswordReset
	}
	result := OpenRegistrationResult{Subject: owner}
	if owner != subject {
		return result, nil
	}
	issued, found, err := s.resetRecord(ctx, digest)
	if err != nil {
		return OpenRegistrationResult{}, err
	}
	if !found || issued.subject != subject || issued.generation != 1 || issued.usage != "password_new" || issued.expiresAt != expires.UnixMilli() || issued.consumed || issued.binding != "" {
		return OpenRegistrationResult{}, ErrInvalidPasswordReset
	}
	return OpenRegistrationResult{Subject: subject, Token: raw, ExpiresAt: expires, Created: true}, nil
}

// RegisterPasskeyUser creates a passkey-only pending account without a
// password reset token. A duplicate converges to its existing subject.
func (s *Store) RegisterPasskeyUser(ctx context.Context, input OpenRegistration) (string, error) {
	if input.PreferredUsernamePolicy.ValidateRegistration(optionalPreferredUsername(input.PreferredUsername)) != nil {
		return "", ErrInvalidPasswordReset
	}
	if input.Language == "" {
		input.Language = "en"
	}
	if !i18n.ValidUserLanguage(input.Language) {
		return "", ErrInvalidPasswordReset
	}
	email, err := CanonicalEmail(input.Email)
	if err != nil || input.TTL < time.Minute || input.TTL > 7*24*time.Hour || len(input.PreferredUsername) > 128 || len(input.GivenName) > 32 || len(input.FamilyName) > 32 || len(input.UserValuesJSON) > 8192 || (input.UserValuesJSON != "" && !json.Valid([]byte(input.UserValuesJSON))) {
		return "", ErrInvalidPasswordReset
	}
	var preferred, given, family, values any
	if input.PreferredUsername != "" {
		preferred = input.PreferredUsername
	}
	if input.GivenName != "" {
		given = input.GivenName
	}
	if input.FamilyName != "" {
		family = input.FamilyName
	}
	if input.UserValuesJSON != "" {
		values = input.UserValuesJSON
	}
	subject, err := s.randomID(32)
	if err != nil {
		return "", ErrPasswordResetUnavailable
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	cleanup, err := s.expiredOpenRegistrationStatements(now.UnixMilli())
	if err != nil {
		return "", err
	}
	statements := append(cleanup, []rhiza.SQLStatement{
		{SQL: `INSERT OR IGNORE INTO identity_users (subject,username,password_phc,password_changed_at_unix_ms,password_generation,created_at_unix_ms,language) SELECT ?,?, '', ?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM identity_recovery_emails WHERE email = ?) AND NOT EXISTS (SELECT 1 FROM identity_user_profiles WHERE email = ?) AND NOT EXISTS (SELECT 1 FROM identity_user_profiles WHERE preferred_username=?)`, Args: []any{subject, email, now.UnixMilli(), now.UnixMilli(), input.Language, email, email, preferred}},
		{SQL: `INSERT OR IGNORE INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) SELECT ?,1,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND username = ? AND password_phc = '')`, Args: []any{subject, now.UnixMilli(), subject, email}},
		{SQL: `INSERT OR IGNORE INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) SELECT ?, 'passkey', 1, ? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND username = ? AND password_phc = '')`, Args: []any{subject, now.UnixMilli(), subject, email}},
		{SQL: `INSERT OR IGNORE INTO identity_recovery_emails (subject,email) SELECT ?,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND username = ? AND password_phc = '')`, Args: []any{subject, email, subject, email}},
		{SQL: `INSERT OR IGNORE INTO identity_user_profiles (subject,email,email_verified,preferred_username,given_name,family_name,user_values_json) SELECT ?,?,0,?,?,?,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND username = ? AND password_phc = '')`, Args: []any{subject, email, preferred, given, family, values, subject, email}},
	}...)
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: mutationID("passkey-register", subject, strconv.FormatInt(now.UnixMilli(), 10)), Statements: statements})
	if err != nil {
		return "", err
	}
	owner, found, err := s.openRegistrationOwner(ctx, email)
	if err != nil {
		return "", err
	}
	if !found {
		return "", ErrInvalidPasswordReset
	}
	if owner != subject {
		return owner, nil
	}
	return subject, nil
}

// BootstrapUser creates an identity exactly once. Existing credentials are
// never updated, including when a concurrent bootstrap races this call.
func (s *Store) BootstrapUser(ctx context.Context, subject, username, passwordPHC string) (User, error) {
	if err := validateSubject(subject); err != nil {
		return User{}, err
	}
	if err := ValidateUsername(username); err != nil {
		return User{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	tombstoned, err := s.subjectTombstoned(ctx, subject)
	if err != nil {
		return User{}, err
	}
	if tombstoned {
		return User{}, ErrBootstrapConflict
	}
	user, found, err := s.lookupByUsername(ctx, username)
	if err != nil {
		return User{}, err
	}
	if found {
		if user.Subject != subject {
			return User{}, ErrBootstrapConflict
		}
		if err := s.ensurePasswordMode(ctx, subject, now.UnixMilli()); err != nil {
			return User{}, err
		}
		return s.bootstrapExistingUser(ctx, subject, username)
	}
	if err := s.hasher.ValidateCurrentPHC(passwordPHC); err != nil {
		return User{}, ErrInvalidPasswordCredential
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("bootstrap", subject, username, passwordPHC, strconv.FormatInt(now.UnixMilli(), 10)),
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT OR IGNORE INTO identity_users (subject, username, password_phc, password_changed_at_unix_ms, password_generation, created_at_unix_ms) SELECT ?, ?, ?, ?, 1, ? WHERE NOT EXISTS (SELECT 1 FROM scim_user_tombstones WHERE local_external_id = ?)`, Args: []any{subject, username, passwordPHC, now.UnixMilli(), now.UnixMilli(), subject}},
			{SQL: `INSERT OR IGNORE INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) SELECT ?,1,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND username = ?)`, Args: []any{subject, now.UnixMilli(), subject, username}},
			{SQL: `INSERT OR IGNORE INTO identity_authentication_modes (subject, mode, generation, updated_at_unix_ms) SELECT ?, 'password', 1, ? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ?)`, Args: []any{subject, now.UnixMilli(), subject}},
		},
	}); err != nil {
		return User{}, err
	}
	user, found, err = s.lookupByUsername(ctx, username)
	if err != nil {
		return User{}, err
	}
	if !found || user.Subject != subject {
		return User{}, ErrBootstrapConflict
	}
	if err := s.ensurePasswordMode(ctx, subject, now.UnixMilli()); err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *Store) bootstrapExistingUser(ctx context.Context, subject, username string) (User, error) {
	tombstoned, err := s.subjectTombstoned(ctx, subject)
	if err != nil {
		return User{}, err
	}
	if tombstoned {
		return User{}, ErrBootstrapConflict
	}
	user, found, err := s.lookupByUsername(ctx, username)
	if err != nil {
		return User{}, err
	}
	if !found || user.Subject != subject {
		return User{}, ErrBootstrapConflict
	}
	return user, nil
}

func (s *Store) subjectTombstoned(ctx context.Context, subject string) (bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM scim_user_tombstones WHERE local_external_id = ?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	return len(result.Rows) != 0, nil
}

// DeleteUser permanently removes one identity and every row owned by its
// subject. The SCIM tombstone snapshot is committed in the same transaction.
func (s *Store) DeleteUser(ctx context.Context, subject string) error {
	return s.deleteUser(ctx, subject, "", nil)
}

// DeleteUserWithGuard atomically snapshots an already-authenticated authority
// and requires that snapshot for every deletion statement. The guard SQL is
// evaluated by the same transaction as the destructive write.
func (s *Store) DeleteUserWithGuard(ctx context.Context, subject, authoritySQL string, authorityArgs []any) error {
	if strings.TrimSpace(authoritySQL) == "" {
		return ErrDeleteUnauthorized
	}
	return s.deleteUser(ctx, subject, authoritySQL, authorityArgs)
}

func (s *Store) deleteUser(ctx context.Context, subject, authoritySQL string, authorityArgs []any) error {
	if err := validateSubject(subject); err != nil {
		return err
	}
	providers := s.freezeSCIMTombstoneProviders()
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT u.username,u.disabled,u.password_phc,m.mode FROM identity_users u JOIN identity_authentication_modes m ON m.subject = u.subject WHERE u.subject = ?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) == 0 {
		return ErrInactiveSubject
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return errors.New("invalid identity deletion row")
	}
	username, usernameOK := result.Rows[0][0].(string)
	disabled, disabledOK := result.Rows[0][1].(int64)
	passwordPHC, passwordOK := result.Rows[0][2].(string)
	mode, modeOK := result.Rows[0][3].(string)
	if !usernameOK || !disabledOK || !passwordOK || !modeOK || ValidateUsername(username) != nil || (disabled != 0 && disabled != 1) || (mode != "password" && mode != "passkey") || (passwordPHC != "" && s.hasher.ValidateCurrentPHC(passwordPHC) != nil) {
		return errors.New("invalid identity deletion row")
	}
	if s.deleteUserAfterRead != nil {
		s.deleteUserAfterRead()
	}
	generation, err := s.randomID(16)
	if err != nil {
		return ErrSCIMTombstoneGenerationUnavailable
	}
	now := s.now().UTC().Truncate(time.Millisecond).UnixMilli()
	event := mutationID("delete-user-event", subject, strconv.FormatInt(now, 10))
	guard := `EXISTS (SELECT 1 FROM identity_users WHERE subject = ?) AND NOT (
		EXISTS (SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject = u.subject JOIN rbac_roles r ON r.id = m.role_id WHERE u.subject = ? AND u.disabled = 0 AND r.name = 'rauthy_admin')
		AND (SELECT COUNT(DISTINCT u.subject) FROM identity_users u JOIN rbac_user_roles m ON m.subject = u.subject JOIN rbac_roles r ON r.id = m.role_id WHERE u.disabled = 0 AND r.name = 'rauthy_admin') = 1
	)`
	requestID := mutationID("delete-user", subject, generation, strconv.FormatInt(now, 10))
	guardedMutation := strings.TrimSpace(authoritySQL) != ""
	if guardedMutation {
		guardedMutationSQL := `EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`
		guard = guard + ` AND ` + guardedMutationSQL
	}
	guarded := func(sql string, args ...any) rhiza.SQLStatement {
		args = append(args, subject, subject)
		if guardedMutation {
			args = append(args, requestID)
		}
		return rhiza.SQLStatement{SQL: sql + ` AND ` + guard, Args: args}
	}
	statements := make([]rhiza.SQLStatement, 0, 40+len(providers))
	if guardedMutation {
		guardSQL := `INSERT INTO api_key_mutation_guards(request_id) SELECT ? WHERE ` + authoritySQL
		statements = append(statements, rhiza.SQLStatement{SQL: guardSQL, Args: append([]any{requestID}, authorityArgs...)})
	}
	statements = append(statements,
		guarded(`UPDATE identity_users SET subject = subject WHERE subject = ?`, subject),
		rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO scim_user_tombstones (local_external_id,user_name,active,hard_delete,provider_snapshot_complete,generation,deleted_at_unix_ms)
			SELECT u.subject,u.username,CASE WHEN u.disabled = 0 AND NOT (u.password_phc = '' AND m.mode = 'password') THEN 1 ELSE 0 END,1,1,?,?
			FROM identity_users u JOIN identity_authentication_modes m ON m.subject = u.subject WHERE u.subject = ? AND ` + guard, Args: func() []any {
			args := []any{generation, now, subject, subject, subject}
			if guardedMutation {
				args = append(args, requestID)
			}
			return args
		}()},
	)
	for _, provider := range providers {
		policy := provider.DeletePolicy
		// DeleteUser is a hard local deletion, so remote records must be
		// deleted regardless of the provider's normal unlink policy.
		policy = scim.DeleteRemote
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy)
			SELECT ?,?,? WHERE EXISTS (SELECT 1 FROM scim_user_tombstones WHERE local_external_id=?) AND ` + guard, Args: func() []any {
			args := []any{subject, provider.ID, int64(policy), subject, subject, subject}
			if guardedMutation {
				args = append(args, requestID)
			}
			return args
		}()})
	}
	statements = append(statements,
		guarded(`DELETE FROM identity_external_links WHERE local_subject = ?`, subject),
		guarded(`DELETE FROM upstream_provider_transactions WHERE link_subject = ?`, subject),
		// User-owned auth collection drafts/connections are local identity data;
		// collection definitions are administrator-owned and must survive.
		guarded(`DELETE FROM auth_collection_connections WHERE owner_subject = ?`, subject),
		guarded(`DELETE FROM rbac_user_roles WHERE subject = ?`, subject),
		guarded(`DELETE FROM rbac_user_groups WHERE subject = ?`, subject),
		guarded(`DELETE FROM rbac_principal_versions WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_password_history WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_password_reset_tokens WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_recovery_emails WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_user_profiles WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_login_locations WHERE subject = ?`, subject),
		guarded(`DELETE FROM user_attribute_values WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_webauthn_service_ceremony_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_ceremonies WHERE subject = ?)`, subject),
		guarded(`DELETE FROM identity_webauthn_mfa_ceremonies WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_webauthn_service_proof_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE subject = ?)`, subject),
		guarded(`DELETE FROM identity_webauthn_mfa_proofs WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_mfa_mod_token_factors WHERE token_digest IN (SELECT token_digest FROM identity_mfa_mod_tokens WHERE subject = ?)`, subject),
		guarded(`DELETE FROM identity_mfa_mod_tokens WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_webauthn_ceremonies WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_webauthn_credentials WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_webauthn_users WHERE subject = ?`, subject),
		guarded(`DELETE FROM scim_user_outbox WHERE json_type(request_json,'$.user') = 'object'
			AND json_type(request_json,'$.group') IS NULL
			AND ((external_id = ?) OR (json_extract(request_json,'$.user.externalId') = ? AND json_extract(request_json,'$.operation') IN ('sync','delete')))`, subject, subject),
		guarded(`INSERT INTO oidc_backchannel_deliveries (event_id,client_id,sid,subject,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms)
			SELECT ?,client_id,NULL,subject,logout_uri,allow_private,allow_http,0,?,? FROM oidc_user_clients WHERE subject = ? AND logout_uri <> ''`, event, now, now, subject),
		guarded(`DELETE FROM oidc_session_clients WHERE sid IN (SELECT token_digest FROM browser_sessions WHERE subject = ?)`, subject),
		guarded(`DELETE FROM oidc_user_clients WHERE subject = ?`, subject),
		guarded(`DELETE FROM browser_authorization_interactions WHERE session_digest IN (SELECT token_digest FROM browser_sessions WHERE subject = ?)`, subject),
		// Rhiza does not enforce a foreign key for the upstream session binding.
		// Delete it in this transaction before its browser session disappears.
		guarded(`DELETE FROM browser_upstream_session_bindings WHERE session_digest IN (SELECT token_digest FROM browser_sessions WHERE subject = ?)`, subject),
		guarded(`DELETE FROM browser_sessions WHERE subject = ?`, subject),
		guarded(`DELETE FROM oauth_pkce_requests WHERE signature IN (SELECT signature FROM oauth_authorize_codes WHERE json_extract(request_json,'$.subject') = ?)`, subject),
		guarded(`DELETE FROM oauth_authorize_codes WHERE json_extract(request_json,'$.subject') = ?`, subject),
		guarded(`DELETE FROM oauth_access_tokens WHERE signature IN (SELECT signature FROM oauth_token_requests WHERE json_extract(request_json,'$.subject') = ?)`, subject),
		guarded(`DELETE FROM oauth_refresh_tokens WHERE json_extract(request_json,'$.subject') = ?`, subject),
		guarded(`DELETE FROM oauth_token_requests WHERE json_extract(request_json,'$.subject') = ?`, subject),
		guarded(`DELETE FROM oauth_device_grants WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_authentication_modes WHERE subject = ?`, subject),
		guarded(`DELETE FROM identity_users WHERE subject = ?`, subject),
	)
	if guardedMutation {
		statements = append(statements, rhiza.SQLStatement{SQL: `DELETE FROM api_key_mutation_guards WHERE request_id=?`, Args: []any{requestID}})
	}
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		return err
	}
	if !guardedMutation && response.RowsAffected != 0 {
		return nil
	}
	if guardedMutation && response.RowsAffected >= 4 {
		return nil
	}
	result, err = s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM identity_users WHERE subject = ?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		if guardedMutation {
			if response.RowsAffected == 0 {
				return ErrDeleteUnauthorized
			}
		}
		return ErrLastActiveAdmin
	}
	return ErrInactiveSubject
}

func (s *Store) ensurePasswordMode(ctx context.Context, subject string, now int64) error {
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("bootstrap-password-mode", subject, strconv.FormatInt(now, 10)),
		SQL: `INSERT OR IGNORE INTO identity_authentication_modes (subject, mode, generation, updated_at_unix_ms)
			SELECT ?, 'password', 1, ? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ?)`,
		Args: []any{subject, now, subject},
	})
	return err
}

// openRegistrationOwner reconciles every pre-existing email ownership record.
// A disagreeing legacy state fails closed instead of attaching a pending user
// to an unrelated active account.
func (s *Store) openRegistrationOwner(ctx context.Context, email string) (string, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject FROM identity_recovery_emails WHERE email = ?
		UNION SELECT subject FROM identity_user_profiles WHERE email = ?
		UNION SELECT subject FROM identity_users WHERE username = ?`, Args: []any{email, email, email}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return "", false, err
	}
	if len(result.Rows) == 0 {
		return "", false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return "", false, errors.New("conflicting open registration email ownership")
	}
	subject, ok := result.Rows[0][0].(string)
	if !ok || validateSubject(subject) != nil {
		return "", false, errors.New("invalid open registration owner")
	}
	return subject, true, nil
}

// Authenticate uses a linearizable lookup. VerifyOrDummy always runs, even
// for disabled and unknown users, then all credential failures share one error.
func (s *Store) Authenticate(ctx context.Context, username string, password []byte) (Authentication, error) {
	return s.authenticate(ctx, username, password, false, nil)
}

// AuthenticatePasswordGrant records credential failures for the password grant.
// Ordinary credential checks keep Authenticate's existing side-effect contract.
func (s *Store) AuthenticatePasswordGrant(ctx context.Context, username string, password []byte, onExpired func(context.Context, string) error) (Authentication, error) {
	return s.authenticate(ctx, username, password, true, onExpired)
}

func (s *Store) authenticate(ctx context.Context, username string, password []byte, recordFailure bool, onExpired func(context.Context, string) error) (Authentication, error) {
	if err := ValidateUsername(username); err != nil {
		_, _, workErr := s.hasher.VerifyOrDummy(ctx, password, "")
		if workErr != nil {
			return Authentication{}, workErr
		}
		return Authentication{}, ErrInvalidCredentials
	}
	user, passwordPHC, changedAt, passwordMode, found, expired, snapshot, err := s.lookupCredential(ctx, username)
	if err != nil {
		return Authentication{}, err
	}
	valid, upgradeEligible, err := s.hasher.VerifyOrDummy(ctx, password, passwordPHC)
	if err != nil {
		return Authentication{}, err
	}
	if !found || user.Disabled || expired {
		return Authentication{}, ErrInvalidCredentials
	}
	if !valid || !passwordMode {
		if recordFailure {
			if err := s.recordPasswordFailure(ctx, snapshot); err != nil {
				return Authentication{}, err
			}
		}
		return Authentication{}, ErrInvalidCredentials
	}
	// Password work can cross the deadline: validate again before publishing
	// an authenticated subject, keeping credential failures indistinguishable.
	if err := s.ValidateSubject(ctx, user.Subject); err != nil {
		if errors.Is(err, ErrInactiveSubject) {
			return Authentication{}, ErrInvalidCredentials
		}
		return Authentication{}, err
	}
	if expires := s.passwordExpiry(changedAt); expires != nil && s.now().UTC().After(*expires) {
		var recoveryErr error
		if onExpired != nil {
			recoveryErr = onExpired(ctx, user.Subject)
		}
		if recordFailure {
			if err := s.recordPasswordFailure(ctx, snapshot); err != nil {
				return Authentication{}, err
			}
		}
		if recoveryErr != nil {
			return Authentication{}, ErrPasswordResetUnavailable
		}
		return Authentication{Subject: user.Subject}, ErrPasswordExpired
	}
	if upgradeEligible {
		s.bestEffortRehash(ctx, user.Subject, passwordPHC, password)
	}
	return snapshot, nil
}

// UserBySubject returns an active user through a linearizable read.
func (s *Store) UserBySubject(ctx context.Context, subject string) (User, error) {
	if err := validateSubject(subject); err != nil {
		return User{}, err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT subject, username, disabled, user_expires_at_unix_ms FROM identity_users WHERE subject = ?`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return User{}, err
	}
	if len(result.Rows) == 0 {
		return User{}, ErrInactiveSubject
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return User{}, errors.New("invalid identity row")
	}
	user, ok := decodeUser(result.Rows[0][:3])
	if !ok {
		return User{}, errors.New("invalid identity row")
	}
	if user.Disabled {
		return User{}, ErrInactiveSubject
	}
	if result.Rows[0][3] != nil {
		if expiry, ok := result.Rows[0][3].(int64); !ok || s.now().UTC().UnixMilli() >= expiry {
			return User{}, ErrInactiveSubject
		}
	}
	return user, nil
}

// AccountProfileBySubject returns an active identity and its public profile
// through one linearizable read. A profile email is preferred; the canonical
// username is a safe fallback for installations that use email usernames.
// Callers must treat an empty Email as unavailable rather than inventing one.
func (s *Store) AccountProfileBySubject(ctx context.Context, subject string) (AccountProfile, error) {
	if err := validateSubject(subject); err != nil {
		return AccountProfile{}, err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT u.subject,u.username,u.disabled,p.email,p.email_verified,p.preferred_username,p.given_name,p.family_name
			FROM identity_users u LEFT JOIN identity_user_profiles p ON p.subject = u.subject
			WHERE u.subject = ? AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?)`,
		Args: []any{subject, s.now().UTC().UnixMilli()}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return AccountProfile{}, err
	}
	if len(result.Rows) == 0 {
		return AccountProfile{}, ErrInactiveSubject
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 8 {
		return AccountProfile{}, errors.New("invalid identity profile row")
	}
	row := result.Rows[0]
	user, ok := decodeUser(row[:3])
	if !ok {
		return AccountProfile{}, errors.New("invalid identity profile row")
	}
	if user.Disabled {
		return AccountProfile{}, ErrInactiveSubject
	}
	profile := AccountProfile{Subject: user.Subject, Username: user.Username}
	if row[4] != nil {
		verified, ok := row[4].(int64)
		if !ok || (verified != 0 && verified != 1) {
			return AccountProfile{}, errors.New("invalid identity profile email verification")
		}
		profile.EmailVerified = verified == 1
	}
	for i, target := range []*string{&profile.Email, &profile.PreferredUsername, &profile.GivenName, &profile.FamilyName} {
		column := i + 4
		if i == 0 {
			column = 3
		}
		if row[column] == nil {
			continue
		}
		value, ok := row[column].(string)
		if !ok {
			return AccountProfile{}, errors.New("invalid identity profile row")
		}
		*target = value
	}
	if profile.Email == "" {
		if email, emailErr := CanonicalEmail(profile.Username); emailErr == nil {
			profile.Email = email
		}
	} else if email, emailErr := CanonicalEmail(profile.Email); emailErr != nil || email != profile.Email {
		return AccountProfile{}, errors.New("invalid identity profile email")
	}
	return profile, nil
}

// VerifyPassword checks an active subject's current password without changing
// its credential. Missing and disabled users still perform dummy hash work.
func (s *Store) VerifyPassword(ctx context.Context, subject string, password []byte) error {
	if err := validateSubject(subject); err != nil {
		_, _, workErr := s.hasher.VerifyOrDummy(ctx, password, "")
		if workErr != nil {
			return workErr
		}
		return err
	}
	record, found, err := s.passwordRecord(ctx, subject)
	if err != nil {
		return err
	}
	valid, _, err := s.hasher.VerifyOrDummy(ctx, password, record.passwordPHC)
	if err != nil {
		return err
	}
	if !found || record.disabled || record.expired {
		return ErrInvalidCredentials
	}
	if !record.passwordMode {
		return ErrPasswordAuthenticationDisabled
	}
	if !valid {
		return ErrInvalidCredentials
	}
	if err := s.ValidateSubject(ctx, subject); err != nil {
		if errors.Is(err, ErrInactiveSubject) {
			return ErrInvalidCredentials
		}
		return err
	}
	if expires := s.passwordExpiry(record.changedAt); expires != nil && s.now().UTC().After(*expires) {
		return ErrPasswordExpired
	}
	return nil
}

// bestEffortRehash never changes a verified authentication result. The
// conditional update also prevents concurrent logins from downgrading or
// replacing a newer credential.
func (s *Store) bestEffortRehash(ctx context.Context, subject, oldPHC string, password []byte) {
	newPHC, err := s.hasher.Hash(ctx, password)
	if err != nil {
		return
	}
	_, _ = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("password-rehash", subject, oldPHC, newPHC),
		SQL: `UPDATE identity_users SET password_phc = ?
			WHERE subject = ? AND password_phc = ? AND disabled = 0`,
		Args: []any{newPHC, subject, oldPHC},
	})
}

// ChangePassword validates the current password before applying the configured
// creation rules. It stores the old PHC and swaps to the new one in one Rhiza
// transaction, so concurrent changes have exactly one winner.
func (s *Store) ChangePassword(ctx context.Context, subject string, current, next []byte) error {
	if err := validateSubject(subject); err != nil {
		return err
	}
	record, found, err := s.passwordRecord(ctx, subject)
	if err != nil {
		return err
	}
	valid, _, err := s.hasher.VerifyOrDummy(ctx, current, record.passwordPHC)
	if err != nil {
		return err
	}
	if !found || record.disabled || record.expired {
		return ErrInvalidCredentials
	}
	if !record.passwordMode {
		return ErrPasswordAuthenticationDisabled
	}
	if !valid {
		return ErrInvalidCredentials
	}
	newPHC, err := s.preparePassword(ctx, subject, record.passwordPHC, next, true)
	if err != nil {
		return err
	}
	older := s.rules.History - 1
	now := s.now().UTC().Truncate(time.Millisecond)
	statements := []rhiza.SQLStatement{
		{SQL: `UPDATE identity_users SET password_phc = ?, password_changed_at_unix_ms = ?, password_generation = password_generation + 1
			WHERE subject = ? AND password_phc = ? AND password_generation = ? AND disabled = 0 AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?)`, Args: []any{newPHC, now.UnixMilli(), subject, record.passwordPHC, record.generation, now.UnixMilli()}},
	}
	minimumChanges := int64(1)
	if older > 0 {
		keepFrom := record.generation - int64(older)
		statements = []rhiza.SQLStatement{
			{SQL: `INSERT INTO identity_password_history (subject, generation, password_phc, changed_at_unix_ms)
				SELECT subject, password_generation, password_phc, password_changed_at_unix_ms
				FROM identity_users WHERE subject = ? AND password_phc = ? AND password_generation = ? AND disabled = 0 AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?)`, Args: []any{subject, record.passwordPHC, record.generation, now.UnixMilli()}},
			statements[0],
			{SQL: `DELETE FROM identity_password_history WHERE subject = ? AND generation <= ?
				AND EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND password_phc = ? AND password_generation = ? AND password_changed_at_unix_ms = ? AND disabled = 0)`, Args: []any{subject, keepFrom, subject, newPHC, record.generation + 1, now.UnixMilli()}},
		}
		minimumChanges = 2
	}
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID:  mutationID("password-change", subject, record.passwordPHC, newPHC, strconv.FormatInt(record.generation, 10)),
		Statements: statements,
	})
	if err != nil {
		return err
	}
	if response.RowsAffected < minimumChanges {
		return ErrPasswordChangeConflict
	}
	return nil
}

// IssuePasswordReset returns a one-time opaque token. Only keyed digests are
// replicated, so a database read cannot be used as a reset bearer token.
func (s *Store) IssuePasswordReset(ctx context.Context, subject string, ttl time.Duration) (string, time.Time, error) {
	return s.issuePasswordReset(ctx, subject, ttl, nil)
}

// IssuePasswordResetForEmail binds issuance to the address the sender will use.
// A lookup made before an administrator email change cannot mint a fresh link
// for the former address after that change commits.
func (s *Store) IssuePasswordResetForEmail(ctx context.Context, subject, email string, ttl time.Duration) (string, time.Time, error) {
	canonical, err := CanonicalEmail(email)
	if err != nil || canonical != email {
		return "", time.Time{}, ErrInvalidPasswordReset
	}
	return s.issuePasswordReset(ctx, subject, ttl, &email)
}

func (s *Store) issuePasswordReset(ctx context.Context, subject string, ttl time.Duration, email *string) (string, time.Time, error) {
	if len(s.resetKey) != sha256.Size {
		return "", time.Time{}, ErrPasswordResetUnavailable
	}
	if err := validateSubject(subject); err != nil || ttl < time.Minute || ttl > 24*time.Hour {
		return "", time.Time{}, ErrInvalidPasswordReset
	}
	record, found, err := s.passwordRecord(ctx, subject)
	if err != nil {
		return "", time.Time{}, err
	}
	if !found || record.disabled || record.expired || !record.passwordMode || record.passwordPHC == "" {
		return "", time.Time{}, ErrInvalidPasswordReset
	}
	rawBytes := make([]byte, 32)
	if err := s.fillRandom(rawBytes); err != nil {
		return "", time.Time{}, ErrPasswordResetUnavailable
	}
	raw := base64.RawURLEncoding.EncodeToString(rawBytes)
	now := s.now().UTC().Truncate(time.Millisecond)
	expires := now.Add(ttl)
	digest := s.resetDigest(raw)
	statements := []rhiza.SQLStatement{}
	if email != nil {
		one := int64(1)
		statements = append(statements, rhiza.SQLStatement{
			SQL: `SELECT subject FROM identity_users WHERE subject=? AND password_generation=? AND password_phc<>'' AND disabled=0
			 AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms>?) AND ` + resetEventEmailSQL + `=?`,
			Args: []any{subject, record.generation, now.UnixMilli(), subject, subject, *email}, WantRows: true, ExpectedReturnedRows: &one,
		})
	}
	statements = append(statements,
		rhiza.SQLStatement{SQL: `DELETE FROM identity_password_reset_tokens WHERE token_digest IN (SELECT token_digest FROM identity_password_reset_tokens WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		rhiza.SQLStatement{SQL: `DELETE FROM identity_password_reset_tokens WHERE subject = ? AND usage = 'password_reset' AND consumed_attempt IS NULL AND EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND password_generation = ? AND password_phc <> '' AND disabled = 0 AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?))`, Args: []any{subject, subject, record.generation, now.UnixMilli()}},
		rhiza.SQLStatement{SQL: `INSERT INTO identity_password_reset_tokens (token_digest,subject,password_generation,issued_at_unix_ms,expires_at_unix_ms,usage,redirect_uri) SELECT ?,?,?,?,?,'password_reset',NULL WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND password_generation = ? AND password_phc <> '' AND disabled = 0 AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?))`, Args: []any{digest, subject, record.generation, now.UnixMilli(), expires.UnixMilli(), subject, record.generation, now.UnixMilli()}},
	)
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID:  mutationID("password-reset-issue", digest, strconv.FormatInt(now.UnixMilli(), 10)),
		Statements: statements,
	})
	if response.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return "", time.Time{}, ErrInvalidPasswordReset
	}
	if err != nil {
		return "", time.Time{}, err
	}
	issued, found, err := s.resetRecord(ctx, digest)
	if err != nil {
		return "", time.Time{}, err
	}
	if !found || issued.subject != subject || issued.generation != record.generation || issued.usage != "password_reset" || issued.expiresAt != expires.UnixMilli() || issued.consumed || issued.binding != "" {
		return "", time.Time{}, ErrInvalidPasswordReset
	}
	return raw, expires, nil
}

// BeginPasswordReset records the browser binding for a valid reset token. A
// later GET intentionally replaces it, so copied links cannot retain a stale
// browser binding.
func (s *Store) BeginPasswordReset(ctx context.Context, subject, raw string) (PasswordResetChallenge, error) {
	if len(s.resetKey) != sha256.Size {
		return PasswordResetChallenge{}, ErrPasswordResetUnavailable
	}
	if err := validateSubject(subject); err != nil || !validResetToken(raw) {
		return PasswordResetChallenge{}, ErrInvalidPasswordReset
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	digest := s.resetDigest(raw)
	token, found, err := s.resetRecord(ctx, digest)
	if err != nil {
		return PasswordResetChallenge{}, err
	}
	record, active, err := s.passwordRecord(ctx, subject)
	if err != nil {
		return PasswordResetChallenge{}, err
	}
	if !found || !active || record.disabled || record.expired || !record.passwordMode || token.subject != subject || token.generation != record.generation || token.consumed || token.expiresAt <= now.UnixMilli() || (token.usage == "password_reset" && record.passwordPHC == "") || (token.usage == "password_new" && record.passwordPHC != "") {
		return PasswordResetChallenge{}, ErrInvalidPasswordReset
	}
	cookie, err := s.randomID(32)
	if err != nil {
		return PasswordResetChallenge{}, ErrPasswordResetUnavailable
	}
	cookieDigest := s.resetCookieDigest(cookie)
	csrf := s.resetCSRF(digest, cookieDigest)
	now = s.now().UTC().Truncate(time.Millisecond)
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("password-reset-bind", digest, cookieDigest, strconv.FormatInt(now.UnixMilli(), 10)),
		SQL: `UPDATE identity_password_reset_tokens SET binding_digest = ?, bound_at_unix_ms = ?
			WHERE token_digest = ? AND subject = ? AND password_generation = ? AND consumed_attempt IS NULL AND expires_at_unix_ms > ?
			AND ((usage = 'password_reset' AND EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND password_generation = ? AND password_phc <> '' AND disabled = 0)) OR (usage = 'password_new' AND EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND password_generation = ? AND password_phc = '' AND disabled = 0)))
			AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?))`,
		Args: []any{cookieDigest, now.UnixMilli(), digest, subject, record.generation, now.UnixMilli(), subject, record.generation, subject, record.generation, subject, now.UnixMilli()},
	})
	if err != nil {
		return PasswordResetChallenge{}, err
	}
	bound, found, err := s.resetRecord(ctx, digest)
	if err != nil {
		return PasswordResetChallenge{}, err
	}
	if !found || bound.subject != subject || bound.generation != record.generation || (bound.usage != "password_reset" && bound.usage != "password_new") || bound.consumed || !hmac.Equal([]byte(bound.binding), []byte(cookieDigest)) {
		return PasswordResetChallenge{}, ErrInvalidPasswordReset
	}
	return PasswordResetChallenge{CookieToken: cookie, CSRFToken: csrf, ExpiresAt: time.UnixMilli(token.expiresAt).UTC()}, nil
}

// ResetPassword consumes one valid token and changes the bound subject's
// password. Every mutation is guarded by the resulting identity state.
// Legacy bootstrap identities may have only a bound recovery address.
const resetEventEmailSQL = `COALESCE((SELECT NULLIF(email,'') FROM identity_user_profiles WHERE subject=?),(SELECT email FROM identity_recovery_emails WHERE subject=?),'')`

func (s *Store) ResetPassword(ctx context.Context, subject, raw, cookie, csrf string, next []byte, sourceIP string) (string, error) {
	if len(s.resetKey) != sha256.Size {
		return "", ErrPasswordResetUnavailable
	}
	if err := validateSubject(subject); err != nil || !validResetToken(raw) || !validResetToken(cookie) || !validDigest(csrf) {
		return "", ErrInvalidPasswordReset
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	digest := s.resetDigest(raw)
	cookieDigest := s.resetCookieDigest(cookie)
	token, found, err := s.resetRecord(ctx, digest)
	if err != nil {
		return "", err
	}
	if !found || token.subject != subject || token.consumed || token.expiresAt <= now.UnixMilli() || token.binding == "" || !hmac.Equal([]byte(token.binding), []byte(cookieDigest)) || !hmac.Equal([]byte(csrf), []byte(s.resetCSRF(digest, cookieDigest))) {
		return "", ErrInvalidPasswordReset
	}
	record, found, err := s.passwordRecord(ctx, subject)
	if err != nil {
		return "", err
	}
	if !found || record.disabled || record.expired || !record.passwordMode || record.generation != token.generation || (token.usage == "password_reset" && record.passwordPHC == "") || (token.usage == "password_new" && record.passwordPHC != "") {
		return "", ErrInvalidPasswordReset
	}
	emailRows, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT ` + resetEventEmailSQL, Args: []any{subject, subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return "", err
	}
	if len(emailRows.Rows) != 1 || len(emailRows.Rows[0]) != 1 {
		return "", ErrInvalidPasswordReset
	}
	email, ok := emailRows.Rows[0][0].(string)
	if !ok {
		return "", ErrInvalidPasswordReset
	}
	newPHC, err := s.preparePassword(ctx, subject, record.passwordPHC, next, token.usage == "password_reset")
	if err != nil {
		return "", err
	}
	older := s.rules.History - 1
	attempt, err := s.randomID(16)
	if err != nil {
		return "", ErrPasswordResetUnavailable
	}
	event, err := s.randomID(16)
	if err != nil {
		return "", ErrPasswordResetUnavailable
	}
	newGeneration := record.generation + 1
	// Do not consume against a timestamp captured before costly password work.
	now = s.now().UTC().Truncate(time.Millisecond)
	operationID := mutationID("password-reset-consume", digest, attempt, event, newPHC)
	lifecycle, err := eventlog.PasswordReset(operationID, "Reset via Password Reset Form: "+email, sourceIP, now).Statement(
		`EXISTS (SELECT 1 FROM identity_password_reset_tokens WHERE token_digest=? AND subject=? AND consumed_attempt=?) AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND password_phc=? AND password_generation=? AND password_changed_at_unix_ms=? AND disabled=0)`,
		digest, subject, attempt, subject, newPHC, newGeneration, now.UnixMilli())
	if err != nil {
		return "", ErrInvalidPasswordReset
	}
	guard := `password_phc = ? AND password_generation = ? AND password_changed_at_unix_ms = ? AND disabled = 0`
	guardArgs := []any{newPHC, newGeneration, now.UnixMilli()}
	statements := []rhiza.SQLStatement{
		{SQL: `UPDATE identity_password_reset_tokens SET consumed_attempt = ?, consumed_at_unix_ms = ? WHERE token_digest = ? AND subject = ? AND password_generation = ? AND binding_digest = ? AND consumed_attempt IS NULL AND expires_at_unix_ms > ? AND ((usage = 'password_reset' AND EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND password_phc = ? AND password_phc <> '' AND password_generation = ? AND disabled = 0)) OR (usage = 'password_new' AND EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND password_phc = ? AND password_phc = '' AND password_generation = ? AND disabled = 0)))
			AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?))
			AND ` + resetEventEmailSQL + `=?`, Args: []any{attempt, now.UnixMilli(), digest, subject, record.generation, cookieDigest, now.UnixMilli(), subject, record.passwordPHC, record.generation, subject, record.passwordPHC, record.generation, subject, now.UnixMilli(), subject, subject, email}},
		{SQL: `UPDATE identity_users SET password_phc = ?,password_changed_at_unix_ms = ?,password_generation = password_generation + 1 WHERE subject = ? AND password_phc = ? AND password_generation = ? AND disabled = 0 AND EXISTS (SELECT 1 FROM identity_password_reset_tokens WHERE token_digest = ? AND consumed_attempt = ?)`, Args: []any{newPHC, now.UnixMilli(), subject, record.passwordPHC, record.generation, digest, attempt}},
	}
	minimum := int64(2)
	if token.usage == "password_new" {
		statements = append(statements, rhiza.SQLStatement{SQL: `UPDATE identity_user_profiles SET email_verified = 1 WHERE subject = ? AND email_verified = 0 AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `) AND EXISTS (SELECT 1 FROM identity_password_reset_tokens WHERE token_digest = ? AND usage = 'password_new' AND consumed_attempt = ?)`, Args: append(append([]any{subject}, guardArgs...), digest, attempt)})
		minimum++
	}
	if token.usage == "password_reset" && older > 0 {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO identity_password_history (subject,generation,password_phc,changed_at_unix_ms) SELECT ?,?,?,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `) AND EXISTS (SELECT 1 FROM identity_password_reset_tokens WHERE token_digest = ? AND consumed_attempt = ?)`, Args: append(append([]any{subject, record.generation, record.passwordPHC, record.changedAt}, guardArgs...), digest, attempt)})
		minimum++
	}
	statements = append(statements,
		rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO oidc_backchannel_deliveries (event_id,client_id,sid,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms) SELECT ? || '/' || sid,client_id,sid,logout_uri,allow_private,allow_http,0,?,? FROM oidc_session_clients WHERE logout_uri <> '' AND sid IN (SELECT token_digest FROM browser_sessions WHERE subject = ?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `)`, Args: append([]any{event, now.UnixMilli(), now.UnixMilli(), subject}, guardArgs...)},
		rhiza.SQLStatement{SQL: `UPDATE browser_sessions SET revoked_at_unix_ms = COALESCE(revoked_at_unix_ms,?) WHERE subject = ? AND revoked_at_unix_ms IS NULL AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `)`, Args: append([]any{now.UnixMilli(), subject}, guardArgs...)},
		rhiza.SQLStatement{SQL: `UPDATE oauth_authorize_codes SET invalidated = 1 WHERE invalidated = 0 AND json_extract(request_json,'$.subject') = ? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `)`, Args: append([]any{subject}, guardArgs...)},
		rhiza.SQLStatement{SQL: `UPDATE oauth_refresh_tokens SET active = 0 WHERE active = 1 AND json_extract(request_json,'$.subject') = ? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `)`, Args: append([]any{subject}, guardArgs...)},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_pkce_requests WHERE signature IN (SELECT signature FROM oauth_authorize_codes WHERE json_extract(request_json,'$.subject') = ?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `)`, Args: append([]any{subject}, guardArgs...)},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_access_tokens WHERE signature IN (SELECT signature FROM oauth_token_requests WHERE json_extract(request_json,'$.subject') = ?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `)`, Args: append([]any{subject}, guardArgs...)},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_token_requests WHERE json_extract(request_json,'$.subject') = ? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `)`, Args: append([]any{subject}, guardArgs...)},
		rhiza.SQLStatement{SQL: `UPDATE oauth_device_grants SET state = 'denied',claim_token_digest = NULL,claim_until_unix_ms = NULL WHERE subject = ? AND state IN ('pending','approved') AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `)`, Args: append([]any{subject}, guardArgs...)},
		rhiza.SQLStatement{SQL: `DELETE FROM oidc_session_clients WHERE sid IN (SELECT token_digest FROM browser_sessions WHERE subject = ?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `)`, Args: append([]any{subject}, guardArgs...)},
	)
	if older > 0 {
		keepFrom := record.generation - int64(older)
		statements = append(statements, rhiza.SQLStatement{SQL: `DELETE FROM identity_password_history WHERE subject = ? AND generation <= ? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `)`, Args: append([]any{subject, keepFrom}, guardArgs...)})
	}
	statements = append(statements, lifecycle)
	minimum++
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: operationID, Statements: statements})
	if err != nil {
		return "", err
	}
	if response.RowsAffected < minimum {
		return "", ErrInvalidPasswordReset
	}
	return token.redirectURI, nil
}

// ConvertToPasskeyOnly irreversibly removes the local password verifier after
// a user-verified WebAuthn credential exists. It deliberately leaves browser
// and OAuth sessions intact, matching Rauthy's conversion contract.
func (s *Store) ConvertToPasskeyOnly(ctx context.Context, subject string) error {
	if err := validateSubject(subject); err != nil {
		return err
	}
	record, found, err := s.passwordRecord(ctx, subject)
	if err != nil {
		return err
	}
	if !found || record.disabled || !record.passwordMode {
		return ErrPasswordAuthenticationDisabled
	}
	modeGeneration, passwordMode, err := s.authenticationMode(ctx, subject)
	if err != nil {
		return err
	}
	if !passwordMode {
		return ErrPasswordAuthenticationDisabled
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	newPasswordGeneration := record.generation + 1
	newModeGeneration := modeGeneration + 1
	attempt, err := s.randomID(16)
	if err != nil {
		return ErrPasswordAuthenticationDisabled
	}
	userGuard := `subject = ? AND password_phc = '' AND password_generation = ? AND disabled = 0`
	statements := []rhiza.SQLStatement{
		{SQL: `UPDATE identity_users SET password_phc = '', password_changed_at_unix_ms = ?, password_generation = password_generation + 1 WHERE subject = ? AND password_phc = ? AND password_generation = ? AND disabled = 0 AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject = ? AND mode = 'password' AND generation = ?) AND EXISTS (SELECT 1 FROM identity_webauthn_credentials WHERE subject = ? AND user_verified = 1)`, Args: []any{now.UnixMilli(), subject, record.passwordPHC, record.generation, subject, modeGeneration, subject}},
		{SQL: `DELETE FROM identity_password_history WHERE subject = ? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)`, Args: []any{subject, subject, newPasswordGeneration}},
		{SQL: `DELETE FROM identity_password_reset_tokens WHERE subject = ? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)`, Args: []any{subject, subject, newPasswordGeneration}},
		{SQL: `DELETE FROM identity_webauthn_ceremonies WHERE subject = ? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)`, Args: []any{subject, subject, newPasswordGeneration}},
		{SQL: `DELETE FROM identity_webauthn_service_ceremony_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_ceremonies WHERE subject = ?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)`, Args: []any{subject, subject, newPasswordGeneration}},
		{SQL: `DELETE FROM identity_webauthn_mfa_ceremonies WHERE subject = ? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)`, Args: []any{subject, subject, newPasswordGeneration}},
		{SQL: `DELETE FROM identity_webauthn_service_proof_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE subject = ?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)`, Args: []any{subject, subject, newPasswordGeneration}},
		{SQL: `DELETE FROM identity_webauthn_mfa_proofs WHERE subject = ? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)`, Args: []any{subject, subject, newPasswordGeneration}},
		{SQL: `DELETE FROM identity_mfa_mod_token_factors WHERE token_digest IN (SELECT token_digest FROM identity_mfa_mod_tokens WHERE subject = ?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)`, Args: []any{subject, subject, newPasswordGeneration}},
		{SQL: `DELETE FROM identity_mfa_mod_tokens WHERE subject = ? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)`, Args: []any{subject, subject, newPasswordGeneration}},
		// This CAS follows all password-state writes in the same transaction.
		{SQL: `UPDATE identity_authentication_modes SET mode = 'passkey', generation = generation + 1, updated_at_unix_ms = ? WHERE subject = ? AND mode = 'password' AND generation = ? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)`, Args: []any{now.UnixMilli(), subject, modeGeneration, subject, newPasswordGeneration}},
	}
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: mutationID("password-to-passkey", subject, strconv.FormatInt(record.generation, 10), strconv.FormatInt(modeGeneration, 10), attempt), Statements: statements})
	if err != nil {
		return err
	}
	if response.RowsAffected < 2 {
		return ErrPasswordAuthenticationDisabled
	}
	modeGenerationAfter, passwordModeAfter, err := s.authenticationMode(ctx, subject)
	if err != nil || passwordModeAfter || modeGenerationAfter != newModeGeneration {
		return ErrPasswordAuthenticationDisabled
	}
	current, active, err := s.passwordRecord(ctx, subject)
	if err != nil || !active || current.passwordPHC != "" || current.generation != newPasswordGeneration {
		return ErrPasswordAuthenticationDisabled
	}
	return nil
}

// SetPasswordWithWebAuthnProof restores password admission for a passkey-only
// account after a fresh PasswordNew WebAuthn service proof. The winning
// transaction consumes that proof and changes the mode together, so a failed
// mode transition cannot burn the proof.
func (s *Store) SetPasswordWithWebAuthnProof(ctx context.Context, subject, sessionDigest, proof string, next []byte) error {
	if err := validateSubject(subject); err != nil || !validDigest(sessionDigest) || !validWebAuthnServiceProof(proof) {
		return ErrPasswordAuthenticationDisabled
	}
	record, found, err := s.passwordRecord(ctx, subject)
	if err != nil {
		return err
	}
	if !found || record.disabled || record.passwordMode {
		return ErrPasswordAuthenticationDisabled
	}
	modeGeneration, passwordMode, err := s.authenticationMode(ctx, subject)
	if err != nil {
		return err
	}
	if passwordMode {
		return ErrPasswordAuthenticationDisabled
	}
	if err := s.rules.ValidatePassword(next); err != nil {
		return ErrPasswordRejected
	}
	newPHC, err := s.hasher.Hash(ctx, next)
	if err != nil {
		return err
	}
	attempt, err := s.randomID(16)
	if err != nil {
		return ErrPasswordAuthenticationDisabled
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	proofDigest := webAuthnServiceProofDigest(proof)
	newPasswordGeneration := record.generation + 1
	newModeGeneration := modeGeneration + 1
	userGuard := `subject = ? AND password_phc = ? AND password_generation = ? AND password_changed_at_unix_ms = ? AND disabled = 0`
	guardArgs := []any{subject, newPHC, newPasswordGeneration, now.UnixMilli()}
	statements := []rhiza.SQLStatement{
		// Keep this guard identical to the following writes: it prevents a stale
		// proof from being consumed when the account state no longer permits it.
		{SQL: `UPDATE identity_webauthn_mfa_proofs SET consumed_attempt=?,consumed_at_unix_ms=?
			WHERE code_digest=? AND subject=? AND session_digest=? AND consumed_attempt IS NULL AND expires_at_unix_ms>?
			AND EXISTS (SELECT 1 FROM identity_webauthn_service_proof_purposes WHERE code_digest=? AND purpose='PasswordNew')
			AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND password_phc=? AND password_generation=? AND disabled=0)
			AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='passkey' AND generation=?)`, Args: []any{attempt, now.UnixMilli(), proofDigest, subject, sessionDigest, now.UnixMilli(), proofDigest, subject, record.passwordPHC, record.generation, subject, modeGeneration}},
		{SQL: `UPDATE identity_users SET password_phc=?,password_changed_at_unix_ms=?,password_generation=password_generation+1
			WHERE subject=? AND password_phc=? AND password_generation=? AND disabled=0
			AND EXISTS (SELECT 1 FROM identity_webauthn_mfa_proofs WHERE code_digest=? AND consumed_attempt=?)
			AND EXISTS (SELECT 1 FROM identity_webauthn_service_proof_purposes WHERE code_digest=? AND purpose='PasswordNew')`, Args: []any{newPHC, now.UnixMilli(), subject, record.passwordPHC, record.generation, proofDigest, attempt, proofDigest}},
		{SQL: `UPDATE identity_authentication_modes SET mode='password',generation=generation+1,updated_at_unix_ms=?
			WHERE subject=? AND mode='passkey' AND generation=?
			AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)
			AND EXISTS (SELECT 1 FROM identity_webauthn_mfa_proofs WHERE code_digest=? AND consumed_attempt=?)`, Args: append([]any{now.UnixMilli(), subject, modeGeneration}, append(guardArgs, proofDigest, attempt)...)},
		// A forward conversion erases password history. Do not reintroduce the
		// deliberately removed old verifier as password history on this reversal.
		{SQL: `DELETE FROM identity_password_history WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_password_reset_tokens WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_webauthn_ceremonies WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_webauthn_service_ceremony_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_ceremonies WHERE subject=?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_webauthn_mfa_ceremonies WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_webauthn_service_proof_purposes WHERE code_digest<>? AND code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE subject=?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{proofDigest, subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_webauthn_mfa_proofs WHERE subject=? AND code_digest<>? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject, proofDigest}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_mfa_mod_token_factors WHERE token_digest IN (SELECT token_digest FROM identity_mfa_mod_tokens WHERE subject=?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_mfa_mod_tokens WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: mutationID("passkey-to-password", subject, sessionDigest, proofDigest, attempt), Statements: statements})
	if err != nil {
		return err
	}
	modeAfter, passwordModeAfter, err := s.authenticationMode(ctx, subject)
	if err != nil || !passwordModeAfter || modeAfter != newModeGeneration {
		return ErrPasswordAuthenticationDisabled
	}
	current, active, err := s.passwordRecord(ctx, subject)
	if err != nil || !active || current.passwordPHC != newPHC || current.generation != newPasswordGeneration {
		return ErrPasswordAuthenticationDisabled
	}
	if !s.webAuthnServiceProofConsumed(ctx, proofDigest, subject, sessionDigest, attempt) {
		return ErrPasswordAuthenticationDisabled
	}
	return nil
}

// SetPasswordAdmin restores password admission for a passkey-only account
// under administrative authority. Unlike SetPasswordWithWebAuthnProof, it does
// not require a WebAuthn service proof.
func (s *Store) SetPasswordAdmin(ctx context.Context, subject string, next []byte) error {
	if err := validateSubject(subject); err != nil {
		return ErrPasswordAuthenticationDisabled
	}
	record, found, err := s.passwordRecord(ctx, subject)
	if err != nil {
		return err
	}
	if !found || record.disabled || record.passwordMode {
		return ErrPasswordAuthenticationDisabled
	}
	modeGeneration, passwordMode, err := s.authenticationMode(ctx, subject)
	if err != nil {
		return err
	}
	if passwordMode {
		return ErrPasswordAuthenticationDisabled
	}
	if err := s.rules.ValidatePassword(next); err != nil {
		return ErrPasswordRejected
	}
	newPHC, err := s.hasher.Hash(ctx, next)
	if err != nil {
		return err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	newPasswordGeneration := record.generation + 1
	newModeGeneration := modeGeneration + 1
	userGuard := `subject = ? AND password_phc = ? AND password_generation = ? AND disabled = 0`
	guardArgs := []any{subject, newPHC, newPasswordGeneration}
	statements := []rhiza.SQLStatement{
		{SQL: `UPDATE identity_users SET password_phc=?,password_changed_at_unix_ms=?,password_generation=password_generation+1
			WHERE subject=? AND password_phc=? AND password_generation=? AND disabled=0`, Args: []any{newPHC, now.UnixMilli(), subject, record.passwordPHC, record.generation}},
		{SQL: `UPDATE identity_authentication_modes SET mode='password',generation=generation+1,updated_at_unix_ms=?
			WHERE subject=? AND mode='passkey' AND generation=?
			AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `)`, Args: append([]any{now.UnixMilli(), subject, modeGeneration}, guardArgs...)},
		{SQL: `DELETE FROM identity_password_history WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_password_reset_tokens WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_webauthn_ceremonies WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_webauthn_service_ceremony_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_ceremonies WHERE subject=?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_webauthn_mfa_ceremonies WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_webauthn_service_proof_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE subject=?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_webauthn_mfa_proofs WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_mfa_mod_token_factors WHERE token_digest IN (SELECT token_digest FROM identity_mfa_mod_tokens WHERE subject=?) AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
		{SQL: `DELETE FROM identity_mfa_mod_tokens WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE ` + userGuard + `) AND EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='password' AND generation=?)`, Args: append([]any{subject}, append(guardArgs, subject, newModeGeneration)...)},
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: mutationID("passkey-to-password-admin", subject, strconv.FormatInt(record.generation, 10), strconv.FormatInt(modeGeneration, 10)), Statements: statements})
	if err != nil {
		return err
	}
	modeAfter, passwordModeAfter, err := s.authenticationMode(ctx, subject)
	if err != nil || !passwordModeAfter || modeAfter != newModeGeneration {
		return ErrPasswordAuthenticationDisabled
	}
	current, active, err := s.passwordRecord(ctx, subject)
	if err != nil || !active || current.passwordPHC != newPHC || current.generation != newPasswordGeneration {
		return ErrPasswordAuthenticationDisabled
	}
	return nil
}

// IsPasskeyOnly reports the durable credential-admission policy for callers
// that need to select the appropriate authentication UI.
func (s *Store) IsPasskeyOnly(ctx context.Context, subject string) (bool, error) {
	if err := validateSubject(subject); err != nil {
		return false, err
	}
	_, mode, err := s.authenticationMode(ctx, subject)
	if err != nil {
		return false, err
	}
	return !mode, err
}

func (s *Store) authenticationMode(ctx context.Context, subject string) (int64, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT mode, generation FROM identity_authentication_modes WHERE subject = ?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return 0, false, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return 0, false, ErrInactiveSubject
	}
	mode, ok := result.Rows[0][0].(string)
	generation, generationOK := result.Rows[0][1].(int64)
	if !ok || !generationOK || generation < 1 || (mode != "password" && mode != "passkey") {
		return 0, false, errors.New("invalid authentication mode")
	}
	return generation, mode == "password", nil
}

// ValidateSubject confirms that subject is currently usable for a token-bound
// identity operation. Callers must not expose ErrInactiveSubject to clients.
func (s *Store) ValidateSubject(ctx context.Context, subject string) error {
	if err := validateSubject(subject); err != nil {
		return err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT disabled, user_expires_at_unix_ms FROM identity_users WHERE subject = ?`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return ErrInactiveSubject
	}
	disabled, ok := result.Rows[0][0].(int64)
	if !ok || (disabled != 0 && disabled != 1) {
		return errors.New("invalid identity row")
	}
	if disabled == 1 {
		return ErrInactiveSubject
	}
	if result.Rows[0][1] != nil {
		expiry, valid := result.Rows[0][1].(int64)
		if !valid || s.now().UTC().UnixMilli() >= expiry {
			return ErrInactiveSubject
		}
	}
	return nil
}

func (s *Store) lookupByUsername(ctx context.Context, username string) (User, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT subject, username, disabled FROM identity_users WHERE username = ?`,
		Args:        []any{username},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return User{}, false, err
	}
	if len(result.Rows) == 0 {
		return User{}, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 3 {
		return User{}, false, errors.New("invalid identity row")
	}
	user, ok := decodeUser(result.Rows[0])
	if !ok {
		return User{}, false, errors.New("invalid identity row")
	}
	return user, true, nil
}

func (s *Store) lookupCredential(ctx context.Context, username string) (User, string, int64, bool, bool, bool, Authentication, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT u.subject, u.username, u.password_phc, u.disabled, u.password_changed_at_unix_ms, m.mode, u.user_expires_at_unix_ms, u.password_generation, m.generation FROM identity_users u JOIN identity_authentication_modes m ON m.subject = u.subject WHERE u.username = ?`,
		Args:        []any{username},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return User{}, "", 0, false, false, false, Authentication{}, err
	}
	if len(result.Rows) == 0 {
		return User{}, "", 0, false, false, false, Authentication{}, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 9 {
		return User{}, "", 0, false, false, false, Authentication{}, errors.New("invalid identity row")
	}
	user, ok := decodeUser([]any{result.Rows[0][0], result.Rows[0][1], result.Rows[0][3]})
	passwordPHC, passwordOK := result.Rows[0][2].(string)
	changedAt, changedOK := result.Rows[0][4].(int64)
	mode, modeOK := result.Rows[0][5].(string)
	expiry, expiryOK := result.Rows[0][6].(int64)
	expired := result.Rows[0][6] != nil && (!expiryOK || s.now().UTC().UnixMilli() >= expiry)
	passwordGeneration, passwordGenerationOK := result.Rows[0][7].(int64)
	authenticationGeneration, authenticationGenerationOK := result.Rows[0][8].(int64)
	if !passwordGenerationOK || passwordGeneration < 1 || !authenticationGenerationOK || authenticationGeneration < 1 || !ok || !passwordOK || !changedOK || !modeOK || changedAt < 0 || (mode != "password" && mode != "passkey") {
		return User{}, "", 0, false, false, false, Authentication{}, errors.New("invalid identity row")
	}
	return user, passwordPHC, changedAt, mode == "password", true, expired, Authentication{Subject: user.Subject, PasswordGeneration: passwordGeneration, AuthenticationGeneration: authenticationGeneration}, nil
}

type passwordRecord struct {
	passwordPHC  string
	disabled     bool
	generation   int64
	changedAt    int64
	passwordMode bool
	expired      bool
}

func (s *Store) passwordRecord(ctx context.Context, subject string) (passwordRecord, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT u.password_phc, u.disabled, u.password_generation, u.password_changed_at_unix_ms, m.mode, u.user_expires_at_unix_ms FROM identity_users u JOIN identity_authentication_modes m ON m.subject = u.subject WHERE u.subject = ?`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return passwordRecord{}, false, err
	}
	if len(result.Rows) == 0 {
		return passwordRecord{}, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 6 {
		return passwordRecord{}, false, errors.New("invalid identity row")
	}
	passwordPHC, passwordOK := result.Rows[0][0].(string)
	disabled, disabledOK := result.Rows[0][1].(int64)
	generation, generationOK := result.Rows[0][2].(int64)
	changedAt, changedOK := result.Rows[0][3].(int64)
	mode, modeOK := result.Rows[0][4].(string)
	expiry, expiryOK := result.Rows[0][5].(int64)
	expired := result.Rows[0][5] != nil && (!expiryOK || s.now().UTC().UnixMilli() >= expiry)
	if !passwordOK || !disabledOK || !generationOK || !changedOK || !modeOK || (disabled != 0 && disabled != 1) || generation < 1 || changedAt < 0 || (mode != "password" && mode != "passkey") || (result.Rows[0][5] != nil && !expiryOK) {
		return passwordRecord{}, false, errors.New("invalid identity row")
	}
	return passwordRecord{passwordPHC: passwordPHC, disabled: disabled == 1, generation: generation, changedAt: changedAt, passwordMode: mode == "password", expired: expired}, true, nil
}

func (s *Store) passwordHistory(ctx context.Context, subject string, limit int) ([]string, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT password_phc FROM identity_password_history WHERE subject = ? ORDER BY generation DESC LIMIT ?`,
		Args:        []any{subject, int64(limit)},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	history := make([]string, len(result.Rows))
	for i, row := range result.Rows {
		if len(row) != 1 {
			return nil, errors.New("invalid password history row")
		}
		value, ok := row[0].(string)
		if !ok {
			return nil, errors.New("invalid password history row")
		}
		history[i] = value
	}
	return history, nil
}

type resetRecord struct {
	subject     string
	generation  int64
	expiresAt   int64
	binding     string
	consumed    bool
	usage       string
	redirectURI string
}

func (s *Store) resetRecord(ctx context.Context, digest string) (resetRecord, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,password_generation,expires_at_unix_ms,binding_digest,consumed_attempt,usage,redirect_uri FROM identity_password_reset_tokens WHERE token_digest = ?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return resetRecord{}, false, err
	}
	if len(result.Rows) == 0 {
		return resetRecord{}, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 7 {
		return resetRecord{}, false, errors.New("invalid password reset row")
	}
	row := result.Rows[0]
	subject, subjectOK := row[0].(string)
	generation, generationOK := row[1].(int64)
	expiresAt, expiryOK := row[2].(int64)
	binding := ""
	if row[3] != nil {
		var bindingOK bool
		binding, bindingOK = row[3].(string)
		if !bindingOK || !validDigest(binding) {
			return resetRecord{}, false, errors.New("invalid password reset row")
		}
	}
	if !subjectOK || !generationOK || !expiryOK || generation < 1 || expiresAt < 1 {
		return resetRecord{}, false, errors.New("invalid password reset row")
	}
	consumed := row[4] != nil
	if consumed {
		if _, ok := row[4].(string); !ok {
			return resetRecord{}, false, errors.New("invalid password reset row")
		}
	}
	usage, usageOK := row[5].(string)
	redirectURI := ""
	if row[6] != nil {
		var redirectOK bool
		redirectURI, redirectOK = row[6].(string)
		if !redirectOK {
			return resetRecord{}, false, errors.New("invalid password reset row")
		}
	}
	if !usageOK || (usage != "password_reset" && usage != "password_new") || len(redirectURI) > 2048 || strings.ContainsAny(redirectURI, "\r\n") {
		return resetRecord{}, false, errors.New("invalid password reset row")
	}
	return resetRecord{subject: subject, generation: generation, expiresAt: expiresAt, binding: binding, consumed: consumed, usage: usage, redirectURI: redirectURI}, true, nil
}

func (s *Store) resetDigest(raw string) string {
	return s.keyedDigest("goauthy-password-reset-token-v1\x00" + raw)
}

func (s *Store) resetCookieDigest(cookie string) string {
	return s.keyedDigest("goauthy-password-reset-cookie-v1\x00" + cookie)
}

func (s *Store) resetCSRF(digest, cookieDigest string) string {
	return s.keyedDigest("goauthy-password-reset-csrf-v1\x00" + digest + "\x00" + cookieDigest)
}

func (s *Store) keyedDigest(value string) string {
	mac := hmac.New(sha256.New, s.resetKey)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Store) randomID(size int) (string, error) {
	value := make([]byte, size)
	if err := s.fillRandom(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// fillRandom requires a complete read. A short read would make a reset token,
// event ID, or consume attempt predictably smaller than its intended entropy.
func (s *Store) fillRandom(value []byte) error {
	n, err := s.random(value)
	if err != nil || n != len(value) {
		return ErrPasswordResetUnavailable
	}
	return nil
}

func validResetToken(raw string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == raw
}

func ascii(value string) bool {
	for i := range len(value) {
		if value[i] > 0x7f {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validWebAuthnServiceProof(value string) bool {
	if len(value) != 48 {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func webAuthnServiceProofDigest(proof string) string {
	digest := sha256.Sum256([]byte(proof))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (s *Store) webAuthnServiceProofConsumed(ctx context.Context, digest, subject, sessionDigest, attempt string) bool {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_webauthn_mfa_proofs WHERE code_digest=? AND subject=? AND session_digest=?`, Args: []any{digest, subject, sessionDigest}, Consistency: rhiza.ConsistencyLinearizable})
	return err == nil && len(result.Rows) == 1 && len(result.Rows[0]) == 1 && result.Rows[0][0] == attempt
}

func decodeUser(row []any) (User, bool) {
	subject, subjectOK := row[0].(string)
	username, usernameOK := row[1].(string)
	disabled, disabledOK := row[2].(int64)
	if !subjectOK || !usernameOK || !disabledOK || (disabled != 0 && disabled != 1) {
		return User{}, false
	}
	return User{Subject: subject, Username: username, Disabled: disabled == 1}, true
}

func validateSubject(subject string) error {
	if len(subject) == 0 || len(subject) > maxSubjectBytes || strings.TrimSpace(subject) != subject {
		return ErrInvalidSubject
	}
	return nil
}

func mutationID(parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "i/" + base64.RawURLEncoding.EncodeToString(digest[:])
}
