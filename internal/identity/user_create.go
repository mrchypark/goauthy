package identity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrCreateUnauthorized = errors.New("identity creation authorization failed")
	ErrCreateConflict     = errors.New("identity creation conflict")
)

// UserCreation describes a fully admitted pending identity. Password setup
// remains a separate, one-use password_new ceremony.
type UserCreation struct {
	OpenRegistration
	Roles       []string
	Groups      []string
	UserExpires *int64
}

// CreateUserWithGuard creates one pending identity and its password_new token
// under the caller's same-transaction authority snapshot.
func (s *Store) CreateUserWithGuard(ctx context.Context, input UserCreation, authoritySQL string, authorityArgs []any) (OpenRegistrationResult, error) {
	if s == nil || s.db == nil || ctx == nil || strings.TrimSpace(authoritySQL) == "" {
		return OpenRegistrationResult{}, ErrCreateUnauthorized
	}
	if input.Language == "" {
		input.Language = "en"
	}
	if !i18n.ValidUserLanguage(input.Language) || len(s.resetKey) != sha256.Size || input.TTL < time.Minute || input.TTL > 7*24*time.Hour {
		return OpenRegistrationResult{}, ErrInvalidPasswordReset
	}
	email, err := CanonicalEmail(input.Email)
	if err != nil || input.PreferredUsernamePolicy.ValidateSyntax(optionalPreferredUsername(input.PreferredUsername)) != nil || utf8.RuneCountInString(input.GivenName) > 32 || utf8.RuneCountInString(input.FamilyName) > 32 || !utf8.ValidString(input.GivenName) || !utf8.ValidString(input.FamilyName) || len(input.UserValuesJSON) > 8192 || (input.UserValuesJSON != "" && !json.Valid([]byte(input.UserValuesJSON))) || input.UserExpires != nil && *input.UserExpires < 0 {
		return OpenRegistrationResult{}, ErrInvalidPasswordReset
	}
	for _, role := range input.Roles {
		if !validCreateName(role, false) {
			return OpenRegistrationResult{}, ErrInvalidPasswordReset
		}
	}
	for _, group := range input.Groups {
		if !validCreateName(group, true) {
			return OpenRegistrationResult{}, ErrInvalidPasswordReset
		}
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
	var expiry any
	if input.UserExpires != nil {
		expiry = *input.UserExpires
	}
	digest := s.resetDigest(raw)
	expires := now.Add(input.TTL)
	requestID := mutationID("user-create", subject, digest, strconv.FormatInt(now.UnixMilli(), 10))
	guard := `EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?) AND EXISTS (SELECT 1 FROM identity_users WHERE subject=?)`
	guardArgs := func(args ...any) []any { return append(args, requestID, subject) }
	statements := []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_key_mutation_guards(request_id) SELECT ? WHERE ` + authoritySQL, Args: append([]any{requestID}, authorityArgs...)},
		{SQL: `INSERT INTO identity_users(subject,username,password_phc,password_changed_at_unix_ms,password_generation,created_at_unix_ms,language,user_expires_at_unix_ms) SELECT ?,?,'',?,1,?,?,? WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?) AND NOT EXISTS (SELECT 1 FROM scim_user_tombstones WHERE local_external_id=?) AND NOT EXISTS (SELECT 1 FROM identity_users WHERE username=?) AND NOT EXISTS (SELECT 1 FROM identity_recovery_emails WHERE email=?) AND NOT EXISTS (SELECT 1 FROM identity_user_profiles WHERE email=?) AND NOT EXISTS (SELECT 1 FROM identity_user_profiles WHERE preferred_username=?)`, Args: []any{subject, email, now.UnixMilli(), now.UnixMilli(), input.Language, expiry, requestID, subject, email, email, email, nullableString(input.PreferredUsername)}},
		{SQL: `INSERT INTO rbac_principal_versions(subject,revision,updated_at_unix_ms) SELECT ?,1,? WHERE ` + guard, Args: guardArgs(subject, now.UnixMilli())},
		{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) SELECT ?,'password',1,? WHERE ` + guard, Args: guardArgs(subject, now.UnixMilli())},
		{SQL: `INSERT INTO identity_recovery_emails(subject,email) SELECT ?,? WHERE ` + guard, Args: guardArgs(subject, email)},
		{SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username,given_name,family_name,user_values_json) SELECT ?,?,0,?,?,?,? WHERE ` + guard, Args: guardArgs(subject, email, nullableString(input.PreferredUsername), nullableString(input.GivenName), nullableString(input.FamilyName), nullableString(input.UserValuesJSON))},
		{SQL: `INSERT INTO identity_password_reset_tokens(token_digest,subject,password_generation,issued_at_unix_ms,expires_at_unix_ms,usage,redirect_uri) SELECT ?,?,?,?,?,'password_new',? WHERE ` + guard, Args: guardArgs(digest, subject, int64(1), now.UnixMilli(), expires.UnixMilli(), nullableString(input.RedirectURI))},
	}
	for _, role := range input.Roles {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) SELECT ?,id,? FROM rbac_roles WHERE name=? AND ` + guard, Args: guardArgs(subject, now.UnixMilli(), role)})
	}
	for _, group := range input.Groups {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) SELECT ?,id,? FROM rbac_groups WHERE name=? AND ` + guard, Args: guardArgs(subject, now.UnixMilli(), group)})
	}
	condition := `EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?) AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND username=? AND password_phc='') AND EXISTS (SELECT 1 FROM identity_user_profiles WHERE subject=? AND email=?) AND EXISTS (SELECT 1 FROM identity_password_reset_tokens WHERE token_digest=? AND subject=? AND usage='password_new' AND consumed_attempt IS NULL)`
	registered, err := eventlog.Creation(requestID, email, input.SourceIP, false, now).Statement(condition, requestID, subject, email, subject, email, digest, subject)
	if err != nil {
		return OpenRegistrationResult{}, err
	}
	statements = append(statements, registered)
	admin, err := eventlog.Creation(requestID, email, input.SourceIP, true, now).Statement(condition+` AND EXISTS (SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id WHERE m.subject=? AND r.name='rauthy_admin')`, requestID, subject, email, subject, email, digest, subject, subject)
	if err != nil {
		return OpenRegistrationResult{}, err
	}
	statements = append(statements, admin)
	statements = append(statements, rhiza.SQLStatement{SQL: `DELETE FROM api_key_mutation_guards WHERE request_id=?`, Args: []any{requestID}})
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		return OpenRegistrationResult{}, err
	}
	// The command itself distinguishes denied authority (zero writes) from an
	// authorized conflict (only the guard inserted/deleted). No duplicate lookup
	// before authority, and no post-commit lookup which could change the outcome.
	if response.RowsAffected == 0 {
		return OpenRegistrationResult{}, ErrCreateUnauthorized
	}
	if response.RowsAffected == 2 {
		return OpenRegistrationResult{}, ErrCreateConflict
	}
	if response.RowsAffected < 8 {
		return OpenRegistrationResult{}, errors.New("incomplete identity creation")
	}
	return OpenRegistrationResult{Subject: subject, Token: raw, ExpiresAt: expires, Created: true}, nil
}

// CreatePasskeyOnlyUser creates one pending identity for passkey-only
// authentication. It follows the same guarded-commit pattern as
// CreateUserWithGuard but sets mode = 'passkey' and does NOT insert
// a password reset token row.
func (s *Store) CreatePasskeyOnlyUser(ctx context.Context, input UserCreation, authoritySQL string, authorityArgs []any) (string, error) {
	if s == nil || s.db == nil || ctx == nil || strings.TrimSpace(authoritySQL) == "" {
		return "", ErrCreateUnauthorized
	}
	if input.Language == "" {
		input.Language = "en"
	}
	if !i18n.ValidUserLanguage(input.Language) {
		return "", ErrInvalidPasswordReset
	}
	email, err := CanonicalEmail(input.Email)
	if err != nil || input.PreferredUsernamePolicy.ValidateSyntax(optionalPreferredUsername(input.PreferredUsername)) != nil || utf8.RuneCountInString(input.GivenName) > 32 || utf8.RuneCountInString(input.FamilyName) > 32 || !utf8.ValidString(input.GivenName) || !utf8.ValidString(input.FamilyName) || len(input.UserValuesJSON) > 8192 || (input.UserValuesJSON != "" && !json.Valid([]byte(input.UserValuesJSON))) || input.UserExpires != nil && *input.UserExpires < 0 {
		return "", ErrInvalidPasswordReset
	}
	for _, role := range input.Roles {
		if !validCreateName(role, false) {
			return "", ErrInvalidPasswordReset
		}
	}
	for _, group := range input.Groups {
		if !validCreateName(group, true) {
			return "", ErrInvalidPasswordReset
		}
	}
	subject, err := s.randomID(32)
	if err != nil {
		return "", ErrPasswordResetUnavailable
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	var expiry any
	if input.UserExpires != nil {
		expiry = *input.UserExpires
	}
	requestID := mutationID("passkey-create", subject, "", strconv.FormatInt(now.UnixMilli(), 10))
	guard := `EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?) AND EXISTS (SELECT 1 FROM identity_users WHERE subject=?)`
	guardArgs := func(args ...any) []any { return append(args, requestID, subject) }
	statements := []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_key_mutation_guards(request_id) SELECT ? WHERE ` + authoritySQL, Args: append([]any{requestID}, authorityArgs...)},
		{SQL: `INSERT INTO identity_users(subject,username,password_phc,password_changed_at_unix_ms,password_generation,created_at_unix_ms,language,user_expires_at_unix_ms) SELECT ?,?,'',?,1,?,?,? WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?) AND NOT EXISTS (SELECT 1 FROM scim_user_tombstones WHERE local_external_id=?) AND NOT EXISTS (SELECT 1 FROM identity_users WHERE username=?) AND NOT EXISTS (SELECT 1 FROM identity_recovery_emails WHERE email=?) AND NOT EXISTS (SELECT 1 FROM identity_user_profiles WHERE email=?) AND NOT EXISTS (SELECT 1 FROM identity_user_profiles WHERE preferred_username=?)`, Args: []any{subject, email, now.UnixMilli(), now.UnixMilli(), input.Language, expiry, requestID, subject, email, email, email, nullableString(input.PreferredUsername)}},
		{SQL: `INSERT INTO rbac_principal_versions(subject,revision,updated_at_unix_ms) SELECT ?,1,? WHERE ` + guard, Args: guardArgs(subject, now.UnixMilli())},
		{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) SELECT ?,'passkey',1,? WHERE ` + guard, Args: guardArgs(subject, now.UnixMilli())},
		{SQL: `INSERT INTO identity_recovery_emails(subject,email) SELECT ?,? WHERE ` + guard, Args: guardArgs(subject, email)},
		{SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username,given_name,family_name,user_values_json) SELECT ?,?,0,?,?,?,? WHERE ` + guard, Args: guardArgs(subject, email, nullableString(input.PreferredUsername), nullableString(input.GivenName), nullableString(input.FamilyName), nullableString(input.UserValuesJSON))},
	}
	for _, role := range input.Roles {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) SELECT ?,id,? FROM rbac_roles WHERE name=? AND ` + guard, Args: guardArgs(subject, now.UnixMilli(), role)})
	}
	for _, group := range input.Groups {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) SELECT ?,id,? FROM rbac_groups WHERE name=? AND ` + guard, Args: guardArgs(subject, now.UnixMilli(), group)})
	}
	condition := `EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?) AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND username=? AND password_phc='') AND EXISTS (SELECT 1 FROM identity_user_profiles WHERE subject=? AND email=?)`
	registered, err := eventlog.Creation(requestID, email, input.SourceIP, false, now).Statement(condition, requestID, subject, email, subject, email)
	if err != nil {
		return "", err
	}
	statements = append(statements, registered)
	admin, err := eventlog.Creation(requestID, email, input.SourceIP, true, now).Statement(condition+` AND EXISTS (SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id WHERE m.subject=? AND r.name='rauthy_admin')`, requestID, subject, email, subject, email, subject)
	if err != nil {
		return "", err
	}
	statements = append(statements, admin)
	statements = append(statements, rhiza.SQLStatement{SQL: `DELETE FROM api_key_mutation_guards WHERE request_id=?`, Args: []any{requestID}})
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		return "", err
	}
	if response.RowsAffected == 0 {
		return "", ErrCreateUnauthorized
	}
	if response.RowsAffected == 2 {
		return "", ErrCreateConflict
	}
	if response.RowsAffected < 6 {
		return "", errors.New("incomplete passkey user creation")
	}
	return subject, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func validCreateName(value string, group bool) bool {
	runes := []rune(value)
	if len(runes) < 2 || len(runes) > 64 {
		return false
	}
	for _, r := range runes {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_/,:*", r) || !group && r == '.') {
			return false
		}
	}
	return true
}

func optionalPreferredUsername(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
