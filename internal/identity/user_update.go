package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrUpdateUnauthorized = errors.New("user update authorization failed")
	ErrUpdateConflict     = errors.New("user update state or authority changed")
	ErrInvalidUserUpdate  = errors.New("invalid user update")
)

// UserUpdate is the validated administrator command, not self-service. Expiry
// is in milliseconds. Nil language/password preserve their current values;
// absent names, groups, expiry and ordinary user values clear those fields.
// Preferred username is managed separately and is never replaced here.
type UserUpdate struct {
	Email                  string
	GivenName, FamilyName  *string
	Language, Password     *string
	Roles, Groups          []string
	Enabled, EmailVerified bool
	UserExpires            *int64
	UserValuesJSON         string
	SourceIP               string
}

// UserUpdateResult supplies only committed notification metadata, no verifier.
// Delivery and SCIM wakeups belong to the caller after a successful commit.
type UserUpdateResult struct {
	Subject, OldEmail, Email, Language string
	EmailChanged                       bool
	User                               UserResponse
	PasswordChanged                    int64
}

// The raw snapshot is private credential-bearing CAS data; never log or return
// it. It also captures profile/recovery and membership revision so hashing does
// not turn a concurrent edit into a silent overwrite.
const userUpdateSnapshotSQL = `SELECT json_object(
	'username',u.username,'phc',u.password_phc,'generation',u.password_generation,
	'changed',u.password_changed_at_unix_ms,'disabled',u.disabled,'language',u.language,
	'expiry',u.user_expires_at_unix_ms,'mode',COALESCE(m.mode,'password'),
	'mode_generation',m.generation,'mode_updated',m.updated_at_unix_ms,
	'email',COALESCE(p.email,re.email,''),'recovery',re.email,
	'profile',json_array(p.email,p.email_verified,p.preferred_username,p.given_name,p.family_name,p.user_values_json),
	'revision',v.revision,'marker',v.updated_at_unix_ms,
	'admin',EXISTS(SELECT 1 FROM rbac_user_roles rm JOIN rbac_roles rr ON rr.id=rm.role_id WHERE rm.subject=u.subject AND rr.name='rauthy_admin'))
	FROM identity_users u LEFT JOIN identity_user_profiles p ON p.subject=u.subject
	LEFT JOIN identity_recovery_emails re ON re.subject=u.subject
	LEFT JOIN identity_authentication_modes m ON m.subject=u.subject
	LEFT JOIN rbac_principal_versions v ON v.subject=u.subject WHERE u.subject=?`

// authority must build trusted SQL with fresh time/session/API-key parameters
// on every call. Expiry arguments captured before password hashing are stale.
func (s *Store) UpdateUserWithGuard(ctx context.Context, subject string, input UserUpdate, authority func() (string, []any)) (UserUpdateResult, error) {
	if s == nil || s.db == nil || ctx == nil || authority == nil {
		return UserUpdateResult{}, ErrUpdateUnauthorized
	}
	if validateSubject(subject) != nil || validateUserUpdate(input) != nil {
		return UserUpdateResult{}, ErrInvalidUserUpdate
	}
	authoritySQL, authorityArgs := authority()
	if strings.TrimSpace(authoritySQL) == "" || strings.Contains(authoritySQL, ";") {
		return UserUpdateResult{}, ErrUpdateUnauthorized
	}
	rows, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: userUpdateSnapshotSQL + ` AND (` + authoritySQL + `)`, Args: append([]any{subject}, authorityArgs...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return UserUpdateResult{}, err
	}
	if len(rows.Rows) == 0 {
		return UserUpdateResult{}, ErrUpdateUnauthorized
	}
	if len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		return UserUpdateResult{}, ErrUpdateConflict
	}
	snapshot, ok := rows.Rows[0][0].(string)
	var old struct {
		Username, PHC, Email, Mode string
		Language                   *string
		Generation, Changed, Admin int64
	}
	if !ok || json.Unmarshal([]byte(snapshot), &old) != nil || old.Generation < 1 || ValidateUsername(old.Username) != nil || (old.Mode != "password" && old.Mode != "passkey") {
		return UserUpdateResult{}, ErrUpdateConflict
	}
	newPHC := old.PHC
	if input.Password != nil {
		newPHC, err = s.preparePassword(ctx, subject, old.PHC, []byte(*input.Password), old.PHC != "")
		if err != nil {
			return UserUpdateResult{}, err
		}
	}
	// Refresh time after password work, immediately before constructing the
	// transactional guard. The supplied authority is re-evaluated in the batch.
	now := s.now().UTC().Truncate(time.Millisecond)
	authoritySQL, authorityArgs = authority()
	if strings.TrimSpace(authoritySQL) == "" || strings.Contains(authoritySQL, ";") {
		return UserUpdateResult{}, ErrUpdateUnauthorized
	}
	nonce, err := s.randomID(16)
	if err != nil {
		return UserUpdateResult{}, err
	}
	operation := mutationID("user-update", subject, nonce)
	one := int64(1)
	statements := []rhiza.SQLStatement{{
		SQL: `SELECT subject FROM identity_users WHERE subject=? AND (` + authoritySQL + `)
		 AND (` + userUpdateSnapshotSQL + `)=?`,
		Args: append(append([]any{subject}, authorityArgs...), subject, snapshot), WantRows: true, ExpectedReturnedRows: &one,
	}, {
		SQL: `SELECT subject FROM identity_users WHERE subject=?
		 AND NOT EXISTS(SELECT 1 FROM identity_users WHERE username=? AND subject<>?)
		 AND NOT EXISTS(SELECT 1 FROM identity_user_profiles WHERE email=? AND subject<>?)
		 AND NOT EXISTS(SELECT 1 FROM identity_recovery_emails WHERE email=? AND subject<>?)`,
		Args: []any{subject, input.Email, subject, input.Email, subject, input.Email, subject}, WantRows: true, ExpectedReturnedRows: &one,
	}}
	if !input.Enabled || !updateContains(input.Roles, "rauthy_admin") || input.UserExpires != nil && *input.UserExpires <= now.UnixMilli() {
		statements = append(statements, rhiza.SQLStatement{
			SQL: `SELECT subject FROM identity_users WHERE subject=? AND NOT (
			 disabled=0 AND EXISTS(SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id WHERE m.subject=? AND r.name='rauthy_admin')
			 AND NOT EXISTS(SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id
			 WHERE u.subject<>? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?) AND r.name='rauthy_admin'))`,
			Args: []any{subject, subject, subject, now.UnixMilli()}, WantRows: true, ExpectedReturnedRows: &one,
		})
	}
	emailChanged := old.Email != input.Email
	username := old.Username
	if old.Username == old.Email {
		username = input.Email // Preserve explicit legacy/bootstrap login names.
	}
	language := old.Language
	if input.Language != nil {
		language = input.Language
	}
	var expiry any
	if input.UserExpires != nil {
		expiry = *input.UserExpires
	}
	disabled, verified := int64(0), int64(0)
	if !input.Enabled {
		disabled = 1
	}
	if input.EmailVerified {
		verified = 1
	}
	// Once the admission barriers pass, do not repeat authority between writes:
	// the operation may remove the caller's role or invalidate its own session.
	if input.Password != nil && old.PHC != "" && s.rules.History > 1 {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO identity_password_history(subject,generation,password_phc,changed_at_unix_ms) VALUES(?,?,?,?)`, Args: []any{subject, old.Generation, old.PHC, old.Changed}})
	}
	statements = append(statements,
		rhiza.SQLStatement{SQL: `UPDATE identity_users SET username=?,disabled=?,language=?,user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{username, disabled, updateOptionalString(language), expiry, subject}},
		rhiza.SQLStatement{SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified,given_name,family_name,user_values_json) VALUES(?,?,?,?,?,?)
		 ON CONFLICT(subject) DO UPDATE SET email=excluded.email,email_verified=excluded.email_verified,given_name=excluded.given_name,family_name=excluded.family_name,user_values_json=excluded.user_values_json`, Args: []any{subject, input.Email, verified, updateOptionalString(input.GivenName), updateOptionalString(input.FamilyName), nullableString(input.UserValuesJSON)}},
		rhiza.SQLStatement{SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES(?,?) ON CONFLICT(subject) DO UPDATE SET email=excluded.email`, Args: []any{subject, input.Email}},
	)
	roles, _ := json.Marshal(append([]string{}, input.Roles...))
	groups, _ := json.Marshal(append([]string{}, input.Groups...))
	statements = append(statements, rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO rbac_principal_versions(subject,revision,updated_at_unix_ms) VALUES(?,1,?)`, Args: []any{subject, now.UnixMilli()}})
	changed := func(table, members, column string) string {
		return `EXISTS(SELECT 1 FROM ` + members + ` m WHERE m.subject=? AND m.` + column + ` NOT IN(SELECT id FROM ` + table + ` WHERE name IN(SELECT value FROM json_each(?)))) OR
		 EXISTS(SELECT 1 FROM ` + table + ` e WHERE e.name IN(SELECT value FROM json_each(?)) AND NOT EXISTS(SELECT 1 FROM ` + members + ` m WHERE m.subject=? AND m.` + column + `=e.id))`
	}
	statements = append(statements, rhiza.SQLStatement{SQL: `UPDATE rbac_principal_versions SET revision=revision+1,updated_at_unix_ms=MAX(updated_at_unix_ms+1,?) WHERE subject=? AND (` + changed("rbac_roles", "rbac_user_roles", "role_id") + ` OR ` + changed("rbac_groups", "rbac_user_groups", "group_id") + `)`, Args: []any{now.UnixMilli(), subject, subject, string(roles), string(roles), subject, subject, string(groups), string(groups), subject}})
	for _, membership := range []struct{ table, members, column, names string }{{"rbac_roles", "rbac_user_roles", "role_id", string(roles)}, {"rbac_groups", "rbac_user_groups", "group_id", string(groups)}} {
		statements = append(statements,
			rhiza.SQLStatement{SQL: `DELETE FROM ` + membership.members + ` WHERE subject=? AND ` + membership.column + ` NOT IN(SELECT id FROM ` + membership.table + ` WHERE name IN(SELECT value FROM json_each(?)))`, Args: []any{subject, membership.names}},
			rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO ` + membership.members + `(subject,` + membership.column + `,granted_at_unix_ms) SELECT ?,id,? FROM ` + membership.table + ` WHERE name IN(SELECT value FROM json_each(?))`, Args: []any{subject, now.UnixMilli(), membership.names}},
		)
	}
	if input.Password != nil {
		statements = append(statements,
			rhiza.SQLStatement{SQL: `UPDATE identity_users SET password_phc=?,password_changed_at_unix_ms=?,password_generation=password_generation+1 WHERE subject=?`, Args: []any{newPHC, now.UnixMilli(), subject}},
			rhiza.SQLStatement{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES(?,'password',1,?) ON CONFLICT(subject) DO UPDATE SET mode='password',generation=generation+1,updated_at_unix_ms=excluded.updated_at_unix_ms`, Args: []any{subject, now.UnixMilli()}},
			rhiza.SQLStatement{SQL: `DELETE FROM identity_password_history WHERE subject=? AND generation NOT IN(SELECT generation FROM identity_password_history WHERE subject=? ORDER BY generation DESC LIMIT ?)`, Args: []any{subject, subject, int64(max(0, s.rules.History-1))}},
		)
	}
	if emailChanged || !input.Enabled {
		statements = append(statements,
			rhiza.SQLStatement{SQL: `UPDATE browser_sessions SET revoked_at_unix_ms=COALESCE(revoked_at_unix_ms,?) WHERE subject=?`, Args: []any{now.UnixMilli(), subject}},
			rhiza.SQLStatement{SQL: `DELETE FROM browser_authorization_interactions WHERE session_digest IN(SELECT token_digest FROM browser_sessions WHERE subject=?)`, Args: []any{subject}},
		)
	}
	if emailChanged || !input.Enabled || input.Password != nil {
		statements = append(statements, rhiza.SQLStatement{SQL: `DELETE FROM identity_password_reset_tokens WHERE subject=?`, Args: []any{subject}})
	}
	if !input.Enabled {
		statements = append(statements,
			rhiza.SQLStatement{SQL: `UPDATE oauth_authorize_codes SET invalidated=1 WHERE json_extract(request_json,'$.subject')=?`, Args: []any{subject}},
			rhiza.SQLStatement{SQL: `DELETE FROM oauth_pkce_requests WHERE signature IN(SELECT signature FROM oauth_authorize_codes WHERE json_extract(request_json,'$.subject')=?)`, Args: []any{subject}},
			rhiza.SQLStatement{SQL: `UPDATE oauth_refresh_tokens SET active=0 WHERE json_extract(request_json,'$.subject')=?`, Args: []any{subject}},
			rhiza.SQLStatement{SQL: `DELETE FROM oauth_access_tokens WHERE signature IN(SELECT signature FROM oauth_token_requests WHERE json_extract(request_json,'$.subject')=? OR json_extract(request_json,'$.extra.act.sub')=?)`, Args: []any{subject, subject}},
			rhiza.SQLStatement{SQL: `DELETE FROM oauth_token_requests WHERE json_extract(request_json,'$.subject')=? OR json_extract(request_json,'$.extra.act.sub')=?`, Args: []any{subject, subject}},
			rhiza.SQLStatement{SQL: `UPDATE oauth_device_grants SET state='denied',claim_token_digest=NULL,claim_until_unix_ms=NULL WHERE subject=? AND state IN('pending','approved')`, Args: []any{subject}},
			rhiza.SQLStatement{SQL: `DELETE FROM upstream_provider_transactions WHERE link_subject=?`, Args: []any{subject}},
		)
	}
	if !input.Enabled || input.Password != nil {
		// Cancel in-flight factor/link proofs without deleting enrolled passkeys
		// or MFA factors. A later reactivation must not revive these ceremonies.
		statements = append(statements,
			rhiza.SQLStatement{SQL: `DELETE FROM identity_webauthn_service_ceremony_purposes WHERE code_digest IN(SELECT code_digest FROM identity_webauthn_mfa_ceremonies WHERE subject=?)`, Args: []any{subject}},
			rhiza.SQLStatement{SQL: `DELETE FROM identity_webauthn_mfa_ceremonies WHERE subject=?`, Args: []any{subject}},
			rhiza.SQLStatement{SQL: `DELETE FROM identity_webauthn_service_proof_purposes WHERE code_digest IN(SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE subject=?)`, Args: []any{subject}},
			rhiza.SQLStatement{SQL: `DELETE FROM identity_webauthn_mfa_proofs WHERE subject=?`, Args: []any{subject}},
			rhiza.SQLStatement{SQL: `DELETE FROM identity_mfa_mod_token_factors WHERE token_digest IN(SELECT token_digest FROM identity_mfa_mod_tokens WHERE subject=?)`, Args: []any{subject}},
			rhiza.SQLStatement{SQL: `DELETE FROM identity_mfa_mod_tokens WHERE subject=?`, Args: []any{subject}},
			rhiza.SQLStatement{SQL: `DELETE FROM identity_webauthn_ceremonies WHERE subject=?`, Args: []any{subject}},
		)
		if input.Password == nil {
			statements = append(statements, rhiza.SQLStatement{SQL: `UPDATE identity_authentication_modes SET generation=generation+1,updated_at_unix_ms=? WHERE subject=?`, Args: []any{now.UnixMilli(), subject}})
		}
	}
	if input.Password != nil {
		event, err := eventlog.PasswordReset(operation, "Reset done by admin for user "+input.Email, "", now).Statement("1=1")
		if err != nil {
			return UserUpdateResult{}, err
		}
		statements = append(statements, event)
	}
	if emailChanged {
		event, err := eventlog.EmailChange(operation, "Change by admin: "+old.Email+" -> "+input.Email, now).Statement("1=1")
		if err != nil {
			return UserUpdateResult{}, err
		}
		statements = append(statements, event)
	}
	newAdmin := old.Admin == 0 && updateContains(input.Roles, "rauthy_admin")
	if newAdmin {
		event, err := eventlog.Creation(operation, input.Email, input.SourceIP, true, now).Statement(`EXISTS(SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id WHERE m.subject=? AND r.name='rauthy_admin')`, subject)
		if err != nil {
			return UserUpdateResult{}, err
		}
		statements = append(statements, event)
	}
	// The authorized mutation includes its own result. Reading after commit
	// could observe a different edit or deny a caller whose scope it removed.
	statements = append(statements, rhiza.SQLStatement{SQL: UserResponseJSONSQL, Args: []any{subject}, WantRows: true, ExpectedReturnedRows: &one})
	result, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: operation, Statements: statements})
	if result.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return UserUpdateResult{}, ErrUpdateConflict
	}
	if err != nil {
		return UserUpdateResult{}, err
	}
	if len(result.Statements) != len(statements) {
		return UserUpdateResult{}, errors.New("missing user update result")
	}
	responseRows := result.Statements[len(statements)-1].Rows
	if len(responseRows) != 1 || len(responseRows[0]) != 1 {
		return UserUpdateResult{}, errors.New("invalid user update result")
	}
	raw, ok := responseRows[0][0].(string)
	if !ok {
		return UserUpdateResult{}, errors.New("invalid user update projection")
	}
	user, passwordChanged, err := DecodeUserResponse(raw)
	if err != nil {
		return UserUpdateResult{}, err
	}
	lang := "en"
	if language != nil {
		lang = *language
	}
	return UserUpdateResult{Subject: subject, OldEmail: old.Email, Email: input.Email, Language: lang, EmailChanged: emailChanged, User: user, PasswordChanged: passwordChanged}, nil
}

func validateUserUpdate(input UserUpdate) error {
	email, err := CanonicalEmail(input.Email)
	if err != nil || email != input.Email || input.Language != nil && !i18n.ValidUserLanguage(*input.Language) || input.UserExpires != nil && *input.UserExpires < 0 {
		return ErrInvalidUserUpdate
	}
	for _, value := range []*string{input.GivenName, input.FamilyName} {
		if value != nil && (!utf8.ValidString(*value) || utf8.RuneCountInString(*value) < 1 || utf8.RuneCountInString(*value) > 32) {
			return ErrInvalidUserUpdate
		}
	}
	for _, names := range [][]string{input.Roles, input.Groups} {
		if len(names) > 256 {
			return ErrInvalidUserUpdate
		}
		for _, name := range names {
			if !utf8.ValidString(name) || utf8.RuneCountInString(name) < 2 || utf8.RuneCountInString(name) > 64 {
				return ErrInvalidUserUpdate
			}
		}
	}
	if input.UserValuesJSON != "" {
		var values map[string]*string
		if len(input.UserValuesJSON) > 8192 || !utf8.ValidString(input.UserValuesJSON) || json.Unmarshal([]byte(input.UserValuesJSON), &values) != nil || values == nil {
			return ErrInvalidUserUpdate
		}
		for key := range values {
			switch key {
			case "birthdate", "phone", "street", "zip", "city", "country", "tz":
			default:
				return ErrInvalidUserUpdate
			}
		}
	}
	return nil
}

func updateOptionalString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func updateContains(values []string, name string) bool {
	for _, value := range values {
		if value == name {
			return true
		}
	}
	return false
}

// preparePassword reuses the same current/history checks for user-initiated
// changes, reset forms and administrator assignment; admission remains outside.
func (s *Store) preparePassword(ctx context.Context, subject, currentPHC string, next []byte, checkHistory bool) (string, error) {
	if err := s.rules.ValidatePassword(next); err != nil {
		return "", ErrPasswordRejected
	}
	if reused, _, err := s.hasher.VerifyOrDummy(ctx, next, currentPHC); err != nil {
		return "", err
	} else if reused {
		return "", ErrPasswordReuse
	}
	if checkHistory && s.rules.History > 1 {
		history, err := s.passwordHistory(ctx, subject, s.rules.History-1)
		if err != nil {
			return "", err
		}
		for _, phc := range history {
			if reused, _, err := s.hasher.VerifyOrDummy(ctx, next, phc); err != nil {
				return "", err
			} else if reused {
				return "", ErrPasswordReuse
			}
		}
	}
	return s.hasher.Hash(ctx, next)
}
