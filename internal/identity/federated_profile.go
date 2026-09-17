// Package identity persists local password identities.
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

var (
	ErrFederatedProfileNotFound     = errors.New("federated profile link not found")
	ErrFederatedProfileConflict     = errors.New("federated profile state changed")
	ErrFederatedProfileDuplicate    = errors.New("federated profile email conflict")
	ErrFederatedProfileAdmin        = errors.New("federated profile admin last admin protection")
	ErrFederatedProfileUnauthorized = errors.New("federated profile authorization failed")
)

type FederatedProfileUpdateInput struct {
	Subject       upstreamprovider.SubjectResult
	Config        FederatedConfigSnapshot
	Email         string
	EmailVerified bool
	GivenName     string
	FamilyName    string
	SourceIP      string
	AdminMapping  *bool
}

type FederatedProfileUpdateResult struct {
	Subject      string
	EmailChanged bool
	AdminChanged bool
}

// federatedProfileSnapshotSQL captures the profile state of a linked
// federated identity. Every field used by the CAS guard is included so the
// transactional re-read inside the same atomic batch can detect mutations.
const federatedProfileSnapshotSQL = "SELECT json_object(" +
	"'subject',u.subject,'username',u.username,'email',p.email,'email_verified',p.email_verified," +
	"'given_name',p.given_name,'family_name',p.family_name," +
	"'recovery',re.email," +
	"'admin',EXISTS(SELECT 1 FROM rbac_user_roles rm JOIN rbac_roles rr ON rr.id=rm.role_id WHERE rm.subject=u.subject AND rr.name='rauthy_admin')," +
	"'revision',v.revision," +
	"'disabled',u.disabled,'expiry',u.user_expires_at_unix_ms)" +
	" FROM identity_users u" +
	" JOIN auth_providers ap ON ap.id=? AND ap.enabled=1" +
	" JOIN auth_provider_runtime_versions rv ON rv.provider_id=ap.id AND rv.version=?" +
	" AND ap.issuer=? AND ap.client_id=?" +
	" AND CASE ap.typ WHEN 'oidc' THEN 'oidc' WHEN 'custom' THEN 'oidc' WHEN 'google' THEN 'oidc' WHEN 'github' THEN 'github' WHEN 'oauth_userinfo' THEN 'oauth_userinfo' ELSE '' END=?" +
	" JOIN identity_external_links l ON l.local_subject=u.subject AND l.provider_id=? AND l.external_key=?" +
	" LEFT JOIN identity_user_profiles p ON p.subject=u.subject" +
	" LEFT JOIN identity_recovery_emails re ON re.subject=u.subject" +
	" LEFT JOIN rbac_principal_versions v ON v.subject=u.subject" +
	" WHERE u.disabled=0"

// federatedProfileSnapshotGuardSQL re-reads the full snapshot inside the batch
// and compares it against the baseline. Returns 1 row matching the baseline if
// no concurrent mutation; 0 rows triggers PreconditionFailed.
const federatedProfileSnapshotGuardSQL = `SELECT subject FROM identity_users WHERE subject=? AND (
	SELECT json_object(
		'subject',u.subject,'username',u.username,'email',p.email,'email_verified',p.email_verified,
		'given_name',p.given_name,'family_name',p.family_name,
		'recovery',re.email,
		'admin',EXISTS(SELECT 1 FROM rbac_user_roles rm JOIN rbac_roles rr ON rr.id=rm.role_id WHERE rm.subject=u.subject AND rr.name='rauthy_admin'),
		'revision',v.revision,
		'disabled',u.disabled,'expiry',u.user_expires_at_unix_ms)
	FROM identity_users u
	JOIN auth_providers ap ON ap.id=? AND ap.enabled=1
	JOIN auth_provider_runtime_versions rv ON rv.provider_id=ap.id AND rv.version=?
	AND ap.issuer=? AND ap.client_id=?
	AND CASE ap.typ WHEN 'oidc' THEN 'oidc' WHEN 'custom' THEN 'oidc' WHEN 'google' THEN 'oidc' WHEN 'github' THEN 'github' WHEN 'oauth_userinfo' THEN 'oauth_userinfo' ELSE '' END=?
	JOIN identity_external_links l ON l.local_subject=u.subject AND l.provider_id=? AND l.external_key=?
	LEFT JOIN identity_user_profiles p ON p.subject=u.subject
	LEFT JOIN identity_recovery_emails re ON re.subject=u.subject
	LEFT JOIN rbac_principal_versions v ON v.subject=u.subject
	WHERE u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?) AND u.subject=?
)=?`

// UpdateFederatedProfile atomically updates the profile of an already-linked
// federated identity. Provider/link/account freshness is checked via snapshot
// CAS inside the same atomic batch. Uniqueness and last-admin protection are
// also transactional. No external Query introduces a TOCTOU window.
func (s *Store) UpdateFederatedProfile(ctx context.Context, input FederatedProfileUpdateInput) (FederatedProfileUpdateResult, error) {
	if s == nil || s.db == nil || ctx == nil {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileUnauthorized
	}
	if err := input.Subject.Validate(); err != nil {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileUnauthorized
	}
	if input.Config.Source != "registry" || input.Config.Version == "" || input.Config.Issuer == "" || input.Config.ClientID == "" || input.Config.Kind == "" {
		return FederatedProfileUpdateResult{}, ErrFederatedProviderChanged
	}
	email, err := CanonicalEmail(input.Email)
	if err != nil {
		return FederatedProfileUpdateResult{}, ErrFederatedInvalidEmail
	}
	if input.Subject.IdentityNamespace != upstreamprovider.ComputeNamespace(input.Config.Issuer, input.Config.ClientID) {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileUnauthorized
	}
	externalKey := input.Subject.ExternalKey()
	now := s.now().UTC().Truncate(time.Millisecond)

	// Read the baseline snapshot. Provider/link freshness is captured here and
	// re-verified inside the atomic batch via CAS.
	rows, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         federatedProfileSnapshotSQL,
		Args:        []any{input.Subject.ProviderID, input.Config.Version, input.Config.Issuer, input.Config.ClientID, input.Config.Kind, input.Subject.ProviderID, externalKey},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return FederatedProfileUpdateResult{}, err
	}
	if len(rows.Rows) == 0 {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileNotFound
	}
	if len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileConflict
	}
	snapshot, ok := rows.Rows[0][0].(string)
	if !ok || json.Unmarshal([]byte(snapshot), &struct{}{}) != nil {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileConflict
	}
	var old struct {
		Subject       string  `json:"subject"`
		Username      string  `json:"username"`
		Email         string  `json:"email"`
		EmailVerified int64   `json:"email_verified"`
		GivenName     *string `json:"given_name"`
		FamilyName    *string `json:"family_name"`
		Admin         int64   `json:"admin"`
		Revision      int64   `json:"revision"`
		Disabled      int64   `json:"disabled"`
		Expiry        *int64  `json:"expiry"`
	}
	if err := json.Unmarshal([]byte(snapshot), &old); err != nil {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileConflict
	}
	if old.Subject == "" || old.Email == "" || old.Revision < 1 {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileConflict
	}
	emailVerified := int64(0)
	if input.EmailVerified {
		emailVerified = 1
	}

	// Refresh time immediately before constructing the transactional batch.
	now = s.now().UTC().Truncate(time.Millisecond)

	// Desired username: preserve the existing username unless it equals the
	// old email, in which case follow the email to the new value. This
	// mirrors the legacy bootstrap rule from user_update.go.
	desiredUsername := old.Username
	if old.Username == old.Email {
		desiredUsername = email
	}
	one := int64(1)

	adminChanged := false
	var roleStatements []rhiza.SQLStatement
	if input.AdminMapping != nil {
		if *input.AdminMapping {
			if old.Admin == 0 {
				adminChanged = true
				roleStatements = append(roleStatements,
					// INSERT fails if the rauthy_admin role does not exist.
					rhiza.SQLStatement{SQL: "INSERT OR IGNORE INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) SELECT ?,id,? FROM rbac_roles WHERE name='rauthy_admin'", Args: []any{old.Subject, now.UnixMilli()}, ExpectedRowsAffected: &one},
				)
			}
		} else {
			if old.Admin == 1 {
				adminChanged = true
				roleStatements = append(roleStatements,
					rhiza.SQLStatement{SQL: "DELETE FROM rbac_user_roles WHERE subject=? AND role_id IN(SELECT id FROM rbac_roles WHERE name='rauthy_admin')", Args: []any{old.Subject}},
				)
			}
		}
	}
	emailChanged := old.Email != email
	requestNonce, err := s.randomID(16)
	if err != nil {
		return FederatedProfileUpdateResult{}, err
	}
	requestID := mutationID("federated-profile-update", input.Subject.ProviderID, externalKey, strconv.FormatInt(now.UnixMilli(), 10), requestNonce)

	statements := make([]rhiza.SQLStatement, 0, 16+len(roleStatements))

	// Statement 0: snapshot CAS. Compares the re-read snapshot against the
	// baseline. The WHERE clause both filters for a valid account (disabled=0,
	// not expired) and verifies the snapshot has not changed. Returns exactly 1
	// row if the state matches; 0 rows triggers PreconditionFailed.
	statements = append(statements, rhiza.SQLStatement{
		SQL:  federatedProfileSnapshotGuardSQL,
		Args: []any{old.Subject, input.Subject.ProviderID, input.Config.Version, input.Config.Issuer, input.Config.ClientID, input.Config.Kind, input.Subject.ProviderID, externalKey, now.UnixMilli(), old.Subject, snapshot},
		WantRows: true, ExpectedReturnedRows: &one,
	})

	// Statement 1: cross-table uniqueness for username, profile email, and
	// recovery email.
	statements = append(statements, rhiza.SQLStatement{
		SQL: `SELECT subject FROM identity_users WHERE subject=?
		AND NOT EXISTS(SELECT 1 FROM identity_users WHERE username=? AND subject<>?)
		AND NOT EXISTS(SELECT 1 FROM identity_user_profiles WHERE email=? AND subject<>?)
		AND NOT EXISTS(SELECT 1 FROM identity_recovery_emails WHERE email=? AND subject<>?)`,
		Args: []any{old.Subject, desiredUsername, old.Subject, email, old.Subject, email, old.Subject},
		WantRows: true, ExpectedReturnedRows: &one,
	})

	// Statement 2: transactional last-admin guard. Only emitted when revoking
	// admin from the current user.
	if adminChanged && old.Admin == 1 && input.AdminMapping != nil && !*input.AdminMapping {
		statements = append(statements, rhiza.SQLStatement{
			SQL: `SELECT subject FROM identity_users WHERE subject=? AND NOT (
			 disabled=0 AND EXISTS(SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id WHERE m.subject=? AND r.name='rauthy_admin')
			 AND NOT EXISTS(SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id
			 WHERE u.subject<>? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?) AND r.name='rauthy_admin'))`,
			Args: []any{old.Subject, old.Subject, old.Subject, now.UnixMilli()},
			WantRows: true, ExpectedReturnedRows: &one,
		})
	}

	// Profile sync.
	statements = append(statements, rhiza.SQLStatement{
		SQL: "INSERT INTO identity_user_profiles(subject,email,email_verified,given_name,family_name) VALUES(?,?,?,?,?)" +
			" ON CONFLICT(subject) DO UPDATE SET email=excluded.email,email_verified=excluded.email_verified,given_name=excluded.given_name,family_name=excluded.family_name",
		Args: []any{old.Subject, email, emailVerified, nullableString(input.GivenName), nullableString(input.FamilyName)},
	})
	// Recovery email consistency.
	statements = append(statements, rhiza.SQLStatement{
		SQL:  "INSERT INTO identity_recovery_emails(subject,email) VALUES(?,?) ON CONFLICT(subject) DO UPDATE SET email=excluded.email",
		Args: []any{old.Subject, email},
	})
	// Update username, last_login, clear failed login state.
	statements = append(statements, rhiza.SQLStatement{
		SQL:  "UPDATE identity_users SET username=?,last_login_at_unix_ms=?,last_failed_login_at_unix_ms=NULL,failed_login_attempts=NULL WHERE subject=?",
		Args: []any{desiredUsername, now.UnixMilli(), old.Subject},
	})
	// Role changes.
	statements = append(statements, roleStatements...)
	if adminChanged {
		statements = append(statements, rhiza.SQLStatement{
			SQL:  "INSERT INTO rbac_principal_versions(subject,revision,updated_at_unix_ms) VALUES(?,1,?) ON CONFLICT(subject) DO UPDATE SET revision=revision+1,updated_at_unix_ms=excluded.updated_at_unix_ms",
			Args: []any{old.Subject, now.UnixMilli()},
		})
	}
	// Session invalidation on email or role changes.
	if emailChanged || adminChanged {
		statements = append(statements,
			rhiza.SQLStatement{SQL: "UPDATE browser_sessions SET revoked_at_unix_ms=COALESCE(revoked_at_unix_ms,?) WHERE subject=?", Args: []any{now.UnixMilli(), old.Subject}},
			rhiza.SQLStatement{SQL: "DELETE FROM browser_authorization_interactions WHERE session_digest IN(SELECT token_digest FROM browser_sessions WHERE subject=?)", Args: []any{old.Subject}},
		)
		if emailChanged {
			statements = append(statements, rhiza.SQLStatement{
				SQL:  "DELETE FROM identity_password_reset_tokens WHERE subject=?",
				Args: []any{old.Subject},
			})
		}
	}
	// Final verification.
	statements = append(statements, rhiza.SQLStatement{
		SQL:  "SELECT subject FROM identity_users WHERE subject=? AND disabled=0",
		Args: []any{old.Subject},
		WantRows: true, ExpectedReturnedRows: &one,
	})
	resp, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if resp.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileConflict
	}
	if err != nil {
		return FederatedProfileUpdateResult{}, err
	}
	if len(resp.Statements) < len(statements) {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileConflict
	}
	lastStmt := resp.Statements[len(statements)-1]
	if len(lastStmt.Rows) != 1 || len(lastStmt.Rows[0]) != 1 {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileConflict
	}
	resultSubject, ok := lastStmt.Rows[0][0].(string)
	if !ok || resultSubject != old.Subject {
		return FederatedProfileUpdateResult{}, ErrFederatedProfileConflict
	}
	return FederatedProfileUpdateResult{Subject: old.Subject, EmailChanged: emailChanged, AdminChanged: adminChanged}, nil
}


