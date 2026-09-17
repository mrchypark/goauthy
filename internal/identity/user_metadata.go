package identity

import (
	"context"
	"encoding/base64"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// RecordLoginForSession records the persisted authenticated session's creation
// time. It is bookkeeping, not a replacement for credential authorization.
func (s *Store) RecordLoginForSession(ctx context.Context, subject, sessionID string) error {
	if err := validateSubject(subject); err != nil {
		return err
	}
	digest, err := base64.RawURLEncoding.Strict().DecodeString(sessionID)
	if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != sessionID {
		return ErrInvalidCredentials
	}
	// A new invocation must revalidate the session, not replay an older receipt.
	nonce, err := s.randomID(16)
	if err != nil {
		return err
	}
	now := s.now().UTC().UnixMilli()
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("user-last-login", subject, sessionID, nonce),
		SQL: `UPDATE identity_users SET last_failed_login_at_unix_ms=NULL,failed_login_attempts=NULL,last_login_at_unix_ms = MAX(COALESCE(last_login_at_unix_ms, 0), login.created_at_unix_ms)
		FROM browser_sessions AS login
		WHERE identity_users.subject = ? AND identity_users.disabled = 0
		AND login.token_digest = ? AND login.subject = identity_users.subject
		AND login.auth_method IN ('pwd', 'mfa', 'webauthn', 'external')
		AND login.revoked_at_unix_ms IS NULL AND login.expires_at_unix_ms > ?
		AND (identity_users.user_expires_at_unix_ms IS NULL OR identity_users.user_expires_at_unix_ms > ?)`,
		Args: []any{subject, sessionID, now, now},
	})
	if err != nil {
		return err
	}
	if response.RowsAffected != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

// RecordPasswordLogin records a successful password admission without a browser
// session. The credential snapshot must still match at the mutation boundary.
func (s *Store) RecordPasswordLogin(ctx context.Context, auth Authentication) error {
	if validateSubject(auth.Subject) != nil || auth.PasswordGeneration < 1 || auth.AuthenticationGeneration < 1 {
		return ErrInvalidCredentials
	}
	nonce, err := s.randomID(16)
	if err != nil {
		return err
	}
	now := s.now().UTC().UnixMilli()
	result, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: mutationID("password-last-login", auth.Subject, nonce), SQL: `UPDATE identity_users SET last_failed_login_at_unix_ms=NULL,failed_login_attempts=NULL,last_login_at_unix_ms=MAX(COALESCE(last_login_at_unix_ms,0),?) WHERE subject=? AND password_generation=? AND disabled=0 AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms>?) AND EXISTS (SELECT 1 FROM identity_authentication_modes m WHERE m.subject=identity_users.subject AND m.mode='password' AND m.generation=?)`, Args: []any{now, auth.Subject, auth.PasswordGeneration, now, auth.AuthenticationGeneration}})
	if err != nil {
		return err
	}
	if result.RowsAffected != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

func (s *Store) recordPasswordFailure(ctx context.Context, auth Authentication) error {
	nonce, err := s.randomID(16)
	if err != nil {
		return err
	}
	now := s.now().UTC().UnixMilli()
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: mutationID("password-failure", auth.Subject, nonce), SQL: `UPDATE identity_users SET last_failed_login_at_unix_ms=MAX(COALESCE(last_failed_login_at_unix_ms,0),?),failed_login_attempts=COALESCE(failed_login_attempts,0)+1 WHERE subject=? AND password_generation=? AND disabled=0 AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms>?) AND EXISTS(SELECT 1 FROM identity_authentication_modes m WHERE m.subject=identity_users.subject AND m.generation=?)`, Args: []any{now, auth.Subject, auth.PasswordGeneration, now, auth.AuthenticationGeneration}})
	// A changed credential/account makes this obsolete failure a no-op; the
	// caller still returns the original generic authentication error.
	return err
}
