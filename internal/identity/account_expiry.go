package identity

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const maxAccountExpiryBatch = 128

// ExpireUsers permanently disables a bounded set of expired identities. Every
// member may run this: the final enabled->disabled write is in the same atomic
// batch as revocation and durable backchannel delivery. A losing/retried worker
// makes no change. No scheduler leader lease or in-memory completion state is
// needed, and moving the deadline forward before the write cancels that work.
func (s *Store) ExpireUsers(ctx context.Context, now time.Time, limit int) (int, error) {
	if s == nil || s.db == nil || ctx == nil || now.IsZero() || now.UnixMilli() < 0 || limit < 1 || limit > maxAccountExpiryBatch {
		return 0, errors.New("invalid account expiry batch")
	}
	nowMS := now.UTC().UnixMilli()
	// ponytail: bounded mutations still scan identities; add an expiry index
	// when measured account volume makes candidate selection costly.
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,user_expires_at_unix_ms FROM identity_users
		WHERE disabled=0 AND user_expires_at_unix_ms <= ? ORDER BY user_expires_at_unix_ms,subject LIMIT ?`, Args: []any{nowMS, limit}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, row := range result.Rows {
		if len(row) != 2 {
			return count, errors.New("invalid account expiry row")
		}
		subject, subjectOK := row[0].(string)
		deadline, deadlineOK := row[1].(int64)
		if !subjectOK || validateSubject(subject) != nil || !deadlineOK || deadline < 0 || deadline > nowMS {
			return count, errors.New("invalid account expiry row")
		}
		attempt, err := s.randomID(16)
		if err != nil {
			return count, err
		}
		guard := `EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0 AND user_expires_at_unix_ms=? AND user_expires_at_unix_ms<=?)`
		guarded := func(sql string, args ...any) rhiza.SQLStatement {
			return rhiza.SQLStatement{SQL: sql + ` AND ` + guard, Args: append(args, subject, deadline, nowMS)}
		}
		event := mutationID("account-expiry-event", subject, attempt)
		statements := []rhiza.SQLStatement{
			guarded(`INSERT INTO oidc_backchannel_deliveries(event_id,client_id,sid,subject,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms)
				SELECT ?,client_id,NULL,subject,logout_uri,allow_private,allow_http,0,?,? FROM oidc_user_clients
				WHERE subject=? AND logout_uri <> ''`, event, nowMS, nowMS, subject),
			guarded(`DELETE FROM oidc_session_clients WHERE sid IN (SELECT token_digest FROM browser_sessions WHERE subject=?)`, subject),
			guarded(`DELETE FROM oidc_user_clients WHERE subject=?`, subject),
			guarded(`DELETE FROM browser_authorization_interactions WHERE session_digest IN (SELECT token_digest FROM browser_sessions WHERE subject=?)`, subject),
			guarded(`UPDATE browser_sessions SET revoked_at_unix_ms=COALESCE(revoked_at_unix_ms,?) WHERE subject=?`, nowMS, subject),
			guarded(`DELETE FROM oauth_pkce_requests WHERE signature IN (SELECT signature FROM oauth_authorize_codes WHERE json_extract(request_json,'$.subject')=?)`, subject),
			guarded(`UPDATE oauth_authorize_codes SET invalidated=1 WHERE json_extract(request_json,'$.subject')=?`, subject),
			// Delegated tokens also become unusable when their actor expires.
			guarded(`DELETE FROM oauth_access_tokens WHERE signature IN (SELECT signature FROM oauth_token_requests WHERE json_extract(request_json,'$.subject')=? OR json_extract(request_json,'$.extra.act.sub')=?)`, subject, subject),
			guarded(`UPDATE oauth_refresh_tokens SET active=0 WHERE json_extract(request_json,'$.subject')=?`, subject),
			guarded(`DELETE FROM oauth_token_requests WHERE (json_extract(request_json,'$.subject')=? OR json_extract(request_json,'$.extra.act.sub')=?)`, subject, subject),
			guarded(`UPDATE oauth_device_grants SET state='denied',claim_token_digest=NULL,claim_until_unix_ms=NULL WHERE subject=? AND state IN ('pending','approved')`, subject),
			guarded(`DELETE FROM identity_password_reset_tokens WHERE subject=?`, subject),
			guarded(`DELETE FROM upstream_provider_transactions WHERE link_subject=?`, subject),
			guarded(`DELETE FROM identity_webauthn_service_ceremony_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_ceremonies WHERE subject=?)`, subject),
			guarded(`DELETE FROM identity_webauthn_mfa_ceremonies WHERE subject=?`, subject),
			guarded(`DELETE FROM identity_webauthn_service_proof_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE subject=?)`, subject),
			guarded(`DELETE FROM identity_webauthn_mfa_proofs WHERE subject=?`, subject),
			guarded(`DELETE FROM identity_mfa_mod_token_factors WHERE token_digest IN (SELECT token_digest FROM identity_mfa_mod_tokens WHERE subject=?)`, subject),
			guarded(`DELETE FROM identity_mfa_mod_tokens WHERE subject=?`, subject),
			guarded(`DELETE FROM identity_webauthn_ceremonies WHERE subject=?`, subject),
			guarded(`UPDATE identity_authentication_modes SET generation=generation+1,updated_at_unix_ms=? WHERE subject=?`, nowMS, subject),
			// Last: all earlier statements evaluate the same enabled snapshot.
			// An expired administrator is not exempt from expiration.
			guarded(`UPDATE identity_users SET disabled=1,password_generation=password_generation+1 WHERE subject=?`, subject),
		}
		response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: mutationID("account-expiry", subject, attempt, strconv.FormatInt(deadline, 10)), Statements: statements})
		if err != nil {
			return count, err
		}
		if response.RowsAffected != 0 {
			count++
		}
	}
	return count, nil
}

// DeleteExpiredUsers is opt-in retention cleanup. Reuse the existing guarded
// deletion and SCIM tombstone lifecycle rather than deleting rows directly.
// The strict retention boundary matches upstream: age must exceed deleteAfter.
func (s *Store) DeleteExpiredUsers(ctx context.Context, now time.Time, deleteAfter time.Duration, limit int) (int, error) {
	if s == nil || s.db == nil || ctx == nil || now.IsZero() || now.UnixMilli() < 0 || deleteAfter <= 0 || limit < 1 || limit > maxAccountExpiryBatch {
		return 0, errors.New("invalid expired account deletion batch")
	}
	cutoff := now.UTC().Add(-deleteAfter).UnixMilli()
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,user_expires_at_unix_ms FROM identity_users WHERE disabled=1 AND user_expires_at_unix_ms < ? ORDER BY user_expires_at_unix_ms,subject LIMIT ?`, Args: []any{cutoff, limit}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, row := range result.Rows {
		if len(row) != 2 {
			return count, errors.New("invalid expired account deletion row")
		}
		subject, ok := row[0].(string)
		deadline, deadlineOK := row[1].(int64)
		if !ok || validateSubject(subject) != nil || !deadlineOK || deadline < 0 || deadline >= cutoff {
			return count, errors.New("invalid expired account deletion row")
		}
		guard := `EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=1 AND user_expires_at_unix_ms=? AND user_expires_at_unix_ms<?)`
		err = s.DeleteUserWithGuard(ctx, subject, guard, []any{subject, deadline, cutoff})
		if errors.Is(err, ErrDeleteUnauthorized) || errors.Is(err, ErrInactiveSubject) {
			continue
		}
		if err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
