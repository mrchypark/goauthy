package rbac

import (
	"context"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// ForceLogout revokes all local login and OAuth state for target and queues
// one subject-only back-channel delivery per known user/client association. authorization
// is trusted SQL assembled by the HTTP/authentication boundary; it must never
// contain request-provided SQL.
func (s *Store) ForceLogout(ctx context.Context, operationID, target, authorization string, authorizationArgs ...any) error {
	if ctx == nil || s == nil || s.db == nil || !validSubjectID(target) || strings.TrimSpace(operationID) == "" || strings.TrimSpace(authorization) == "" || strings.Contains(authorization, ";") {
		return ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Millisecond).UnixMilli()
	event, err := eventlog.ForceLogout(operationID, "", time.UnixMilli(now).UTC()).Statement("1=1")
	if err != nil {
		return err
	}
	// The first statement is the sole authority decision and target
	// precondition. Its RETURNING row also supplies the event's authoritative
	// email without a post-revocation read.
	firstArgs := append([]any{target}, authorizationArgs...)
	first := rhiza.SQLStatement{SQL: `UPDATE identity_users SET subject=subject
		WHERE subject=? AND (` + authorization + `)
		RETURNING subject, COALESCE((SELECT NULLIF(email,'') FROM identity_user_profiles WHERE subject=identity_users.subject),
			(SELECT NULLIF(email,'') FROM identity_recovery_emails WHERE subject=identity_users.subject), '') AS email`, Args: firstArgs, WantRows: true}
	one := int64(1)
	first.ExpectedReturnedRows = &one
	event.Args[6] = nil
	event.OutputRefs = []rhiza.SQLStatementOutputRef{{ArgIndex: 6, StatementIndex: 0, ColumnName: "email"}}

	// Enqueue before removing associations. The first barrier above is
	// deliberately not repeated: a caller revoking its own session must still
	// execute the remaining statements in this transaction.
	statements := []rhiza.SQLStatement{first,
		{SQL: `INSERT INTO oidc_backchannel_deliveries
			(event_id,client_id,sid,subject,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms)
			SELECT ?,client_id,NULL,subject,logout_uri,allow_private,allow_http,0,?,?
			FROM oidc_user_clients WHERE subject=? AND logout_uri <> ''`,
			Args: []any{operationID, now, now, target}},
		{SQL: `UPDATE browser_sessions SET revoked_at_unix_ms=COALESCE(revoked_at_unix_ms,?) WHERE subject=?`, Args: []any{now, target}},
		{SQL: `DELETE FROM browser_authorization_interactions WHERE session_digest IN (SELECT token_digest FROM browser_sessions WHERE subject=?)`, Args: []any{target}},
		{SQL: `UPDATE oauth_authorize_codes SET invalidated=1 WHERE invalidated=0 AND json_extract(request_json,'$.subject')=?`, Args: []any{target}},
		{SQL: `DELETE FROM oauth_pkce_requests WHERE signature IN (SELECT signature FROM oauth_authorize_codes WHERE json_extract(request_json,'$.subject')=?)`, Args: []any{target}},
		{SQL: `UPDATE oauth_refresh_tokens SET active=0 WHERE active=1 AND json_extract(request_json,'$.subject')=?`, Args: []any{target}},
		{SQL: `DELETE FROM oauth_access_tokens WHERE signature IN (SELECT signature FROM oauth_token_requests WHERE json_extract(request_json,'$.subject')=?)`, Args: []any{target}},
		{SQL: `DELETE FROM oauth_token_requests WHERE json_extract(request_json,'$.subject')=?`, Args: []any{target}},
		{SQL: `UPDATE oauth_device_grants SET state='denied',claim_token_digest=NULL,claim_until_unix_ms=NULL WHERE subject=? AND state IN ('pending','approved')`, Args: []any{target}},
		{SQL: `DELETE FROM oidc_session_clients WHERE sid IN (SELECT token_digest FROM browser_sessions WHERE subject=?)`, Args: []any{target}},
		{SQL: `DELETE FROM oidc_user_clients WHERE subject=?`, Args: []any{target}},
		event,
	}
	result, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: operationID, Statements: statements})
	if result.Status == "rejected" && result.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return ErrUnauthorized
	}
	return err
}
