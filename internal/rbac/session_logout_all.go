package rbac

import (
	"context"
	"strings"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// LogoutAllSessions revokes existing browser sessions and issued OAuth state,
// not the credentials or pending device authorizations needed for future logins.
// authorization is trusted application SQL; request values must be bound args.
func (s *Store) LogoutAllSessions(ctx context.Context, operationID, authorization string, authorizationArgs ...any) error {
	if s == nil || s.db == nil || ctx == nil || strings.TrimSpace(operationID) == "" || strings.TrimSpace(authorization) == "" || strings.Contains(authorization, ";") {
		return ErrInvalid
	}
	now := s.now().UTC().UnixMilli()
	one := int64(1)
	// Native SELECT preconditions work even when an API key performs an empty
	// cleanup. Authority is checked before revoking the caller's own session.
	statements := []rhiza.SQLStatement{
		{SQL: `SELECT 1 AS authorized WHERE (` + authorization + `)`, Args: authorizationArgs, WantRows: true, ExpectedReturnedRows: &one},
		{SQL: `INSERT INTO oidc_backchannel_deliveries
		 (event_id,client_id,sid,subject,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms)
		 SELECT ? || '/' || subject,client_id,NULL,subject,logout_uri,allow_private,allow_http,0,?,?
		 FROM oidc_user_clients WHERE logout_uri <> ''`, Args: []any{operationID, now, now}},
		{SQL: `UPDATE browser_sessions SET revoked_at_unix_ms=COALESCE(revoked_at_unix_ms,?)`, Args: []any{now}},
		{SQL: `DELETE FROM browser_authorization_interactions`},
		{SQL: `UPDATE oauth_authorize_codes SET invalidated=1 WHERE invalidated=0`},
		{SQL: `DELETE FROM oauth_pkce_requests`},
		{SQL: `UPDATE oauth_refresh_tokens SET active=0 WHERE active=1`},
		{SQL: `DELETE FROM oauth_access_tokens`},
		{SQL: `DELETE FROM oauth_token_requests`},
		{SQL: `DELETE FROM oidc_session_clients`},
		{SQL: `DELETE FROM oidc_user_clients`},
	}
	result, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: operationID, Statements: statements})
	if result.Status == "rejected" && result.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return ErrUnauthorized
	}
	return err
}
