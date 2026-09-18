package rbac

import (
	"context"
	"strings"

	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// DeleteSession removes one session, not every session belonging to its user.
// authorization is trusted SQL from the HTTP boundary; values are bound args.
func (s *Store) DeleteSession(ctx context.Context, operationID, sid, authorization string, authorizationArgs ...any) error {
	if s == nil || s.db == nil || ctx == nil || strings.TrimSpace(operationID) == "" || strings.TrimSpace(authorization) == "" || strings.Contains(authorization, ";") {
		return ErrInvalid
	}
	statements, err := oauth.SessionRevocationStatements(sid, operationID, s.now())
	if err != nil {
		return ErrInvalid
	}
	// Advisory classification preserves 404 for an absent target. The first
	// mutation below repeats authority in the committing transaction.
	decision, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT CASE WHEN NOT (` + authorization + `) THEN 403 WHEN NOT EXISTS (SELECT 1 FROM browser_sessions WHERE token_digest=?) THEN 404 ELSE 200 END`, Args: append(append([]any{}, authorizationArgs...), sid), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(decision.Rows) != 1 || len(decision.Rows[0]) != 1 {
		return ErrInvalid
	}
	switch decision.Rows[0][0] {
	case int64(403):
		return ErrUnauthorized
	case int64(404):
		return ErrNotFound
	case int64(200):
	default:
		return ErrInvalid
	}
	one := int64(1)
	first := rhiza.SQLStatement{SQL: `UPDATE browser_sessions SET token_digest=token_digest WHERE token_digest=? AND (` + authorization + `) RETURNING token_digest`, Args: append([]any{sid}, authorizationArgs...), WantRows: true, ExpectedReturnedRows: &one}
	// Decide authority once before revocation: deleting the caller's own
	// session must not suppress its remaining OAuth/back-channel cleanup.
	batch := append([]rhiza.SQLStatement{first}, statements...)
	// Rhiza does not enforce a foreign key for the upstream session binding.
	// Keep the binding lifetime identical to its browser session.
	batch = append(batch, rhiza.SQLStatement{SQL: `DELETE FROM browser_upstream_session_bindings WHERE session_digest=?`, Args: []any{sid}})
	batch = append(batch, rhiza.SQLStatement{SQL: `DELETE FROM browser_sessions WHERE token_digest=?`, Args: []any{sid}})
	result, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: operationID, Statements: batch})
	if result.Status == "rejected" && result.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return ErrUnauthorized
	}
	return err
}
