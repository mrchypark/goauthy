package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// UpstreamLogout is the verified, non-bearer portion of an upstream OIDC
// back-channel logout token. TokenDigest is base64url(SHA-256(raw token)); the
// raw token must never reach durable storage. ExpiresAt is the verifier-bounded
// replay retention deadline, not an unbounded upstream exp claim.
type UpstreamLogout struct {
	Issuer      string
	ClientID    string
	Subject     string
	SessionID   string
	JTI         string
	TokenDigest string
	ExpiresAt   time.Time
}

// RevokeUpstreamSessions consumes one verified upstream logout token and
// revokes only local external sessions bound to its exact issuer and client.
// Subject and SessionID are intersected when both are present.
func (s *Store) RevokeUpstreamSessions(ctx context.Context, logout UpstreamLogout) error {
	if s == nil || s.db == nil {
		return errors.New("OAuth store is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if txFrom(ctx) != nil {
		return errors.New("upstream logout cannot run inside an OAuth transaction")
	}
	if !validUpstreamLogout(logout) {
		return errors.New("invalid upstream logout")
	}
	now := time.Now().UTC()
	if s.now != nil {
		now = s.now().UTC()
	}
	if !logout.ExpiresAt.After(now) {
		return errors.New("expired upstream logout")
	}
	operationID, err := upstreamLogoutOperationID()
	if err != nil {
		return err
	}
	requestID := "oauth-upstream-logout/" + logout.TokenDigest[:16] + "/" + operationID
	statements := upstreamLogoutStatements(logout, operationID, now)
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements}); err != nil {
		// In particular, do not convert ErrCommitUnknown into success by reading a
		// receipt: the caller must retry and receive an acknowledged mutation.
		return err
	}
	return s.confirmUpstreamLogoutReceipt(ctx, logout)
}

// RevokeUpstreamSessions exposes durable upstream logout consumption to the
// HTTP boundary after it has verified the signed logout token.
func (s *Server) RevokeUpstreamSessions(ctx context.Context, logout UpstreamLogout) error {
	if s == nil || s.store == nil {
		return errors.New("OAuth server is not configured")
	}
	return s.store.RevokeUpstreamSessions(ctx, logout)
}

func validUpstreamLogout(logout UpstreamLogout) bool {
	if strings.TrimSpace(logout.Issuer) != logout.Issuer || strings.TrimSpace(logout.ClientID) != logout.ClientID ||
		strings.TrimSpace(logout.Subject) != logout.Subject || strings.TrimSpace(logout.SessionID) != logout.SessionID ||
		strings.TrimSpace(logout.JTI) != logout.JTI || logout.Issuer == "" || logout.ClientID == "" || logout.JTI == "" ||
		(logout.Subject == "" && logout.SessionID == "") || len(logout.Issuer) > 2048 || len(logout.ClientID) > 256 ||
		len(logout.Subject) > 512 || len(logout.SessionID) > 512 || len(logout.JTI) > 512 || logout.ExpiresAt.IsZero() {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(logout.TokenDigest)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == logout.TokenDigest
}

func upstreamLogoutStatements(logout UpstreamLogout, operationID string, now time.Time) []rhiza.SQLStatement {
	createdAt, expiresAt := now.UnixMilli(), logout.ExpiresAt.UTC().UnixMilli()
	receiptArgs := []any{logout.Issuer, logout.ClientID, logout.JTI, logout.TokenDigest, logout.Subject, logout.SessionID, expiresAt, operationID}
	selectionArgs := []any{logout.Issuer, logout.ClientID, logout.Subject, logout.Subject, logout.SessionID, logout.SessionID}
	eventPrefix := upstreamLogoutEventPrefix(logout)
	const receipt = `EXISTS (SELECT 1 FROM upstream_logout_receipts r WHERE r.issuer=? AND r.client_id=? AND r.jti=? AND r.token_digest=? AND r.upstream_subject=? AND r.upstream_sid=? AND r.expires_at_unix_ms=? AND r.operation_id=?)`
	const selected = `ub.issuer=? AND ub.client_id=? AND (?='' OR ub.upstream_subject=?) AND (?='' OR ub.upstream_sid=?)`
	const sidJSONPath = "$.extra.goauthy_oidc_session_id"
	sessionSelection := `SELECT ub.session_digest FROM browser_upstream_session_bindings ub WHERE ` + selected + ` AND ` + receipt
	selectionAndReceipt := append(append([]any{}, selectionArgs...), receiptArgs...)
	return []rhiza.SQLStatement{
		// Keep replay receipts only while the signed token can still be accepted.
		{SQL: `DELETE FROM upstream_logout_receipts WHERE expires_at_unix_ms <= ?`, Args: []any{createdAt}},
		{SQL: `INSERT OR IGNORE INTO upstream_logout_receipts
			(issuer,client_id,jti,token_digest,upstream_subject,upstream_sid,expires_at_unix_ms,operation_id,created_at_unix_ms)
			VALUES (?,?,?,?,?,?,?,?,?)`, Args: append(receiptArgs, createdAt)},
		// This is the same durable downstream logout outbox used by local OIDC
		// logout. A reauthentication replacement can revoke the bound parent before
		// its upstream logout arrives, but its RP logout obligation remains.
		{SQL: `INSERT OR IGNORE INTO oidc_backchannel_deliveries
			(event_id,client_id,sid,subject,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms)
			SELECT ? || '/' || ub.session_digest, sc.client_id, ub.session_digest, '', sc.logout_uri, sc.allow_private, sc.allow_http, 0, ?, ?
			FROM browser_upstream_session_bindings ub
			JOIN oidc_session_clients sc ON sc.sid=ub.session_digest
			JOIN browser_sessions bs ON bs.token_digest=ub.session_digest
			WHERE ` + selected + ` AND sc.logout_uri <> '' AND ` + receipt,
			Args: append(append([]any{eventPrefix, createdAt, createdAt}, selectionArgs...), receiptArgs...)},
		{SQL: `UPDATE browser_sessions SET revoked_at_unix_ms=COALESCE(revoked_at_unix_ms, ?)
			WHERE token_digest IN (` + sessionSelection + `)`, Args: append([]any{createdAt}, selectionAndReceipt...)},
		{SQL: `DELETE FROM browser_authorization_interactions WHERE session_digest IN (` + sessionSelection + `)`, Args: selectionAndReceipt},
		{SQL: `UPDATE oauth_authorize_codes SET invalidated=1 WHERE invalidated=0
			AND json_extract(request_json, '` + sidJSONPath + `') IN (` + sessionSelection + `)`, Args: selectionAndReceipt},
		{SQL: `DELETE FROM oauth_pkce_requests WHERE signature IN (SELECT signature FROM oauth_authorize_codes
			WHERE json_extract(request_json, '` + sidJSONPath + `') IN (` + sessionSelection + `))`, Args: selectionAndReceipt},
		{SQL: `UPDATE oauth_refresh_tokens SET active=0 WHERE active=1
			AND json_extract(request_json, '` + sidJSONPath + `') IN (` + sessionSelection + `)`, Args: selectionAndReceipt},
		{SQL: `DELETE FROM oauth_access_tokens WHERE signature IN (SELECT signature FROM oauth_token_requests
			WHERE json_extract(request_json, '` + sidJSONPath + `') IN (` + sessionSelection + `))`, Args: selectionAndReceipt},
		{SQL: `DELETE FROM oauth_token_requests WHERE json_extract(request_json, '` + sidJSONPath + `') IN (` + sessionSelection + `)`, Args: selectionAndReceipt},
		{SQL: `DELETE FROM oidc_session_clients WHERE sid IN (` + sessionSelection + `)`, Args: selectionAndReceipt},
	}
}

func (s *Store) confirmUpstreamLogoutReceipt(ctx context.Context, logout UpstreamLogout) error {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT token_digest,upstream_subject,upstream_sid,expires_at_unix_ms
		FROM upstream_logout_receipts WHERE issuer=? AND client_id=? AND jti=?`, Args: []any{logout.Issuer, logout.ClientID, logout.JTI}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 4 || result.Rows[0][0] != logout.TokenDigest ||
		result.Rows[0][1] != logout.Subject || result.Rows[0][2] != logout.SessionID || result.Rows[0][3] != logout.ExpiresAt.UTC().UnixMilli() {
		return errors.New("upstream logout JTI conflicts with an accepted token")
	}
	return nil
}

func upstreamLogoutEventPrefix(logout UpstreamLogout) string {
	sum := sha256.Sum256([]byte(logout.Issuer + "\x00" + logout.ClientID + "\x00" + logout.JTI + "\x00" + logout.TokenDigest))
	return "upstream/" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func upstreamLogoutOperationID() (string, error) {
	attempt := make([]byte, 16)
	if _, err := rand.Read(attempt); err != nil {
		return "", fmt.Errorf("random upstream logout operation ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(attempt), nil
}
