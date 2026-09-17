package device

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrUserSessionNotFound     = errors.New("device user session not found")
	ErrUserSessionUnauthorized = errors.New("device user session unauthorized")
)

type UserSession struct {
	ID              string   `json:"id"`
	ClientID        string   `json:"client_id"`
	Scopes          []string `json:"scopes"`
	CreatedAtUnixMS int64    `json:"created_at_unix_ms"`
	RevokedAtUnixMS *int64   `json:"revoked_at_unix_ms,omitempty"`
}

func (s *Store) ListUserSessions(ctx context.Context, owner string, authority func() (string, []any)) ([]UserSession, error) {
	if s == nil || s.db == nil || owner == "" || authority == nil {
		return nil, ErrInvalid
	}
	a, args := authority()
	if a == "" {
		return nil, ErrUserSessionUnauthorized
	}
	a = "(" + a + ")"
	query := `SELECT d.token_request_id,d.client_id,d.scopes_json,d.created_at_unix_ms,d.revoked_at_unix_ms FROM oauth_device_grants d WHERE d.subject=? AND d.state='consumed' AND d.token_request_id IS NOT NULL AND ` + a + ` ORDER BY d.created_at_unix_ms,d.token_request_id`
	rows, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: query, Args: append([]any{owner}, args...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	out := make([]UserSession, 0, len(rows.Rows))
	for _, row := range rows.Rows {
		if len(row) != 5 {
			return nil, ErrInvalid
		}
		id, ok := row[0].(string)
		if !ok || id == "" {
			return nil, ErrInvalid
		}
		clientID, clientOK := row[1].(string)
		scopesJSON, scopesOK := row[2].(string)
		createdAt, createdOK := row[3].(int64)
		if !clientOK || !scopesOK || !createdOK {
			return nil, ErrInvalid
		}
		var scopes []string
		if err := json.Unmarshal([]byte(scopesJSON), &scopes); err != nil {
			return nil, err
		}
		item := UserSession{ID: id, ClientID: clientID, Scopes: scopes, CreatedAtUnixMS: createdAt}
		if row[4] != nil {
			value, ok := row[4].(int64)
			if !ok {
				return nil, ErrInvalid
			}
			item.RevokedAtUnixMS = &value
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *Store) RevokeUserSession(ctx context.Context, owner, id string, authority func() (string, []any)) error {
	if s == nil || s.db == nil || owner == "" || id == "" || strings.ContainsAny(id, "\x00\n") || authority == nil {
		return ErrInvalid
	}
	a, args := authority()
	if a == "" {
		return ErrUserSessionUnauthorized
	}
	a = "(" + a + ")"
	guard := `EXISTS (SELECT 1 FROM oauth_device_grants d WHERE d.token_request_id=? AND d.subject=? AND d.state='consumed' AND ` + a + `)`
	allArgs := append([]any{id, owner}, args...)
	now := s.now
	if now == nil {
		now = time.Now
	}
	revokedAt := now().UTC().UnixMilli()
	statements := []rhiza.SQLStatement{
		{SQL: `UPDATE oauth_refresh_tokens SET active=0 WHERE request_id=? AND ` + guard, Args: append([]any{id}, allArgs...)},
		{SQL: `DELETE FROM oauth_token_requests WHERE signature IN (SELECT signature FROM oauth_access_tokens WHERE request_id=?) AND ` + guard, Args: append([]any{id}, allArgs...)},
		{SQL: `DELETE FROM oauth_access_tokens WHERE request_id=? AND ` + guard, Args: append([]any{id}, allArgs...)},
		{SQL: `UPDATE oauth_device_grants SET revoked_at_unix_ms=coalesce(revoked_at_unix_ms, ?) WHERE token_request_id=? AND subject=? AND state='consumed' AND ` + a, Args: append([]any{revokedAt, id, owner}, args...)},
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	requestID := "device-session-revoke/" + base64.RawURLEncoding.EncodeToString(nonce)
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		return err
	}
	if response.RowsAffected == 0 {
		return ErrUserSessionNotFound
	}
	return nil
}
