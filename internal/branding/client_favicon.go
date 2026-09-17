package branding

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrClientFaviconNotFound     = errors.New("client favicon not found")
	ErrClientFaviconPrecondition = errors.New("client favicon precondition failed")
	ErrClientFaviconForbidden    = errors.New("client favicon mutation forbidden")
)

// ClientFaviconStore persists one immutable validated favicon per configured
// client. The durable row is the shared HA source of truth; ETags are derived
// from bytes so every node returns the same cache validator.
type ClientFaviconStore struct {
	db  *rhiza.DB
	now func() time.Time
}

func NewClientFaviconStore(db *rhiza.DB) (*ClientFaviconStore, error) {
	if db == nil {
		return nil, errors.New("client favicon store requires database")
	}
	return &ClientFaviconStore{db: db, now: time.Now}, nil
}

func (s *ClientFaviconStore) Get(ctx context.Context, clientID string) (*Asset, error) {
	if s == nil || s.db == nil || !validClientID(clientID) {
		return nil, ErrClientFaviconNotFound
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT data FROM client_favicons WHERE client_id = ?`, Args: []any{clientID}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, ErrClientFaviconNotFound
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return nil, ErrClientFaviconNotFound
	}
	data, ok := result.Rows[0][0].([]byte)
	if !ok {
		return nil, ErrInvalidFormat
	}
	return NewAsset(data)
}

func (s *ClientFaviconStore) Put(ctx context.Context, clientID string, asset *Asset) error {
	if s == nil || s.db == nil || !validClientID(clientID) || asset == nil || len(asset.bytes) == 0 {
		return ErrInvalidFormat
	}
	now := s.now().UTC()
	if now.IsZero() {
		return ErrInvalidFormat
	}
	requestIDBytes := make([]byte, 16)
	if _, err := rand.Read(requestIDBytes); err != nil {
		return err
	}
	requestID := "branding-favicon/" + base64.RawURLEncoding.EncodeToString(requestIDBytes)
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{{
		SQL: `INSERT INTO client_favicons (client_id, content_type, data, updated_at_unix_ms)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(client_id) DO UPDATE SET content_type=excluded.content_type, data=excluded.data, updated_at_unix_ms=excluded.updated_at_unix_ms`,
		Args: []any{clientID, asset.contentType, append([]byte(nil), asset.bytes...), now.UnixMilli()},
	}}})
	return err
}

func (s *ClientFaviconStore) Delete(ctx context.Context, clientID string) error {
	if s == nil || s.db == nil || !validClientID(clientID) {
		return ErrClientFaviconNotFound
	}
	requestIDBytes := make([]byte, 16)
	if _, err := rand.Read(requestIDBytes); err != nil {
		return err
	}
	requestID := "branding-favicon-delete/" + base64.RawURLEncoding.EncodeToString(requestIDBytes)
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{{
		SQL: `DELETE FROM client_favicons WHERE client_id = ?`, Args: []any{clientID},
	}}})
	return err
}

// PutConditional creates an absent favicon or replaces the exact asset read by
// the caller. API-key authorization is rechecked in the same replicated
// mutation. Browser-admin authorization is necessarily a preflight boundary:
// its session/RBAC state is not representable in the durable API-key guard.
func (s *ClientFaviconStore) PutConditional(ctx context.Context, clientID string, asset, expected *Asset, keys *apikey.Store, principal *apikey.Principal) error {
	if s == nil || s.db == nil || !validClientID(clientID) || asset == nil || len(asset.bytes) == 0 || keys == nil {
		return ErrInvalidFormat
	}
	now := s.now().UTC()
	if now.IsZero() {
		return ErrInvalidFormat
	}
	requestID, err := clientFaviconRequestID("branding-favicon")
	if err != nil {
		return err
	}
	var statement rhiza.SQLStatement
	if expected == nil {
		statement = rhiza.SQLStatement{SQL: `INSERT INTO client_favicons (client_id, content_type, data, updated_at_unix_ms)
			SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM client_favicons WHERE client_id=?)
			AND ` + apikey.GuardExistsSQL(), Args: []any{clientID, asset.contentType, append([]byte(nil), asset.bytes...), now.UnixMilli(), clientID, requestID}}
	} else {
		statement = rhiza.SQLStatement{SQL: `UPDATE client_favicons SET content_type=?, data=?, updated_at_unix_ms=?
			WHERE client_id=? AND data=? AND ` + apikey.GuardExistsSQL(), Args: []any{asset.contentType, append([]byte(nil), asset.bytes...), now.UnixMilli(), clientID, append([]byte(nil), expected.bytes...), requestID}}
	}
	response, authorized, err := keys.RunMutation(ctx, principal, "Clients", apikey.Update, requestID, []rhiza.SQLStatement{statement})
	if err != nil {
		return err
	}
	if !authorized {
		return ErrClientFaviconForbidden
	}
	if response.RowsAffected < 3 {
		return ErrClientFaviconPrecondition
	}
	return nil
}

// DeleteConditional removes only the exact asset read by the caller. See
// PutConditional for the browser-admin authorization boundary.
func (s *ClientFaviconStore) DeleteConditional(ctx context.Context, clientID string, expected *Asset, keys *apikey.Store, principal *apikey.Principal) error {
	if s == nil || s.db == nil || !validClientID(clientID) || expected == nil || keys == nil {
		return ErrInvalidFormat
	}
	requestID, err := clientFaviconRequestID("branding-favicon-delete")
	if err != nil {
		return err
	}
	statement := rhiza.SQLStatement{SQL: `DELETE FROM client_favicons WHERE client_id=? AND data=? AND ` + apikey.GuardExistsSQL(), Args: []any{clientID, append([]byte(nil), expected.bytes...), requestID}}
	response, authorized, err := keys.RunMutation(ctx, principal, "Clients", apikey.Update, requestID, []rhiza.SQLStatement{statement})
	if err != nil {
		return err
	}
	if !authorized {
		return ErrClientFaviconForbidden
	}
	if response.RowsAffected < 3 {
		return ErrClientFaviconPrecondition
	}
	return nil
}

func clientFaviconRequestID(prefix string) (string, error) {
	requestIDBytes := make([]byte, 16)
	if _, err := rand.Read(requestIDBytes); err != nil {
		return "", err
	}
	return prefix + "/" + base64.RawURLEncoding.EncodeToString(requestIDBytes), nil
}

func validClientID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func readClientFavicon(r io.Reader) (*Asset, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxFaviconBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read favicon: %w", err)
	}
	if len(data) > maxFaviconBytes {
		return nil, ErrInvalidFormat
	}
	return NewAsset(data)
}
