package loginpolicy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type LockdownStore struct {
	db *rhiza.DB
}

func NewLockdownStore(db *rhiza.DB) *LockdownStore {
	return &LockdownStore{db: db}
}

func (s *LockdownStore) SetLockdown(ctx context.Context, enabled bool, reason string, until time.Time) error {
	if s == nil || s.db == nil {
		return errors.New("lockdown store is not configured")
	}
	nowMs := time.Now().UTC().Truncate(time.Millisecond).UnixMilli()
	var untilMs int64
	if enabled && !until.IsZero() {
		untilMs = until.UTC().Truncate(time.Millisecond).UnixMilli()
	}
	reasonB64 := base64.RawURLEncoding.EncodeToString([]byte(reason))

	requestID, err := randomLockdownRequestID()
	if err != nil {
		return err
	}

	var sql string
	if enabled {
		sql = `INSERT INTO system_lockdown (id,enabled,reason,until_unix_ms,created_at_unix_ms,updated_at_unix_ms)
			VALUES (1, 1, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				enabled = 1,
				reason = excluded.reason,
				until_unix_ms = excluded.until_unix_ms,
				updated_at_unix_ms = excluded.updated_at_unix_ms`
	} else {
		sql = `INSERT INTO system_lockdown (id,enabled,reason,until_unix_ms,created_at_unix_ms,updated_at_unix_ms)
			VALUES (1, 0, '', 0, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				enabled = 0,
				reason = '',
				until_unix_ms = 0,
				updated_at_unix_ms = excluded.updated_at_unix_ms`
	}

	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: requestID,
		Statements: []rhiza.SQLStatement{
			{SQL: sql, Args: []any{reasonB64, untilMs, nowMs, nowMs}},
		},
	})
	return err
}

func (s *LockdownStore) IsLockedDown(ctx context.Context) (bool, string, time.Time, error) {
	if s == nil || s.db == nil {
		return false, "", time.Time{}, errors.New("lockdown store is not configured")
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:       `SELECT enabled, reason, until_unix_ms FROM system_lockdown WHERE id = 1`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return false, "", time.Time{}, err
	}
	if len(result.Rows) == 0 {
		return false, "", time.Time{}, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 3 {
		return false, "", time.Time{}, errors.New("invalid lockdown row")
	}
	enabled, enabledOK := result.Rows[0][0].(int64)
	reasonB64, reasonOK := result.Rows[0][1].(string)
	untilMs, untilOK := result.Rows[0][2].(int64)
	if !enabledOK || !reasonOK || !untilOK {
		return false, "", time.Time{}, errors.New("invalid lockdown data")
	}
	if enabled == 0 {
		return false, "", time.Time{}, nil
	}

	nowMs := time.Now().UTC().Truncate(time.Millisecond).UnixMilli()
	if untilMs > 0 && nowMs >= untilMs {
		return false, "", time.Time{}, nil
	}

	reasonBytes, err := base64.RawURLEncoding.DecodeString(reasonB64)
	if err != nil {
		return false, "", time.Time{}, nil
	}

	var until time.Time
	if untilMs > 0 {
		until = time.UnixMilli(untilMs).UTC()
	}
	return true, string(reasonBytes), until, nil
}

func (s *LockdownStore) ClearExpiredLockdown(ctx context.Context) error {
	if s == nil || s.db == nil {
		return nil
	}
	nowMs := time.Now().UTC().Truncate(time.Millisecond).UnixMilli()
	requestID, err := randomLockdownRequestID()
	if err != nil {
		return err
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: requestID,
		Statements: []rhiza.SQLStatement{
			{SQL: `UPDATE system_lockdown SET enabled = 0, reason = '', until_unix_ms = 0, updated_at_unix_ms = ?
				WHERE id = 1 AND enabled = 1 AND until_unix_ms > 0 AND until_unix_ms <= ?`, Args: []any{nowMs, nowMs}},
		},
	})
	return err
}

func (s *LockdownStore) IsAdmin(ctx context.Context, subject string) (bool, error) {
	if s == nil || s.db == nil || subject == "" {
		return false, errors.New("invalid input")
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:       `SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject = u.subject JOIN rbac_roles r ON r.id = m.role_id WHERE u.subject = ? AND u.disabled = 0 AND r.name = 'rauthy_admin'`,
		Args:      []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return false, err
	}
	return len(result.Rows) == 1, nil
}

func (s *LockdownStore) IsAdminByUsername(ctx context.Context, username string) (bool, error) {
	if s == nil || s.db == nil || username == "" {
		return false, errors.New("invalid input")
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:       `SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject = u.subject JOIN rbac_roles r ON r.id = m.role_id WHERE u.username = ? AND u.disabled = 0 AND r.name = 'rauthy_admin'`,
		Args:      []any{username},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return false, err
	}
	return len(result.Rows) == 1, nil
}

func randomLockdownRequestID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("random lockdown mutation: %w", err)
	}
	return "lockdown/" + base64.RawURLEncoding.EncodeToString(value), nil
}
