package identity

import (
	"context"
	"errors"
	"time"

	"github.com/mrchypark/rhiza"
)

func (s *Store) passwordExpiry(changedAtUnixMS int64) *time.Time {
	if s == nil || s.rules.ValidDays <= 0 || changedAtUnixMS <= 0 {
		return nil
	}
	expires := time.UnixMilli(changedAtUnixMS).UTC().AddDate(0, 0, s.rules.ValidDays)
	return &expires
}

// PasswordExpiresAt returns the configured password expiry as Unix seconds.
// A disabled policy and legacy unknown timestamp both return nil.
func (s *Store) PasswordExpiresAt(changedAtUnixMS int64) *int64 {
	expires := s.passwordExpiry(changedAtUnixMS)
	if expires == nil {
		return nil
	}
	seconds := expires.Unix()
	return &seconds
}

// PasswordExpiryStatus represents the password expiry state
type PasswordExpiryStatus struct {
	Expired    bool
	ExpiresAt  *time.Time
	DaysLeft   int
	ShouldWarn bool // 7일 이내 만료 시 경고
}

// CheckPasswordExpiry checks the password expiry status for a user
func (s *Store) CheckPasswordExpiry(ctx context.Context, subject string) (*PasswordExpiryStatus, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("identity store unavailable")
	}

	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT password_changed_at_unix_ms FROM identity_users WHERE subject = ? AND disabled = 0`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, nil
	}

	changedAt, ok := result.Rows[0][0].(int64)
	if !ok {
		return nil, nil
	}

	expires := s.passwordExpiry(changedAt)
	if expires == nil {
		return nil, nil
	}

	now := s.now().UTC()
	daysLeft := int(time.Until(*expires).Hours() / 24)

	return &PasswordExpiryStatus{
		Expired:    now.After(*expires),
		ExpiresAt:  expires,
		DaysLeft:   daysLeft,
		ShouldWarn: daysLeft <= 7 && daysLeft > 0,
	}, nil
}

// GetExpiringSoonPasswords returns subjects with passwords expiring within the given days
func (s *Store) GetExpiringSoonPasswords(ctx context.Context, withinDays int) ([]string, error) {
	if s == nil || s.db == nil || withinDays <= 0 {
		return nil, errors.New("invalid parameters")
	}

	now := s.now().UTC()
	cutoff := now.AddDate(0, 0, withinDays).UnixMilli()

	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT subject FROM identity_users 
		      WHERE disabled = 0 
		      AND password_changed_at_unix_ms > 0
		      AND password_changed_at_unix_ms + (? * 86400000) <= ?`,
		Args:        []any{s.rules.ValidDays, cutoff},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}

	subjects := make([]string, 0, len(result.Rows))
	for _, row := range result.Rows {
		if subject, ok := row[0].(string); ok {
			subjects = append(subjects, subject)
		}
	}
	return subjects, nil
}
