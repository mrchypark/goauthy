package identity

import (
	"context"
	"errors"

	"github.com/mrchypark/rhiza"
)

// ErrAccountDataMode distinguishes capability failures from an inactive profile.
// The dashboard historically returns 503 for the former and 401 for the latter.
var ErrAccountDataMode = errors.New("account data authentication mode unavailable")

// AccountDataBySubject reads public profile and mode from one linearizable
// snapshot. It does not load, authorize, or touch the caller's browser session.
func (s *Store) AccountDataBySubject(ctx context.Context, subject string) (AccountProfile, bool, error) {
	if err := validateSubject(subject); err != nil {
		return AccountProfile{}, false, err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT u.subject,u.username,u.disabled,p.email,p.email_verified,p.preferred_username,p.given_name,p.family_name,
			m.subject,m.mode,m.generation FROM identity_users u
			LEFT JOIN identity_user_profiles p ON p.subject=u.subject
			LEFT JOIN identity_authentication_modes m ON m.subject=u.subject
			WHERE u.subject=? AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?)`,
		Args: []any{subject, s.now().UTC().UnixMilli()}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return AccountProfile{}, false, err
	}
	if len(result.Rows) == 0 {
		return AccountProfile{}, false, ErrInactiveSubject
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 11 {
		return AccountProfile{}, false, errors.New("invalid identity profile row")
	}
	row := result.Rows[0]
	profile, err := decodeAccountProfile(row[:8])
	if err != nil {
		return AccountProfile{}, false, err
	}
	var modeRows [][]any
	if row[8] != nil {
		modeRows = [][]any{row[9:]}
	}
	_, password, err := decodeAuthenticationMode(modeRows)
	if err != nil {
		return AccountProfile{}, false, errors.Join(ErrAccountDataMode, err)
	}
	return profile, !password, nil
}
