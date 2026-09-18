package identity

import (
	"context"
	"errors"

	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/rhiza"
)

// UserLanguage returns the persisted preference, or empty for unknown legacy
// users. Empty deliberately preserves the caller's configured mail fallback.
func (s *Store) UserLanguage(ctx context.Context, subject string) (string, error) {
	if err := validateSubject(subject); err != nil {
		return "", err
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT language FROM identity_users WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return "", err
	}
	if len(r.Rows) == 0 {
		return "", ErrInactiveSubject
	}
	if len(r.Rows) != 1 || len(r.Rows[0]) != 1 {
		return "", errors.New("invalid user language row")
	}
	if r.Rows[0][0] == nil {
		return "", nil
	}
	lang, ok := r.Rows[0][0].(string)
	if !ok || !i18n.ValidUserLanguage(lang) {
		return "", errors.New("invalid stored user language")
	}
	return lang, nil
}
