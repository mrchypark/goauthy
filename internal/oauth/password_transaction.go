package oauth

import (
	"context"
	"errors"

	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

// beginPasswordTX retains the generations read before password verification.
// A subsequent credential change must not authorize tokens for the old proof.
func (s *Store) beginPasswordTX(ctx context.Context, subject string, passwordGeneration, authenticationGeneration int64) (context.Context, error) {
	if subject == "" || passwordGeneration < 1 || authenticationGeneration < 1 {
		return ctx, errors.New("invalid password authentication snapshot")
	}
	ctx, err := s.BeginTX(ctx)
	if err != nil {
		return ctx, err
	}
	tx := txFrom(ctx)
	if tx.principalSubject != "" && tx.principalSubject != subject {
		return ctx, errors.New("password principal mismatch")
	}
	tx.kind, tx.principalSubject = "password", subject
	tx.passwordGeneration, tx.authenticationGeneration = passwordGeneration, authenticationGeneration
	return ctx, nil
}

func (s *Store) verifyPasswordIssue(ctx context.Context, tx *transaction) error {
	r, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?),
		(SELECT COUNT(*) FROM oauth_token_requests WHERE signature=?),
		(SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature=? AND access_signature=?)`,
		Args:        []any{tx.targetAccessSignature, tx.targetAccessSignature, tx.targetRefreshSignature, tx.targetAccessSignature},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	wantRefresh := int64(0)
	if tx.targetRefreshSignature != "" {
		wantRefresh = 1
	}
	if len(r.Rows) != 1 || len(r.Rows[0]) != 3 || r.Rows[0][0] != int64(1) || r.Rows[0][1] != int64(1) || r.Rows[0][2] != wantRefresh {
		return fosite.ErrSerializationFailure
	}
	return nil
}
