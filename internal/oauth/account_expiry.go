package oauth

import (
	"context"
	"time"

	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

type accountExpiryContextKey struct{}

type accountExpiry struct {
	subject  string
	deadline *int64 // Only SQL NULL is unlimited.
}

// Replaced with the submission clock before a replicated Execute. Never send
// a local clock expression to followers or freeze this cutoff at request start.
type accountExpiryCutoff struct{}

func (s *Store) issuanceAccounts(ctx context.Context, request fosite.AccessRequester) (context.Context, error) {
	subjects, err := tokenAccountSubjects(request)
	if err != nil {
		return ctx, fosite.ErrInvalidGrant
	}
	ctx, err = s.accountContext(ctx, subjects...)
	if err != nil {
		return ctx, err
	}
	if err := capAccountSession(ctx, request.GetSession(), s.now().UTC()); err != nil {
		return ctx, err
	}
	return ctx, nil
}

// accountContext captures exact nullable deadlines for a subsequent guarded
// mutation. Identity reads do not replace the final replicated write guard.
func (s *Store) accountContext(ctx context.Context, subjects ...string) (context.Context, error) {
	accounts := make([]accountExpiry, 0, len(subjects))
	for _, subject := range subjects {
		result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT user_expires_at_unix_ms FROM identity_users WHERE subject=? AND disabled=0`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return ctx, err
		}
		if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
			return ctx, fosite.ErrInvalidGrant
		}
		account := accountExpiry{subject: subject}
		if value := result.Rows[0][0]; value != nil {
			deadline, ok := value.(int64)
			if !ok || deadline < 0 {
				return ctx, fosite.ErrInvalidGrant
			}
			account.deadline = &deadline
		}
		accounts = append(accounts, account)
	}
	return context.WithValue(ctx, accountExpiryContextKey{}, accounts), nil
}

// validateTokenAccounts belongs at consumption boundaries, not raw storage
// lookup: Fosite also uses raw lookups to discover tokens for explicit revocation
// and to detect refresh reuse. Hiding a row there can turn revocation into a no-op.
func (s *Store) validateTokenAccounts(ctx context.Context, request fosite.Requester) error {
	if request == nil || request.GetSession() == nil {
		return fosite.ErrInactiveToken
	}
	subjects, err := tokenAccountSubjects(request)
	if err != nil {
		return fosite.ErrInactiveToken
	}
	if len(subjects) == 0 {
		// machineTokenSubject accepted a durable machine representation.
		return nil
	}
	// Evaluate all accounts in one linearizable query, using the millisecond
	// policy boundary rather than JWT rounding or the eventual expiry worker.
	guard := ""
	args := []any{}
	now := s.now().UTC().UnixMilli()
	for _, subject := range subjects {
		guard += ` AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0
			AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms>?))`
		args = append(args, subject, now)
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 WHERE 1=1` + guard, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 {
		return fosite.ErrInactiveToken
	}
	return nil
}

func capAuthorizeCodeSession(ctx context.Context, session fosite.Session, now time.Time) error {
	limit := accountDeadline(ctx)
	if limit.IsZero() {
		return nil
	}
	if !limit.After(now) {
		return fosite.ErrInvalidGrant
	}
	if expiry := session.GetExpiresAt(fosite.AuthorizeCode); expiry.IsZero() || expiry.After(limit) {
		session.SetExpiresAt(fosite.AuthorizeCode, limit)
	}
	return nil
}

func accountDeadline(ctx context.Context) time.Time {
	accounts, _ := ctx.Value(accountExpiryContextKey{}).([]accountExpiry)
	var limit time.Time
	for _, account := range accounts {
		if account.deadline != nil {
			// JWT NumericDate is in seconds. Round down, never extend an account
			// deadline to the next second, and use that same cap in persisted rows.
			deadline := time.UnixMilli(*account.deadline).UTC().Truncate(time.Second)
			if limit.IsZero() || deadline.Before(limit) {
				limit = deadline
			}
		}
	}
	return limit
}

func capAccountSession(ctx context.Context, session fosite.Session, now time.Time) error {
	limit := accountDeadline(ctx)
	if limit.IsZero() {
		return nil
	}
	if !limit.After(now) {
		return fosite.ErrInvalidGrant
	}
	for _, kind := range []fosite.TokenType{fosite.AccessToken, fosite.RefreshToken} {
		if expiry := session.GetExpiresAt(kind); expiry.IsZero() || expiry.After(limit) {
			session.SetExpiresAt(kind, limit)
		}
	}
	return nil
}

func (tx *transaction) accountExpiryGuard() (string, []any) {
	var guard string
	var args []any
	for _, account := range tx.accounts {
		var deadline any
		if account.deadline != nil {
			deadline = *account.deadline
		}
		guard += ` AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0
			AND user_expires_at_unix_ms IS ? AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?))`
		args = append(args, account.subject, deadline, accountExpiryCutoff{})
	}
	return guard, args
}

// Recheck after signing/commit, before writing any successful response bytes.
// A subsequent network delay or offline RP verification cannot be made atomic
// with the database; tokens themselves retain the bounded signed expiry.
func (s *Store) validateIssuanceAccounts(ctx context.Context) error {
	accounts, _ := ctx.Value(accountExpiryContextKey{}).([]accountExpiry)
	if len(accounts) == 0 {
		return nil
	}
	guard, args := (&transaction{accounts: accounts}).accountExpiryGuard()
	for i, arg := range args {
		if _, ok := arg.(accountExpiryCutoff); ok {
			args[i] = s.now().UTC().UnixMilli()
		}
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 WHERE 1=1` + guard, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 || (!accountDeadline(ctx).IsZero() && !accountDeadline(ctx).After(s.now().UTC())) {
		return fosite.ErrInvalidGrant
	}
	return nil
}
