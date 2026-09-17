package saas

import (
	"context"
	"errors"
	"time"
)

var errRefreshUncertain = errors.New("saas refresh outcome uncertain; reconnect required")

// refreshCredential never retries the external operation. exchange is a trusted
// provider adapter, not a callback or destination supplied by an API caller.
// Only the new binding is returned, after persistence and current-authority checks.
func (s *CredentialStore) refreshCredential(ctx context.Context, b credentialBinding, authority func() (string, []any), exchange func(context.Context, credential) (credential, error)) (credentialBinding, error) {
	if ctx == nil || exchange == nil {
		return credentialBinding{}, errCredential
	}
	if err := ctx.Err(); err != nil {
		return credentialBinding{}, err
	}
	current, err := s.Load(ctx, b, authority)
	if err != nil {
		return credentialBinding{}, err
	}
	if current.RefreshToken == "" || (current.RefreshExpiresAtUnixMS != 0 && current.RefreshExpiresAtUnixMS <= s.now()) {
		return credentialBinding{}, errCredential
	}
	claim, err := s.ClaimRefresh(ctx, b, authority)
	if err != nil {
		return credentialBinding{}, err
	}
	updated, exchangeErr := exchange(ctx, current)
	if exchangeErr == nil {
		exchangeErr = s.CompleteRefresh(ctx, b, claim, updated, authority)
	}
	if exchangeErr != nil {
		// Cancellation cannot erase a possibly consumed refresh token. Persist an
		// uncertainty marker with a bounded cleanup context; a failed marker leaves
		// the durable claim in refreshing, which also forbids another exchange.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.MarkRefreshUncertain(cleanup, b, claim)
		// Provider errors can contain token-bearing response bodies. Never return
		// them to the caller. A commit error is not proof that the commit failed.
		return credentialBinding{}, errRefreshUncertain
	}
	b.TokenVersion++
	return b, nil
}
