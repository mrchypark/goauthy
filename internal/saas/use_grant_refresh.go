package saas

import (
	"context"

	"github.com/mrchypark/rhiza"
)

// RefreshOAuth2UseGrant permits one upstream refresh only under separately
// opted-in owner consent. It returns public status, never provider credentials.
// An expired upstream access token is eligible; an expired consumer token or
// consent is not. A failed/ambiguous exchange is never automatically retried.
func (s *CredentialStore) RefreshOAuth2UseGrant(ctx context.Context, providers *ProviderStore, owner, consumer, grantID, resource string, expectedVersion int64, authority func() (string, []any)) (OAuth2Status, error) {
	if expectedVersion < 1 || expectedVersion == 1<<63-1 {
		return OAuth2Status{}, ErrUseGrantInvalid
	}
	g, guard, err := s.authorizeUseRefresh(ctx, owner, consumer, grantID, resource, authority)
	if err != nil {
		return OAuth2Status{}, err
	}
	return s.RefreshOAuth2(ctx, providers, owner, g.CollectionID, g.ConnectionID, expectedVersion, guard)
}

func (s *CredentialStore) authorizeUseRefresh(ctx context.Context, owner, consumer, grantID, resource string, authority func() (string, []any)) (UseGrant, func() (string, []any), error) {
	g, auth, aa, err := s.loadUseGrant(ctx, owner, consumer, grantID, resource, "credential_delivery", authority)
	if err != nil {
		return UseGrant{}, nil, err
	}
	if !g.AllowRefresh || g.ConnectorDigest != "" || g.ProviderRevision < 1 {
		return UseGrant{}, nil, ErrUseGrantNotFound
	}
	policy := `EXISTS(SELECT 1` + usePolicyWithoutState + ` AND d.auth_method='oauth2' AND c.generation=? AND m.generation=? AND x.provider_id=? AND p.revision=? AND x.token_version>0)`
	pa := append(s.usePolicyArgs(g), g.Generation, g.ConsumerGeneration, g.ProviderID, g.ProviderRevision)
	q, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT x.state FROM saas_connection_credentials x WHERE x.connection_id=? AND ` + policy + ` AND (` + auth + `)`,
		Args:        append(append([]any{g.ConnectionID}, pa...), aa...),
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return UseGrant{}, nil, err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 1 {
		return UseGrant{}, nil, ErrUseGrantNotFound
	}
	state, _ := q.Rows[0][0].(string)
	if state == "refreshing" {
		return UseGrant{}, nil, ErrUseGrantConflict
	}
	if state != "ready" {
		return UseGrant{}, nil, ErrUseGrantNotFound
	}
	guard := func() (string, []any) {
		auth, aa, err := authorityGuard(authority)
		if err != nil {
			return "0", nil
		}
		// The credential operations themselves fence version and refresh claim.
		// Pinning the ready-only use guard here would reject our own claim and
		// lose a successfully rotated upstream token at CompleteRefresh.
		policy, pa := s.useStatePolicy(g, 0, true)
		args := append([]any{g.ID, g.Revision, s.now()}, pa...)
		args = append(args, aa...)
		return `EXISTS(SELECT 1 FROM saas_use_grants WHERE id=? AND revision=? AND revoked=0 AND allow_refresh=1 AND expires_at_unix_ms>?) AND ` + policy + ` AND (` + auth + `)`, args
	}
	return g, guard, nil
}
