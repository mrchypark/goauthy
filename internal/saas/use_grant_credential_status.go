package saas

import (
	"context"
	"errors"

	"github.com/mrchypark/rhiza"
)

// OAuth2UseGrantStatus exposes only public credential metadata to the consented
// consumer. It does not require a live upstream access token or refresh opt-in,
// and never exchanges tokens or changes credential state.
func (s *CredentialStore) OAuth2UseGrantStatus(ctx context.Context, owner, consumer, id, resource string, authority func() (string, []any)) (OAuth2Status, error) {
	g, _, _, err := s.loadUseGrant(ctx, owner, consumer, id, resource, "credential_delivery", authority)
	if err != nil {
		return OAuth2Status{}, err
	}
	if g.ConnectorDigest != "" || g.ProviderRevision < 1 {
		return OAuth2Status{}, ErrUseGrantNotFound
	}
	guard := func() (string, []any) {
		auth, aa, err := authorityGuard(authority)
		if err != nil {
			return "0", nil
		}
		// Metadata recovery deliberately admits non-ready states, unlike use or
		// refresh. All owner, consumer, provider and generation fences stay intact.
		policy := `EXISTS(SELECT 1` + usePolicyWithoutState + ` AND d.auth_method='oauth2' AND c.generation=? AND m.generation=? AND x.provider_id=? AND p.revision=? AND x.token_version>0)`
		args := append([]any{g.ID, g.Revision, s.now()}, s.usePolicyArgs(g)...)
		args = append(args, g.Generation, g.ConsumerGeneration, g.ProviderID, g.ProviderRevision)
		args = append(args, aa...)
		return `EXISTS(SELECT 1 FROM saas_use_grants WHERE id=? AND revision=? AND revoked=0 AND expires_at_unix_ms>?) AND ` + policy + ` AND (` + auth + `)`, args
	}
	status, err := s.OAuth2Status(ctx, owner, g.CollectionID, g.ConnectionID, guard)
	if errors.Is(err, ErrCredentialNotFound) {
		return OAuth2Status{}, ErrUseGrantNotFound
	}
	if err != nil {
		return OAuth2Status{}, err
	}
	// Decryption is outside the query snapshot. Recheck authority and the exact
	// observed state/version before publishing metadata, without making a claim.
	check, args := guard()
	args = append(args, g.ConnectionID, status.Version, status.State)
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 WHERE ` + check + ` AND EXISTS(SELECT 1 FROM saas_connection_credentials WHERE connection_id=? AND token_version=? AND state=?)`, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return OAuth2Status{}, err
	}
	if len(q.Rows) != 1 {
		return OAuth2Status{}, ErrUseGrantNotFound
	}
	return status, nil
}
