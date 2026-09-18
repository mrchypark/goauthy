package saas

import "context"

// CompleteAuthorization installs credentials only for the exact consumed consent
// request which still has current session/provider-policy authority. The caller
// must verify provider identity and granted scopes before supplying value.
func (s *CredentialStore) CompleteAuthorization(ctx context.Context, b credentialBinding, stateDigest, sessionDigest, providerDigest string, value credential, authority func() (string, []any)) error {
	if ctx == nil || s == nil || !validAuthorizationDigest(stateDigest) || !validAuthorizationDigest(sessionDigest) || !validAuthorizationDigest(providerDigest) {
		return errAuthorization
	}
	g, args, err := authorityGuard(authority)
	if err != nil {
		return err
	}
	return s.Install(ctx, b, value, func() (string, []any) {
		guard := `EXISTS(SELECT 1 FROM saas_authorization_requests a WHERE a.state_digest=? AND a.session_digest=? AND a.provider_digest=? AND a.owner_subject=? AND a.collection_id=? AND a.connection_id=? AND a.provider_id=? AND a.generation=? AND a.token_version=? AND a.consumed_at_unix_ms IS NOT NULL AND a.invalidated=0 AND a.expires_at_unix_ms>?) AND ` + g
		bound := []any{stateDigest, sessionDigest, providerDigest, b.Owner, b.CollectionID, b.ConnectionID, b.ProviderID, b.Generation, b.TokenVersion, s.now()}
		return guard, append(bound, args...)
	})
}
