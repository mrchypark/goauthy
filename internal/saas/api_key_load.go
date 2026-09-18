package saas

import (
	"context"

	"github.com/mrchypark/rhiza"
)

// loadAPIKey returns the current, authenticated API-key binding and its
// decrypted value. The parent and authority predicates are evaluated in the
// same linearizable read as the credential lookup.
func (s *CredentialStore) loadAPIKey(ctx context.Context, owner, collection, connection string, authority func() (string, []any)) (credentialBinding, credential, error) {
	info, generation, err := s.registeredAPIKeyInfo(ctx, owner, collection, connection, authority)
	if err != nil {
		return credentialBinding{}, credential{}, err
	}
	providerID := apiKeyProviderID
	if info.ID != "" {
		providerID = info.ID
	}
	b := credentialBinding{Owner: owner, CollectionID: collection, ConnectionID: connection, ProviderID: providerID, Generation: generation, TokenVersion: 1}
	provider, ppa := s.apiKeyProviderGuard(b, info.Revision)
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return credentialBinding{}, credential{}, err
	}
	parent, pa := s.apiKeyParentGuard(b)
	args := []any{b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation}
	args = append(args, pa...)
	args = append(args, ppa...)
	args = append(args, ga...)
	q, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:  `SELECT token_version,credential FROM saas_connection_credentials WHERE connection_id=? AND owner_subject=? AND collection_id=? AND provider_id=? AND generation=? AND state='ready' AND ` + parent + ` AND ` + provider + ` AND ` + g + ` ORDER BY token_version DESC LIMIT 1`,
		Args: args, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return credentialBinding{}, credential{}, err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 2 {
		return credentialBinding{}, credential{}, ErrCredentialNotFound
	}
	version, ok := q.Rows[0][0].(int64)
	if !ok || version < 1 {
		return credentialBinding{}, credential{}, errCredential
	}
	envelope, ok := q.Rows[0][1].([]byte)
	if !ok {
		return credentialBinding{}, credential{}, errCredential
	}
	b.TokenVersion = version
	value, err := openCredential(s.keys, b, envelope)
	if err != nil || value.APIKey == "" {
		return credentialBinding{}, credential{}, errCredential
	}
	if info.ID != "" && value.ConnectorDigest != info.Connector.Digest() {
		return credentialBinding{}, credential{}, ErrCredentialUnauthorized
	}
	return b, value, nil
}
