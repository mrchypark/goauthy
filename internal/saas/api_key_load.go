package saas

import (
	"context"

	"github.com/mrchypark/rhiza"
)

// loadAPIKey returns the current, authenticated API-key binding and its
// decrypted value. The parent and authority predicates are evaluated in the
// same linearizable read as the credential lookup.
func (s *CredentialStore) loadAPIKey(ctx context.Context, owner, collection, connection string, authority func() (string, []any)) (credentialBinding, credential, error) {
	return s.loadAPIKeyForDispatch(ctx, owner, collection, connection, authority, nil)
}

// loadAPIKeyForDispatch reads the current provider metadata and the ready
// credential in one linearizable snapshot. The provider configuration and the
// credential version are selected together, so a concurrent provider or
// credential change cannot produce a mixed pair. The dispatch-time binding
// check and the postflight reload still fence the outbound request.
func (s *CredentialStore) loadAPIKeyForDispatch(ctx context.Context, owner, collection, connection string, authority func() (string, []any), expected *providerHTTPBinding) (credentialBinding, credential, error) {
	if ctx == nil || s == nil || s.db == nil || !validText(owner) || !validText(collection) || !validText(connection) {
		return credentialBinding{}, credential{}, errCredential
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return credentialBinding{}, credential{}, err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         loadAPIKeyForDispatchSQL + ` AND ` + g + ` ORDER BY x.token_version DESC LIMIT 1`,
		Args:        append([]any{apiKeyProviderID, connection, owner, collection, s.now()}, ga...),
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return credentialBinding{}, credential{}, err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 8 {
		return credentialBinding{}, credential{}, ErrCredentialNotFound
	}
	row := q.Rows[0]
	info, generation, err := s.registeredAPIKeyFromRow(row[:6])
	if err != nil {
		return credentialBinding{}, credential{}, err
	}
	if expected != nil {
		var current providerHTTPBinding
		if info.ID != "" {
			current = info.Connector.registered
		}
		if *expected != current {
			return credentialBinding{}, credential{}, ErrCredentialUnauthorized
		}
	}
	providerID := apiKeyProviderID
	if info.ID != "" {
		providerID = info.ID
	}
	version, ok := row[6].(int64)
	if !ok || version < 1 {
		return credentialBinding{}, credential{}, errCredential
	}
	envelope, ok := row[7].([]byte)
	if !ok {
		return credentialBinding{}, credential{}, errCredential
	}
	b := credentialBinding{Owner: owner, CollectionID: collection, ConnectionID: connection, ProviderID: providerID, Generation: generation, TokenVersion: version}
	value, err := openCredential(s.keys, b, envelope)
	if err != nil || value.APIKey == "" {
		return credentialBinding{}, credential{}, errCredential
	}
	if info.ID != "" && value.ConnectorDigest != info.Connector.Digest() {
		return credentialBinding{}, credential{}, ErrCredentialUnauthorized
	}
	return b, value, nil
}

// loadAPIKeyForDispatchSQL joins the current generation/provider configuration
// with the ready credential in one statement. The provider_id join uses the
// legacy empty-provider sentinel apiKeyProviderID; a registered provider must
// be enabled and match its collection's single provider reference. The caller
// appends the parent authority predicate.
const loadAPIKeyForDispatchSQL = `SELECT c.generation,COALESCE(json_extract(d.providers_json,'$[0]'),''),COALESCE(p.kind,''),COALESCE(p.enabled,0),COALESCE(p.revision,0),COALESCE(p.connector_json,''),x.token_version,x.credential
	FROM auth_collection_connections c
	JOIN auth_collection_definitions d ON d.id=c.collection_id
	JOIN identity_users u ON u.subject=c.owner_subject
	LEFT JOIN saas_providers p ON p.id=json_extract(d.providers_json,'$[0]') AND p.deleted=0
	JOIN saas_connection_credentials x ON x.connection_id=c.id AND x.owner_subject=c.owner_subject AND x.collection_id=c.collection_id AND x.generation=c.generation AND x.provider_id=COALESCE(NULLIF(json_extract(d.providers_json,'$[0]'),''),?) AND x.state='ready'
	WHERE c.id=? AND c.owner_subject=? AND c.collection_id=? AND d.enabled=1 AND d.deleted=0 AND d.auth_method='api_key' AND json_array_length(d.providers_json) <= 1 AND ((json_array_length(d.providers_json)=0) OR (json_array_length(d.providers_json)=1 AND p.kind='api_key' AND p.enabled=1 AND p.deleted=0 AND p.id=json_extract(d.providers_json,'$[0]'))) AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?)`
