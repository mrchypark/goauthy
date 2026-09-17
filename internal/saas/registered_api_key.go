package saas

import (
	"context"
	"encoding/json"

	"github.com/mrchypark/rhiza"
)

type registeredAPIKey struct {
	ID        string
	Revision  int64
	Enabled   bool
	Connector *APIKeyConnector
}

// registeredAPIKeyInfo resolves the optional provider reference on an API-key
// collection. Empty providers_json is the legacy sentinel mode.
func (s *CredentialStore) registeredAPIKeyInfo(ctx context.Context, owner, collection, connection string, authority func() (string, []any)) (registeredAPIKey, string, error) {
	if ctx == nil || s == nil || s.db == nil || !validText(owner) || !validText(collection) || !validText(connection) {
		return registeredAPIKey{}, "", errCredential
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return registeredAPIKey{}, "", err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT c.generation,COALESCE(json_extract(d.providers_json,'$[0]'),''),COALESCE(p.kind,''),COALESCE(p.enabled,0),COALESCE(p.revision,0),COALESCE(p.connector_json,'') FROM auth_collection_connections c JOIN auth_collection_definitions d ON d.id=c.collection_id JOIN identity_users u ON u.subject=c.owner_subject LEFT JOIN saas_providers p ON p.id=json_extract(d.providers_json,'$[0]') AND p.deleted=0 WHERE c.id=? AND c.owner_subject=? AND c.collection_id=? AND d.enabled=1 AND d.deleted=0 AND d.auth_method='api_key' AND json_array_length(d.providers_json) <= 1 AND (json_array_length(d.providers_json)=0 OR (p.kind='api_key' AND p.id IS NOT NULL)) AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?) AND (` + g + `)`, Args: append([]any{connection, owner, collection, s.now()}, ga...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return registeredAPIKey{}, "", err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 6 {
		return registeredAPIKey{}, "", ErrCredentialNotFound
	}
	row := q.Rows[0]
	generation, ok := row[0].(string)
	if !ok || !validText(generation) {
		return registeredAPIKey{}, "", errCredential
	}
	id, ok := row[1].(string)
	if !ok {
		return registeredAPIKey{}, "", errCredential
	}
	if id == "" {
		return registeredAPIKey{}, generation, nil
	}
	kind, _ := row[2].(string)
	enabled, _ := row[3].(int64)
	revision, ok := row[4].(int64)
	if kind != "api_key" || revision < 1 || !ok {
		return registeredAPIKey{}, "", ErrCredentialNotFound
	}
	configJSON, ok := row[5].(string)
	if !ok {
		return registeredAPIKey{}, "", errCredential
	}
	var config APIKeyConnectorConfig
	if json.Unmarshal([]byte(configJSON), &config) != nil || config.ID != id {
		return registeredAPIKey{}, "", errCredential
	}
	connector, err := NewAPIKeyConnector(config)
	if err != nil {
		return registeredAPIKey{}, "", errCredential
	}
	return registeredAPIKey{ID: id, Revision: revision, Enabled: enabled != 0, Connector: connector}, generation, nil
}

func (s *CredentialStore) apiKeyProviderGuard(b credentialBinding, revision int64) (string, []any) {
	if revision <= 0 {
		return `EXISTS (SELECT 1 FROM auth_collection_definitions d WHERE d.id=? AND json_array_length(d.providers_json)=0)`, []any{b.CollectionID}
	}
	return `EXISTS (SELECT 1 FROM saas_providers p JOIN auth_collection_definitions d ON d.id=? WHERE p.id=? AND p.kind='api_key' AND p.deleted=0 AND p.enabled=1 AND p.revision=? AND json_array_length(d.providers_json)=1 AND json_extract(d.providers_json,'$[0]')=p.id)`, []any{b.CollectionID, b.ProviderID, revision}
}

// APIKeyConnector returns the current registered connector for owner consent.
// Legacy collections have no registered connector and return not-found.
func (s *CredentialStore) APIKeyConnector(ctx context.Context, owner, collection, connection string, authority func() (string, []any)) (*APIKeyConnector, error) {
	if ctx == nil || s == nil || s.db == nil || !validText(owner) || !validText(collection) || !validText(connection) {
		return nil, ErrCredentialNotFound
	}
	p, _, err := s.registeredAPIKeyInfo(ctx, owner, collection, connection, authority)
	if err != nil {
		return nil, err
	}
	if p.ID == "" || p.Connector == nil || !p.Enabled || p.Connector.id != p.ID {
		return nil, ErrCredentialNotFound
	}
	return p.Connector, nil
}
