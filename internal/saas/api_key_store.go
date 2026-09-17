package saas

import (
	"context"
	"errors"
	"strings"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const apiKeyProviderID = "api-key"

var ErrInvalidAPIKey = errors.New("invalid SaaS API key input")

type APIKeyStatus struct {
	Registered bool  `json:"registered"`
	Version    int64 `json:"version"`
}

func (s *CredentialStore) apiKeyBinding(ctx context.Context, owner, collection, connection string, authority func() (string, []any)) (credentialBinding, error) {
	if ctx == nil || s == nil || s.db == nil || !validText(owner) || !validText(collection) || !validText(connection) {
		return credentialBinding{}, errCredential
	}
	p, generation, err := s.registeredAPIKeyInfo(ctx, owner, collection, connection, authority)
	if err != nil {
		return credentialBinding{}, err
	}
	providerID := apiKeyProviderID
	if p.ID != "" {
		providerID = p.ID
	}
	return credentialBinding{Owner: owner, CollectionID: collection, ConnectionID: connection, ProviderID: providerID, Generation: generation, TokenVersion: 1}, nil
}

func (s *CredentialStore) apiKeyParentGuard(b credentialBinding) (string, []any) {
	return `EXISTS (SELECT 1 FROM auth_collection_connections c JOIN auth_collection_definitions d ON d.id=c.collection_id JOIN identity_users u ON u.subject=c.owner_subject WHERE c.id=? AND c.owner_subject=? AND c.collection_id=? AND c.generation=? AND d.enabled=1 AND d.deleted=0 AND d.auth_method='api_key' AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?))`, []any{b.ConnectionID, b.Owner, b.CollectionID, b.Generation, s.now()}
}

func (s *CredentialStore) APIKeyStatus(ctx context.Context, owner, collection, connection string, authority func() (string, []any)) (APIKeyStatus, error) {
	b, err := s.apiKeyBinding(ctx, owner, collection, connection, authority)
	if err != nil {
		return APIKeyStatus{}, err
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return APIKeyStatus{}, err
	}
	parent, pa := s.apiKeyParentGuard(b)
	args := []any{b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation}
	args = append(args, pa...)
	args = append(args, ga...)
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT token_version,state FROM saas_connection_credentials WHERE connection_id=? AND owner_subject=? AND collection_id=? AND provider_id=? AND generation=? AND ` + parent + ` AND ` + g, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return APIKeyStatus{}, err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 2 {
		return APIKeyStatus{}, nil
	}
	version, vok := q.Rows[0][0].(int64)
	state, sok := q.Rows[0][1].(string)
	if !vok || !sok || version < 1 || (state != "ready" && state != "revoked") {
		return APIKeyStatus{}, errCredential
	}
	return APIKeyStatus{Registered: state == "ready", Version: version}, nil
}

func validateAPIKey(key string) bool {
	return key != "" && len(key) <= 2048 && strings.TrimSpace(key) == key && !strings.ContainsAny(key, "\x00\r\n")
}

func (s *CredentialStore) PutAPIKey(ctx context.Context, owner, collection, connection string, expectedVersion int64, key string, authority func() (string, []any)) (APIKeyStatus, error) {
	return s.putAPIKey(ctx, owner, collection, connection, expectedVersion, key, "", "", authority)
}

func (s *CredentialStore) PutBoundAPIKey(ctx context.Context, owner, collection, connection string, expectedVersion int64, key string, connector *APIKeyConnector, consentDigest string, authority func() (string, []any)) (APIKeyStatus, error) {
	if connector == nil || consentDigest == "" || consentDigest != connector.Digest() || !validAuthorizationDigest(consentDigest) {
		return APIKeyStatus{}, ErrInvalidAPIKey
	}
	return s.putAPIKey(ctx, owner, collection, connection, expectedVersion, key, consentDigest, connector.id, authority)
}

func (s *CredentialStore) putAPIKey(ctx context.Context, owner, collection, connection string, expectedVersion int64, key string, digest, connectorID string, authority func() (string, []any)) (APIKeyStatus, error) {
	if expectedVersion < 0 || expectedVersion == 1<<63-1 || !validateAPIKey(key) {
		return APIKeyStatus{}, ErrInvalidAPIKey
	}
	info, generation, err := s.registeredAPIKeyInfo(ctx, owner, collection, connection, authority)
	if err != nil {
		return APIKeyStatus{}, err
	}
	if info.ID != "" {
		if digest == "" || connectorID != info.ID || info.Connector == nil || digest != info.Connector.Digest() || !info.Enabled {
			return APIKeyStatus{}, ErrCredentialConflict
		}
	}
	providerID := apiKeyProviderID
	if info.ID != "" {
		providerID = info.ID
	}
	b := credentialBinding{Owner: owner, CollectionID: collection, ConnectionID: connection, ProviderID: providerID, Generation: generation, TokenVersion: 1}
	// Legacy rotation must not silently change the consent contract. A concurrent
	// binding update is still rejected by the token-version CAS below.
	if expectedVersion > 0 && digest == "" {
		_, current, err := s.loadAPIKey(ctx, owner, collection, connection, authority)
		if err != nil {
			if errors.Is(err, ErrCredentialNotFound) {
				return APIKeyStatus{}, ErrCredentialConflict
			}
			return APIKeyStatus{}, err
		}
		if current.ConnectorDigest != "" {
			return APIKeyStatus{}, ErrCredentialConflict
		}
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return APIKeyStatus{}, err
	}
	parent, pa := s.apiKeyParentGuard(b)
	provider, ppa := s.apiKeyProviderGuard(b, info.Revision)
	version := int64(1)
	if expectedVersion > 0 {
		version = expectedVersion + 1
	}
	b.TokenVersion = version
	value := credential{APIKey: key, ConnectorDigest: digest}
	envelope, err := sealCredential(s.keys, b, value)
	if err != nil {
		return APIKeyStatus{}, err
	}
	var sql string
	var args []any
	if expectedVersion == 0 {
		args = []any{b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation, version, "ready", envelope}
		args = append(args, pa...)
		args = append(args, ppa...)
		args = append(args, b.ConnectionID)
		args = append(args, ga...)
		sql = `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential) SELECT ?,?,?,?,?,?,?,? WHERE ` + parent + ` AND ` + provider + ` AND NOT EXISTS(SELECT 1 FROM saas_connection_credentials WHERE connection_id=? ) AND (` + g + `)`
	} else {
		args = []any{envelope, version, b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation, expectedVersion}
		args = append(args, pa...)
		args = append(args, ppa...)
		args = append(args, ga...)
		sql = `UPDATE saas_connection_credentials SET credential=?,token_version=? WHERE connection_id=? AND owner_subject=? AND collection_id=? AND provider_id=? AND generation=? AND token_version=? AND state='ready' AND ` + parent + ` AND ` + provider + ` AND ` + g
	}
	r, err := s.executeEnvelope(ctx, "saas-api-key-put", sql, args)
	if err != nil {
		return APIKeyStatus{}, err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return APIKeyStatus{}, ErrCredentialConflict
	}
	return APIKeyStatus{Registered: true, Version: version}, nil
}

func (s *CredentialStore) RevokeAPIKey(ctx context.Context, owner, collection, connection string, expectedVersion int64, authority func() (string, []any)) error {
	if expectedVersion < 1 {
		return ErrInvalidAPIKey
	}
	b, err := s.apiKeyBinding(ctx, owner, collection, connection, authority)
	if err != nil {
		return err
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return err
	}
	parent, pa := s.apiKeyParentGuard(b)
	requestEntropy := randomCredentialClaim()
	if requestEntropy == "" {
		return errCredential
	}
	args := []any{b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation, expectedVersion}
	args = append(args, pa...)
	args = append(args, ga...)
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "saas-api-key-revoke-" + requestEntropy, SQL: `UPDATE saas_connection_credentials SET state='revoked',refresh_claim=NULL WHERE connection_id=? AND owner_subject=? AND collection_id=? AND provider_id=? AND generation=? AND token_version=? AND state='ready' AND ` + parent + ` AND ` + g, Args: args})
	if err != nil {
		return err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return ErrCredentialConflict
	}
	return nil
}
