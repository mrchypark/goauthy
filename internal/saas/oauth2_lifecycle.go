package saas

import (
	"context"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type OAuth2Status struct {
	Connected  bool     `json:"connected"`
	State      string   `json:"state"`
	Version    int64    `json:"version"`
	ProviderID string   `json:"provider_id"`
	AccountID  string   `json:"account_id"`
	Scopes     []string `json:"scopes"`
}

func (s *CredentialStore) OAuth2Status(ctx context.Context, owner, collection, connection string, authority func() (string, []any)) (OAuth2Status, error) {
	if ctx == nil || s == nil || s.db == nil || !validText(owner) || !validText(collection) || !validText(connection) {
		return OAuth2Status{}, ErrCredentialNotFound
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return OAuth2Status{}, err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT c.owner_subject,c.collection_id,c.id,c.generation,COALESCE(x.provider_id,''),COALESCE(x.token_version,0),COALESCE(x.state,'draft'),x.credential,COALESCE(x.generation,'') FROM auth_collection_connections c JOIN auth_collection_definitions d ON d.id=c.collection_id JOIN identity_users u ON u.subject=c.owner_subject LEFT JOIN saas_connection_credentials x ON x.connection_id=c.id WHERE c.owner_subject=? AND c.collection_id=? AND c.id=? AND d.auth_method='oauth2' AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?) AND (` + g + `)`, Args: append([]any{owner, collection, connection, s.now()}, ga...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return OAuth2Status{}, err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 9 {
		return OAuth2Status{}, ErrCredentialNotFound
	}
	row := q.Rows[0]
	bowner, ok := row[0].(string)
	if !ok {
		return OAuth2Status{}, errCredential
	}
	coll, ok := row[1].(string)
	if !ok {
		return OAuth2Status{}, errCredential
	}
	conn, ok := row[2].(string)
	if !ok {
		return OAuth2Status{}, errCredential
	}
	gen, ok := row[3].(string)
	if !ok {
		return OAuth2Status{}, errCredential
	}
	provider, ok := row[4].(string)
	if !ok {
		return OAuth2Status{}, errCredential
	}
	version, ok := row[5].(int64)
	if !ok {
		return OAuth2Status{}, errCredential
	}
	state, ok := row[6].(string)
	if !ok {
		return OAuth2Status{}, errCredential
	}
	status := OAuth2Status{State: state, Version: version, ProviderID: provider, Scopes: []string{}}
	if state != "draft" && state != "ready" && state != "refreshing" && state != "uncertain" && state != "revoked" {
		return OAuth2Status{}, errCredential
	}
	if version == 0 {
		return status, nil
	}
	credentialGeneration, ok := row[8].(string)
	if !ok {
		return OAuth2Status{}, errCredential
	}
	if credentialGeneration != gen && state == "revoked" {
		status.State = "reconnecting"
		return status, nil
	}
	env, ok := row[7].([]byte)
	if !ok {
		return OAuth2Status{}, errCredential
	}
	b := credentialBinding{Owner: bowner, CollectionID: coll, ConnectionID: conn, ProviderID: provider, Generation: gen, TokenVersion: version}
	value, err := openCredential(s.keys, b, env)
	if err != nil {
		return OAuth2Status{}, err
	}
	status.AccountID = value.AccountID
	status.Scopes = append([]string{}, value.Scopes...)
	status.Connected = state == "ready"
	return status, nil
}

// PrepareOAuth2Reconnect preserves the connection ID and metadata. A new
// generation fences old callbacks/refreshes; the old revoked ciphertext remains
// until a new authorization atomically replaces it at the next token version.
func (s *CredentialStore) PrepareOAuth2Reconnect(ctx context.Context, owner, collection, connection string, expectedVersion int64, authority func() (string, []any)) (OAuth2Status, error) {
	if ctx == nil || s == nil || s.db == nil || !validText(owner) || !validText(collection) || !validText(connection) || expectedVersion < 1 || expectedVersion == 1<<63-1 {
		return OAuth2Status{}, ErrCredentialConflict
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return OAuth2Status{}, err
	}
	generation := randomCredentialClaim()
	if generation == "" {
		return OAuth2Status{}, errCredential
	}
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "saas-oauth2-reconnect-" + generation, SQL: `UPDATE auth_collection_connections SET generation=?,revision=revision+1 WHERE id=? AND owner_subject=? AND collection_id=? AND revision<9223372036854775807 AND EXISTS(SELECT 1 FROM saas_connection_credentials x WHERE x.connection_id=auth_collection_connections.id AND x.owner_subject=auth_collection_connections.owner_subject AND x.collection_id=auth_collection_connections.collection_id AND x.generation=auth_collection_connections.generation AND x.token_version=? AND x.state='revoked') AND EXISTS(SELECT 1 FROM auth_collection_definitions d WHERE d.id=collection_id AND d.auth_method='oauth2' AND d.enabled=1 AND d.deleted=0) AND EXISTS(SELECT 1 FROM identity_users u WHERE u.subject=owner_subject AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?)) AND (` + g + `)`, Args: append([]any{generation, connection, owner, collection, expectedVersion, s.now()}, ga...)})
	if err != nil {
		return OAuth2Status{}, err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return OAuth2Status{}, ErrCredentialConflict
	}
	return s.OAuth2Status(ctx, owner, collection, connection, authority)
}

func (s *CredentialStore) RevokeOAuth2(ctx context.Context, owner, collection, connection string, expectedVersion int64, authority func() (string, []any)) error {
	if ctx == nil || s == nil || s.db == nil || !validText(owner) || !validText(collection) || !validText(connection) || expectedVersion < 1 {
		return ErrCredentialConflict
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return err
	}
	now := s.now()
	claim := randomCredentialClaim()
	if claim == "" {
		return errCredential
	}
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "saas-oauth2-revoke-" + claim, SQL: `UPDATE saas_connection_credentials SET state='revoked',refresh_claim=NULL WHERE connection_id=? AND owner_subject=? AND collection_id=? AND generation=(SELECT generation FROM auth_collection_connections WHERE id=? AND owner_subject=? AND collection_id=?) AND token_version=? AND state IN ('ready','refreshing','uncertain') AND EXISTS (SELECT 1 FROM auth_collection_connections c JOIN auth_collection_definitions d ON d.id=c.collection_id JOIN identity_users u ON u.subject=c.owner_subject WHERE c.id=? AND c.owner_subject=? AND c.collection_id=? AND d.auth_method='oauth2' AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?) AND (` + g + `))`, Args: append([]any{connection, owner, collection, connection, owner, collection, expectedVersion, connection, owner, collection, now}, ga...)})
	if err != nil {
		return err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return ErrCredentialConflict
	}
	return nil
}
