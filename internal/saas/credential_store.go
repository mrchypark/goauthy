package saas

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrCredentialNotFound     = errors.New("saas credential not found")
	ErrCredentialConflict     = errors.New("saas credential conflict")
	ErrCredentialUnauthorized = errors.New("saas credential unauthorized")
)

type CredentialStore struct {
	db   *rhiza.DB
	keys *oidc.Keyring
	now  func() int64
}

func NewCredentialStore(db *rhiza.DB, keys *oidc.Keyring) (*CredentialStore, error) {
	if db == nil || keys == nil {
		return nil, errCredential
	}
	if _, err := keys.ActiveMasterKeyID(); err != nil {
		return nil, err
	}
	return &CredentialStore{db: db, keys: keys, now: func() int64 { return time.Now().UTC().UnixMilli() }}, nil
}

func validBinding(b credentialBinding) bool {
	return validText(b.Owner) && validText(b.CollectionID) && validText(b.ConnectionID) && validText(b.ProviderID) && validText(b.Generation) && b.TokenVersion >= 1
}

func authorityGuard(authority func() (string, []any)) (string, []any, error) {
	if authority == nil {
		return "", nil, ErrCredentialUnauthorized
	}
	g, args := authority()
	if strings.TrimSpace(g) == "" {
		return "", nil, ErrCredentialUnauthorized
	}
	return "(" + g + ")", args, nil
}

func (s *CredentialStore) parentGuard(b credentialBinding) (string, []any) {
	return `EXISTS (SELECT 1 FROM auth_collection_connections c
		JOIN auth_collection_definitions d ON d.id=c.collection_id
		JOIN identity_users u ON u.subject=c.owner_subject
		WHERE c.id=? AND c.owner_subject=? AND c.collection_id=? AND c.generation=?
		AND d.enabled=1 AND d.deleted=0 AND d.auth_method='oauth2'
		AND EXISTS(SELECT 1 FROM json_each(d.providers_json) p WHERE p.type='text' AND p.value=?)
		AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?))`, []any{b.ConnectionID, b.Owner, b.CollectionID, b.Generation, b.ProviderID, s.now()}
}

func (s *CredentialStore) Install(ctx context.Context, b credentialBinding, value credential, authority func() (string, []any)) error {
	if s == nil || !validBinding(b) {
		return errCredential
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return err
	}
	parent, pa := s.parentGuard(b)
	envelope, err := sealCredential(s.keys, b, value)
	if err != nil {
		return err
	}
	args := []any{b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation, b.TokenVersion, "ready", envelope}
	args = append(args, pa...)
	args = append(args, ga...)
	args = append(args, b.TokenVersion, b.ConnectionID, b.ConnectionID, b.Owner, b.CollectionID, b.Generation, b.TokenVersion-1)
	r, err := s.executeEnvelope(ctx, "saas-credential-install", `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential)
		SELECT ?,?,?,?,?,?,?,? WHERE `+parent+` AND (`+g+`) AND ((?=1 AND NOT EXISTS(SELECT 1 FROM saas_connection_credentials old0 WHERE old0.connection_id=?)) OR EXISTS(SELECT 1 FROM saas_connection_credentials old WHERE old.connection_id=? AND old.owner_subject=? AND old.collection_id=? AND old.state='revoked' AND old.generation<>? AND old.token_version=?)) ON CONFLICT(connection_id) DO UPDATE SET owner_subject=excluded.owner_subject,collection_id=excluded.collection_id,provider_id=excluded.provider_id,generation=excluded.generation,token_version=excluded.token_version,state=excluded.state,credential=excluded.credential,refresh_claim=NULL WHERE saas_connection_credentials.state='revoked' AND saas_connection_credentials.owner_subject=excluded.owner_subject AND saas_connection_credentials.collection_id=excluded.collection_id AND saas_connection_credentials.generation<>excluded.generation AND saas_connection_credentials.token_version+1=excluded.token_version`, args)
	if err != nil {
		return err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return ErrCredentialConflict
	}
	return nil
}

func (s *CredentialStore) Load(ctx context.Context, b credentialBinding, authority func() (string, []any)) (credential, error) {
	if s == nil || !validBinding(b) {
		return credential{}, errCredential
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return credential{}, err
	}
	parent, pa := s.parentGuard(b)
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials WHERE connection_id=? AND owner_subject=? AND collection_id=? AND provider_id=? AND generation=? AND token_version=? AND state='ready' AND ` + parent + ` AND ` + g, Args: append([]any{b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation, b.TokenVersion}, append(pa, ga...)...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return credential{}, err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 1 {
		return credential{}, ErrCredentialNotFound
	}
	env, ok := q.Rows[0][0].([]byte)
	if !ok {
		return credential{}, errCredential
	}
	return openCredential(s.keys, b, env)
}

func (s *CredentialStore) ClaimRefresh(ctx context.Context, b credentialBinding, authority func() (string, []any)) (string, error) {
	if s == nil || !validBinding(b) {
		return "", errCredential
	}
	claim := randomCredentialClaim()
	if claim == "" {
		return "", errCredential
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return "", err
	}
	parent, pa := s.parentGuard(b)
	args := []any{"refreshing", claim, b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation, b.TokenVersion}
	args = append(args, pa...)
	args = append(args, ga...)
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "saas-credential-claim-" + claim, SQL: `UPDATE saas_connection_credentials SET state=?,refresh_claim=? WHERE connection_id=? AND owner_subject=? AND collection_id=? AND provider_id=? AND generation=? AND token_version=? AND state='ready' AND ` + parent + ` AND ` + g, Args: args})
	if err != nil {
		return "", err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return "", ErrCredentialConflict
	}
	return claim, nil
}

func (s *CredentialStore) CompleteRefresh(ctx context.Context, b credentialBinding, claim string, value credential, authority func() (string, []any)) error {
	if ctx == nil || s == nil || s.db == nil || !validBinding(b) || claim == "" {
		return errCredential
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return err
	}
	parent, pa := s.parentGuard(b)
	// Refresh rotates tokens within one authorized account. A different account
	// requires reconnect (new generation), not silent reuse of existing consent.
	current, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials WHERE connection_id=? AND owner_subject=? AND collection_id=? AND provider_id=? AND generation=? AND token_version=? AND refresh_claim=? AND state='refreshing' AND ` + parent + ` AND (` + g + `)`, Args: append([]any{b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation, b.TokenVersion, claim}, append(pa, ga...)...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(current.Rows) != 1 || len(current.Rows[0]) != 1 {
		return ErrCredentialConflict
	}
	ciphertext, ok := current.Rows[0][0].([]byte)
	if !ok {
		return errCredential
	}
	previous, err := openCredential(s.keys, b, ciphertext)
	if err != nil {
		return err
	}
	if previous.AccountID != value.AccountID {
		return ErrCredentialConflict
	}
	if len(value.Scopes) > 64 {
		return errCredential
	}
	for i, scope := range value.Scopes {
		if !oauthScopeToken(scope) || !slices.Contains(previous.Scopes, scope) || slices.Contains(value.Scopes[:i], scope) {
			return ErrCredentialConflict
		}
	}
	next := b
	next.TokenVersion++
	envelope, err := sealCredential(s.keys, next, value)
	if err != nil {
		return err
	}
	// Rebuild time-sensitive caller and parent authority after the read/decrypt.
	g, ga, err = authorityGuard(authority)
	if err != nil {
		return err
	}
	parent, pa = s.parentGuard(b)
	args := []any{envelope, next.TokenVersion, b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation, b.TokenVersion, claim}
	args = append(args, pa...)
	args = append(args, ga...)
	r, err := s.executeEnvelope(ctx, "saas-credential-complete", `UPDATE saas_connection_credentials SET credential=?,token_version=?,state='ready',refresh_claim=NULL WHERE connection_id=? AND owner_subject=? AND collection_id=? AND provider_id=? AND generation=? AND token_version=? AND refresh_claim=? AND state='refreshing' AND `+parent+` AND `+g, args)
	if err != nil {
		return err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return ErrCredentialConflict
	}
	return nil
}

func (s *CredentialStore) MarkRefreshUncertain(ctx context.Context, b credentialBinding, claim string) error {
	if s == nil || !validBinding(b) || claim == "" {
		return errCredential
	}
	parent, pa := s.parentGuard(b)
	args := []any{b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation, b.TokenVersion, claim}
	args = append(args, pa...)
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "saas-credential-uncertain-" + claim, SQL: `UPDATE saas_connection_credentials SET state='uncertain',refresh_claim=NULL WHERE connection_id=? AND owner_subject=? AND collection_id=? AND provider_id=? AND generation=? AND token_version=? AND refresh_claim=? AND state='refreshing' AND ` + parent, Args: args})
	if err != nil {
		return err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return ErrCredentialConflict
	}
	return nil
}

func (s *CredentialStore) Revoke(ctx context.Context, b credentialBinding, authority func() (string, []any)) error {
	if s == nil || !validBinding(b) {
		return errCredential
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return err
	}
	parent, pa := s.parentGuard(b)
	requestEntropy := randomCredentialClaim()
	if requestEntropy == "" {
		return errCredential
	}
	args := []any{b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation, b.TokenVersion}
	args = append(args, pa...)
	args = append(args, ga...)
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "saas-credential-revoke-" + requestEntropy, SQL: `UPDATE saas_connection_credentials SET state='revoked',refresh_claim=NULL WHERE connection_id=? AND owner_subject=? AND collection_id=? AND provider_id=? AND generation=? AND token_version=? AND ` + parent + ` AND ` + g, Args: args})
	if err != nil {
		return err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return ErrCredentialConflict
	}
	return nil
}

func (s *CredentialStore) executeEnvelope(ctx context.Context, id, sql string, args []any) (rhiza.ExecuteResponse, error) {
	requestEntropy := randomCredentialClaim()
	if requestEntropy == "" {
		return rhiza.ExecuteResponse{}, errCredential
	}
	key, err := s.keys.ActiveMasterKeyID()
	if err != nil {
		return rhiza.ExecuteResponse{}, err
	}
	return storage.ExecuteEnvelope(ctx, s.db, key, rhiza.ExecuteRequest{RequestID: id + "-" + requestEntropy, SQL: sql, Args: args})
}

func randomCredentialClaim() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
