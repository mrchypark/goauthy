package saas

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const authorizationVerifierBatchSize = 32

type authorizationVerifier struct {
	Verifier                                                   string `json:"verifier"`
	Owner, CollectionID, ConnectionID, ProviderID, Generation  string
	TokenVersion                                               int64
	StateDigest, VerifierDigest, SessionDigest, ProviderDigest string
	ExpiresAtUnixMS                                            int64
}

func (authorizationVerifier) String() string   { return "[redacted SaaS authorization verifier]" }
func (authorizationVerifier) GoString() string { return "[redacted SaaS authorization verifier]" }

func authorizationVerifierPurpose(stateDigest string) string { return "saas/proof/v1/" + stateDigest }

func sealAuthorizationVerifier(keys *oidc.Keyring, request authorizationRequest) ([]byte, error) {
	if keys == nil || !validAuthorizationDigest(request.StateDigest) || !validVerifier(request.Verifier) {
		return nil, errAuthorization
	}
	plain, err := json.Marshal(authorizationVerifier{Verifier: request.Verifier,
		Owner: request.Binding.Owner, CollectionID: request.Binding.CollectionID, ConnectionID: request.Binding.ConnectionID, ProviderID: request.Binding.ProviderID, Generation: request.Binding.Generation, TokenVersion: request.Binding.TokenVersion,
		StateDigest: request.StateDigest, VerifierDigest: request.VerifierDigest, SessionDigest: request.SessionDigest, ProviderDigest: request.ProviderDigest, ExpiresAtUnixMS: request.ExpiresAtUnixMS})
	if err != nil {
		return nil, errAuthorization
	}
	defer clear(plain)
	return keys.SealEnvelope(authorizationVerifierPurpose(request.StateDigest), plain)
}

func openAuthorizationVerifier(keys *oidc.Keyring, stateDigest string, envelope []byte) (authorizationVerifier, error) {
	if keys == nil || !validAuthorizationDigest(stateDigest) || len(envelope) == 0 {
		return authorizationVerifier{}, errAuthorization
	}
	plain, err := keys.OpenEnvelope(authorizationVerifierPurpose(stateDigest), envelope)
	if err != nil {
		return authorizationVerifier{}, errAuthorization
	}
	defer clear(plain)
	var value authorizationVerifier
	if err := json.Unmarshal(plain, &value); err != nil || !validVerifier(value.Verifier) {
		return authorizationVerifier{}, errAuthorization
	}
	return value, nil
}

func (s *CredentialStore) loadAuthorizationVerifier(ctx context.Context, stateDigest, sessionDigest, providerDigest string, authority func() (string, []any)) (credentialBinding, string, error) {
	if ctx == nil || s == nil || s.db == nil || !validAuthorizationDigest(stateDigest) || !validAuthorizationDigest(sessionDigest) || !validAuthorizationDigest(providerDigest) {
		return credentialBinding{}, "", errAuthorization
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return credentialBinding{}, "", err
	}
	now := s.now()
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT owner_subject,collection_id,connection_id,provider_id,generation,verifier_digest,session_digest,provider_digest,state_digest,token_version,expires_at_unix_ms,verifier_envelope FROM saas_authorization_requests WHERE state_digest=? AND session_digest=? AND provider_digest=? AND invalidated=0 AND consumed_at_unix_ms IS NULL AND expires_at_unix_ms>? AND verifier_envelope IS NOT NULL AND ` + g, Args: append([]any{stateDigest, sessionDigest, providerDigest, now}, ga...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return credentialBinding{}, "", err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 12 {
		return credentialBinding{}, "", ErrAuthorizationNotFound
	}
	row := q.Rows[0]
	b, ok := decodeAuthorizationBinding([]any{row[0], row[1], row[2], row[3], row[4], row[9]})
	if !ok {
		return credentialBinding{}, "", errAuthorization
	}
	digest, ok := row[5].(string)
	if !ok || !validAuthorizationDigest(digest) {
		return credentialBinding{}, "", errAuthorization
	}
	envelope, ok := row[11].([]byte)
	if !ok {
		return credentialBinding{}, "", errAuthorization
	}
	payload, err := openAuthorizationVerifier(s.keys, stateDigest, envelope)
	if err != nil || authorizationDigest(payload.Verifier) != digest || payload.VerifierDigest != digest || payload.StateDigest != row[8] || payload.SessionDigest != row[6] || payload.ProviderDigest != row[7] || payload.Owner != b.Owner || payload.CollectionID != b.CollectionID || payload.ConnectionID != b.ConnectionID || payload.ProviderID != b.ProviderID || payload.Generation != b.Generation || payload.TokenVersion != b.TokenVersion || payload.TokenVersion != row[9] {
		return credentialBinding{}, "", errAuthorization
	}
	expires, ok := row[10].(int64)
	if !ok || payload.ExpiresAtUnixMS != expires {
		return credentialBinding{}, "", errAuthorization
	}
	parent, pa := s.parentGuard(b)
	args := append([]any{}, pa...)
	args = append(args, ga...)
	p, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 WHERE ` + parent + ` AND (` + g + `)`, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return credentialBinding{}, "", err
	}
	if len(p.Rows) != 1 {
		return credentialBinding{}, "", ErrAuthorizationNotFound
	}
	return b, payload.Verifier, nil
}

func InspectAuthorizationEnvelopeReferences(ctx context.Context, db *rhiza.DB, keys *oidc.Keyring) (oidc.MasterKeyReferenceFamily, error) {
	family := oidc.MasterKeyReferenceFamily{ByKeyID: map[string]int64{}}
	if ctx == nil || db == nil || keys == nil {
		return family, errors.New("invalid SaaS authorization reference scan")
	}
	cursor := ""
	for {
		q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state_digest,verifier_envelope FROM saas_authorization_requests WHERE state_digest>? AND verifier_envelope IS NOT NULL ORDER BY state_digest LIMIT ?`, Args: []any{cursor, int64(authorizationVerifierBatchSize)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return oidc.MasterKeyReferenceFamily{}, err
		}
		for _, row := range q.Rows {
			if len(row) != 2 {
				return oidc.MasterKeyReferenceFamily{}, errors.New("invalid SaaS authorization row")
			}
			state, ok := row[0].(string)
			env, ok2 := row[1].([]byte)
			if !ok || !ok2 || !validAuthorizationDigest(state) || len(env) == 0 {
				return oidc.MasterKeyReferenceFamily{}, errors.New("invalid SaaS authorization envelope")
			}
			kid, e := keys.PurposeEnvelopeKeyID(authorizationVerifierPurpose(state), env)
			if e != nil {
				return oidc.MasterKeyReferenceFamily{}, e
			}
			family.ByKeyID[kid]++
			family.Total++
			cursor = state
		}
		if len(q.Rows) < authorizationVerifierBatchSize {
			return family, nil
		}
	}
}

func RewrapAuthorizationEnvelopeBatch(ctx context.Context, db *rhiza.DB, keys *oidc.Keyring, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
	if ctx == nil || db == nil || keys == nil {
		return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid SaaS authorization rewrap")
	}
	if cursor != "" && !validAuthorizationDigest(cursor) {
		return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid SaaS authorization cursor")
	}
	active, err := keys.ActiveMasterKeyID()
	if err != nil {
		return oidc.SigningKeyRewrapBatchResult{}, err
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state_digest,verifier_envelope FROM saas_authorization_requests WHERE state_digest>? AND verifier_envelope IS NOT NULL ORDER BY state_digest LIMIT ?`, Args: []any{cursor, int64(authorizationVerifierBatchSize)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return oidc.SigningKeyRewrapBatchResult{}, err
	}
	if len(q.Rows) == 0 {
		return oidc.SigningKeyRewrapBatchResult{Cursor: cursor, Done: true}, nil
	}
	last := cursor
	sql := "UPDATE saas_authorization_requests SET verifier_envelope=CASE state_digest "
	args := []any{}
	states := []string{}
	old := [][]byte{}
	for _, row := range q.Rows {
		if len(row) != 2 {
			return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid SaaS authorization row")
		}
		state, ok := row[0].(string)
		env, ok2 := row[1].([]byte)
		if !ok || !ok2 || !validAuthorizationDigest(state) || len(env) == 0 {
			return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid SaaS authorization envelope")
		}
		replacement, e := keys.RewrapEnvelope(authorizationVerifierPurpose(state), env)
		if e != nil {
			return oidc.SigningKeyRewrapBatchResult{}, e
		}
		sql += "WHEN ? THEN ? "
		args = append(args, state, replacement)
		states = append(states, state)
		old = append(old, env)
		last = state
	}
	sql += "ELSE verifier_envelope END WHERE state_digest IN ("
	for i, state := range states {
		if i > 0 {
			sql += ","
		}
		sql += "?"
		args = append(args, state)
	}
	sql += ") AND (SELECT COUNT(*) FROM saas_authorization_requests WHERE "
	for i, state := range states {
		if i > 0 {
			sql += " OR "
		}
		sql += "(state_digest=? AND verifier_envelope=?)"
		args = append(args, state, old[i])
	}
	sql += ") = ?"
	args = append(args, int64(len(states)))
	requestID := randomCredentialClaim()
	if requestID == "" {
		return oidc.SigningKeyRewrapBatchResult{}, errAuthorization
	}
	resp, err := storage.ExecuteEnvelope(ctx, db, active, rhiza.ExecuteRequest{RequestID: "saas-authorization-rewrap-" + requestID, SQL: sql, Args: args})
	if err != nil {
		return oidc.SigningKeyRewrapBatchResult{}, err
	}
	if resp.Status != "committed" {
		return oidc.SigningKeyRewrapBatchResult{}, errors.New("SaaS authorization rewrap was not committed")
	}
	changed := resp.MutationReceipt.RowsAffected
	if changed != 0 && changed != int64(len(states)) {
		return oidc.SigningKeyRewrapBatchResult{}, errors.New("SaaS authorization rewrap changed a partial batch")
	}
	return oidc.SigningKeyRewrapBatchResult{Cursor: last, Rewrapped: int(changed), Done: len(q.Rows) < authorizationVerifierBatchSize}, nil
}
