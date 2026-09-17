package saas

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrAuthorizationNotFound = errors.New("saas authorization request not found")
	ErrAuthorizationConflict = errors.New("saas authorization request conflict")
)

const maxAuthorizationTTLMS int64 = 10 * 60 * 1000

type authorizationRequest struct {
	Binding                                                    credentialBinding
	StateDigest, VerifierDigest, SessionDigest, ProviderDigest string
	Verifier                                                   string
	ExpiresAtUnixMS                                            int64
}

func (s *CredentialStore) CreateAuthorization(ctx context.Context, request authorizationRequest, authority func() (string, []any)) error {
	now := int64(0)
	if s != nil {
		now = s.now()
	}
	if ctx == nil || s == nil || s.db == nil || !validAuthorizationRequest(request) || request.ExpiresAtUnixMS <= now || request.ExpiresAtUnixMS > now+maxAuthorizationTTLMS {
		return errAuthorization
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return err
	}
	parent, pa := s.parentGuard(request.Binding)
	requestID := randomCredentialClaim()
	if requestID == "" {
		return errAuthorization
	}
	args := []any{request.StateDigest, request.VerifierDigest, request.SessionDigest, request.ProviderDigest, request.Binding.Owner, request.Binding.CollectionID, request.Binding.ConnectionID, request.Binding.ProviderID, request.Binding.Generation, request.Binding.TokenVersion, now, request.ExpiresAtUnixMS}
	var verifierEnvelope any
	if request.Verifier != "" {
		var sealErr error
		sealed, sealErr := sealAuthorizationVerifier(s.keys, request)
		if sealErr != nil {
			return sealErr
		}
		verifierEnvelope = sealed
	}
	args = append(args, verifierEnvelope)
	args = append(args, pa...)
	args = append(args, ga...)
	args = append(args, request.Binding.TokenVersion, request.Binding.ConnectionID, request.Binding.ConnectionID, request.Binding.Owner, request.Binding.CollectionID, request.Binding.Generation, request.Binding.TokenVersion-1)
	statement := rhiza.ExecuteRequest{RequestID: requestID, SQL: `INSERT INTO saas_authorization_requests(state_digest,verifier_digest,session_digest,provider_digest,owner_subject,collection_id,connection_id,provider_id,generation,token_version,created_at_unix_ms,expires_at_unix_ms,verifier_envelope)
		SELECT ?,?,?,?,?,?,?,?,?,?,?,?,? WHERE ` + parent + ` AND (` + g + `) AND ((?=1 AND NOT EXISTS(SELECT 1 FROM saas_connection_credentials old0 WHERE old0.connection_id=?)) OR EXISTS(SELECT 1 FROM saas_connection_credentials old WHERE old.connection_id=? AND old.owner_subject=? AND old.collection_id=? AND old.state='revoked' AND old.generation<>? AND old.token_version=?))`, Args: args}
	var r rhiza.ExecuteResponse
	if request.Verifier != "" {
		r, err = s.executeEnvelope(ctx, "saas-authorization-create", statement.SQL, statement.Args)
	} else {
		r, err = storage.Execute(ctx, s.db, statement)
	}
	if err != nil {
		return err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return ErrAuthorizationConflict
	}
	return nil
}

func (s *CredentialStore) ConsumeAuthorization(ctx context.Context, stateDigest, verifierDigest, sessionDigest, providerDigest string, authority func() (string, []any)) (credentialBinding, error) {
	if ctx == nil || s == nil || s.db == nil || !validAuthorizationDigest(stateDigest) || !validAuthorizationDigest(verifierDigest) || !validAuthorizationDigest(sessionDigest) || !validAuthorizationDigest(providerDigest) {
		return credentialBinding{}, errAuthorization
	}
	g, ga, err := authorityGuard(authority)
	if err != nil {
		return credentialBinding{}, err
	}
	now := s.now()
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT owner_subject,collection_id,connection_id,provider_id,generation,token_version FROM saas_authorization_requests WHERE state_digest=? AND verifier_digest=? AND session_digest=? AND provider_digest=? AND invalidated=0 AND consumed_at_unix_ms IS NULL AND expires_at_unix_ms>? AND ` + g, Args: append([]any{stateDigest, verifierDigest, sessionDigest, providerDigest, now}, ga...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return credentialBinding{}, err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 6 {
		return credentialBinding{}, ErrAuthorizationNotFound
	}
	b, ok := decodeAuthorizationBinding(q.Rows[0])
	if !ok {
		return credentialBinding{}, errAuthorization
	}
	parent, pa := s.parentGuard(b)
	requestID := randomCredentialClaim()
	if requestID == "" {
		return credentialBinding{}, errAuthorization
	}
	commitNow := s.now()
	args := []any{commitNow, stateDigest, verifierDigest, sessionDigest, providerDigest, commitNow, b.Owner, b.CollectionID, b.ConnectionID, b.ProviderID, b.Generation, b.TokenVersion}
	args = append(args, pa...)
	args = append(args, ga...)
	args = append(args, b.TokenVersion, b.ConnectionID, b.ConnectionID, b.Owner, b.CollectionID, b.Generation, b.TokenVersion-1)
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "saas-authorization-consume-" + requestID, SQL: `UPDATE saas_authorization_requests SET consumed_at_unix_ms=? WHERE state_digest=? AND verifier_digest=? AND session_digest=? AND provider_digest=? AND invalidated=0 AND consumed_at_unix_ms IS NULL AND expires_at_unix_ms>? AND owner_subject=? AND collection_id=? AND connection_id=? AND provider_id=? AND generation=? AND token_version=? AND ` + parent + ` AND (` + g + `) AND ((?=1 AND NOT EXISTS(SELECT 1 FROM saas_connection_credentials old0 WHERE old0.connection_id=?)) OR EXISTS(SELECT 1 FROM saas_connection_credentials old WHERE old.connection_id=? AND old.owner_subject=? AND old.collection_id=? AND old.state='revoked' AND old.generation<>? AND old.token_version=?))`, Args: args})
	if err != nil {
		return credentialBinding{}, err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return credentialBinding{}, ErrAuthorizationNotFound
	}
	return b, nil
}

var errAuthorization = errors.New("saas authorization request invalid")

func validAuthorizationRequest(r authorizationRequest) bool {
	if !validBinding(r.Binding) || !validAuthorizationDigest(r.StateDigest) || !validAuthorizationDigest(r.VerifierDigest) || !validAuthorizationDigest(r.SessionDigest) || !validAuthorizationDigest(r.ProviderDigest) {
		return false
	}
	return r.Verifier == "" || (validVerifier(r.Verifier) && authorizationDigest(r.Verifier) == r.VerifierDigest)
}

func validAuthorizationDigest(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func decodeAuthorizationBinding(row []any) (credentialBinding, bool) {
	if len(row) != 5 && len(row) != 6 {
		return credentialBinding{}, false
	}
	owner, a := row[0].(string)
	collection, b := row[1].(string)
	connection, c := row[2].(string)
	provider, d := row[3].(string)
	generation, e := row[4].(string)
	if !a || !b || !c || !d || !e {
		return credentialBinding{}, false
	}
	version := int64(1)
	if len(row) == 6 {
		version, e = row[5].(int64)
		if !e {
			return credentialBinding{}, false
		}
	}
	binding := credentialBinding{Owner: owner, CollectionID: collection, ConnectionID: connection, ProviderID: provider, Generation: generation, TokenVersion: version}
	return binding, validBinding(binding)
}
