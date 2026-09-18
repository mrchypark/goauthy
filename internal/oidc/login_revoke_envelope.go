package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// LoginRevokeCodePurpose binds a recoverable code to one user's revoke generation.
func LoginRevokeCodePurpose(subject, generation string) string {
	digest := sha256.Sum256([]byte(subject + "\x00" + generation))
	return "login-revoke/" + base64.RawURLEncoding.EncodeToString(digest[:])
}

// RewrapLoginRevokeCodeBatch re-encrypts at most 32 shared login-revoke codes
// under the active master key, preserving each code and generation binding.
func RewrapLoginRevokeCodeBatch(ctx context.Context, db *rhiza.DB, keyring *Keyring, cursor string) (SigningKeyRewrapBatchResult, error) {
	if db == nil || keyring == nil {
		return SigningKeyRewrapBatchResult{}, errors.New("login-revoke rewrap is not configured")
	}
	active, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	exists, err := loginRevokeTableExists(ctx, db)
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	if !exists {
		return SigningKeyRewrapBatchResult{Cursor: cursor, Done: true}, nil
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,generation,code_envelope FROM identity_login_revoke WHERE subject > ? ORDER BY subject LIMIT 32`, Args: []any{cursor}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	if len(result.Rows) == 0 {
		return SigningKeyRewrapBatchResult{Cursor: cursor, Done: true}, nil
	}
	last := cursor
	changed := int64(0)
	for _, row := range result.Rows {
		if len(row) != 3 {
			return SigningKeyRewrapBatchResult{}, errors.New("invalid login-revoke envelope row")
		}
		subject, subjectOK := row[0].(string)
		generation, generationOK := row[1].(string)
		envelope, envelopeOK := loginRevokeEnvelopeBytes(row[2])
		if !subjectOK || !generationOK || !envelopeOK || subject == "" || generation == "" || len(envelope) == 0 {
			return SigningKeyRewrapBatchResult{}, errors.New("invalid login-revoke envelope row")
		}
		last = subject
		purpose := LoginRevokeCodePurpose(subject, generation)
		keyID, err := keyring.PurposeEnvelopeKeyID(purpose, envelope)
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		if keyID == active {
			continue
		}
		plain, err := keyring.OpenEnvelope(purpose, envelope)
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		replacement, err := keyring.SealEnvelope(purpose, plain)
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		digest := sha256.Sum256(append(append([]byte(subject+"\x00"+generation+"\x00"), envelope...), replacement...))
		response, err := storage.ExecuteEnvelope(ctx, db, active, rhiza.ExecuteRequest{
			RequestID: "login-revoke-rewrap/" + base64.RawURLEncoding.EncodeToString(digest[:16]),
			SQL:       `UPDATE identity_login_revoke SET code_envelope=? WHERE subject=? AND generation=? AND code_envelope=?`,
			Args:      []any{replacement, subject, generation, envelope},
		})
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		changed += response.RowsAffected
	}
	return SigningKeyRewrapBatchResult{Cursor: last, Rewrapped: int(changed), Done: len(result.Rows) < 32}, nil
}

func loginRevokeTableExists(ctx context.Context, db *rhiza.DB) (bool, error) {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='identity_login_revoke')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return false, errors.New("invalid login-revoke table inspection")
	}
	exists, ok := result.Rows[0][0].(int64)
	if !ok || (exists != 0 && exists != 1) {
		return false, errors.New("invalid login-revoke table inspection")
	}
	return exists == 1, nil
}

func loginRevokeEnvelopeBytes(value any) ([]byte, bool) {
	switch value := value.(type) {
	case []byte:
		return value, true
	case string:
		return []byte(value), true
	default:
		return nil, false
	}
}
