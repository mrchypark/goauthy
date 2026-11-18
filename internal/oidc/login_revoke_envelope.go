package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

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
	return rewrapEnvelopeBatch(
		ctx,
		db,
		keyring,
		cursor,
		"login-revoke rewrap is not configured",
		func(ctx context.Context, db *rhiza.DB, cursor string) ([]envelopeRow, bool, error) {
			exists, err := loginRevokeTableExists(ctx, db)
			if err != nil {
				return nil, false, err
			}
			if !exists {
				return nil, true, nil
			}
			result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,generation,code_envelope FROM identity_login_revoke WHERE subject > ? ORDER BY subject LIMIT 32`, Args: []any{cursor}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil {
				return nil, false, err
			}
			rows := make([]envelopeRow, 0, len(result.Rows))
			for _, row := range result.Rows {
				if len(row) != 3 {
					return nil, false, errors.New("invalid login-revoke envelope row")
				}
				subject, subjectOK := row[0].(string)
				generation, generationOK := row[1].(string)
				envelope, envelopeOK := loginRevokeEnvelopeBytes(row[2])
				if !subjectOK || !generationOK || !envelopeOK || subject == "" || generation == "" || len(envelope) == 0 {
					return nil, false, errors.New("invalid login-revoke envelope row")
				}
				rows = append(rows, envelopeRow{key: subject, generation: generation, envelope: envelope})
			}
			return rows, false, nil
		},
		LoginRevokeCodePurpose,
		"login-revoke-rewrap/",
		`UPDATE identity_login_revoke SET code_envelope=? WHERE subject=? AND generation=? AND code_envelope=?`,
	)
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
