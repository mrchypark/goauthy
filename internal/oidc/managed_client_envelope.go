package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// ManagedClientSecretPurpose is the authenticated-envelope purpose for one
// managed OAuth client generation. Keep this builder shared by storage,
// rewrap, and client-secret consumers so ID/generation remain AAD-bound.
func ManagedClientSecretPurpose(id, generation string) string {
	digest := sha256.Sum256([]byte(id + "\x00" + generation))
	return "client-secret/" + base64.RawURLEncoding.EncodeToString(digest[:])
}

// RewrapManagedClientSecretBatch re-encrypts at most 32 managed-client
// envelopes and CASes each original ciphertext to avoid clobbering writers.
func RewrapManagedClientSecretBatch(ctx context.Context, db *rhiza.DB, keyring *Keyring, cursor string) (SigningKeyRewrapBatchResult, error) {
	if db == nil || keyring == nil {
		return SigningKeyRewrapBatchResult{}, errors.New("managed-client rewrap is not configured")
	}
	active, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,generation,secret_envelope FROM managed_oauth_clients WHERE secret_envelope IS NOT NULL AND id > ? ORDER BY id LIMIT 32`, Args: []any{cursor}, Consistency: rhiza.ConsistencyLinearizable})
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
			return SigningKeyRewrapBatchResult{}, errors.New("invalid managed-client envelope row")
		}
		id, a := row[0].(string)
		generation, b := row[1].(string)
		envelope, c := row[2].([]byte)
		if !a || !b || !c || id == "" || generation == "" || len(envelope) == 0 {
			return SigningKeyRewrapBatchResult{}, errors.New("invalid managed-client envelope row")
		}
		keyID, err := keyring.PurposeEnvelopeKeyID(ManagedClientSecretPurpose(id, generation), envelope)
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		last = id
		if keyID == active {
			continue
		}
		plain, err := keyring.OpenEnvelope(ManagedClientSecretPurpose(id, generation), envelope)
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		replacement, err := keyring.SealEnvelope(ManagedClientSecretPurpose(id, generation), plain)
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		digest := sha256.Sum256(append(append([]byte(id+"\x00"+generation+"\x00"), envelope...), replacement...))
		r, err := storage.ExecuteEnvelope(ctx, db, active, rhiza.ExecuteRequest{RequestID: "managed-client-rewrap/" + base64.RawURLEncoding.EncodeToString(digest[:16]), SQL: `UPDATE managed_oauth_clients SET secret_envelope=? WHERE id=? AND generation=? AND secret_envelope=?`, Args: []any{replacement, id, generation, envelope}})
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		changed += r.RowsAffected
	}
	return SigningKeyRewrapBatchResult{Cursor: last, Rewrapped: int(changed), Done: len(result.Rows) < 32}, nil
}
