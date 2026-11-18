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
	return rewrapEnvelopeBatch(
		ctx,
		db,
		keyring,
		cursor,
		"managed-client rewrap is not configured",
		func(ctx context.Context, db *rhiza.DB, cursor string) ([]envelopeRow, bool, error) {
			result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,generation,secret_envelope FROM managed_oauth_clients WHERE secret_envelope IS NOT NULL AND id > ? ORDER BY id LIMIT 32`, Args: []any{cursor}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil {
				return nil, false, err
			}
			rows := make([]envelopeRow, 0, len(result.Rows))
			for _, row := range result.Rows {
				if len(row) != 3 {
					return nil, false, errors.New("invalid managed-client envelope row")
				}
				id, a := row[0].(string)
				generation, b := row[1].(string)
				envelope, c := row[2].([]byte)
				if !a || !b || !c || id == "" || generation == "" || len(envelope) == 0 {
					return nil, false, errors.New("invalid managed-client envelope row")
				}
				rows = append(rows, envelopeRow{key: id, generation: generation, envelope: envelope})
			}
			return rows, false, nil
		},
		ManagedClientSecretPurpose,
		"managed-client-rewrap/",
		`UPDATE managed_oauth_clients SET secret_envelope=? WHERE id=? AND generation=? AND secret_envelope=?`,
	)
}

type envelopeRow struct {
	key        string
	generation string
	envelope   []byte
}

func rewrapEnvelopeBatch(
	ctx context.Context,
	db *rhiza.DB,
	keyring *Keyring,
	cursor string,
	notConfiguredMsg string,
	queryFn func(ctx context.Context, db *rhiza.DB, cursor string) ([]envelopeRow, bool, error),
	purposeFn func(id, generation string) string,
	reqPrefix string,
	updateSQL string,
) (SigningKeyRewrapBatchResult, error) {
	if db == nil || keyring == nil {
		return SigningKeyRewrapBatchResult{}, errors.New(notConfiguredMsg)
	}
	active, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	rows, doneEarly, err := queryFn(ctx, db, cursor)
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	if doneEarly || len(rows) == 0 {
		return SigningKeyRewrapBatchResult{Cursor: cursor, Done: true}, nil
	}
	last := cursor
	changed := int64(0)
	for _, row := range rows {
		last = row.key
		purpose := purposeFn(row.key, row.generation)
		keyID, err := keyring.PurposeEnvelopeKeyID(purpose, row.envelope)
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		if keyID == active {
			continue
		}
		replacement, err := keyring.RewrapEnvelope(purpose, row.envelope)
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		digest := sha256.Sum256(append(append([]byte(row.key+"\x00"+row.generation+"\x00"), row.envelope...), replacement...))
		r, err := storage.ExecuteEnvelope(ctx, db, active, rhiza.ExecuteRequest{
			RequestID: reqPrefix + base64.RawURLEncoding.EncodeToString(digest[:16]),
			SQL:       updateSQL,
			Args:      []any{replacement, row.key, row.generation, row.envelope},
		})
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		changed += r.RowsAffected
	}
	return SigningKeyRewrapBatchResult{Cursor: last, Rewrapped: int(changed), Done: len(rows) < 32}, nil
}
