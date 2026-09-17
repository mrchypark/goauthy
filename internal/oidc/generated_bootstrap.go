package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// GeneratedAPIKeyBootstrapEnvelopePurpose binds the shared Generate payload
// to its sole use. The plaintext is the existing version/deadline/entries JSON.
const GeneratedAPIKeyBootstrapEnvelopePurpose = "bootstrap/api-keys/v1"

// RewrapGeneratedAPIKeyBootstrapEnvelope re-encrypts the singleton Generate
// artifact under the active master key. The original-ciphertext CAS leaves an
// expiry tombstone or a concurrent rewrap untouched.
func RewrapGeneratedAPIKeyBootstrapEnvelope(ctx context.Context, db *rhiza.DB, keyring *Keyring) (SigningKeyRewrapBatchResult, error) {
	if db == nil || keyring == nil {
		return SigningKeyRewrapBatchResult{}, errors.New("generated API-key bootstrap rewrap is not configured")
	}
	active, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT payload_envelope FROM generated_api_key_bootstrap WHERE singleton=1 AND payload_envelope IS NOT NULL`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	if len(result.Rows) == 0 {
		return SigningKeyRewrapBatchResult{Done: true}, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return SigningKeyRewrapBatchResult{}, errors.New("invalid generated API-key bootstrap envelope row")
	}
	envelope, ok := result.Rows[0][0].([]byte)
	if !ok || len(envelope) == 0 {
		return SigningKeyRewrapBatchResult{}, errors.New("invalid generated API-key bootstrap envelope row")
	}
	keyID, err := keyring.PurposeEnvelopeKeyID(GeneratedAPIKeyBootstrapEnvelopePurpose, envelope)
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	if keyID == active {
		return SigningKeyRewrapBatchResult{Done: true}, nil
	}
	replacement, err := keyring.RewrapEnvelope(GeneratedAPIKeyBootstrapEnvelopePurpose, envelope)
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	digest := sha256.Sum256(append(append([]byte(GeneratedAPIKeyBootstrapEnvelopePurpose+"\x00"), envelope...), replacement...))
	response, err := storage.ExecuteEnvelope(ctx, db, active, rhiza.ExecuteRequest{
		RequestID: "generated-api-key-bootstrap-rewrap/" + base64.RawURLEncoding.EncodeToString(digest[:16]),
		SQL: `UPDATE generated_api_key_bootstrap SET payload_envelope=?
			WHERE singleton=1 AND payload_envelope IS NOT NULL AND payload_envelope=?`,
		Args: []any{replacement, envelope},
	})
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	return SigningKeyRewrapBatchResult{Rewrapped: int(response.RowsAffected), Done: true}, nil
}
