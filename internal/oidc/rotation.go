package oidc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type KeyPreparationResult struct {
	PendingKID     string
	ActivatesAfter time.Time
	Prepared       bool
}

type RotationResult struct {
	Active    SigningKey
	Activated bool
}

const signingKeyRewrapBatchSize = 32

// SigningKeyRewrapBatchResult reports one bounded cursor batch. Cursor is the
// last visited kid and is empty only when the batch reached the end.
type SigningKeyRewrapBatchResult struct {
	Cursor    string
	Rewrapped int
	Done      bool
}

type signingKeyRewrapCandidate struct {
	kid, publicJWK, oldEnvelope, state, newEnvelope string
}

// RewrapSigningKeyEnvelopeBatch re-encrypts at most 32 signing-key rows under
// the active master key. All rows are preflighted before one atomic CAS update;
// a concurrent row change therefore cannot produce a partial batch.
func RewrapSigningKeyEnvelopeBatch(ctx context.Context, db *rhiza.DB, keyring *Keyring, issuer, cursor string) (SigningKeyRewrapBatchResult, error) {
	if db == nil || keyring == nil {
		return SigningKeyRewrapBatchResult{}, errors.New("signing-key rewrap is not configured")
	}
	activeID, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	normalizedIssuer, err := NormalizeIssuer(issuer)
	if err != nil || normalizedIssuer != issuer {
		return SigningKeyRewrapBatchResult{}, errors.New("signing-key rewrap requires a normalized issuer")
	}
	if cursor != "" && !validKeyID(cursor) {
		return SigningKeyRewrapBatchResult{}, errors.New("invalid signing-key rewrap cursor")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT kid, public_jwk, private_envelope, state
			FROM oidc_signing_keys WHERE kid > ? ORDER BY kid LIMIT 32`,
		Args:        []any{cursor},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	if len(result.Rows) == 0 {
		if _, err := LoadActiveSigningKey(ctx, db, keyring, normalizedIssuer); err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		return SigningKeyRewrapBatchResult{Cursor: cursor, Done: true}, nil
	}

	candidates := make([]signingKeyRewrapCandidate, 0, len(result.Rows))
	lastKID := ""
	for _, row := range result.Rows {
		if len(row) != 4 {
			return SigningKeyRewrapBatchResult{}, errors.New("invalid signing-key rewrap row")
		}
		kid, kidOK := row[0].(string)
		publicJWK, publicOK := row[1].(string)
		envelopeText, envelopeOK := row[2].(string)
		state, stateOK := row[3].(string)
		if !kidOK || !validKeyID(kid) || !publicOK || publicJWK == "" || !envelopeOK || !stateOK || (state != "active" && state != "pending" && state != "retiring") {
			return SigningKeyRewrapBatchResult{}, errors.New("invalid signing-key rewrap row")
		}
		lastKID = kid
		envelope, err := base64.RawURLEncoding.DecodeString(envelopeText)
		if err != nil {
			return SigningKeyRewrapBatchResult{}, errors.New("invalid signing-key envelope encoding")
		}
		masterID, _, err := parseEnvelopeHeader(envelope, envelopeMagic, envelopeVersion, "invalid signing key envelope")
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		seed, err := openEnvelope(keyring, normalizedIssuer, kid, envelope)
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		key, _, derivedKID, err := signingKeyFromSeed(seed, time.Time{})
		if err != nil || derivedKID != kid {
			return SigningKeyRewrapBatchResult{}, errors.New("signing-key envelope does not match kid")
		}
		var stored jose.JSONWebKey
		storedOK := json.Unmarshal([]byte(publicJWK), &stored) == nil && stored.IsPublic()
		storedPublic, publicKeyOK := stored.Key.(ed25519.PublicKey)
		if !storedOK || !publicKeyOK || stored.KeyID != kid || stored.Algorithm != string(jose.EdDSA) || stored.Use != "sig" || !bytes.Equal(storedPublic, key.PublicJWK.Key.(ed25519.PublicKey)) {
			return SigningKeyRewrapBatchResult{}, errors.New("stored public JWK does not match signing envelope")
		}
		if masterID == activeID {
			continue
		}
		newEnvelope, err := sealEnvelopeWithKeyID(keyring, activeID, normalizedIssuer, kid, seed)
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		candidates = append(candidates, signingKeyRewrapCandidate{kid: kid, publicJWK: publicJWK, oldEnvelope: envelopeText, state: state, newEnvelope: base64.RawURLEncoding.EncodeToString(newEnvelope)})
	}

	rewrapped := 0
	if len(candidates) > 0 {
		requestID, sql, args := signingKeyRewrapMutation(lastKID, normalizedIssuer, candidates)
		response, err := storage.ExecuteEnvelope(ctx, db, activeID, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql, Args: args})
		if err != nil {
			return SigningKeyRewrapBatchResult{}, err
		}
		if response.RowsAffected != 0 && response.RowsAffected != int64(len(candidates)) {
			return SigningKeyRewrapBatchResult{}, fmt.Errorf("signing-key rewrap CAS changed %d rows, want %d", response.RowsAffected, len(candidates))
		}
		rewrapped = int(response.RowsAffected)
	}
	if _, err := LoadActiveSigningKey(ctx, db, keyring, normalizedIssuer); err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	return SigningKeyRewrapBatchResult{Cursor: lastKID, Rewrapped: rewrapped, Done: len(result.Rows) < signingKeyRewrapBatchSize}, nil
}

func signingKeyRewrapMutation(lastKID, issuer string, candidates []signingKeyRewrapCandidate) (string, string, []any) {
	// The request ID includes the prepared ciphertext, so concurrent workers
	// with independently randomized payloads cannot collide. A commit-unknown
	// retry reuses this exact request object inside storage.Execute.
	hashInput := issuer + "\x00" + lastKID
	for _, row := range candidates {
		hashInput += "\x00" + row.kid + "\x00" + row.state + "\x00" + row.publicJWK + "\x00" + row.oldEnvelope + "\x00" + row.newEnvelope
	}
	digest := sha256.Sum256([]byte(hashInput))
	requestID := "oidc-key-rewrap/" + base64.RawURLEncoding.EncodeToString(digest[:16])

	var sql strings.Builder
	sql.WriteString("UPDATE oidc_signing_keys SET private_envelope = CASE kid ")
	args := make([]any, 0, len(candidates)*6+1)
	for _, row := range candidates {
		sql.WriteString("WHEN ? THEN ? ")
		args = append(args, row.kid, row.newEnvelope)
	}
	sql.WriteString("ELSE private_envelope END WHERE kid IN (")
	for index, row := range candidates {
		if index > 0 {
			sql.WriteString(",")
		}
		sql.WriteString("?")
		args = append(args, row.kid)
	}
	sql.WriteString(") AND (SELECT COUNT(*) FROM oidc_signing_keys WHERE ")
	for index, row := range candidates {
		if index > 0 {
			sql.WriteString(" OR ")
		}
		sql.WriteString("(kid=? AND state=? AND public_jwk=? AND private_envelope=?)")
		args = append(args, row.kid, row.state, row.publicJWK, row.oldEnvelope)
	}
	sql.WriteString(") = ?")
	args = append(args, int64(len(candidates)))
	return requestID, sql.String(), args
}

// PrepareSigningKey publishes a new public key before it can sign tokens.
func PrepareSigningKey(ctx context.Context, db *rhiza.DB, keyring *Keyring, issuer string, now time.Time) (KeyPreparationResult, error) {
	if now.IsZero() {
		return KeyPreparationResult{}, fmt.Errorf("signing key preparation time is required")
	}
	if kid, activatesAfter, found, err := pendingSigningKey(ctx, db); err != nil {
		return KeyPreparationResult{}, err
	} else if found {
		return KeyPreparationResult{PendingKID: kid, ActivatesAfter: activatesAfter}, nil
	}
	writerKeyID, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return KeyPreparationResult{}, err
	}
	candidate, publicJSON, envelope, err := generateSigningKey(keyring, writerKeyID, issuer, now)
	if err != nil {
		return KeyPreparationResult{}, err
	}
	activatesAfter := now.Add(JWKSCacheMaxAge)
	_, prepareErr := storage.ExecuteEnvelope(ctx, db, writerKeyID, rhiza.ExecuteRequest{
		RequestID: "oidc-key-prepare/" + candidate.PublicJWK.KeyID,
		SQL: `INSERT INTO oidc_signing_keys
			(kid, public_jwk, private_envelope, state, created_at_unix_ms, activates_after_unix_ms)
			SELECT ?, ?, ?, 'pending', ?, ?
			WHERE NOT EXISTS (SELECT 1 FROM oidc_signing_keys WHERE state = 'pending')`,
		Args: []any{candidate.PublicJWK.KeyID, string(publicJSON), base64.RawURLEncoding.EncodeToString(envelope), now.UnixMilli(), activatesAfter.UnixMilli()},
	})
	winner, winnerAfter, found, loadErr := pendingSigningKey(ctx, db)
	if found {
		return KeyPreparationResult{PendingKID: winner, ActivatesAfter: winnerAfter, Prepared: winner == candidate.PublicJWK.KeyID}, nil
	}
	return KeyPreparationResult{}, errors.Join(prepareErr, loadErr, ErrNoSigningKey)
}

// ActivatePreparedSigningKey atomically retires expectedActiveKID and activates
// pendingKID only after its public JWK has been published for JWKSCacheMaxAge.
func ActivatePreparedSigningKey(ctx context.Context, db *rhiza.DB, keyring *Keyring, issuer, expectedActiveKID, pendingKID string, retireAfter, now time.Time) (RotationResult, error) {
	if !validKeyID(expectedActiveKID) || !validKeyID(pendingKID) || expectedActiveKID == pendingKID {
		return RotationResult{}, fmt.Errorf("invalid signing key activation IDs")
	}
	if now.IsZero() {
		return RotationResult{}, fmt.Errorf("signing key activation time is required")
	}
	if retireAfter.Before(now.Add(MinimumSigningKeyRetirement)) {
		return RotationResult{}, fmt.Errorf("signing key retirement is shorter than the token and JWKS safety window")
	}
	active, err := LoadActiveSigningKey(ctx, db, keyring, issuer)
	if err != nil {
		return RotationResult{}, err
	}
	if active.PublicJWK.KeyID != expectedActiveKID {
		return RotationResult{Active: active}, nil
	}
	storedPendingKID, activatesAfter, found, err := pendingSigningKey(ctx, db)
	if err != nil {
		return RotationResult{}, err
	}
	if !found || storedPendingKID != pendingKID || now.Before(activatesAfter) {
		// A concurrent activation can remove the pending row between our active
		// key read and this check. Return the committed winner rather than
		// reporting a transient readiness failure.
		winner, winnerErr := LoadActiveSigningKey(ctx, db, keyring, issuer)
		if winnerErr == nil && winner.PublicJWK.KeyID != expectedActiveKID {
			return RotationResult{Active: winner, Activated: winner.PublicJWK.KeyID == pendingKID}, nil
		}
		return RotationResult{}, fmt.Errorf("pending signing key is not ready to activate")
	}
	if _, err := loadSigningKey(ctx, db, keyring, issuer, pendingKID, "pending"); err != nil {
		// A peer can commit an activation after the pending-state read. A newer
		// verified active key is the committed winner; otherwise retain the
		// validation error and fail closed.
		winner, winnerErr := LoadActiveSigningKey(ctx, db, keyring, issuer)
		if winnerErr == nil && winner.PublicJWK.KeyID != expectedActiveKID {
			return RotationResult{Active: winner, Activated: winner.PublicJWK.KeyID == pendingKID}, nil
		}
		return RotationResult{}, fmt.Errorf("validate pending signing key: %w", err)
	}
	rotationEvent := eventlog.JWKSRotated(expectedActiveKID+"/"+pendingKID, now)
	eventStatement, eventErr := rotationEvent.Statement(`EXISTS (SELECT 1 FROM oidc_signing_keys WHERE kid=? AND state='active')
		AND EXISTS (SELECT 1 FROM oidc_signing_keys WHERE kid=? AND state='pending' AND activates_after_unix_ms <= ?)`, expectedActiveKID, pendingKID, now.UnixMilli())
	if eventErr != nil {
		return RotationResult{}, eventErr
	}
	_, activateErr := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: activationRequestID(expectedActiveKID, pendingKID, retireAfter, now),
		Statements: []rhiza.SQLStatement{
			eventStatement,
			{SQL: `UPDATE oidc_signing_keys SET state = 'retiring', activates_after_unix_ms = NULL, retire_after_unix_ms = ?
				WHERE kid = ? AND state = 'active' AND EXISTS (
					SELECT 1 FROM oidc_signing_keys WHERE kid = ? AND state = 'pending' AND activates_after_unix_ms <= ?
				)`, Args: []any{retireAfter.UnixMilli(), expectedActiveKID, pendingKID, now.UnixMilli()}},
			{SQL: `UPDATE oidc_signing_keys SET state = 'active', activates_after_unix_ms = NULL
				WHERE kid = ? AND state = 'pending' AND activates_after_unix_ms <= ?
				AND EXISTS (SELECT 1 FROM oidc_signing_keys WHERE kid = ? AND state = 'retiring' AND retire_after_unix_ms = ?)
				AND NOT EXISTS (SELECT 1 FROM oidc_signing_keys WHERE state = 'active')`,
				Args: []any{pendingKID, now.UnixMilli(), expectedActiveKID, retireAfter.UnixMilli()}},
		},
	})
	winner, loadErr := LoadActiveSigningKey(ctx, db, keyring, issuer)
	if loadErr == nil && winner.PublicJWK.KeyID != expectedActiveKID {
		return RotationResult{Active: winner, Activated: winner.PublicJWK.KeyID == pendingKID}, nil
	}
	if loadErr != nil {
		return RotationResult{}, errors.Join(activateErr, loadErr)
	}
	if activateErr != nil {
		return RotationResult{}, activateErr
	}
	return RotationResult{}, fmt.Errorf("signing key activation did not replace %q", expectedActiveKID)
}

// activationRequestID binds every value that changes the replicated activation
// mutation. Reusing a request ID for different arguments is a Rhiza conflict,
// so the time values intentionally use the same millisecond representation as
// the SQL arguments below.
func activationRequestID(expectedActiveKID, pendingKID string, retireAfter, now time.Time) string {
	input := expectedActiveKID + "\x00" + pendingKID + "\x00" +
		fmt.Sprint(retireAfter.UTC().UnixMilli()) + "\x00" + fmt.Sprint(now.UTC().UnixMilli())
	digest := sha256.Sum256([]byte(input))
	return "oidc-key-activate/" + base64.RawURLEncoding.EncodeToString(digest[:16])
}

// LoadJWKSKeys returns active, prepublished pending, and still-valid retiring keys.
func LoadJWKSKeys(ctx context.Context, db *rhiza.DB, now time.Time) ([]jose.JSONWebKey, error) {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT public_jwk FROM oidc_signing_keys
		WHERE state IN ('active', 'pending') OR (state = 'retiring' AND retire_after_unix_ms >= ?)
		ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, created_at_unix_ms, kid`, Args: []any{now.UnixMilli()}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, ErrNoSigningKey
	}
	keys := make([]jose.JSONWebKey, 0, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) != 1 {
			return nil, fmt.Errorf("invalid public signing key row")
		}
		encoded, ok := row[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid public JWK storage type")
		}
		var key jose.JSONWebKey
		if err := json.Unmarshal([]byte(encoded), &key); err != nil || !key.IsPublic() {
			return nil, fmt.Errorf("invalid stored public JWK")
		}
		if _, ok := key.Key.(ed25519.PublicKey); !ok || !validKeyID(key.KeyID) || key.Algorithm != string(jose.EdDSA) || key.Use != "sig" {
			return nil, fmt.Errorf("invalid stored public JWK")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func CleanupRetiredSigningKeys(ctx context.Context, db *rhiza.DB, cutoff time.Time) error {
	if cutoff.IsZero() {
		return fmt.Errorf("retired signing key cutoff is required")
	}
	// Cleanup is eventual: a local miss only defers deletion to a later tick.
	// LoadJWKSKeys independently filters retired keys by their expiry time.
	pending, err := db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT 1 FROM oidc_signing_keys
			WHERE state = 'retiring' AND retire_after_unix_ms < ? LIMIT 1`,
		Args:        []any{cutoff.UnixMilli()},
		Consistency: rhiza.ConsistencyLocal,
	})
	if err != nil {
		return err
	}
	if len(pending.Rows) == 0 {
		return nil
	}
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "oidc-key-cleanup/" + fmt.Sprint(cutoff.UnixMilli()), SQL: `DELETE FROM oidc_signing_keys WHERE state = 'retiring' AND retire_after_unix_ms < ?`, Args: []any{cutoff.UnixMilli()}})
	return err
}

func pendingSigningKey(ctx context.Context, db *rhiza.DB) (string, time.Time, bool, error) {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT kid, activates_after_unix_ms FROM oidc_signing_keys WHERE state = 'pending' LIMIT 1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return "", time.Time{}, false, err
	}
	if len(result.Rows) == 0 {
		return "", time.Time{}, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return "", time.Time{}, false, fmt.Errorf("invalid pending signing key row")
	}
	kid, keyOK := result.Rows[0][0].(string)
	activatesAfter, timeOK := result.Rows[0][1].(int64)
	if !keyOK || !validKeyID(kid) || !timeOK {
		return "", time.Time{}, false, fmt.Errorf("invalid pending signing key")
	}
	return kid, time.UnixMilli(activatesAfter), true, nil
}
