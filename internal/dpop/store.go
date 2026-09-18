// Package dpop provides Rhiza-backed, multi-pod DPoP nonce and replay state.
package dpop

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const DefaultNonceTTL = 5 * time.Minute

var (
	ErrInvalid = errors.New("invalid DPoP state")
	ErrReplay  = errors.New("DPoP proof replayed")
)

type Store struct{ db *rhiza.DB }

func NewStore(db *rhiza.DB) *Store { return &Store{db: db} }

// IssueNonce returns an opaque, one-time nonce bound to the authenticated
// client and proof JWK thumbprint. Only its SHA-256 digest is persisted.
func (s *Store) IssueNonce(ctx context.Context, clientID, jkt string, now time.Time) (string, error) {
	if s == nil || s.db == nil || clientID == "" || jkt == "" {
		return "", ErrInvalid
	}
	now = canonicalTime(now)
	for range 4 {
		nonce, err := randomValue(32)
		if err != nil {
			return "", err
		}
		digest := valueDigest(nonce)
		expires := now.Add(DefaultNonceTTL).UnixMilli()
		requestID := mutationID("dpop-nonce-issue", digest, clientID, jkt, fmt.Sprint(expires))
		_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: append(expiredCleanup(now), rhiza.SQLStatement{SQL: `INSERT INTO dpop_nonces (nonce_digest,client_id,jkt,expires_at_unix_ms,consumed_attempt,created_at_unix_ms)
			VALUES (?, ?, ?, ?, NULL, ?)`, Args: []any{digest, clientID, jkt, expires, now.UnixMilli()}})})
		if err == nil {
			recovered, _, reconcileErr := s.reconcileNonceIssue(ctx, digest, clientID, jkt, expires)
			if reconcileErr == nil && recovered {
				return nonce, nil
			}
			if reconcileErr != nil {
				return "", reconcileErr
			}
			return "", ErrInvalid
		}
		recovered, collision, reconcileErr := s.reconcileNonceIssue(ctx, digest, clientID, jkt, expires)
		if reconcileErr != nil {
			return "", err
		}
		if recovered {
			return nonce, nil
		}
		if !collision {
			return "", err
		}
	}
	return "", fmt.Errorf("%w: nonce collision", ErrInvalid)
}

// ConsumeNonce verifies the binding, expiry and exact one-use property.
func (s *Store) ConsumeNonce(ctx context.Context, nonce, clientID, jkt string, now time.Time) error {
	if s == nil || s.db == nil || nonce == "" || clientID == "" || jkt == "" {
		return ErrInvalid
	}
	now = canonicalTime(now)
	digest := valueDigest(nonce)
	attempt, err := randomAttempt("dpop-nonce-consume", digest)
	if err != nil {
		return err
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: attempt, Statements: append(expiredCleanup(now), rhiza.SQLStatement{SQL: `UPDATE dpop_nonces SET consumed_attempt = ?
		WHERE nonce_digest = ? AND client_id = ? AND jkt = ? AND expires_at_unix_ms > ? AND consumed_attempt IS NULL`, Args: []any{attempt, digest, clientID, jkt, now.UnixMilli()}})})
	if err != nil {
		if s.nonceConsumedBy(ctx, digest, clientID, jkt, attempt, now) {
			return nil
		}
		return err
	}
	if s.nonceConsumedBy(ctx, digest, clientID, jkt, attempt, now) {
		return nil
	}
	return s.nonceFailure(ctx, digest, clientID, jkt, now)
}

// MarkReplay records the jkt+jti pair until expiresAt. It returns ErrReplay
// when any pod has already recorded that proof identity.
func (s *Store) MarkReplay(ctx context.Context, jkt, jti string, now, expiresAt time.Time) error {
	if s == nil || s.db == nil || jkt == "" || jti == "" {
		return ErrInvalid
	}
	now, expiresAt = canonicalTime(now), canonicalTime(expiresAt)
	if !expiresAt.After(now) {
		return ErrInvalid
	}
	digest := replayDigest(jkt, jti)
	attempt, err := randomAttempt("dpop-replay", digest)
	if err != nil {
		return err
	}
	requestID := attempt
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: append(expiredCleanup(now), rhiza.SQLStatement{SQL: `INSERT INTO dpop_replays (replay_digest,expires_at_unix_ms,created_attempt,created_at_unix_ms)
		VALUES (?, ?, ?, ?) ON CONFLICT(replay_digest) DO UPDATE SET expires_at_unix_ms = excluded.expires_at_unix_ms, created_attempt = excluded.created_attempt, created_at_unix_ms = excluded.created_at_unix_ms
		WHERE dpop_replays.expires_at_unix_ms <= ?`, Args: []any{digest, expiresAt.UnixMilli(), attempt, now.UnixMilli(), now.UnixMilli()}})})
	if err != nil {
		applied, exists, reconcileErr := s.reconcileReplay(ctx, digest, expiresAt, attempt)
		if reconcileErr != nil {
			return err
		}
		if applied {
			return nil
		}
		if exists {
			return ErrReplay
		}
		return err
	}
	applied, exists, reconcileErr := s.reconcileReplay(ctx, digest, expiresAt, attempt)
	if reconcileErr != nil {
		return reconcileErr
	}
	if applied {
		return nil
	}
	if exists {
		return ErrReplay
	}
	return ErrInvalid
}

// expiredCleanup is deliberately bounded. Its statements run in the same
// replicated transaction as the state mutation, so each successful DPoP call
// amortizes storage cleanup without a separate worker or a race window.
func expiredCleanup(now time.Time) []rhiza.SQLStatement {
	cutoff := now.UnixMilli()
	return []rhiza.SQLStatement{
		{SQL: `DELETE FROM dpop_nonces WHERE nonce_digest IN (SELECT nonce_digest FROM dpop_nonces WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 128)`, Args: []any{cutoff}},
		{SQL: `DELETE FROM dpop_replays WHERE replay_digest IN (SELECT replay_digest FROM dpop_replays WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 128)`, Args: []any{cutoff}},
	}
}

func (s *Store) reconcileNonceIssue(ctx context.Context, digest, clientID, jkt string, expires int64) (recovered, collision bool, err error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id,jkt,expires_at_unix_ms FROM dpop_nonces WHERE nonce_digest = ?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, false, err
	}
	if len(result.Rows) == 0 {
		return false, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 3 {
		return false, true, nil
	}
	row := result.Rows[0]
	storedClient, clientOK := row[0].(string)
	storedJKT, jktOK := row[1].(string)
	storedExpiry, expiryOK := row[2].(int64)
	return clientOK && jktOK && expiryOK && storedClient == clientID && storedJKT == jkt && storedExpiry == expires, true, nil
}

func (s *Store) nonceConsumedBy(ctx context.Context, digest, clientID, jkt, attempt string, now time.Time) bool {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id,jkt,expires_at_unix_ms,consumed_attempt FROM dpop_nonces WHERE nonce_digest = ?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return false
	}
	row := result.Rows[0]
	storedClient, clientOK := row[0].(string)
	storedJKT, jktOK := row[1].(string)
	expires, expiryOK := row[2].(int64)
	storedAttempt, attemptOK := row[3].(string)
	return clientOK && jktOK && expiryOK && attemptOK && storedClient == clientID && storedJKT == jkt && storedAttempt == attempt && expires > now.UnixMilli()
}

func (s *Store) nonceFailure(ctx context.Context, digest, clientID, jkt string, now time.Time) error {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id,jkt,expires_at_unix_ms,consumed_attempt FROM dpop_nonces WHERE nonce_digest = ?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return ErrInvalid
	}
	row := result.Rows[0]
	storedClient, clientOK := row[0].(string)
	storedJKT, jktOK := row[1].(string)
	expires, expiryOK := row[2].(int64)
	if !clientOK || !jktOK || !expiryOK || storedClient != clientID || storedJKT != jkt || expires <= now.UnixMilli() {
		return ErrInvalid
	}
	return ErrReplay
}

func (s *Store) reconcileReplay(ctx context.Context, digest string, expiresAt time.Time, attempt string) (applied, exists bool, err error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT expires_at_unix_ms,created_attempt FROM dpop_replays WHERE replay_digest = ?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, false, err
	}
	if len(result.Rows) == 0 {
		return false, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return false, true, nil
	}
	storedExpiry, ok := result.Rows[0][0].(int64)
	storedAttempt, attemptOK := result.Rows[0][1].(string)
	return ok && attemptOK && storedExpiry == expiresAt.UnixMilli() && storedAttempt == attempt, true, nil
}

func canonicalTime(value time.Time) time.Time { return value.UTC().Truncate(time.Millisecond) }

func valueDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func replayDigest(jkt, jti string) string {
	input := fmt.Sprintf("%d:%s%d:%s", len(jkt), jkt, len(jti), jti)
	return valueDigest(input)
}

func mutationID(prefix string, values ...string) string {
	joined := ""
	for _, value := range values {
		joined += fmt.Sprintf("%d:%s", len(value), value)
	}
	return prefix + "/" + valueDigest(joined)[:32]
}

func randomAttempt(prefix, value string) (string, error) {
	entropy, err := randomValue(16)
	if err != nil {
		return "", err
	}
	return mutationID(prefix, value, entropy), nil
}

func randomValue(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
