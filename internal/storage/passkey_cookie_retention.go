package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/mrchypark/rhiza"
)

// migrateSchemaV112 records the longest passwordless-cookie lifetime issued
// under each master key. Rows are independent of passkey configuration so
// disabling passkeys cannot discard the decryption-retention obligation.
func migrateSchemaV112(ctx context.Context, db *rhiza.DB) error {
	// Keep this exact request stable and idempotent. Retrying it through Execute
	// confirms an unknown commit's durability before startup proceeds.
	_, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v112", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS passkey_cookie_key_retention (
			master_key_id TEXT PRIMARY KEY NOT NULL CHECK (length(master_key_id) BETWEEN 1 AND 64),
			max_ttl_ns INTEGER NOT NULL CHECK (max_ttl_ns > 0)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations(version) VALUES(112)`},
	}})
	return err
}

// RegisterPasswordlessCookieKeyTTL durably raises the lifetime watermark for
// the exact master key that sealed a cookie. The upsert is monotonic so older
// or concurrently running instances cannot shorten the retention obligation.
func RegisterPasswordlessCookieKeyTTL(ctx context.Context, db *rhiza.DB, keyID string, ttl time.Duration) error {
	if db == nil || ctx == nil || ctx.Err() != nil || !validRetirementKeyID(keyID) || ttl <= 0 {
		return errors.New("invalid passwordless-cookie retention registration")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("create passwordless-cookie retention request id: %w", err)
	}
	requestID := "passkey-cookie-ttl-" + hex.EncodeToString(nonce[:])
	_, err := ExecuteEnvelope(ctx, db, keyID, rhiza.ExecuteRequest{
		RequestID: requestID,
		SQL: `INSERT INTO passkey_cookie_key_retention(master_key_id,max_ttl_ns) VALUES(?,?)
			ON CONFLICT(master_key_id) DO UPDATE SET max_ttl_ns=MAX(passkey_cookie_key_retention.max_ttl_ns,excluded.max_ttl_ns)`,
		Args: []any{keyID, int64(ttl)},
	})
	if err != nil {
		return fmt.Errorf("register passwordless-cookie key lifetime: %w", err)
	}
	return nil
}

// PasswordlessCookieKeyTTL reads the durable high-water mark. A missing row is
// reported as zero so callers can apply the supported legacy 90-day default.
// A pre-ledger custom fork's longer lifetime cannot be inferred from its
// database; operators must retain its historical maximum before enabling
// automatic pruning. Read errors must be handled fail-closed by retirement
// and pruning paths.
func PasswordlessCookieKeyTTL(ctx context.Context, db *rhiza.DB, keyID string) (time.Duration, error) {
	if db == nil || ctx == nil || ctx.Err() != nil || !validRetirementKeyID(keyID) {
		return 0, errors.New("invalid passwordless-cookie retention lookup")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:  `SELECT max_ttl_ns FROM passkey_cookie_key_retention WHERE master_key_id=?`,
		Args: []any{keyID}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return 0, err
	}
	if len(result.Rows) == 0 {
		return 0, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return 0, errors.New("invalid passwordless-cookie retention row")
	}
	nanos, ok := result.Rows[0][0].(int64)
	if !ok || nanos <= 0 {
		return 0, errors.New("invalid passwordless-cookie retention lifetime")
	}
	return time.Duration(nanos), nil
}
