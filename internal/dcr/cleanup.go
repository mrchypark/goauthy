package dcr

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const DefaultAnonymousCleanupLimit int64 = 100

const (
	maxAnonymousCleanupMinutes int64 = 525600
	maxAnonymousInactiveDays   int64 = 3650
	maxAnonymousCleanupLimit   int64 = 1000
)

// AnonymousCleanupConfig bounds one cleanup pass. InactiveDays disables
// cleanup of used clients when zero; never-used clients use CleanupMinutes.
type AnonymousCleanupConfig struct {
	CleanupMinutes int64
	InactiveDays   int64
	Limit          int64
}

func (c AnonymousCleanupConfig) valid() bool {
	return c.CleanupMinutes >= 0 && c.CleanupMinutes <= maxAnonymousCleanupMinutes && c.InactiveDays >= 0 && c.InactiveDays <= maxAnonymousInactiveDays && c.Limit > 0 && c.Limit <= maxAnonymousCleanupLimit
}

// CleanupAnonymousClients atomically removes one deterministic batch of
// anonymous dynamic clients and state directly keyed by their client IDs.
func CleanupAnonymousClients(ctx context.Context, db *rhiza.DB, config AnonymousCleanupConfig, now time.Time) error {
	if ctx == nil || db == nil || now.IsZero() || !config.valid() {
		return errors.New("invalid anonymous dynamic client cleanup configuration")
	}
	now = now.UTC().Truncate(time.Millisecond)
	createdBefore := now.Add(-time.Duration(config.CleanupMinutes) * time.Minute).UnixMilli()
	inactiveBefore := now.AddDate(0, 0, -int(config.InactiveDays)).UnixMilli()
	requestID, err := cleanupRequestID()
	if err != nil {
		return fmt.Errorf("generate anonymous dynamic client cleanup request ID: %w", err)
	}

	// Every statement repeats this selection. Rhiza evaluates the complete
	// batch at commit, so competing workers cannot delete a client that became
	// ineligible before its own parent DELETE.
	candidates := `SELECT client_id FROM dynamic_oauth_clients
		WHERE anonymous = 1 AND (
			(last_used_at_unix_ms IS NULL AND created_at_unix_ms <= ?)
			OR (? > 0 AND last_used_at_unix_ms IS NOT NULL AND last_used_at_unix_ms <= ?)
		)
		ORDER BY CASE WHEN last_used_at_unix_ms IS NULL THEN created_at_unix_ms ELSE last_used_at_unix_ms END, client_id LIMIT ?`
	args := []any{createdBefore, config.InactiveDays, inactiveBefore, config.Limit}
	forClient := func(table, column string) rhiza.SQLStatement {
		return rhiza.SQLStatement{SQL: `DELETE FROM ` + table + ` WHERE ` + column + ` IN (` + candidates + `)`, Args: args}
	}
	accessSignatures := `SELECT signature FROM oauth_access_tokens WHERE client_id IN (` + candidates + `)`
	statements := []rhiza.SQLStatement{
		{SQL: `DELETE FROM oauth_refresh_tokens WHERE access_signature IN (` + accessSignatures + `)`, Args: args},
		{SQL: `DELETE FROM oauth_token_requests WHERE signature IN (` + accessSignatures + `)`, Args: args},
		forClient("oauth_access_tokens", "client_id"),
		forClient("oauth_device_grants", "client_id"),
		forClient("dpop_nonces", "client_id"),
		forClient("oidc_backchannel_deliveries", "client_id"),
		forClient("oidc_session_clients", "client_id"),
		forClient("oidc_user_clients", "client_id"),
		forClient("dcr_registration_idempotency", "client_id"),
		forClient("dynamic_oauth_clients", "client_id"), // parent last
	}
	// storage.Execute resolves Rhiza's commit-unknown response with this exact
	// request ID. A retry must not create a new ID, while each new pass does.
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	return err
}

func cleanupRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "dcr-cleanup/" + base64.RawURLEncoding.EncodeToString(value[:]), nil
}
