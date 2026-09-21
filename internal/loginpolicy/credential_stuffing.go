// Package loginpolicy - Credential stuffing detection for distributed login attacks.
//
// This module detects when multiple different source IPs attempt to log into the
// same account within a short time window, which is the hallmark of a credential
// stuffing attack. Unlike per-IP brute-force protection (which this package already
// provides), credential stuffing detection correlates failures across IPs to identify
// attacks that distribute attempts across many sources.
package loginpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	// StuffingWindow is the time window for counting distinct IP failures per account.
	StuffingWindow = 10 * time.Minute

	// StuffingThreshold is the number of distinct IPs that trigger a credential
	// stuffing alert. At this point, the account is temporarily locked.
	StuffingThreshold = 5

	// AccountLockDuration is how long an account stays locked after a credential
	// stuffing detection.
	AccountLockDuration = 30 * time.Minute

	// StuffingEntryTTL is how long individual IP failure records persist.
	StuffingEntryTTL = StuffingWindow * 2
)

// AccountStatus reports the credential stuffing state for an account.
type AccountStatus struct {
	// DistinctIPs is the number of distinct source IPs that failed to log in
	// within the current window.
	DistinctIPs int

	// LockedUntil is the time until which the account is locked. Zero if not locked.
	LockedUntil time.Time

	// WindowStart is the start of the current observation window.
	WindowStart time.Time
}

// RecordAccountFailure records a failed login attempt for a specific account from
// a specific IP. This is used to detect credential stuffing attacks where many
// different IPs try to log into the same account.
//
// The account identifier is a SHA-256 hash of the subject (never the plaintext).
// Returns the updated account status and whether the account is now locked.
func (s *Store) RecordAccountFailure(ctx context.Context, accountHash, ip string, now time.Time) (AccountStatus, bool, error) {
	if s == nil || s.db == nil || accountHash == "" || ip == "" {
		return AccountStatus{}, false, ErrInvalid
	}
	now = now.UTC().Truncate(time.Millisecond)
	windowStart := now.UnixMilli() / StuffingWindow.Milliseconds() * StuffingWindow.Milliseconds()

	// Step 1: Upsert the IP failure record for this account+IP+window. The window
	// is part of the row identity so a source that returns in a later window is
	// counted there instead of staying attributed to the window it first failed in.
	ipKey := accountStuffingIPDigest(accountHash, ip, windowStart)
	requestID, err := randomRequestID("stuffing-failure")
	if err != nil {
		return AccountStatus{}, false, err
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: requestID,
		SQL: `INSERT INTO login_account_ip_failures (key_digest, account_hash, ip_hash, window_start_unix_ms, expires_at_unix_ms)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(key_digest) DO UPDATE SET
				expires_at_unix_ms = MAX(login_account_ip_failures.expires_at_unix_ms, excluded.expires_at_unix_ms)`,
		Args: []any{ipKey, accountHash, ipDigest(ip), windowStart, now.UnixMilli() + StuffingEntryTTL.Milliseconds()},
	})
	if err != nil {
		return AccountStatus{}, false, err
	}

	// Step 2: Count distinct IPs in the current window for this account.
	status := AccountStatus{WindowStart: time.UnixMilli(windowStart).UTC()}
	countResult, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT COUNT(DISTINCT ip_hash) FROM login_account_ip_failures WHERE account_hash = ? AND window_start_unix_ms = ? AND expires_at_unix_ms > ?`,
		Args:        []any{accountHash, windowStart, now.UnixMilli()},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return AccountStatus{}, false, err
	}
	if len(countResult.Rows) == 1 && len(countResult.Rows[0]) == 1 {
		if count, ok := countResult.Rows[0][0].(int64); ok {
			status.DistinctIPs = int(count)
		}
	}

	// Step 3: If threshold exceeded, lock the account.
	locked := status.DistinctIPs >= StuffingThreshold
	if locked {
		lockRequestID, err := randomRequestID("stuffing-lock")
		if err != nil {
			return AccountStatus{}, false, err
		}
		lockedUntil := now.Add(AccountLockDuration)
		status.LockedUntil = lockedUntil
		_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
			RequestID: lockRequestID,
			SQL: `INSERT INTO login_account_locks (account_hash, locked_until_unix_ms, reason, created_at_unix_ms)
				VALUES (?, ?, 'credential_stuffing', ?)
				ON CONFLICT(account_hash) DO UPDATE SET
					locked_until_unix_ms = MAX(login_account_locks.locked_until_unix_ms, excluded.locked_until_unix_ms),
					reason = CASE WHEN excluded.locked_until_unix_ms > login_account_locks.locked_until_unix_ms THEN excluded.reason ELSE login_account_locks.reason END,
					created_at_unix_ms = CASE WHEN excluded.locked_until_unix_ms > login_account_locks.locked_until_unix_ms THEN excluded.created_at_unix_ms ELSE login_account_locks.created_at_unix_ms END`,
			Args: []any{accountHash, lockedUntil.UnixMilli(), now.UnixMilli()},
		})
		if err != nil {
			return AccountStatus{}, false, err
		}

		// Emit security event.
		eventRequestID, _ := randomRequestID("stuffing-event")
		if eventRequestID != "" {
			event := eventlog.CredentialStuffingEvent(eventRequestID, accountHash, ip, int64(status.DistinctIPs), now)
			if stmt, err := event.Statement("1=1"); err == nil {
				storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
					RequestID:  eventRequestID,
					Statements: []rhiza.SQLStatement{stmt},
				})
			}
		}
	}

	return status, locked, nil
}

// CheckAccountLock checks whether an account is currently locked due to
// credential stuffing detection. Returns the lock status and remaining duration.
func (s *Store) CheckAccountLock(ctx context.Context, accountHash string, now time.Time) (locked bool, remaining time.Duration, err error) {
	if s == nil || s.db == nil || accountHash == "" {
		return false, 0, ErrInvalid
	}
	now = now.UTC().Truncate(time.Millisecond)

	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT locked_until_unix_ms FROM login_account_locks WHERE account_hash = ?`,
		Args:        []any{accountHash},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return false, 0, err
	}
	if len(result.Rows) == 0 {
		return false, 0, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return false, 0, ErrInvalid
	}

	lockedUntil, ok := result.Rows[0][0].(int64)
	if !ok {
		return false, 0, ErrInvalid
	}

	if lockedUntil > now.UnixMilli() {
		return true, time.Duration(lockedUntil-now.UnixMilli()) * time.Millisecond, nil
	}
	return false, 0, nil
}

// ClearAccountLock removes an account lock. This should be called when:
// - An administrator manually unlocks the account
// - The lock duration has expired (handled by TTL)
// - A successful login confirms the account owner
func (s *Store) ClearAccountLock(ctx context.Context, accountHash string) error {
	if s == nil || s.db == nil || accountHash == "" {
		return ErrInvalid
	}
	requestID, err := randomRequestID("stuffing-unlock")
	if err != nil {
		return err
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: requestID,
		SQL:       `DELETE FROM login_account_locks WHERE account_hash = ?`,
		Args:      []any{accountHash},
	})
	return err
}

// CleanupStuffingEntries removes expired credential stuffing tracking entries.
// This is intended to be called periodically to prevent unbounded table growth.
func (s *Store) CleanupStuffingEntries(ctx context.Context, now time.Time) (int, error) {
	if s == nil || s.db == nil {
		return 0, ErrInvalid
	}
	now = now.UTC().Truncate(time.Millisecond)
	requestID, err := randomRequestID("stuffing-cleanup")
	if err != nil {
		return 0, err
	}
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: requestID,
		SQL:       `DELETE FROM login_account_ip_failures WHERE expires_at_unix_ms <= ?`,
		Args:      []any{now.UnixMilli()},
	})
	if err != nil {
		return 0, err
	}
	return int(response.RowsAffected), nil
}

// AccountStuffingDigest returns the domain-separated digest for an account identifier.
// Callers should use this to hash the subject before passing to RecordAccountFailure.
func AccountStuffingDigest(subject string) string {
	sum := sha256.Sum256([]byte("login-account/" + subject))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func accountStuffingIPDigest(accountHash, ip string, windowStartUnixMilli int64) string {
	sum := sha256.Sum256([]byte("stuffing-ip/" + accountHash + "/" + ip + "/" + strconv.FormatInt(windowStartUnixMilli, 10)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func ipDigest(ip string) string {
	sum := sha256.Sum256([]byte("ip/" + ip))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
