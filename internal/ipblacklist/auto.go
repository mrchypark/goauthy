package ipblacklist

import (
	"net/netip"
	"time"

	"github.com/mrchypark/rhiza"
)

// AutomaticFailureStatement returns the blacklist upsert used by the login
// policy's failure transaction. The failure counter is read after its update,
// so callers can append this statement to the same Rhiza mutation.
//
// The key digest is deliberately supplied by the caller: the blacklist
// package must not own or duplicate login-policy key derivation.
func (s *Store) AutomaticFailureStatement(prefix, failureKeyDigest string, now time.Time) (rhiza.SQLStatement, error) {
	if s == nil || s.db == nil || failureKeyDigest == "" {
		return rhiza.SQLStatement{}, ErrInvalid
	}
	p, err := CanonicalPrefix(prefix)
	if err != nil || (p.Bits() != 32 && p.Bits() != 128) {
		return rhiza.SQLStatement{}, ErrInvalid
	}
	nowMs := now.UTC().Truncate(time.Millisecond).UnixMilli()
	// A full table still permits refreshing an existing prefix. Permanent
	// manual entries remain permanent; finite entries are only extended.
	return rhiza.SQLStatement{
		SQL: `INSERT INTO ip_blacklist_entries(prefix, note, expires_at_unix_ms, created_at_unix_ms, updated_at_unix_ms)
			SELECT ?, '', ? + CASE
				WHEN failures >= 25 THEN 86400000
				WHEN failures >= 20 THEN 3600000
				WHEN failures >= 15 THEN 900000
				WHEN failures >= 10 THEN 600000
				WHEN failures >= 7 THEN 60000
				ELSE 0 END, ?, ?
			FROM login_ip_failures
			WHERE key_digest = ? AND (failures IN (7, 10, 15, 20) OR failures >= 25)
				AND updated_at_unix_ms = ? AND blocked_until_unix_ms > ?
				AND ((SELECT COUNT(*) FROM ip_blacklist_entries) < ?
					OR EXISTS (SELECT 1 FROM ip_blacklist_entries WHERE prefix = ?))
			ON CONFLICT(prefix) DO UPDATE SET
				expires_at_unix_ms = CASE
					WHEN ip_blacklist_entries.expires_at_unix_ms IS NULL THEN NULL
					WHEN ip_blacklist_entries.expires_at_unix_ms >= excluded.expires_at_unix_ms THEN ip_blacklist_entries.expires_at_unix_ms
					ELSE excluded.expires_at_unix_ms END,
				updated_at_unix_ms = MAX(ip_blacklist_entries.updated_at_unix_ms, excluded.updated_at_unix_ms)`,
		Args: []any{p.String(), nowMs, nowMs, nowMs, failureKeyDigest, nowMs, nowMs, int64(s.maxEntries), p.String()},
	}, nil
}

// AutomaticExpiryPruneStatement removes expired finite entries immediately
// before an automatic admission. Permanent manual entries have NULL expiry
// and are never touched.
func (s *Store) AutomaticExpiryPruneStatement(now time.Time, failureKeyDigest string) (rhiza.SQLStatement, error) {
	if s == nil || s.db == nil || failureKeyDigest == "" {
		return rhiza.SQLStatement{}, ErrInvalid
	}
	return rhiza.SQLStatement{
		SQL: `DELETE FROM ip_blacklist_entries
			WHERE expires_at_unix_ms IS NOT NULL AND expires_at_unix_ms <= ?
				AND EXISTS (SELECT 1 FROM login_ip_failures
					WHERE key_digest = ? AND (failures IN (7, 10, 15, 20) OR failures >= 25)
					AND updated_at_unix_ms = ? AND blocked_until_unix_ms > ?)`,
		Args: []any{now.UTC().Truncate(time.Millisecond).UnixMilli(), failureKeyDigest, now.UnixMilli(), now.UnixMilli()},
	}, nil
}

// AutomaticFailurePrefix canonicalizes a client address as an exact host
// prefix. IPv4-mapped IPv6 addresses are normalized to IPv4 /32 entries.
func AutomaticFailurePrefix(rawIP string) (string, error) {
	ip, err := netip.ParseAddr(rawIP)
	if err != nil || !ip.IsValid() || ip.IsUnspecified() {
		return "", ErrInvalid
	}
	ip = ip.Unmap()
	bits := 128
	if ip.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(ip, bits).String(), nil
}
