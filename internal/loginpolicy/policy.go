// Package loginpolicy provides replicated brute-force protection for password login.
package loginpolicy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/ipblacklist"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const DefaultSuccessFloor = 2 * time.Second
const maxSuccessMean = 30 * time.Second
const DefaultAttemptWindow = time.Minute
const DefaultAttemptLimit = 20
const PasswordResetAttemptWindow = time.Minute
const PasswordResetAttemptLimit = 5
const OpenRegistrationAttemptWindow = time.Minute
const OpenRegistrationAttemptLimit = 5
const failureIdleTTL = 24 * time.Hour

// A stale reset is trusted for one bounded hour beyond the idle TTL. A larger
// jump needs two observations: the first records a marker without resetting
// failures, and the next confirms the new clock before resetting. This keeps a
// single forward-skewed request from erasing protection while allowing a real
// long-idle IP to recover on its next login.
const maxTrustedStaleAge = failureIdleTTL + time.Hour

var ErrInvalid = errors.New("invalid login policy input")

type Store struct {
	db        *rhiza.DB
	blacklist *ipblacklist.Store
	// Deterministic interposition seam; production leaves this nil.
	beforeFailureMutation func()
}

func NewStore(db *rhiza.DB) *Store { return &Store{db: db} }

// NewStoreWithBlacklist enables automatic failed-login IP blacklisting. The
// blacklist mutation is appended to the failure counter mutation, preserving
// one Rhiza transaction for both pieces of state.
func NewStoreWithBlacklist(db *rhiza.DB, blacklist *ipblacklist.Store) *Store {
	return &Store{db: db, blacklist: blacklist}
}

// PeerIP accepts only the direct TCP peer. Existing callers retain this safe
// default; HTTP handlers that explicitly configure trusted proxies can use
// PeerIPFromRequest.
func PeerIP(remoteAddr string) (string, bool) {
	ip, ok := directPeerIP(remoteAddr)
	if !ok {
		return "", false
	}
	return ip.String(), true
}

// ParseTrustedProxyCIDRs parses the explicit immediate-peer networks allowed
// to supply forwarding headers. An empty list means forwarding is never used.
func ParseTrustedProxyCIDRs(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Addr().Is6() && prefix.Addr().IsLinkLocalUnicast() {
			return nil, ErrInvalid
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

// PeerIPFromRequest returns the direct peer unless it belongs to an explicitly
// trusted proxy network. Trusted peers may supply one unambiguous Forwarded
// header, or (only when Forwarded is absent) one X-Forwarded-For header. Both
// headers, or any malformed trusted-proxy header, fail closed rather than
// silently falling back to an attacker-controlled direct identity.
func PeerIPFromRequest(remoteAddr string, headers http.Header, trustedProxies []netip.Prefix) (string, bool) {
	peer, ok := directPeerIP(remoteAddr)
	if !ok {
		return "", false
	}
	if !isTrustedProxy(peer, trustedProxies) {
		return peer.String(), true
	}
	forwarded, xff := headers.Values("Forwarded"), headers.Values("X-Forwarded-For")
	if len(forwarded) != 0 && len(xff) != 0 {
		return "", false
	}
	if len(forwarded) != 0 {
		ip, ok := forwardedIP(forwarded)
		if !ok {
			return "", false
		}
		return ip.String(), true
	}
	if len(xff) != 0 {
		ip, ok := forwardedForIP(xff, trustedProxies)
		if !ok {
			return "", false
		}
		return ip.String(), true
	}
	return peer.String(), true
}

func directPeerIP(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func isTrustedProxy(peer netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.IsValid() && prefix.Contains(peer) {
			return true
		}
	}
	return false
}

func forwardedIP(values []string) (netip.Addr, bool) {
	if len(values) != 1 || values[0] == "" || strings.Contains(values[0], ",") {
		return netip.Addr{}, false
	}
	var value string
	for _, part := range strings.Split(values[0], ";") {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || key == "" || raw == "" {
			return netip.Addr{}, false
		}
		if !strings.EqualFold(key, "for") {
			continue
		}
		if value != "" {
			return netip.Addr{}, false
		}
		var valid bool
		value, valid = unquoteForwarded(strings.TrimSpace(raw))
		if !valid {
			return netip.Addr{}, false
		}
	}
	if value == "" {
		return netip.Addr{}, false
	}
	return forwardedLiteralIP(value)
}

func forwardedForIP(values []string, trustedProxies []netip.Prefix) (netip.Addr, bool) {
	if len(values) != 1 || values[0] == "" {
		return netip.Addr{}, false
	}
	chain := strings.Split(values[0], ",")
	for index := len(chain) - 1; index >= 0; index-- {
		part := chain[index]
		ip, ok := forwardedLiteralIP(strings.TrimSpace(part))
		if !ok {
			return netip.Addr{}, false
		}
		if !isTrustedProxy(ip, trustedProxies) {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func unquoteForwarded(value string) (string, bool) {
	if !strings.HasPrefix(value, "\"") {
		return value, !strings.ContainsAny(value, " \t\"")
	}
	if len(value) < 2 || !strings.HasSuffix(value, "\"") {
		return "", false
	}
	unquoted, err := strconv.Unquote(value)
	if err != nil || unquoted == "" {
		return "", false
	}
	return unquoted, true
}

func forwardedLiteralIP(value string) (netip.Addr, bool) {
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end < 1 || (len(value) != end+1 && !validPort(value[end+1:])) {
			return netip.Addr{}, false
		}
		value = value[1:end]
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		return ip.Unmap(), true
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || !validPort(":"+port) {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Is6() {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func validPort(value string) bool {
	if !strings.HasPrefix(value, ":") {
		return false
	}
	port, err := strconv.ParseUint(value[1:], 10, 16)
	return err == nil && port <= 65535
}

type Status struct {
	Failures     int64
	BlockedUntil time.Time
	Mean         time.Duration
}

// Allow reserves an attempt before Argon work. It is intentionally consumed
// by successful attempts too, so cross-pod bursts cannot bypass the quota.
func (s *Store) Allow(ctx context.Context, ip string, now time.Time) (bool, error) {
	if s == nil || s.db == nil || ip == "" {
		return false, ErrInvalid
	}
	now = now.UTC().Truncate(time.Millisecond)
	windowStart := now.UnixMilli() / DefaultAttemptWindow.Milliseconds() * DefaultAttemptWindow.Milliseconds()
	expiresAt := windowStart + DefaultAttemptWindow.Milliseconds()*2
	requestID, err := randomRequestID("login-attempt")
	if err != nil {
		return false, err
	}
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)
		ON CONFLICT(key_digest) DO UPDATE SET window_start_unix_ms = excluded.window_start_unix_ms,
		count = CASE WHEN oauth_rate_limits.window_start_unix_ms = excluded.window_start_unix_ms THEN oauth_rate_limits.count + 1 ELSE 1 END,
		expires_at_unix_ms = excluded.expires_at_unix_ms,
		last_window_at_unix_ms = excluded.last_window_at_unix_ms
		WHERE oauth_rate_limits.window_start_unix_ms != excluded.window_start_unix_ms OR oauth_rate_limits.count < ?`, Args: []any{digest("attempt/" + ip), windowStart, expiresAt, now.UnixMilli(), int64(DefaultAttemptLimit)}})
	if err != nil {
		return false, err
	}
	return response.RowsAffected == 1, nil
}

// AllowPasswordReset reserves one bounded reset attempt per canonical direct
// peer IP. Its domain-separated key cannot consume the login-attempt quota.
func (s *Store) AllowPasswordReset(ctx context.Context, ip string, now time.Time) (bool, error) {
	return s.allowBounded(ctx, ip, now, "password-reset-attempt", passwordResetDigest(ip), PasswordResetAttemptWindow, PasswordResetAttemptLimit)
}

// AllowOpenRegistration reserves a domain-separated public registration
// attempt. It never trusts forwarding headers; callers supply the direct peer.
func (s *Store) AllowOpenRegistration(ctx context.Context, ip string, now time.Time) (bool, error) {
	return s.allowBounded(ctx, ip, now, "open-registration-attempt", openRegistrationDigest(ip), OpenRegistrationAttemptWindow, OpenRegistrationAttemptLimit)
}

func (s *Store) allowBounded(ctx context.Context, ip string, now time.Time, requestPrefix, key string, window time.Duration, limit int) (bool, error) {
	if s == nil || s.db == nil || !canonicalIP(ip) {
		return false, ErrInvalid
	}
	now = now.UTC().Truncate(time.Millisecond)
	windowStart := now.UnixMilli() / window.Milliseconds() * window.Milliseconds()
	expiresAt := windowStart + window.Milliseconds()*2
	requestID, err := randomRequestID(requestPrefix)
	if err != nil {
		return false, err
	}
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)
		ON CONFLICT(key_digest) DO UPDATE SET window_start_unix_ms = excluded.window_start_unix_ms,
		count = CASE WHEN oauth_rate_limits.window_start_unix_ms = excluded.window_start_unix_ms THEN oauth_rate_limits.count + 1 ELSE 1 END,
		expires_at_unix_ms = excluded.expires_at_unix_ms,
		last_window_at_unix_ms = excluded.last_window_at_unix_ms
		WHERE oauth_rate_limits.window_start_unix_ms != excluded.window_start_unix_ms OR oauth_rate_limits.count < ?`, Args: []any{key, windowStart, expiresAt, now.UnixMilli(), int64(limit)}})
	if err != nil {
		return false, err
	}
	return response.RowsAffected == 1, nil
}

func (s *Store) Check(ctx context.Context, ip string, now time.Time) (Status, error) {
	if s == nil || s.db == nil || ip == "" {
		return Status{}, ErrInvalid
	}
	status := Status{Mean: DefaultSuccessFloor}
	key := digest(ip)
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT failures,blocked_until_unix_ms,updated_at_unix_ms FROM login_ip_failures WHERE key_digest = ?`, Args: []any{key}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Status{}, err
	}
	if len(result.Rows) == 1 && len(result.Rows[0]) == 3 {
		failures, failuresOK := result.Rows[0][0].(int64)
		until, untilOK := result.Rows[0][1].(int64)
		updated, updatedOK := result.Rows[0][2].(int64)
		if !failuresOK || !untilOK || !updatedOK || failures < 0 {
			return Status{}, ErrInvalid
		}
		nowMs := now.UTC().Truncate(time.Millisecond).UnixMilli()
		if nowMs < updated {
			return Status{}, ErrInvalid
		}
		if updated <= nowMs-failureIdleTTL.Milliseconds() {
			return s.withMean(ctx, status)
		}
		status.Failures = failures
		if until > nowMs {
			status.BlockedUntil = time.UnixMilli(until).UTC()
		}
	} else if len(result.Rows) != 0 {
		return Status{}, ErrInvalid
	}
	return s.withMean(ctx, status)
}

// Failure atomically increments the direct-peer failure counter and assigns a
// Rauthy-compatible block duration at the documented thresholds.
func (s *Store) Failure(ctx context.Context, ip string, now time.Time) (Status, error) {
	if s == nil || s.db == nil || !canonicalIP(ip) {
		return Status{}, ErrInvalid
	}
	now = now.UTC().Truncate(time.Millisecond)
	if err := s.validateFailureClock(ctx, digest(ip), now.UnixMilli()); err != nil {
		return Status{}, err
	}
	if s.beforeFailureMutation != nil {
		s.beforeFailureMutation()
	}
	requestID, err := randomRequestID("login-failure")
	if err != nil {
		return Status{}, err
	}
	request := rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{{SQL: `INSERT INTO login_ip_failures (key_digest,failures,blocked_until_unix_ms,updated_at_unix_ms)
		VALUES (?, 1, 0, ?)
		ON CONFLICT(key_digest) DO UPDATE SET failures = CASE
			WHEN login_ip_failures.updated_at_unix_ms > 0 AND login_ip_failures.blocked_until_unix_ms = login_ip_failures.updated_at_unix_ms AND excluded.updated_at_unix_ms > login_ip_failures.updated_at_unix_ms THEN 1
			WHEN login_ip_failures.updated_at_unix_ms > 0 AND login_ip_failures.blocked_until_unix_ms = login_ip_failures.updated_at_unix_ms THEN login_ip_failures.failures
			WHEN login_ip_failures.updated_at_unix_ms <= ? AND login_ip_failures.updated_at_unix_ms > ? THEN 1
			WHEN login_ip_failures.updated_at_unix_ms <= ? THEN login_ip_failures.failures
			ELSE login_ip_failures.failures + 1 END,
		blocked_until_unix_ms = CASE
			WHEN login_ip_failures.updated_at_unix_ms > 0 AND login_ip_failures.blocked_until_unix_ms = login_ip_failures.updated_at_unix_ms AND excluded.updated_at_unix_ms > login_ip_failures.updated_at_unix_ms THEN 0
			WHEN login_ip_failures.updated_at_unix_ms > 0 AND login_ip_failures.blocked_until_unix_ms = login_ip_failures.updated_at_unix_ms THEN login_ip_failures.blocked_until_unix_ms
			WHEN login_ip_failures.updated_at_unix_ms <= ? AND login_ip_failures.updated_at_unix_ms > ? THEN 0
			WHEN login_ip_failures.updated_at_unix_ms <= ? THEN excluded.updated_at_unix_ms
			WHEN login_ip_failures.failures + 1 >= 25 THEN ?
			WHEN login_ip_failures.failures + 1 = 20 THEN ?
			WHEN login_ip_failures.failures + 1 = 15 THEN ?
			WHEN login_ip_failures.failures + 1 = 10 THEN ?
			WHEN login_ip_failures.failures + 1 = 7 THEN ?
			ELSE login_ip_failures.blocked_until_unix_ms END,
		updated_at_unix_ms = MAX(login_ip_failures.updated_at_unix_ms, excluded.updated_at_unix_ms)
		WHERE login_ip_failures.updated_at_unix_ms <= excluded.updated_at_unix_ms`, Args: []any{digest(ip), now.UnixMilli(), now.Add(-failureIdleTTL).UnixMilli(), now.Add(-maxTrustedStaleAge).UnixMilli(), now.Add(-failureIdleTTL).UnixMilli(), now.Add(-failureIdleTTL).UnixMilli(), now.Add(-maxTrustedStaleAge).UnixMilli(), now.Add(-failureIdleTTL).UnixMilli(), now.Add(24 * time.Hour).UnixMilli(), now.Add(time.Hour).UnixMilli(), now.Add(15 * time.Minute).UnixMilli(), now.Add(10 * time.Minute).UnixMilli(), now.Add(time.Minute).UnixMilli()}}}}
	one := int64(1)
	// RETURNING binds the event to this committed increment, not a later
	// concurrent count observed by Check. Upstream caps its wire count at u32.
	request.Statements[0].SQL += ` RETURNING MIN(failures,4294967295) AS failures,
		CASE WHEN failures>=20 THEN 3 WHEN failures>=10 THEN 2 WHEN failures>=7 THEN 1 ELSE 0 END AS level`
	request.Statements[0].WantRows = true
	request.Statements[0].ExpectedReturnedRows = &one
	invalidEvent, eventErr := eventlog.InvalidLogin(requestID, ip, 0, now).Statement("1=1")
	if eventErr != nil {
		return Status{}, eventErr
	}
	// Event.Statement binds level at argument 2 and data at argument 5.
	invalidEvent.Args[2], invalidEvent.Args[5] = nil, nil
	invalidEvent.OutputRefs = []rhiza.SQLStatementOutputRef{
		{ArgIndex: 2, StatementIndex: 0, ColumnName: "level"},
		{ArgIndex: 5, StatementIndex: 0, ColumnName: "failures"},
	}
	request.Statements = append(request.Statements, invalidEvent)
	if s.blacklist != nil {
		prefix, prefixErr := ipblacklist.AutomaticFailurePrefix(ip)
		if prefixErr != nil {
			return Status{}, ErrInvalid
		}
		failureKey := digest(ip)
		prune, pruneErr := s.blacklist.AutomaticExpiryPruneStatement(now, failureKey)
		if pruneErr != nil {
			return Status{}, pruneErr
		}
		request.Statements = append(request.Statements, prune)
		statement, statementErr := s.blacklist.AutomaticFailureStatement(prefix, failureKey, now)
		if statementErr != nil {
			return Status{}, statementErr
		}
		request.Statements = append(request.Statements, statement)
		// A scalar projection always returns one row; NULL means no finite
		// automatic block was admitted. Bind its value inside this transaction,
		// never from a separate pre/post-commit read or a second expiry formula.
		projectionIndex := len(request.Statements)
		request.Statements = append(request.Statements, rhiza.SQLStatement{
			SQL: `SELECT (SELECT b.expires_at_unix_ms / 1000 FROM ip_blacklist_entries b
				JOIN login_ip_failures f ON f.key_digest=? WHERE b.prefix=?
				AND f.updated_at_unix_ms=? AND f.blocked_until_unix_ms>?
				AND (f.failures IN (7,10,15,20) OR f.failures>=25)) AS expiry`,
			Args: []any{failureKey, prefix, now.UnixMilli(), now.UnixMilli()}, WantRows: true, ExpectedReturnedRows: &one,
		})
		event := eventlog.IPBlacklisted(requestID, ip, 0, now)
		eventStatement, eventErr := event.Statement("? IS NOT NULL", nil)
		if eventErr != nil {
			return Status{}, eventErr
		}
		// Event.Statement binds data at argument 5; the condition arg is the final element.
		eventStatement.Args[5] = nil
		eventStatement.Args[len(eventStatement.Args)-1] = nil
		eventStatement.OutputRefs = []rhiza.SQLStatementOutputRef{
			{ArgIndex: 5, StatementIndex: projectionIndex, ColumnName: "expiry"},
			{ArgIndex: len(eventStatement.Args) - 1, StatementIndex: projectionIndex, ColumnName: "expiry"},
		}
		request.Statements = append(request.Statements, eventStatement)
	}
	_, err = storage.Execute(ctx, s.db, request)
	if err != nil {
		return Status{}, err
	}
	return s.Check(ctx, ip, now)
}

func (s *Store) validateFailureClock(ctx context.Context, key string, nowMs int64) error {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT updated_at_unix_ms FROM login_ip_failures WHERE key_digest = ?`, Args: []any{key}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) == 0 {
		return nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return ErrInvalid
	}
	updated, ok := result.Rows[0][0].(int64)
	if !ok || updated < 0 || nowMs < updated {
		return ErrInvalid
	}
	return nil
}

// Success updates only the replicated successful-login timing floor. Failure
// state is never cleared by a valid password because an attacker that knows
// one account must not reset the IP's attack state against another account.
func (s *Store) Success(ctx context.Context, ip string, elapsed time.Duration) error {
	if s == nil || s.db == nil || ip == "" || elapsed < 0 {
		return ErrInvalid
	}
	requestID, err := randomRequestID("login-success")
	if err != nil {
		return err
	}
	mean := elapsed.Milliseconds()
	if mean < 1 {
		mean = 1
	}
	if mean > maxSuccessMean.Milliseconds() {
		mean = maxSuccessMean.Milliseconds()
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO login_timing (id,success_mean_unix_ms) VALUES (1, ?)
			ON CONFLICT(id) DO UPDATE SET success_mean_unix_ms = (login_timing.success_mean_unix_ms + excluded.success_mean_unix_ms) / 2`, Args: []any{mean}},
	}})
	return err
}

func (s *Store) withMean(ctx context.Context, status Status) (Status, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT success_mean_unix_ms FROM login_timing WHERE id = 1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Status{}, err
	}
	if len(result.Rows) == 0 {
		return status, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return Status{}, ErrInvalid
	}
	mean, ok := result.Rows[0][0].(int64)
	if !ok || mean < 1 || mean > maxSuccessMean.Milliseconds() {
		return Status{}, ErrInvalid
	}
	status.Mean = time.Duration(mean) * time.Millisecond
	return status, nil
}

func Delay(status Status, elapsed time.Duration) time.Duration {
	if !status.BlockedUntil.IsZero() {
		return 0
	}
	base := status.Mean - elapsed
	if base < 0 {
		base = 0
	}
	var extra time.Duration
	switch {
	case status.Failures > 20:
		extra = time.Duration(status.Failures) * 20 * time.Second
	case status.Failures > 15:
		extra = time.Duration(status.Failures) * 15 * time.Second
	case status.Failures > 10:
		extra = time.Duration(status.Failures) * 10 * time.Second
	case status.Failures > 7:
		extra = time.Duration(status.Failures) * 5 * time.Second
	case status.Failures >= 5:
		extra = time.Duration(status.Failures) * 3 * time.Second
	case status.Failures >= 3:
		extra = time.Duration(status.Failures) * 2 * time.Second
	}
	return base + extra
}

func digest(value string) string {
	sum := sha256.Sum256([]byte("login-ip/" + value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func passwordResetDigest(ip string) string {
	sum := sha256.Sum256([]byte("password-reset/" + ip))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func openRegistrationDigest(ip string) string {
	sum := sha256.Sum256([]byte("open-registration/" + ip))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func canonicalIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.String() == ip
}

func randomRequestID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("random login mutation: %w", err)
	}
	return prefix + "/" + base64.RawURLEncoding.EncodeToString(value), nil
}
