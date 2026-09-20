// Package backchannel delivers OpenID Connect Back-Channel Logout Tokens.
package backchannel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const responseBodyLimit = 64 << 10

var (
	errEndpointUnsafe     = errors.New("endpoint address is not permitted")
	errEndpointResolution = errors.New("endpoint resolution failed")
)

// Worker delivers one durable logout notification at a time. Its values must
// not be changed after Run begins.
type Worker struct {
	DB             *rhiza.DB
	Issuer         string
	LoadSigningKey func(context.Context) (oidc.SigningKey, error)
	WorkerID       string
	TickInterval   time.Duration
	RetryBase      time.Duration
	LeaseDuration  time.Duration
	RequestTimeout time.Duration
	MaxAttempts    int
	TokenLifetime  time.Duration
	// RootCAs optionally replaces the system roots for HTTPS delivery. A nil
	// pool preserves the system trust store and existing HTTP behavior.
	RootCAs *x509.CertPool
	// RootCAReloader reloads an explicit replacement trust bundle before each
	// delivery, retaining the last known-good bundle if a projected Secret is
	// briefly incomplete or invalid.
	RootCAReloader *RootCAReloader
	// AllowPrivate and AllowHTTP are the current runtime policy ceilings. A
	// durable delivery snapshot can only retain an exception while the current
	// configuration still permits it.
	AllowPrivate bool
	AllowHTTP    bool
	OnError      func(error)
}

type delivery struct {
	eventID      string
	clientID     string
	subject      string
	sid          string
	logoutURI    string
	allowPrivate bool
	allowHTTP    bool
	attempts     int
	leaseToken   string
}

// ValidateEndpoint checks an administratively configured delivery URI without
// resolving host names. Resolution is repeated and pinned immediately before
// every delivery to prevent DNS rebinding.
func ValidateEndpoint(raw string, allowPrivate, allowHTTP bool) error {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return errors.New("backchannel endpoint is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid backchannel endpoint")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return errors.New("backchannel endpoint must use HTTPS")
	}
	if u.Hostname() == "" || invalidPort(u.Port()) {
		return errors.New("invalid backchannel endpoint")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !allowedIP(ip, allowPrivate) {
		return errors.New("backchannel endpoint address is not permitted")
	}
	return nil
}

func invalidPort(port string) bool {
	if port == "" {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err != nil || n == 0
}

// Run reconciles immediately, then at the requested interval. Delivery errors
// are reported and retried; invalid worker configuration is returned.
func (w Worker) Run(ctx context.Context) error {
	if err := w.valid(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	w.stepOrReport(ctx, time.Now().UTC())
	ticker := time.NewTicker(w.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// A tick buffered during a slow pass is already old when it is
			// serviced; attempts and durable timestamps must carry the time the
			// work actually begins.
			w.stepOrReport(ctx, time.Now().UTC())
		}
	}
}

func (w Worker) stepOrReport(ctx context.Context, now time.Time) {
	if err := w.Step(ctx, now); err != nil && ctx.Err() == nil && w.OnError != nil {
		w.OnError(err)
	}
}

// Step claims and delivers at most one due record. A supplied time makes the
// durable state machine deterministic in tests.
func (w Worker) Step(ctx context.Context, now time.Time) error {
	if err := w.valid(); err != nil {
		return err
	}
	if now.IsZero() {
		return errors.New("backchannel delivery time is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now = now.UTC()
	claimStarted := time.Now()
	// The recorded lease and the request budget are derived from this one clock
	// read, so an aged reconciliation time cannot store a lease that ends before
	// the attempt it authorises.
	d, found, err := w.claim(ctx, now, claimStarted.Add(w.LeaseDuration))
	if err != nil || !found {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	allowPrivate := d.allowPrivate && w.AllowPrivate
	allowHTTP := d.allowHTTP && w.AllowHTTP
	if err := ValidateEndpoint(d.logoutURI, allowPrivate, allowHTTP); err != nil {
		return w.complete(ctx, d, now, false, true, "delivery endpoint is not permitted")
	}
	remaining := remainingLease(claimStarted, w.LeaseDuration)
	if remaining <= 0 {
		return w.complete(ctx, d, now, false, false, "delivery lease expired")
	}
	attemptCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	key, err := w.LoadSigningKey(attemptCtx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return w.complete(ctx, d, now, false, false, "logout token signing failed")
	}
	token, err := oidc.SignLogoutToken(key, oidc.LogoutTokenClaims{
		Issuer: w.Issuer, Subject: d.subject, Audience: d.clientID, JTI: stableJTI(d.eventID, d.clientID, d.leaseToken), SessionID: d.sid,
		IssuedAt: now, ExpiresAt: now.Add(w.TokenLifetime),
	})
	if err != nil {
		return w.complete(ctx, d, now, false, false, "logout token signing failed")
	}

	status, retry, permanent, err := w.post(attemptCtx, d, token)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return w.complete(ctx, d, now, false, permanent, "delivery transport failed")
	}
	if status >= 200 && status < 300 {
		return w.complete(ctx, d, now, true, false, "")
	}
	if retry {
		return w.complete(ctx, d, now, false, false, fmt.Sprintf("delivery response %d", status))
	}
	if permanent {
		return w.complete(ctx, d, now, false, true, fmt.Sprintf("delivery response %d", status))
	}
	return w.complete(ctx, d, now, false, false, "delivery transport failed")
}

func remainingLease(claimStarted time.Time, duration time.Duration) time.Duration {
	return duration - time.Since(claimStarted)
}

func (w Worker) valid() error {
	if w.DB == nil || w.Issuer == "" || w.LoadSigningKey == nil || w.WorkerID == "" {
		return errors.New("backchannel worker is not configured")
	}
	if w.TickInterval <= 0 || w.RetryBase <= 0 || w.LeaseDuration <= 0 || w.RequestTimeout <= 0 || w.RequestTimeout >= w.LeaseDuration || w.MaxAttempts <= 0 || w.TokenLifetime <= 0 {
		return errors.New("invalid backchannel worker intervals")
	}
	return nil
}

// claim elects a sender for at most one due record. now is the reconciliation
// time used by the due and expiry predicates; leaseUntil is the lease recorded
// for this attempt, read from the worker clock as the attempt begins.
func (w Worker) claim(ctx context.Context, now, leaseUntil time.Time) (delivery, bool, error) {
	// A local candidate read intentionally permits a stale empty result: the next
	// tick retries it. It never grants a lease; the conditional replicated UPDATE
	// below is the sole winner election, followed by a linearizable winner read.
	result, err := w.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT event_id, client_id, sid, logout_uri, allow_private, allow_http, attempts, subject
		FROM oidc_backchannel_deliveries
		WHERE delivered_at_unix_ms IS NULL AND failed_at_unix_ms IS NULL
			AND next_attempt_at_unix_ms <= ?
			AND (lease_until_unix_ms IS NULL OR lease_until_unix_ms <= ?)
		ORDER BY next_attempt_at_unix_ms, event_id, client_id LIMIT 1`, Args: []any{now.UnixMilli(), now.UnixMilli()}, Consistency: rhiza.ConsistencyLocal})
	if err != nil {
		return delivery{}, false, err
	}
	if len(result.Rows) == 0 {
		return delivery{}, false, nil
	}
	d, err := decodeDelivery(result.Rows[0])
	if err != nil {
		return delivery{}, false, err
	}
	lease, err := randomToken()
	if err != nil {
		return delivery{}, false, err
	}
	lease = w.WorkerID + "." + lease
	requestID, err := randomToken()
	if err != nil {
		return delivery{}, false, err
	}
	response, err := storage.Execute(ctx, w.DB, rhiza.ExecuteRequest{RequestID: "backchannel-claim/" + requestID, SQL: `UPDATE oidc_backchannel_deliveries
		SET lease_token = ?, lease_until_unix_ms = ?
		WHERE event_id = ? AND client_id = ? AND delivered_at_unix_ms IS NULL AND failed_at_unix_ms IS NULL
			AND next_attempt_at_unix_ms <= ? AND (lease_until_unix_ms IS NULL OR lease_until_unix_ms <= ?)`,
		Args: []any{lease, leaseUntil.UnixMilli(), d.eventID, d.clientID, now.UnixMilli(), now.UnixMilli()}})
	if err != nil {
		return delivery{}, false, err
	}
	if response.MutationReceipt.RowsAffected != 1 {
		return delivery{}, false, nil
	}
	winner, err := w.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT event_id, client_id, sid, logout_uri, allow_private, allow_http, attempts, subject
		FROM oidc_backchannel_deliveries WHERE event_id = ? AND client_id = ? AND lease_token = ? LIMIT 1`, Args: []any{d.eventID, d.clientID, lease}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return delivery{}, false, err
	}
	if len(winner.Rows) != 1 {
		return delivery{}, false, nil
	}
	d, err = decodeDelivery(winner.Rows[0])
	if err != nil {
		return delivery{}, false, err
	}
	d.leaseToken = lease
	return d, true, nil
}

func decodeDelivery(row []any) (delivery, error) {
	if len(row) != 8 {
		return delivery{}, errors.New("invalid backchannel delivery row")
	}
	d := delivery{}
	var private, httpAllowed int64
	var ok bool
	if d.eventID, ok = row[0].(string); !ok || d.eventID == "" {
		return delivery{}, errors.New("invalid backchannel delivery row")
	}
	if d.clientID, ok = row[1].(string); !ok || d.clientID == "" {
		return delivery{}, errors.New("invalid backchannel delivery row")
	}
	if row[2] != nil {
		if d.sid, ok = row[2].(string); !ok || d.sid == "" {
			return delivery{}, errors.New("invalid backchannel delivery row")
		}
	}
	if d.logoutURI, ok = row[3].(string); !ok || d.logoutURI == "" {
		return delivery{}, errors.New("invalid backchannel delivery row")
	}
	if private, ok = row[4].(int64); !ok || (private != 0 && private != 1) {
		return delivery{}, errors.New("invalid backchannel delivery row")
	}
	if httpAllowed, ok = row[5].(int64); !ok || (httpAllowed != 0 && httpAllowed != 1) {
		return delivery{}, errors.New("invalid backchannel delivery row")
	}
	if d.attempts, ok = asInt(row[6]); !ok || d.attempts < 0 {
		return delivery{}, errors.New("invalid backchannel delivery row")
	}
	if d.subject, ok = row[7].(string); !ok || (d.sid == "" && d.subject == "") {
		return delivery{}, errors.New("invalid backchannel delivery row")
	}
	d.allowPrivate, d.allowHTTP = private == 1, httpAllowed == 1
	return d, nil
}

func asInt(v any) (int, bool) {
	n, ok := v.(int64)
	if !ok || n > math.MaxInt {
		return 0, false
	}
	return int(n), true
}

func (w Worker) complete(ctx context.Context, d delivery, now time.Time, success, permanent bool, reason string) error {
	requestID, err := randomToken()
	if err != nil {
		return err
	}
	var sql string
	var args []any
	if success {
		sql = `UPDATE oidc_backchannel_deliveries SET attempts = attempts + 1, delivered_at_unix_ms = ?, lease_token = NULL, lease_until_unix_ms = NULL, last_error = NULL
			WHERE event_id = ? AND client_id = ? AND lease_token = ?`
		args = []any{now.UnixMilli(), d.eventID, d.clientID, d.leaseToken}
	} else if permanent || d.attempts+1 >= w.MaxAttempts {
		sql = `UPDATE oidc_backchannel_deliveries SET attempts = attempts + 1, failed_at_unix_ms = ?, lease_token = NULL, lease_until_unix_ms = NULL, last_error = ?
			WHERE event_id = ? AND client_id = ? AND lease_token = ?`
		args = []any{now.UnixMilli(), reason, d.eventID, d.clientID, d.leaseToken}
	} else {
		sql = `UPDATE oidc_backchannel_deliveries SET attempts = attempts + 1, next_attempt_at_unix_ms = ?, lease_token = NULL, lease_until_unix_ms = NULL, last_error = ?
			WHERE event_id = ? AND client_id = ? AND lease_token = ?`
		args = []any{now.Add(w.retryDelay(d)).UnixMilli(), reason, d.eventID, d.clientID, d.leaseToken}
	}
	one := int64(1)
	statement := rhiza.SQLStatement{SQL: sql, Args: args, ExpectedRowsAffected: &one}
	request := rhiza.ExecuteRequest{RequestID: "backchannel-complete/" + requestID, Statements: []rhiza.SQLStatement{statement}}
	if !success && d.attempts+1 >= w.MaxAttempts {
		// Only the lease winner may persist the retry-limit event. RETURNING
		// binds its count to the stored transition, not a stale delivery copy.
		request.Statements[0].SQL += ` RETURNING attempts`
		request.Statements[0].WantRows = true
		request.Statements[0].ExpectedRowsAffected = nil
		request.Statements[0].ExpectedReturnedRows = &one
		// Identity is stable per delivery; SID-only rows retain an empty subject.
		event, eventErr := eventlog.BackchannelFailure(d.eventID+"\x00"+d.clientID, d.clientID, d.subject, 0, now).Statement("1=1")
		if eventErr != nil {
			return eventErr
		}
		event.Args[5] = nil
		event.OutputRefs = []rhiza.SQLStatementOutputRef{{ArgIndex: 5, StatementIndex: 0, ColumnName: "attempts"}}
		request.Statements = append(request.Statements, event)
	}
	_, err = storage.Execute(ctx, w.DB, request)
	if err != nil {
		return err
	}
	return nil
}

func (w Worker) retryDelay(d delivery) time.Duration {
	sum := sha256.Sum256([]byte(d.eventID + "\x00" + d.clientID + "\x00" + strconv.Itoa(d.attempts+1)))
	half := w.RetryBase / 2
	if half == 0 {
		return w.RetryBase
	}
	n := uint64(sum[0])<<56 | uint64(sum[1])<<48 | uint64(sum[2])<<40 | uint64(sum[3])<<32 | uint64(sum[4])<<24 | uint64(sum[5])<<16 | uint64(sum[6])<<8 | uint64(sum[7])
	return w.RetryBase + time.Duration(n%uint64(half+1))
}

func (w Worker) post(ctx context.Context, d delivery, token string) (status int, retry, permanent bool, err error) {
	u, _ := url.Parse(d.logoutURI)
	ip, err := resolveEndpoint(ctx, u, d.allowPrivate && w.AllowPrivate)
	if err != nil {
		return 0, false, errors.Is(err, errEndpointUnsafe), err
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	dialer := &net.Dialer{}
	roots := w.RootCAs
	if w.RootCAReloader != nil {
		if reloadErr := w.RootCAReloader.Reload(); reloadErr != nil && w.OnError != nil {
			w.OnError(fmt.Errorf("reload back-channel CA bundle: %w", reloadErr))
		}
		roots = w.RootCAReloader.Pool()
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if roots != nil {
		tlsConfig.RootCAs = roots.Clone()
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	requestCtx, cancel := context.WithTimeout(ctx, w.RequestTimeout)
	defer cancel()
	form := url.Values{"logout_token": {token}}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, d.logoutURI, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, false, true, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, responseBodyLimit+1))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, false, false, nil
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooEarly || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return resp.StatusCode, true, false, nil
	}
	return resp.StatusCode, false, true, nil
}

func resolveEndpoint(ctx context.Context, u *url.URL, allowPrivate bool) (net.IP, error) {
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		if !allowedIP(ip, allowPrivate) {
			return nil, errEndpointUnsafe
		}
		return ip, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, errEndpointResolution
	}
	for _, ip := range ips {
		resolved := net.IP(ip.AsSlice())
		if allowedIP(resolved, allowPrivate) {
			return resolved, nil
		}
	}
	return nil, errEndpointUnsafe
}

func allowedIP(ip net.IP, allowPrivate bool) bool {
	if ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || isCGNAT(ip) {
		return allowPrivate
	}
	return ip.IsGlobalUnicast()
}

func isCGNAT(ip net.IP) bool {
	ip = ip.To4()
	return ip != nil && ip[0] == 100 && ip[1]&0xc0 == 0x40
}

func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func stableJTI(eventID, clientID, leaseToken string) string {
	sum := sha256.Sum256([]byte(eventID + "\x00" + clientID + "\x00" + leaseToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
