// Package device stores RFC 8628 device authorization state in Rhiza.
package device

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	DefaultExpiry   = 10 * time.Minute
	DefaultInterval = 5 * time.Second
	claimLease      = 30 * time.Second
	StatusPending   = "pending"
	StatusSlowDown  = "slow_down"
	StatusDenied    = "denied"
	StatusExpired   = "expired"
	StatusClaimed   = "claimed"
)

var ErrInvalid = errors.New("invalid device grant")
var ErrInvalidTarget = errors.New("invalid resource target")

type Grant struct {
	DeviceCode, UserCode string
	ExpiresAt            time.Time
	Interval             time.Duration
}
type PollResult struct {
	MFAVerified                                          bool
	Status, ClaimToken, Subject, ManagedClientGeneration string
	Resource                                             string
	Scopes                                               []string
}
type Store struct {
	db  *rhiza.DB
	now func() time.Time
}

func NewStore(db *rhiza.DB) *Store { return &Store{db: db, now: time.Now} }

// User codes use uppercase Crockford-like characters, grouped as XXXX-XXXX-XX.
// Input normalization ignores ASCII spaces and hyphens and folds ASCII letters
// to uppercase before hashing, so users can type the displayed code naturally.
func NormalizeUserCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "", "\n", "", "\r", "").Replace(code))
}

func (s *Store) Create(ctx context.Context, clientID string, scopes []string, now time.Time) (Grant, error) {
	return s.create(ctx, clientID, scopes, ClientBinding{}, now)
}

// CreateWithBinding persists only the exact managed policy authenticated by
// the HTTP request. Bootstrap and DCR clients use the zero binding.
func (s *Store) CreateWithBinding(ctx context.Context, clientID string, scopes []string, binding ClientBinding, now time.Time) (Grant, error) {
	return s.create(ctx, clientID, scopes, binding, now)
}

func (s *Store) create(ctx context.Context, clientID string, scopes []string, binding ClientBinding, now time.Time) (Grant, error) {
	managed := binding.ID != "" || binding.Generation != "" || binding.Revision != 0
	if s == nil || s.db == nil || clientID == "" || len(scopes) > 32 || managed && (binding.ID != clientID || binding.Generation == "" || binding.Revision < 1) {
		return Grant{}, ErrInvalid
	}
	if !validResourceOrEmpty(binding.Resource) {
		return Grant{}, ErrInvalidTarget
	}
	encodedScopes, err := json.Marshal(scopes)
	if err != nil {
		return Grant{}, err
	}
	now = now.UTC().Truncate(time.Millisecond)
	for i := 0; i < 4; i++ {
		deviceCode, err := randomCode(32)
		if err != nil {
			return Grant{}, err
		}
		userCode, err := randomUserCode()
		if err != nil {
			return Grant{}, err
		}
		deviceDigest, userDigest := digest(deviceCode), digest(NormalizeUserCode(userCode))
		grant := Grant{DeviceCode: deviceCode, UserCode: userCode, ExpiresAt: now.Add(DefaultExpiry), Interval: DefaultInterval}
		id := "device-create/" + deviceDigest[:24]
		generation := nilIfEmpty(binding.Generation)
		response, execErr := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: id, SQL: `INSERT INTO oauth_device_grants
			(device_code_digest,user_code_digest,client_id,managed_client_generation,resource,scopes_json,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms)
			SELECT ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ? WHERE
			((? IS NULL AND NOT EXISTS (SELECT 1 FROM managed_oauth_clients WHERE id=?)) OR
			 (? IS NOT NULL AND EXISTS (SELECT 1 FROM managed_oauth_clients WHERE id=? AND generation=? AND revision=? AND enabled=1 AND deleted=0)))`, Args: []any{deviceDigest, userDigest, clientID, generation, nilIfEmpty(binding.Resource), string(encodedScopes), grant.ExpiresAt.UnixMilli(), int64(DefaultInterval / time.Second), now.UnixMilli(), now.UnixMilli(), generation, clientID, generation, clientID, binding.Generation, binding.Revision}})
		err = execErr
		if err == nil && response.RowsAffected != 1 {
			err = ErrInvalid
		}
		if err == nil {
			return grant, nil
		}
		recovered, collision, reconcileErr := s.recoverCreate(ctx, deviceDigest, userDigest, clientID, binding.Generation, binding.Resource, string(encodedScopes), grant)
		if reconcileErr != nil {
			return Grant{}, err
		}
		if recovered {
			return grant, nil
		}
		if !collision {
			return Grant{}, err
		}
	}
	return Grant{}, fmt.Errorf("%w: code collision", ErrInvalid)
}

// recoverCreate distinguishes a replicated commit whose response was lost from
// an actual digest collision. It never turns infrastructure failures into an
// apparently harmless collision.
func (s *Store) recoverCreate(ctx context.Context, deviceDigest, userDigest, clientID, generation, resource, scopes string, grant Grant) (recovered, collision bool, err error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT device_code_digest,user_code_digest,client_id,managed_client_generation,resource,scopes_json,expires_at_unix_ms,interval_seconds
		FROM oauth_device_grants WHERE device_code_digest = ? OR user_code_digest = ?`, Args: []any{deviceDigest, userDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, false, err
	}
	if len(result.Rows) == 0 {
		return false, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 8 {
		return false, true, nil
	}
	row := result.Rows[0]
	storedDevice, deviceOK := row[0].(string)
	storedUser, userOK := row[1].(string)
	storedClient, clientOK := row[2].(string)
	storedGeneration, generationOK := row[3].(string)
	storedResource, resourceOK := row[4].(string)
	if row[4] == nil {
		storedResource, resourceOK = "", true
	}
	storedScopes, scopesOK := row[5].(string)
	expires, expiresOK := row[6].(int64)
	interval, intervalOK := row[7].(int64)
	if (generationOK || row[3] == nil) && deviceOK && userOK && clientOK && resourceOK && scopesOK && expiresOK && intervalOK && storedDevice == deviceDigest && storedUser == userDigest && storedClient == clientID && (storedGeneration == generation || row[3] == nil && generation == "") && storedResource == resource && storedScopes == scopes && expires == grant.ExpiresAt.UnixMilli() && interval == int64(DefaultInterval/time.Second) {
		return true, false, nil
	}
	return false, true, nil
}

func (s *Store) Approve(ctx context.Context, userCode, subject string, now time.Time) error {
	return s.ApproveWithMFA(ctx, userCode, subject, false, now)
}

// ApproveWithMFA accepts evidence only from the server's authenticated browser session.
func (s *Store) ApproveWithMFA(ctx context.Context, userCode, subject string, mfa bool, now time.Time) error {
	return s.decide(ctx, userCode, subject, "approved", mfa, now)
}
func (s *Store) Deny(ctx context.Context, userCode string, now time.Time) error {
	return s.decide(ctx, userCode, "", "denied", false, now)
}
func (s *Store) decide(ctx context.Context, userCode, subject, state string, mfa bool, now time.Time) error {
	if s == nil || s.db == nil || NormalizeUserCode(userCode) == "" || (state == "approved" && subject == "") {
		return ErrInvalid
	}
	d := digest(NormalizeUserCode(userCode))
	now = now.UTC().Truncate(time.Millisecond)
	id := "device-decide/" + d[:20] + "/" + state + fmt.Sprint(now.UnixMilli(), "/", mfa)
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: id, SQL: `UPDATE oauth_device_grants SET state = ?, subject = ?, decision_attempt = ?, mfa_verified = ?, claim_token_digest = NULL, claim_until_unix_ms = NULL
		WHERE user_code_digest = ? AND state = 'pending' AND expires_at_unix_ms > ?
 AND (? = 'denied' OR ? = 1 OR NOT EXISTS (SELECT 1 FROM managed_oauth_clients c WHERE c.id=oauth_device_grants.client_id AND c.force_mfa=1))`, Args: []any{state, nilIfEmpty(subject), id, mfa, d, now.UnixMilli(), state, mfa}})
	if err != nil {
		if s.decisionApplied(ctx, d, state, subject, id, now) {
			return nil
		}
		return err
	}
	if response.RowsAffected != 0 {
		return nil
	}
	return ErrInvalid
}

func (s *Store) decisionApplied(ctx context.Context, userDigest, state, subject, attempt string, now time.Time) bool {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state,subject,decision_attempt,expires_at_unix_ms FROM oauth_device_grants WHERE user_code_digest = ?`, Args: []any{userDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return false
	}
	actual, ok := result.Rows[0][0].(string)
	if !ok {
		return false
	}
	if actual != state {
		return false
	}
	storedAttempt, ok := result.Rows[0][2].(string)
	if !ok || storedAttempt != attempt {
		return false
	}
	if state == "approved" {
		got, ok := result.Rows[0][1].(string)
		if !ok || got != subject {
			return false
		}
	}
	expires, ok := result.Rows[0][3].(int64)
	if !ok || expires <= now.UnixMilli() {
		return false
	}
	return true
}

// Allow applies a fixed-window, distributed quota. It hashes the caller key
// before it reaches Rhiza; callers must pass a stable composite key such as
// a direct peer address plus client ID, never an untrusted forwarding header.
func (s *Store) Allow(ctx context.Context, key string, now time.Time, window time.Duration, limit int) (bool, error) {
	if s == nil || s.db == nil || key == "" || window <= 0 || window.Milliseconds() <= 0 || limit <= 0 {
		return false, ErrInvalid
	}
	now = now.UTC().Truncate(time.Millisecond)
	windowMS := window.Milliseconds()
	windowStart := now.UnixMilli() / windowMS * windowMS
	expiresAt := windowStart + windowMS*2
	requestEntropy, err := randomCode(16)
	if err != nil {
		return false, err
	}
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "device-rate/" + requestEntropy, SQL: `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)
		ON CONFLICT(key_digest) DO UPDATE SET window_start_unix_ms = excluded.window_start_unix_ms,
		count = CASE WHEN oauth_rate_limits.window_start_unix_ms = excluded.window_start_unix_ms THEN oauth_rate_limits.count + 1 ELSE 1 END,
		expires_at_unix_ms = excluded.expires_at_unix_ms,
		last_window_at_unix_ms = excluded.last_window_at_unix_ms
		WHERE oauth_rate_limits.window_start_unix_ms != excluded.window_start_unix_ms OR oauth_rate_limits.count < ?`, Args: []any{digest(key), windowStart, expiresAt, now.UnixMilli(), int64(limit)}})
	if err != nil {
		return false, err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT window_start_unix_ms,count FROM oauth_rate_limits WHERE key_digest = ?`, Args: []any{digest(key)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return false, ErrInvalid
	}
	storedWindow, windowOK := result.Rows[0][0].(int64)
	count, countOK := result.Rows[0][1].(int64)
	if !windowOK || !countOK || storedWindow != windowStart || count < 1 || count > int64(limit) {
		return false, ErrInvalid
	}
	return response.RowsAffected != 0, nil
}

func (s *Store) Poll(ctx context.Context, deviceCode, clientID string, now time.Time) (PollResult, error) {
	if s == nil || s.db == nil || deviceCode == "" || clientID == "" {
		return PollResult{}, ErrInvalid
	}
	d := digest(deviceCode)
	now = now.UTC().Truncate(time.Millisecond)
	row, ok, err := s.load(ctx, d, clientID)
	if err != nil {
		return PollResult{}, err
	}
	if !ok || row.expires <= now.UnixMilli() {
		return PollResult{Status: StatusExpired}, nil
	}
	switch row.state {
	case "denied":
		return PollResult{Status: StatusDenied}, nil
	case "consumed":
		return PollResult{Status: StatusExpired}, nil
	case "pending":
		interval := row.interval
		status := StatusPending
		if now.UnixMilli() < row.nextPoll {
			interval += 5
			status = StatusSlowDown
		}
		next := now.Add(time.Duration(interval) * time.Second).UnixMilli()
		if next < row.nextPoll {
			next = row.nextPoll
		}
		id := "device-poll/" + d[:20] + "/" + fmt.Sprint(now.UnixMilli(), "/", row.nextPoll, "/", row.interval)
		response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: id, SQL: `UPDATE oauth_device_grants SET next_poll_at_unix_ms = ?, interval_seconds = ? WHERE device_code_digest = ? AND client_id = ? AND state = 'pending' AND expires_at_unix_ms > ? AND next_poll_at_unix_ms = ? AND interval_seconds = ?`, Args: []any{next, int64(interval), d, clientID, now.UnixMilli(), row.nextPoll, row.interval}})
		if err != nil {
			return PollResult{}, err
		}
		if response.RowsAffected == 0 {
			return PollResult{Status: StatusSlowDown}, nil
		}
		fresh, ok, err := s.load(ctx, d, clientID)
		if err != nil {
			return PollResult{}, err
		}
		if !ok || fresh.expires <= now.UnixMilli() || fresh.state == "consumed" {
			return PollResult{Status: StatusExpired}, nil
		}
		if fresh.state == "denied" {
			return PollResult{Status: StatusDenied}, nil
		}
		if fresh.state != "pending" {
			return PollResult{Status: StatusSlowDown}, nil
		}
		if fresh.nextPoll >= next && fresh.interval >= interval {
			return PollResult{Status: status}, nil
		}
		if now.UnixMilli() < fresh.nextPoll {
			return PollResult{Status: StatusSlowDown}, nil
		}
		return PollResult{Status: StatusPending}, nil
	case "approved":
		if row.claimUntil > now.UnixMilli() {
			return PollResult{Status: StatusSlowDown}, nil
		}
		token, err := randomCode(32)
		if err != nil {
			return PollResult{}, err
		}
		td := digest(token)
		until := now.Add(claimLease).UnixMilli()
		id := "device-claim/" + d[:20] + "/" + td[:16]
		_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: id, SQL: `UPDATE oauth_device_grants SET claim_token_digest = ?, claim_until_unix_ms = ? WHERE device_code_digest = ? AND client_id = ? AND state = 'approved' AND expires_at_unix_ms > ? AND (claim_until_unix_ms IS NULL OR claim_until_unix_ms <= ?)`, Args: []any{td, until, d, clientID, now.UnixMilli(), now.UnixMilli()}})
		if err != nil {
			return PollResult{}, err
		}
		// The predicate can lose a cross-pod race; only return a token after a
		// linearizable read proves that this exact claim owns the lease.
		fresh, ok, err := s.load(ctx, d, clientID)
		if err != nil {
			return PollResult{}, err
		}
		if !ok || fresh.claim != td {
			return PollResult{Status: StatusSlowDown}, nil
		}
		return PollResult{Status: StatusClaimed, ClaimToken: token, Subject: fresh.subject, MFAVerified: fresh.mfa, Scopes: fresh.scopes, ManagedClientGeneration: fresh.generation, Resource: fresh.resource}, nil
	}
	return PollResult{Status: StatusExpired}, nil
}

func (s *Store) Complete(ctx context.Context, claimToken string, success bool, now time.Time) error {
	if s == nil || s.db == nil || claimToken == "" {
		return ErrInvalid
	}
	d := digest(claimToken)
	now = now.UTC().Truncate(time.Millisecond)
	state := "approved"
	if success {
		state = "consumed"
	}
	id := "device-complete/" + d[:20] + "/" + state
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: id, SQL: `UPDATE oauth_device_grants SET state = ?, claim_token_digest = NULL, claim_until_unix_ms = NULL WHERE claim_token_digest = ? AND claim_until_unix_ms > ? AND state = 'approved'`, Args: []any{state, d, now.UnixMilli()}})
	return err
}

type row struct {
	mfa                                         bool
	state, subject, claim, generation, resource string
	scopes                                      []string
	expires, nextPoll, claimUntil, interval     int64
}

func (s *Store) load(ctx context.Context, d, client string) (row, bool, error) {
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state,subject,managed_client_generation,resource,scopes_json,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,claim_token_digest,claim_until_unix_ms,mfa_verified FROM oauth_device_grants WHERE device_code_digest=? AND client_id=?`, Args: []any{d, client}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return row{}, false, err
	}
	if len(r.Rows) == 0 {
		return row{}, false, nil
	}
	if len(r.Rows) != 1 || len(r.Rows[0]) != 11 {
		return row{}, false, ErrInvalid
	}
	v := r.Rows[0]
	out := row{}
	mfa, validMFA := v[10].(int64)
	if !validMFA || (mfa != 0 && mfa != 1) {
		return out, false, ErrInvalid
	}
	out.mfa = mfa == 1
	var ok bool
	if out.state, ok = v[0].(string); !ok {
		return out, false, ErrInvalid
	}
	if v[1] != nil {
		out.subject, ok = v[1].(string)
		if !ok {
			return out, false, ErrInvalid
		}
	}
	if v[2] != nil {
		out.generation, ok = v[2].(string)
		if !ok {
			return out, false, ErrInvalid
		}
	}
	if v[3] != nil {
		out.resource, ok = v[3].(string)
		if !ok || !validResource(out.resource) {
			return out, false, ErrInvalid
		}
	}
	raw, ok := v[4].(string)
	if !ok || json.Unmarshal([]byte(raw), &out.scopes) != nil {
		return out, false, ErrInvalid
	}
	for i, p := range [](*int64){&out.expires, &out.interval, &out.nextPoll} {
		x, ok := v[i+5].(int64)
		if !ok {
			return out, false, ErrInvalid
		}
		*p = x
	}
	if v[8] != nil {
		out.claim, ok = v[8].(string)
		if !ok {
			return out, false, ErrInvalid
		}
		out.claimUntil, ok = v[9].(int64)
		if !ok {
			return out, false, ErrInvalid
		}
	}
	return out, true, nil
}
func validResourceOrEmpty(value string) bool { return value == "" || validResource(value) }
func validResource(value string) bool {
	if value == "" || len(value) > 2048 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\t") {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Opaque == "" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(value, "#") && !strings.ContainsFunc(value, unicode.IsSpace)
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func randomCode(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func randomUserCode() (string, error) {
	const alphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
	b := make([]byte, 10)
	for i := range b {
		for {
			var random [1]byte
			if _, err := rand.Read(random[:]); err != nil {
				return "", err
			}
			limit := 256 - 256%len(alphabet)
			if int(random[0]) < limit {
				b[i] = alphabet[int(random[0])%len(alphabet)]
				break
			}
		}
	}
	return string(b[:4]) + "-" + string(b[4:8]) + "-" + string(b[8:]), nil
}
func nilIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
