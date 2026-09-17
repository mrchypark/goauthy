// Package browser persists the opaque, short-lived state used by the browser
// login and authorization UI. It deliberately has no account or HTML policy.
package browser

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	maxSubjectLength     = 512
	maxRequestIDLength   = 512
	maxPayloadLength     = 64 << 10
	maxIssuerLength      = 2048
	maxClientIDLength    = 256
	maxUpstreamSIDLength = 512
	DefaultIdleTimeout   = 90 * time.Minute
	touchInterval        = 10 * time.Second
	// Initialization sessions have no identity. Every authenticated session must
	// retain a live identity in the same snapshot as its authorization decision.
	activeSessionSubjectSQL = `(browser_sessions.subject='' OR EXISTS (SELECT 1 FROM identity_users u WHERE u.subject=browser_sessions.subject AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?)))`
)

var (
	ErrNotFound       = errors.New("browser state not found")
	ErrExpired        = errors.New("browser state expired")
	ErrRevoked        = errors.New("browser session revoked")
	ErrConsumed       = errors.New("browser authorization interaction consumed")
	ErrPeerIPMismatch = errors.New("browser session peer IP mismatch")
)

type peerIPKey struct{}

// ContextWithPeerIP returns a new context carrying the canonical peer IP
// resolved at the HTTP boundary by trusted-proxy middleware.
func ContextWithPeerIP(ctx context.Context, peerIP string) context.Context {
	return context.WithValue(ctx, peerIPKey{}, peerIP)
}

// PeerIPFromContext retrieves the canonical peer IP stored by middleware. An
// empty string means no middleware resolved a peer IP for this request.
func PeerIPFromContext(ctx context.Context) string {
	v, _ := ctx.Value(peerIPKey{}).(string)
	return v
}

// SchemaStatements is the table contract for the browser-state migration.
// Tokens are never persisted: token_digest is base64url(SHA-256(token)).
// request_id is the stable ID of the parsed authorization request. payload is
// application-owned serialized request state; it must not contain credentials.
func SchemaStatements() []rhiza.SQLStatement {
	return []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS browser_sessions (
			token_digest TEXT PRIMARY KEY NOT NULL,
			subject TEXT NOT NULL,
			auth_method TEXT NOT NULL DEFAULT '' CHECK (auth_method IN ('', 'pwd', 'webauthn', 'mfa', 'external')),
			created_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			last_seen_at_unix_ms INTEGER NOT NULL,
			revoked_at_unix_ms INTEGER,
			peer_ip TEXT NOT NULL DEFAULT ''
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS browser_sessions_expiry ON browser_sessions(expires_at_unix_ms)`},
		{SQL: `CREATE TABLE IF NOT EXISTS browser_upstream_session_bindings (
			session_digest TEXT PRIMARY KEY NOT NULL,
			issuer TEXT NOT NULL CHECK(length(issuer) BETWEEN 1 AND 2048),
			client_id TEXT NOT NULL CHECK(length(client_id) BETWEEN 1 AND 256),
			upstream_subject TEXT NOT NULL CHECK(length(upstream_subject) BETWEEN 1 AND 512),
			upstream_sid TEXT CHECK(upstream_sid IS NULL OR length(upstream_sid) BETWEEN 1 AND 512),
			created_at_unix_ms INTEGER NOT NULL
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS browser_upstream_session_bindings_subject
			ON browser_upstream_session_bindings(issuer, client_id, upstream_subject)`},
		{SQL: `CREATE INDEX IF NOT EXISTS browser_upstream_session_bindings_sid
			ON browser_upstream_session_bindings(issuer, client_id, upstream_sid)
			WHERE upstream_sid IS NOT NULL`},
		{SQL: `CREATE TABLE IF NOT EXISTS browser_authorization_interactions (
			token_digest TEXT PRIMARY KEY NOT NULL,
			request_id TEXT NOT NULL UNIQUE,
			session_digest TEXT NOT NULL,
			payload TEXT NOT NULL,
			created_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			consumed_attempt TEXT,
			consumed_at_unix_ms INTEGER
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS browser_authorization_interactions_expiry ON browser_authorization_interactions(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX IF NOT EXISTS browser_authorization_interactions_session ON browser_authorization_interactions(session_digest)`},
	}
}

type Store struct {
	db          *rhiza.DB
	idleTimeout time.Duration
	now         func() time.Time
}

// NewStore uses Rauthy's 90 minute idle lifetime unless one explicit positive
// duration is supplied. The optional argument preserves the original call
// shape while allowing deployments to set a stricter policy.
func NewStore(db *rhiza.DB, idleTimeout ...time.Duration) (*Store, error) {
	if db == nil {
		return nil, errors.New("browser store requires Rhiza DB")
	}
	if len(idleTimeout) > 1 || (len(idleTimeout) == 1 && idleTimeout[0] <= 0) {
		return nil, errors.New("browser store idle timeout must be positive")
	}
	idle := DefaultIdleTimeout
	if len(idleTimeout) == 1 {
		idle = idleTimeout[0]
	}
	return &Store{db: db, idleTimeout: idle, now: time.Now}, nil
}

type Session struct {
	// ID is the persisted token digest. It is stable for the session but cannot
	// be used as the HttpOnly cookie bearer token.
	ID                   string
	Subject              string
	AuthenticationMethod string
	CreatedAt            time.Time
	ExpiresAt            time.Time
	PeerIP               string
}

// SessionAuthorizationGuard returns a commit-time predicate for this exact
// session. It carries only the persisted digest and session metadata; the raw
// cookie bearer never crosses the package boundary.
func (s *Store) SessionAuthorizationGuard(session Session, peerIP string) (string, []any) {
	now := s.timeNow()
	return `EXISTS (SELECT 1 FROM browser_sessions WHERE token_digest=? AND subject=? AND auth_method=? AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms > ? AND last_seen_at_unix_ms > ? AND (peer_ip='' OR peer_ip=?) AND ` + activeSessionSubjectSQL + `)`, []any{session.ID, session.Subject, session.AuthenticationMethod, now.UnixMilli(), now.Add(-s.idleTimeout).UnixMilli(), peerIP, now.UnixMilli()}
}

// Authenticated reports whether this is a post-login session. An empty subject
// is reserved exclusively for the short-lived authorization-init session.
func (s Session) Authenticated() bool {
	return s.Subject != "" && validAuthenticationMethod(s.AuthenticationMethod) && s.AuthenticationMethod != ""
}

// IssuedSession contains the one-time raw token. Callers must place it only in
// the HttpOnly cookie; subsequent reads return Session and never the token.
type IssuedSession struct {
	Session
	Token string
}

// UpstreamSessionBinding identifies the upstream OIDC session that established
// an external browser session. SessionID is the optional upstream `sid` claim.
// All values are persisted exactly as verified by the upstream provider.
type UpstreamSessionBinding struct {
	Issuer    string
	ClientID  string
	Subject   string
	SessionID string
	MFAPassed bool
}

func (s *Store) CreateSession(ctx context.Context, subject, authMethod string, expiresAt time.Time, peerIP string) (IssuedSession, error) {
	if strings.TrimSpace(subject) == "" || len(subject) > maxSubjectLength {
		return IssuedSession{}, errors.New("invalid browser session subject")
	}
	if !validAuthenticationMethod(authMethod) || authMethod == "" {
		return IssuedSession{}, errors.New("invalid browser session authentication method")
	}
	return s.createSession(ctx, subject, authMethod, expiresAt, peerIP, nil)
}

// CreateUpstreamSession creates an external authenticated session and its
// verified upstream OIDC binding in one replicated transaction.
func (s *Store) CreateUpstreamSession(ctx context.Context, subject string, binding UpstreamSessionBinding, authMethod string, expiresAt time.Time, peerIP string) (IssuedSession, error) {
	if strings.TrimSpace(subject) == "" || len(subject) > maxSubjectLength {
		return IssuedSession{}, errors.New("invalid browser session subject")
	}
	if !validUpstreamSessionBinding(binding) {
		return IssuedSession{}, errors.New("invalid upstream browser session binding")
	}
	if !validAuthenticationMethod(authMethod) || authMethod == "" {
		return IssuedSession{}, errors.New("invalid browser session authentication method")
	}
	return s.createSession(ctx, subject, authMethod, expiresAt, peerIP, &binding)
}

// CreateInitSession creates short-lived pre-login state. It must be exchanged
// for a new authenticated session after credentials are verified.
func (s *Store) CreateInitSession(ctx context.Context, expiresAt time.Time, peerIP string) (IssuedSession, error) {
	return s.createSession(ctx, "", "", expiresAt, peerIP, nil)
}

func (s *Store) createSession(ctx context.Context, subject, authMethod string, expiresAt time.Time, peerIP string, binding *UpstreamSessionBinding) (IssuedSession, error) {
	now := s.timeNow()
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now) {
		return IssuedSession{}, errors.New("browser session expiry must be in the future")
	}
	token, digest, err := newToken()
	if err != nil {
		return IssuedSession{}, err
	}
	insert := rhiza.SQLStatement{SQL: `INSERT INTO browser_sessions (token_digest, subject, auth_method, created_at_unix_ms, expires_at_unix_ms, last_seen_at_unix_ms, peer_ip) VALUES (?, ?, ?, ?, ?, ?, ?)`, Args: []any{digest, subject, authMethod, now.UnixMilli(), expiresAt.UnixMilli(), now.UnixMilli(), peerIP}}
	if subject != "" {
		insert = rhiza.SQLStatement{SQL: `INSERT INTO browser_sessions (token_digest, subject, auth_method, created_at_unix_ms, expires_at_unix_ms, last_seen_at_unix_ms, peer_ip)
			SELECT ?,subject,?,?,MIN(?,COALESCE(user_expires_at_unix_ms,?)),?,? FROM identity_users
			WHERE subject=? AND disabled=0 AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?)`,
			Args: []any{digest, authMethod, now.UnixMilli(), expiresAt.UnixMilli(), expiresAt.UnixMilli(), now.UnixMilli(), peerIP, subject, now.UnixMilli()}}
	}
	statements := []rhiza.SQLStatement{
		// Rhiza does not enforce SQLite foreign keys. Remove bindings before their
		// expired sessions so session-digest lookups cannot retain stale rows.
		{SQL: `DELETE FROM browser_upstream_session_bindings WHERE session_digest IN (SELECT token_digest FROM browser_sessions WHERE expires_at_unix_ms <= ?)`, Args: []any{now.UnixMilli()}},
		{SQL: `DELETE FROM browser_sessions WHERE expires_at_unix_ms <= ?`, Args: []any{now.UnixMilli()}},
		insert,
	}
	if binding != nil {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO browser_upstream_session_bindings (session_digest, issuer, client_id, upstream_subject, upstream_sid, created_at_unix_ms)
			SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM browser_sessions WHERE token_digest=? AND subject=? AND auth_method=? AND created_at_unix_ms=?)`,
			Args: []any{digest, binding.Issuer, binding.ClientID, binding.Subject, nullableUpstreamSessionID(binding.SessionID), now.UnixMilli(), digest, subject, authMethod, now.UnixMilli()}})
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID:  mutationID("session-create", digest),
		Statements: statements,
	})
	if err != nil {
		return IssuedSession{}, err
	}
	// Read the stored cap and require that the guarded insert actually happened.
	session, _, err := s.loadSession(ctx, digest, now)
	if err != nil {
		return IssuedSession{}, err
	}
	return IssuedSession{Session: session, Token: token}, nil
}

// LoadSession uses a linearizable read because a revoked or expired session is
// a security decision.
func (s *Store) LoadSession(ctx context.Context, token string) (Session, error) {
	digest, err := tokenDigest(token)
	if err != nil {
		return Session{}, ErrNotFound
	}
	now := s.timeNow()
	session, lastSeen, err := s.loadSession(ctx, digest, now)
	if err != nil {
		return Session{}, err
	}
	if now.Sub(lastSeen) < touchInterval {
		return session, nil
	}
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("session-touch", digest, fmt.Sprint(now.UnixMilli())),
		SQL: `UPDATE browser_sessions SET last_seen_at_unix_ms = ?
			WHERE token_digest = ? AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms > ?
			AND last_seen_at_unix_ms > ? AND last_seen_at_unix_ms <= ? AND ` + activeSessionSubjectSQL,
		Args: []any{now.UnixMilli(), digest, now.UnixMilli(), now.Add(-s.idleTimeout).UnixMilli(), now.Add(-touchInterval).UnixMilli(), now.UnixMilli()},
	})
	if err != nil {
		return Session{}, err
	}
	if response.MutationReceipt.RowsAffected != 0 {
		return session, nil
	}
	// A concurrent touch can make the guarded update a no-op. Re-read rather
	// than treating an ambiguous write as authorization.
	session, _, err = s.loadSession(ctx, digest, now)
	return session, err
}

// LoadSessionReadOnly applies the same linearizable validity checks without
// extending idle lifetime. It is for endpoints that must inspect a cookie
// before deciding whether a state-changing interaction is necessary.
func (s *Store) LoadSessionReadOnly(ctx context.Context, token string) (Session, error) {
	digest, err := tokenDigest(token)
	if err != nil {
		return Session{}, ErrNotFound
	}
	session, _, err := s.loadSession(ctx, digest, s.timeNow())
	return session, err
}

// LoadSessionForPeer loads a session and atomically verifies the peer IP
// in a single call. It is the mandatory entry point for HTTP handlers that
// resolve a browser session from a cookie. Callers must not call LoadSession
// followed by a separate CheckPeerIP, as reordering or early-return bugs
// can silently weaken the binding.
func (s *Store) LoadSessionForPeer(ctx context.Context, token string, peerIP string) (Session, error) {
	session, err := s.LoadSession(ctx, token)
	if err != nil {
		return session, err
	}
	return session, CheckPeerIP(session, peerIP)
}

// LoadSessionReadOnlyForPeer applies the same atomic load+check without
// extending idle lifetime. Use for read-only cookie inspection (e.g.
// logout) where no state mutation follows.
func (s *Store) LoadSessionReadOnlyForPeer(ctx context.Context, token string, peerIP string) (Session, error) {
	session, err := s.LoadSessionReadOnly(ctx, token)
	if err != nil {
		return session, err
	}
	return session, CheckPeerIP(session, peerIP)
}

func (s *Store) loadSession(ctx context.Context, digest string, now time.Time) (Session, time.Time, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT subject, auth_method, created_at_unix_ms,
			MIN(expires_at_unix_ms,COALESCE((SELECT u.user_expires_at_unix_ms FROM identity_users u WHERE u.subject=browser_sessions.subject),expires_at_unix_ms)),
			last_seen_at_unix_ms, revoked_at_unix_ms, peer_ip FROM browser_sessions WHERE token_digest = ? AND ` + activeSessionSubjectSQL,
		Args: []any{digest, now.UnixMilli()}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return Session{}, time.Time{}, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 7 {
		return Session{}, time.Time{}, ErrNotFound
	}
	subject, subjectOK := result.Rows[0][0].(string)
	authMethod, authMethodOK := result.Rows[0][1].(string)
	createdAt, createdOK := result.Rows[0][2].(int64)
	expiresAt, expiresOK := result.Rows[0][3].(int64)
	lastSeen, lastSeenOK := result.Rows[0][4].(int64)
	if !subjectOK || !authMethodOK || !validSessionAuthentication(subject, authMethod) || !createdOK || !expiresOK || !lastSeenOK {
		return Session{}, time.Time{}, errors.New("invalid browser session row")
	}
	if expiresAt <= now.UnixMilli() || lastSeen <= now.Add(-s.idleTimeout).UnixMilli() {
		return Session{}, time.Time{}, ErrExpired
	}
	if result.Rows[0][5] != nil {
		if _, ok := result.Rows[0][5].(int64); !ok {
			return Session{}, time.Time{}, errors.New("invalid browser session revocation time")
		}
		return Session{}, time.Time{}, ErrRevoked
	}
	peerIP, _ := result.Rows[0][6].(string)
	session := Session{ID: digest, Subject: subject, AuthenticationMethod: authMethod, CreatedAt: time.UnixMilli(createdAt).UTC(), ExpiresAt: time.UnixMilli(expiresAt).UTC(), PeerIP: peerIP}
	lastSeenTime := time.UnixMilli(lastSeen).UTC()
	return session, lastSeenTime, nil
}

func (s *Store) RevokeSession(ctx context.Context, token string) error {
	digest, err := tokenDigest(token)
	if err != nil {
		return ErrNotFound
	}
	return s.RevokeSessionID(ctx, digest)
}

// RevokeSessionID revokes the session identified by Session.ID. ID is the
// persisted SHA-256 digest, never the browser cookie bearer token.
func (s *Store) RevokeSessionID(ctx context.Context, id string) error {
	if !validSessionID(id) {
		return ErrNotFound
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT 1 FROM browser_sessions WHERE token_digest = ?`,
		Args:        []any{id},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return ErrNotFound
	}
	now := s.timeNow().UnixMilli()
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("session-revoke", id, fmt.Sprint(now)),
		SQL:       `UPDATE browser_sessions SET revoked_at_unix_ms = COALESCE(revoked_at_unix_ms, ?) WHERE token_digest = ?`,
		Args:      []any{now, id},
	})
	if err != nil {
		return err
	}
	if response.MutationReceipt.RowsAffected != 1 {
		return ErrNotFound
	}
	return nil
}

// AuthorizationInteraction is the state consumed exactly once after a user
// makes the login/consent decision.
type AuthorizationInteraction struct {
	RequestID string
	Payload   []byte
	Subject   string
	ExpiresAt time.Time
}

// IssuedAuthorizationInteraction contains the raw one-time browser token.
type IssuedAuthorizationInteraction struct {
	AuthorizationInteraction
	Token string
}

func (s *Store) CreateAuthorizationInteraction(ctx context.Context, sessionToken, requestID string, payload []byte, expiresAt time.Time) (IssuedAuthorizationInteraction, error) {
	if err := validateInteraction(requestID, payload); err != nil {
		return IssuedAuthorizationInteraction{}, err
	}
	sessionDigest, err := tokenDigest(sessionToken)
	if err != nil {
		return IssuedAuthorizationInteraction{}, ErrNotFound
	}
	if _, err := s.LoadSession(ctx, sessionToken); err != nil {
		return IssuedAuthorizationInteraction{}, err
	}
	now := s.timeNow()
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now) {
		return IssuedAuthorizationInteraction{}, errors.New("browser authorization interaction expiry must be in the future")
	}
	token, digest, err := newToken()
	if err != nil {
		return IssuedAuthorizationInteraction{}, err
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("authorization-create", digest),
		Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM browser_authorization_interactions WHERE expires_at_unix_ms <= ?`, Args: []any{now.UnixMilli()}},
			{SQL: `INSERT INTO browser_authorization_interactions (token_digest, request_id, session_digest, payload, created_at_unix_ms, expires_at_unix_ms)
				SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM browser_sessions WHERE token_digest=?
				AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms > ? AND last_seen_at_unix_ms > ? AND ` + activeSessionSubjectSQL + `)`,
				Args: []any{digest, requestID, sessionDigest, base64.RawURLEncoding.EncodeToString(payload), now.UnixMilli(), expiresAt.UnixMilli(), sessionDigest, now.UnixMilli(), now.Add(-s.idleTimeout).UnixMilli(), now.UnixMilli()}},
		},
	})
	if err != nil {
		return IssuedAuthorizationInteraction{}, err
	}
	created, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM browser_authorization_interactions WHERE token_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return IssuedAuthorizationInteraction{}, err
	}
	if len(created.Rows) != 1 {
		return IssuedAuthorizationInteraction{}, ErrNotFound
	}
	return IssuedAuthorizationInteraction{AuthorizationInteraction: AuthorizationInteraction{RequestID: requestID, Payload: append([]byte(nil), payload...), ExpiresAt: expiresAt}, Token: token}, nil
}

// LoadAuthorizationInteractionReadOnly returns an unconsumed authorization
// request bound to a live initialization session without extending its idle
// lifetime. It lets credential verification apply client policy before the
// one-time interaction is consumed.
func (s *Store) LoadAuthorizationInteractionReadOnly(ctx context.Context, sessionToken, token string) (AuthorizationInteraction, error) {
	sessionDigest, err := tokenDigest(sessionToken)
	if err != nil {
		return AuthorizationInteraction{}, ErrNotFound
	}
	digest, err := tokenDigest(token)
	if err != nil {
		return AuthorizationInteraction{}, ErrNotFound
	}
	return s.loadAuthorizationInteractionReadOnly(ctx, sessionDigest, digest, true)
}

// LoadAuthorizationInteractionReadOnlyByDigest loads an interaction identified
// by its canonical persisted SHA-256 base64url digest.
func (s *Store) LoadAuthorizationInteractionReadOnlyByDigest(ctx context.Context, sessionToken, interactionDigest string) (AuthorizationInteraction, error) {
	sessionDigest, err := tokenDigest(sessionToken)
	if err != nil || !validSessionID(interactionDigest) {
		return AuthorizationInteraction{}, ErrNotFound
	}
	return s.loadAuthorizationInteractionReadOnly(ctx, sessionDigest, interactionDigest, true)
}

func (s *Store) loadAuthorizationInteractionReadOnly(ctx context.Context, sessionDigest, digest string, requireInitSession bool) (AuthorizationInteraction, error) {
	session, _, err := s.loadSession(ctx, sessionDigest, s.timeNow())
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	if requireInitSession && (session.Subject != "" || session.AuthenticationMethod != "") {
		return AuthorizationInteraction{}, ErrNotFound
	}
	now := s.timeNow().UnixMilli()
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT request_id, payload, expires_at_unix_ms, consumed_attempt
			FROM browser_authorization_interactions
			WHERE token_digest = ? AND session_digest = ?`,
		Args: []any{digest, sessionDigest}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return AuthorizationInteraction{}, ErrNotFound
	}
	requestID, requestIDOK := result.Rows[0][0].(string)
	encodedPayload, payloadOK := result.Rows[0][1].(string)
	expiresAt, expiresOK := result.Rows[0][2].(int64)
	if !requestIDOK || !payloadOK || !expiresOK {
		return AuthorizationInteraction{}, errors.New("invalid browser authorization interaction row")
	}
	if expiresAt <= now {
		return AuthorizationInteraction{}, ErrExpired
	}
	if result.Rows[0][3] != nil {
		return AuthorizationInteraction{}, ErrConsumed
	}
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil || validateInteraction(requestID, payload) != nil {
		return AuthorizationInteraction{}, errors.New("invalid browser authorization interaction row")
	}
	return AuthorizationInteraction{RequestID: requestID, Payload: append([]byte(nil), payload...), ExpiresAt: time.UnixMilli(expiresAt).UTC()}, nil
}

// ConsumeAuthorizationInteraction atomically marks one interaction consumed
// only while its bound session remains active. A distinct random attempt makes
// a concurrent or replayed consume observable after Rhiza's idempotent write.
func (s *Store) ConsumeAuthorizationInteraction(ctx context.Context, sessionToken, token string) (AuthorizationInteraction, error) {
	sessionDigest, err := tokenDigest(sessionToken)
	if err != nil {
		return AuthorizationInteraction{}, ErrNotFound
	}
	digest, err := tokenDigest(token)
	if err != nil {
		return AuthorizationInteraction{}, ErrNotFound
	}
	return s.consumeAuthorizationInteraction(ctx, sessionDigest, digest, false)
}

// ConsumeAuthorizationInteractionByDigest consumes an interaction identified
// by its canonical persisted SHA-256 base64url digest. It accepts only a live
// initialization session, never an already authenticated browser session.
func (s *Store) ConsumeAuthorizationInteractionByDigest(ctx context.Context, sessionToken, interactionDigest string) (AuthorizationInteraction, error) {
	sessionDigest, err := tokenDigest(sessionToken)
	if err != nil || !validSessionID(interactionDigest) {
		return AuthorizationInteraction{}, ErrNotFound
	}
	return s.consumeAuthorizationInteraction(ctx, sessionDigest, interactionDigest, true)
}

func (s *Store) consumeAuthorizationInteraction(ctx context.Context, sessionDigest, digest string, requireInitSession bool) (AuthorizationInteraction, error) {
	attempt, err := randomID(16)
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	now := s.timeNow().UnixMilli()
	sessionCondition := `(subject = '' AND auth_method = '') OR (subject <> '' AND auth_method IN ('pwd', 'webauthn', 'mfa', 'external'))`
	if requireInitSession {
		sessionCondition = `subject = '' AND auth_method = ''`
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("authorization-consume", digest, attempt),
		Statements: []rhiza.SQLStatement{{SQL: `UPDATE browser_authorization_interactions
			SET consumed_attempt = ?, consumed_at_unix_ms = ?
			WHERE token_digest = ? AND session_digest = ? AND consumed_attempt IS NULL AND expires_at_unix_ms > ?
			AND EXISTS (SELECT 1 FROM browser_sessions WHERE token_digest = ? AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms > ? AND last_seen_at_unix_ms > ?
				AND (` + sessionCondition + `) AND ` + activeSessionSubjectSQL + `)`,
			Args: []any{attempt, now, digest, sessionDigest, now, sessionDigest, now, now - s.idleTimeout.Milliseconds(), now}},
			{SQL: `UPDATE browser_sessions SET last_seen_at_unix_ms = ?
			WHERE token_digest = ? AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms > ?
			AND last_seen_at_unix_ms > ? AND last_seen_at_unix_ms <= ?
			AND (` + sessionCondition + `)
			AND EXISTS (SELECT 1 FROM browser_authorization_interactions WHERE token_digest = ? AND session_digest = ? AND consumed_attempt = ?)`,
				Args: []any{now, sessionDigest, now, now - s.idleTimeout.Milliseconds(), now - touchInterval.Milliseconds(), digest, sessionDigest, attempt}},
		},
	})
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT i.request_id, i.payload, i.expires_at_unix_ms, s.subject, s.auth_method
			FROM browser_authorization_interactions AS i JOIN browser_sessions AS s ON s.token_digest = i.session_digest
			WHERE i.token_digest = ? AND i.session_digest = ? AND i.consumed_attempt = ?
			AND i.expires_at_unix_ms > ? AND s.revoked_at_unix_ms IS NULL AND s.expires_at_unix_ms > ? AND s.last_seen_at_unix_ms > ?
			AND (` + strings.ReplaceAll(strings.ReplaceAll(sessionCondition, "subject", "s.subject"), "auth_method", "s.auth_method") + `)
			AND ` + strings.ReplaceAll(activeSessionSubjectSQL, "browser_sessions.", "s."),
		Args: []any{digest, sessionDigest, attempt, now, now, now - s.idleTimeout.Milliseconds(), now}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	if len(result.Rows) == 1 && len(result.Rows[0]) == 5 {
		requestID, idOK := result.Rows[0][0].(string)
		encodedPayload, payloadOK := result.Rows[0][1].(string)
		expiresAt, expiryOK := result.Rows[0][2].(int64)
		subject, subjectOK := result.Rows[0][3].(string)
		authMethod, authMethodOK := result.Rows[0][4].(string)
		payload, decodeErr := base64.RawURLEncoding.DecodeString(encodedPayload)
		if !idOK || !payloadOK || decodeErr != nil || !expiryOK || !subjectOK || !authMethodOK || !validSessionAuthentication(subject, authMethod) {
			return AuthorizationInteraction{}, errors.New("invalid browser authorization interaction row")
		}
		return AuthorizationInteraction{RequestID: requestID, Payload: append([]byte(nil), payload...), Subject: subject, ExpiresAt: time.UnixMilli(expiresAt).UTC()}, nil
	}
	return AuthorizationInteraction{}, s.consumeError(ctx, digest, sessionDigest, now, requireInitSession)
}

func (s *Store) consumeError(ctx context.Context, digest, sessionDigest string, now int64, requireInitSession bool) error {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT i.expires_at_unix_ms, i.consumed_attempt, s.subject, s.auth_method, s.expires_at_unix_ms, s.last_seen_at_unix_ms, s.revoked_at_unix_ms
			FROM browser_authorization_interactions AS i LEFT JOIN browser_sessions AS s ON s.token_digest = i.session_digest
			WHERE i.token_digest = ? AND i.session_digest = ?`,
		Args: []any{digest, sessionDigest}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 7 {
		return ErrNotFound
	}
	interactionExpiry, interactionOK := result.Rows[0][0].(int64)
	if !interactionOK {
		return errors.New("invalid browser authorization interaction expiry")
	}
	if interactionExpiry <= now {
		return ErrExpired
	}
	if result.Rows[0][1] != nil {
		return ErrConsumed
	}
	subject, subjectOK := result.Rows[0][2].(string)
	authMethod, authMethodOK := result.Rows[0][3].(string)
	if !subjectOK || !authMethodOK || !validSessionAuthentication(subject, authMethod) {
		return errors.New("invalid browser session row")
	}
	if requireInitSession && (subject != "" || authMethod != "") {
		return ErrNotFound
	}
	if result.Rows[0][4] == nil {
		return ErrNotFound
	}
	sessionExpiry, sessionOK := result.Rows[0][4].(int64)
	if !sessionOK {
		return errors.New("invalid browser session expiry")
	}
	if sessionExpiry <= now {
		return ErrExpired
	}
	lastSeen, lastSeenOK := result.Rows[0][5].(int64)
	if !lastSeenOK {
		return errors.New("invalid browser session last seen time")
	}
	if lastSeen <= now-s.idleTimeout.Milliseconds() {
		return ErrExpired
	}
	if result.Rows[0][6] != nil {
		return ErrRevoked
	}
	return ErrNotFound
}

// CheckPeerIP validates that the request's canonical peer IP matches the
// session's bound peer IP. An empty session PeerIP (legacy pre-v31 session) is
// always accepted. A nonempty session PeerIP that does not match the current
// peer IP fails closed with ErrPeerIPMismatch.
func CheckPeerIP(session Session, currentPeerIP string) error {
	if session.PeerIP == "" {
		return nil
	}
	if currentPeerIP == "" || currentPeerIP != session.PeerIP {
		return ErrPeerIPMismatch
	}
	return nil
}

func (s *Store) timeNow() time.Time { return s.now().UTC() }

func validateInteraction(requestID string, payload []byte) error {
	if strings.TrimSpace(requestID) == "" || len(requestID) > maxRequestIDLength {
		return errors.New("invalid browser authorization request ID")
	}
	if len(payload) == 0 || len(payload) > maxPayloadLength {
		return errors.New("invalid browser authorization payload")
	}
	return nil
}

func validAuthenticationMethod(method string) bool {
	switch method {
	case "", "pwd", "webauthn", "mfa", "external":
		return true
	default:
		return false
	}
}

func validSessionAuthentication(subject, method string) bool {
	if subject == "" {
		return method == ""
	}
	return method == "pwd" || method == "webauthn" || method == "mfa" || method == "external"
}

func validUpstreamSessionBinding(binding UpstreamSessionBinding) bool {
	return validBoundText(binding.Issuer, maxIssuerLength) &&
		validBoundText(binding.ClientID, maxClientIDLength) &&
		validBoundText(binding.Subject, maxSubjectLength) &&
		(binding.SessionID == "" || validBoundText(binding.SessionID, maxUpstreamSIDLength))
}

func validBoundText(value string, max int) bool {
	return value == strings.TrimSpace(value) && value != "" && len(value) <= max
}

func nullableUpstreamSessionID(sessionID string) any {
	if sessionID == "" {
		return nil
	}
	return sessionID
}

func newToken() (string, string, error) {
	token, err := randomID(32)
	if err != nil {
		return "", "", err
	}
	digest, err := tokenDigest(token)
	return token, digest, err
}

func randomID(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("random browser token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// CanonicalTokenDigest returns the persisted base64url(SHA-256(token)) form
// of a canonical opaque browser token. It is safe to pass across package
// boundaries; callers must keep the raw token in memory only as needed.
func CanonicalTokenDigest(token string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return "", errors.New("invalid browser token")
	}
	digest := sha256.Sum256(decoded)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func tokenDigest(token string) (string, error) { return CanonicalTokenDigest(token) }

func validSessionID(id string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == id
}

// Rhiza bounds request IDs at 64 bytes. Hashing preserves a stable idempotency
// key without leaking browser tokens or making the key depend on retries.
func mutationID(parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "b/" + base64.RawURLEncoding.EncodeToString(digest[:])
}
