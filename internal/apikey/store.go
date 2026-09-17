// Package apikey implements Rauthy-compatible, narrowly scoped API keys.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/audit"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	GroupAPIKeys = "ApiKeys"
	secretLength = 64
)

var (
	ErrUnauthorized = errors.New("API key unauthorized")
	ErrForbidden    = errors.New("API key forbidden")
	ErrInvalid      = errors.New("invalid API key")
	ErrNotFound     = errors.New("API key not found")
	nameRE          = regexp.MustCompile(`^[A-Za-z0-9_/-]{2,24}$`)
)

type Right string

const (
	Read   Right = "read"
	Create Right = "create"
	Update Right = "update"
	Delete Right = "delete"
)

type Access struct {
	Group        string  `json:"group"`
	AccessRights []Right `json:"access_rights"`
}
type Key struct {
	Name    string   `json:"name"`
	Created int64    `json:"created"`
	Expires *int64   `json:"expires"`
	Access  []Access `json:"access"`
}
type Request struct {
	Name   string   `json:"name"`
	Exp    *int64   `json:"exp"`
	Access []Access `json:"access"`
}
type Principal struct {
	Name   string
	digest string
}
type Store struct {
	db              *rhiza.DB
	now             func() time.Time
	random          func([]byte) (int, error)
	beforeMutation  func()
	beforeAuditRead func()
	OnAuthFailure   func(keyName, ip string)
}

func NewStore(db *rhiza.DB) (*Store, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &Store{db: db, now: time.Now, random: rand.Read}, nil
}

func (s *Store) Authenticate(ctx context.Context, header string) (Principal, error) {
	if !strings.HasPrefix(header, "API-Key ") || strings.Count(header, " ") != 1 {
		return Principal{}, ErrUnauthorized
	}
	name, secret, ok := strings.Cut(strings.TrimPrefix(header, "API-Key "), "$")
	if !ok || !validName(name) || len(secret) != secretLength || !alphaNum(secret) {
		return Principal{}, ErrUnauthorized
	}
	d := digest(secret)
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT secret_digest, expires_at_unix_ms FROM api_keys WHERE name=?`, Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 || len(r.Rows[0]) != 2 {
		return Principal{}, ErrUnauthorized
	}
	stored, ok := r.Rows[0][0].(string)
	if !ok || subtle.ConstantTimeCompare([]byte(stored), []byte(d)) != 1 {
		if s.OnAuthFailure != nil {
			s.OnAuthFailure(name, "")
		}
		return Principal{}, ErrUnauthorized
	}
	if r.Rows[0][1] != nil {
		e, ok := r.Rows[0][1].(int64)
		if !ok || s.timeNow().UnixMilli() > e {
			if s.OnAuthFailure != nil {
				s.OnAuthFailure(name, "")
			}
			return Principal{}, ErrUnauthorized
		}
	}
	return Principal{Name: name, digest: d}, nil
}
func (s *Store) Authorize(ctx context.Context, p Principal, group string, right Right) error {
	if p.Name == "" || !validGroup(group) || !validRight(right) {
		return ErrForbidden
	}
	now := s.timeNow().UnixMilli()
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM api_keys k JOIN api_key_access a ON a.key_name=k.name WHERE k.name=? AND k.secret_digest=? AND (k.expires_at_unix_ms IS NULL OR k.expires_at_unix_ms >= ?) AND a.group_name=? AND a.right_name=?`, Args: []any{p.Name, p.digest, now, group, string(right)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(r.Rows) != 1 {
		return ErrForbidden
	}
	return nil
}

// AuthorizationGuard returns the SQL predicate used to revalidate this exact
// key and grant inside a larger Rhiza mutation. It exposes only the persisted
// digest, never the bearer secret.
func (s *Store) AuthorizationGuard(p Principal, group string, right Right) (string, []any) {
	return `EXISTS (SELECT 1 FROM api_keys k JOIN api_key_access a ON a.key_name=k.name WHERE k.name=? AND k.secret_digest=? AND (k.expires_at_unix_ms IS NULL OR k.expires_at_unix_ms >= ?) AND a.group_name=? AND a.right_name=?)`, []any{p.Name, p.digest, s.timeNow().UnixMilli(), group, string(right)}
}

// AuthorizationSnapshot returns the persisted API-key identity and the exact
// grant requested by a guarded transition. The bearer secret never leaves
// Authenticate, and the digest is only used inside storage predicates.
func (s *Store) AuthorizationSnapshot(p Principal, group string, right Right) storage.MasterKeyRetirementAuthorization {
	return s.AuthorizationSnapshotAt(p, group, right, s.timeNow())
}

// AuthorizationSnapshotAt is the operation-timestamp form used by handlers
// that need the authorization read and guarded mutation to share one cutoff.
func (s *Store) AuthorizationSnapshotAt(p Principal, group string, right Right, at time.Time) storage.MasterKeyRetirementAuthorization {
	return storage.MasterKeyRetirementAuthorization{
		KeyName: p.Name, KeyDigest: p.digest, Group: group, Right: string(right),
		AuthorizedAt: at.UTC().Truncate(time.Millisecond),
	}
}
func (s *Store) Create(ctx context.Context, p *Principal, req Request) (Key, string, error) {
	if err := validate(req); err != nil {
		return Key{}, "", err
	}
	if err := s.guard(ctx, p, Create); err != nil {
		return Key{}, "", err
	}
	secret, err := s.newSecret()
	if err != nil {
		return Key{}, "", err
	}
	now := s.timeNow().UTC()
	key := Key{Name: req.Name, Created: now.Unix(), Expires: req.Exp, Access: normalize(req.Access)}
	requestID := id("create", key.Name, digest(secret))
	newDigest := digest(secret)
	stmts := []rhiza.SQLStatement{{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms,expires_at_unix_ms) SELECT ?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM api_keys WHERE name=?) AND EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{key.Name, newDigest, now.UnixMilli(), millis(key.Expires), key.Name, requestID}}}
	for _, a := range key.Access {
		for _, right := range a.AccessRights {
			stmts = append(stmts, rhiza.SQLStatement{SQL: `INSERT INTO api_key_access(key_name,group_name,right_name) SELECT ?,?,? WHERE EXISTS (SELECT 1 FROM api_keys WHERE name=? AND secret_digest=?) AND EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{key.Name, a.Group, string(right), key.Name, newDigest, requestID}})
		}
	}
	event, err := s.auditStatement(requestID, "api_key.created", "create", p, key.Name, newDigest, now, `EXISTS (SELECT 1 FROM api_keys WHERE name=? AND secret_digest=?) AND `+GuardExistsSQL(), key.Name, newDigest, requestID)
	if err != nil {
		return Key{}, "", err
	}
	stmts = append(stmts, event)
	response, ok, err := s.RunDelegatedMutation(ctx, p, GroupAPIKeys, Create, requestID, key.Access, stmts)
	if err != nil {
		return Key{}, "", err
	} else if !ok {
		return Key{}, "", ErrForbidden
	} else if response.RowsAffected < 5 {
		return Key{}, "", ErrNotFound
	}
	return key, key.Name + "$" + secret, nil
}
func (s *Store) List(ctx context.Context, p *Principal) ([]Key, error) {
	if err := s.guard(ctx, p, Read); err != nil {
		return nil, err
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name,created_at_unix_ms,expires_at_unix_ms FROM api_keys ORDER BY name`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	out := make([]Key, 0, len(r.Rows))
	for _, row := range r.Rows {
		k, err := s.row(ctx, row)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// Get returns the authenticated key's own metadata; this is not key-management
// authorization. Recheck the digest and expiry so stale principals fail closed.
func (s *Store) Get(ctx context.Context, p Principal) (Key, error) {
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT k.name,k.created_at_unix_ms,k.expires_at_unix_ms,a.group_name,a.right_name
 FROM api_keys k LEFT JOIN api_key_access a ON a.key_name=k.name
 WHERE k.name=? AND k.secret_digest=? AND (k.expires_at_unix_ms IS NULL OR k.expires_at_unix_ms>=?)
 ORDER BY a.group_name,a.right_name`, Args: []any{p.Name, p.digest, s.timeNow().UnixMilli()}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) == 0 {
		return Key{}, ErrUnauthorized
	}
	access := make([][]any, 0, len(r.Rows))
	for _, row := range r.Rows {
		if len(row) != 5 {
			return Key{}, ErrInvalid
		}
		if row[3] != nil || row[4] != nil {
			access = append(access, row[3:])
		}
	}
	return keyFromRows(r.Rows[0][:3], access)
}
func (s *Store) Update(ctx context.Context, p *Principal, name string, req Request) (Key, error) {
	if !validName(name) || req.Name != name {
		return Key{}, ErrInvalid
	}
	if err := validate(req); err != nil {
		return Key{}, err
	}
	if err := s.guard(ctx, p, Update); err != nil {
		return Key{}, err
	}
	expectedDigest, err := s.targetDigest(ctx, name)
	if err != nil {
		return Key{}, err
	}
	if s.beforeMutation != nil {
		s.beforeMutation()
	}
	// The authorization read above is followed by this single replicated
	// transaction; no revoke or competing policy change can interleave its
	// delete-and-replace sequence.
	requestID := id("update", name, expectedDigest, fmt.Sprint(req.Exp), fmt.Sprint(req.Access))
	stmts := []rhiza.SQLStatement{{SQL: `UPDATE api_keys SET expires_at_unix_ms=? WHERE name=? AND secret_digest=? AND EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{millis(req.Exp), name, expectedDigest, requestID}}, {SQL: `DELETE FROM api_key_access WHERE key_name=? AND EXISTS (SELECT 1 FROM api_keys WHERE name=? AND secret_digest=?) AND EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{name, name, expectedDigest, requestID}}}
	for _, a := range normalize(req.Access) {
		for _, right := range a.AccessRights {
			stmts = append(stmts, rhiza.SQLStatement{SQL: `INSERT INTO api_key_access(key_name,group_name,right_name) SELECT ?,?,? WHERE EXISTS (SELECT 1 FROM api_keys WHERE name=? AND secret_digest=?) AND EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{name, a.Group, string(right), name, expectedDigest, requestID}})
		}
	}
	event, err := s.auditStatement(requestID, "api_key.updated", "update", p, name, expectedDigest, s.timeNow(), `EXISTS (SELECT 1 FROM api_keys WHERE name=? AND secret_digest=?) AND `+GuardExistsSQL(), name, expectedDigest, requestID)
	if err != nil {
		return Key{}, err
	}
	stmts = append(stmts, event)
	response, ok, err := s.RunDelegatedMutation(ctx, p, GroupAPIKeys, Update, requestID, normalize(req.Access), stmts)
	if err != nil {
		return Key{}, err
	} else if !ok {
		return Key{}, ErrForbidden
	} else if response.RowsAffected < 4 {
		return Key{}, ErrNotFound
	}
	return s.byName(ctx, name)
}
func (s *Store) Delete(ctx context.Context, p *Principal, name string) error {
	if !validName(name) {
		return ErrInvalid
	}
	if err := s.guard(ctx, p, Delete); err != nil {
		return err
	}
	expectedDigest, err := s.targetDigest(ctx, name)
	if err != nil {
		return err
	}
	if s.beforeMutation != nil {
		s.beforeMutation()
	}
	requestID := id("delete", name, expectedDigest)
	event, err := s.auditStatement(requestID, "api_key.deleted", "delete", p, name, expectedDigest, s.timeNow(), `EXISTS (SELECT 1 FROM api_keys WHERE name=? AND secret_digest=?) AND `+GuardExistsSQL(), name, expectedDigest, requestID)
	if err != nil {
		return err
	}
	response, ok, err := s.RunMutation(ctx, p, GroupAPIKeys, Delete, requestID, []rhiza.SQLStatement{event, {SQL: `DELETE FROM api_key_access WHERE key_name=? AND EXISTS (SELECT 1 FROM api_keys WHERE name=? AND secret_digest=?) AND EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{name, name, expectedDigest, requestID}}, {SQL: `DELETE FROM api_keys WHERE name=? AND secret_digest=? AND EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{name, expectedDigest, requestID}}})
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	if response.RowsAffected < 4 {
		return ErrNotFound
	}
	return nil
}
func (s *Store) Rotate(ctx context.Context, p *Principal, name string) (string, error) {
	if !validName(name) {
		return "", ErrInvalid
	}
	if err := s.guard(ctx, p, Update); err != nil {
		return "", err
	}
	expectedDigest, err := s.targetDigest(ctx, name)
	if err != nil {
		return "", err
	}
	if s.beforeMutation != nil {
		s.beforeMutation()
	}
	secret, err := s.newSecret()
	if err != nil {
		return "", err
	}
	requestID := id("rotate", name, expectedDigest, digest(secret))
	newDigest := digest(secret)
	event, err := s.auditStatement(requestID, "api_key.rotated", "rotate", p, name, newDigest, s.timeNow(), `EXISTS (SELECT 1 FROM api_keys WHERE name=? AND secret_digest=?) AND `+GuardExistsSQL(), name, newDigest, requestID)
	if err != nil {
		return "", err
	}
	r, ok, err := s.RunMutation(ctx, p, GroupAPIKeys, Update, requestID, []rhiza.SQLStatement{{SQL: `UPDATE api_keys SET secret_digest=? WHERE name=? AND secret_digest=? AND EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{newDigest, name, expectedDigest, requestID}}, event})
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrForbidden
	}
	if r.RowsAffected < 4 {
		return "", ErrNotFound
	}
	return name + "$" + secret, nil
}

// ListAuditEvents exposes the narrow audit reader only to API keys carrying
// Events:read; it never returns bearer secrets or mutation payloads.
func (s *Store) ListAuditEvents(ctx context.Context, p Principal, cursor *audit.Cursor, limit int) ([]audit.Event, *audit.Cursor, error) {
	now := s.timeNow().UnixMilli()
	guard := `EXISTS (SELECT 1 FROM api_keys k JOIN api_key_access a ON a.key_name=k.name WHERE k.name=? AND k.secret_digest=? AND (k.expires_at_unix_ms IS NULL OR k.expires_at_unix_ms >= ?) AND a.group_name=? AND a.right_name=?)`
	args := []any{p.Name, p.digest, now, "Events", string(Read)}
	if s.beforeAuditRead != nil {
		s.beforeAuditRead()
	}
	store, err := audit.NewStore(s.db)
	if err != nil {
		return nil, nil, err
	}
	events, next, authorized, err := store.ListGuarded(ctx, guard, args, cursor, limit)
	if err != nil {
		return nil, nil, err
	}
	if !authorized {
		return nil, nil, ErrForbidden
	}
	return events, next, nil
}

func (s *Store) auditStatement(requestID, eventType, action string, principal *Principal, target, targetDigest string, occurredAt time.Time, condition string, conditionArgs ...any) (rhiza.SQLStatement, error) {
	actorKind, actorHash := "browser_admin", ""
	if principal != nil {
		actorKind, actorHash = "api_key", audit.Pseudonym(principal.digest, "actor", principal.Name)
	}
	event := audit.NewEvent(requestID, eventType, action, actorKind, actorHash, audit.Pseudonym(targetDigest, "target", target), occurredAt)
	return event.Statement(condition, conditionArgs...)
}
func (s *Store) guard(ctx context.Context, p *Principal, right Right) error {
	if p == nil {
		return nil
	}
	return s.Authorize(ctx, *p, GroupAPIKeys, right)
}

// runMutation snapshots browser-admin or API-key authorization in a durable
// row and conditions every target statement on it. The row is deleted before
// commit, so a revoked key cannot authorize a later statement and no guard is
// retained after a successful or rejected transaction.
func GuardExistsSQL() string {
	return `EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`
}

// RunMutation snapshots authorization. Every target SQL must include
// GuardExistsSQL() with requestID as its final argument.
func (s *Store) RunMutation(ctx context.Context, p *Principal, group string, right Right, requestID string, targets []rhiza.SQLStatement) (rhiza.ExecuteResponse, bool, error) {
	return s.runMutation(ctx, p, group, right, requestID, nil, targets)
}

// RunDelegatedMutation additionally requires an API-key actor to already hold
// every requested grant. Browser-admin principals remain unrestricted.
func (s *Store) RunDelegatedMutation(ctx context.Context, p *Principal, group string, right Right, requestID string, grants []Access, targets []rhiza.SQLStatement) (rhiza.ExecuteResponse, bool, error) {
	return s.runMutation(ctx, p, group, right, requestID, normalize(grants), targets)
}

// RunEnvelopeMutation snapshots authorization and routes through
// storage.ExecuteEnvelope so the master-key retirement fence is evaluated
// in the same replicated transaction. The caller supplies the actual
// sealed writerKeyID. Every target SQL must include GuardExistsSQL() with
// requestID as its final argument, identical to RunMutation.
func (s *Store) RunEnvelopeMutation(ctx context.Context, writerKeyID string, p *Principal, group string, right Right, requestID string, targets []rhiza.SQLStatement) (rhiza.ExecuteResponse, bool, error) {
	if len(targets) == 0 {
		return rhiza.ExecuteResponse{}, false, ErrInvalid
	}
	for _, target := range targets {
		if !strings.Contains(target.SQL, GuardExistsSQL()) {
			return rhiza.ExecuteResponse{}, false, ErrInvalid
		}
	}
	guard := s.guardMutation(p, group, right, requestID, nil)
	statements := append([]rhiza.SQLStatement{guard}, targets...)
	statements = append(statements, rhiza.SQLStatement{SQL: `DELETE FROM api_key_mutation_guards WHERE request_id=?`, Args: []any{requestID}})
	response, err := storage.ExecuteEnvelope(ctx, s.db, writerKeyID, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		return response, false, err
	}
	return response, p == nil || response.RowsAffected >= 2, nil
}

// guardMutation builds the INSERT guard statement shared by RunMutation and
// RunEnvelopeMutation. The guard is deleted before commit so a revoked key
// cannot authorize a later statement and no guard is retained after commit.
func (s *Store) guardMutation(p *Principal, group string, right Right, requestID string, grants []Access) rhiza.SQLStatement {
	if p == nil {
		return rhiza.SQLStatement{SQL: `INSERT INTO api_key_mutation_guards(request_id) VALUES(?)`, Args: []any{requestID}}
	}
	guardSQL, guardArgs := s.AuthorizationGuard(*p, group, right)
	sql := `INSERT INTO api_key_mutation_guards(request_id) SELECT ? WHERE ` + guardSQL
	args := append([]any{requestID}, guardArgs...)
	for _, grant := range grants {
		for _, grantRight := range grant.AccessRights {
			sql += ` AND EXISTS (SELECT 1 FROM api_key_access d WHERE d.key_name=? AND d.group_name=? AND d.right_name=?)`
			args = append(args, p.Name, grant.Group, string(grantRight))
		}
	}
	return rhiza.SQLStatement{SQL: sql, Args: args}
}

func (s *Store) runMutation(ctx context.Context, p *Principal, group string, right Right, requestID string, grants []Access, targets []rhiza.SQLStatement) (rhiza.ExecuteResponse, bool, error) {
	if len(targets) == 0 {
		return rhiza.ExecuteResponse{}, false, ErrInvalid
	}
	for _, target := range targets {
		if !strings.Contains(target.SQL, GuardExistsSQL()) {
			return rhiza.ExecuteResponse{}, false, ErrInvalid
		}
	}
	guard := s.guardMutation(p, group, right, requestID, grants)
	statements := append([]rhiza.SQLStatement{guard}, targets...)
	statements = append(statements, rhiza.SQLStatement{SQL: `DELETE FROM api_key_mutation_guards WHERE request_id=?`, Args: []any{requestID}})
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		return response, false, err
	}
	return response, p == nil || response.RowsAffected >= 2, nil
}
func (s *Store) byName(ctx context.Context, name string) (Key, error) {
	r, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name,created_at_unix_ms,expires_at_unix_ms FROM api_keys WHERE name=?`, Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return Key{}, e
	}
	if len(r.Rows) != 1 {
		return Key{}, ErrNotFound
	}
	return s.row(ctx, r.Rows[0])
}
func (s *Store) targetDigest(ctx context.Context, name string) (string, error) {
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT secret_digest FROM api_keys WHERE name=?`, Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return "", err
	}
	if len(r.Rows) != 1 || len(r.Rows[0]) != 1 {
		return "", ErrNotFound
	}
	d, ok := r.Rows[0][0].(string)
	if !ok || len(d) != 43 {
		return "", ErrInvalid
	}
	return d, nil
}
func (s *Store) row(ctx context.Context, row []any) (Key, error) {
	if len(row) != 3 {
		return Key{}, ErrInvalid
	}
	name, ok := row[0].(string)
	if !ok {
		return Key{}, ErrInvalid
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT group_name,right_name FROM api_key_access WHERE key_name=? ORDER BY group_name,right_name`, Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Key{}, err
	}
	return keyFromRows(row, r.Rows)
}

func keyFromRows(row []any, access [][]any) (Key, error) {
	if len(row) != 3 {
		return Key{}, ErrInvalid
	}
	n, ok := row[0].(string)
	c, ok2 := row[1].(int64)
	if !ok || !ok2 {
		return Key{}, ErrInvalid
	}
	k := Key{Name: n, Created: c / 1000}
	if row[2] != nil {
		e, ok := row[2].(int64)
		if !ok {
			return Key{}, ErrInvalid
		}
		v := e / 1000
		k.Expires = &v
	}
	m := map[string][]Right{}
	for _, x := range access {
		if len(x) != 2 {
			return Key{}, ErrInvalid
		}
		g, gok := x[0].(string)
		right, rok := x[1].(string)
		if !gok || !rok {
			return Key{}, ErrInvalid
		}
		m[g] = append(m[g], Right(right))
	}
	for g, rs := range m {
		k.Access = append(k.Access, Access{Group: g, AccessRights: rs})
	}
	sort.Slice(k.Access, func(i, j int) bool { return k.Access[i].Group < k.Access[j].Group })
	return k, nil
}
func (s *Store) newSecret() (string, error) {
	b := make([]byte, secretLength)
	for i := range b {
		for {
			var x [1]byte
			if _, e := s.random(x[:]); e != nil {
				return "", e
			}
			if x[0] < 248 {
				b[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[x[0]%62]
				break
			}
		}
	}
	return string(b), nil
}
func (s *Store) timeNow() time.Time { return s.now().UTC() }
func digest(v string) string {
	x := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(x[:])
}
func millis(v *int64) any {
	if v == nil {
		return nil
	}
	return *v * 1000
}
func id(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "apikey/" + base64.RawURLEncoding.EncodeToString(sum[:24])
}
func validName(v string) bool { return nameRE.MatchString(v) }
func alphaNum(v string) bool {
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func validGroup(v string) bool {
	for _, g := range []string{"Blacklist", "Clients", "Events", "Generic", "Groups", "Roles", "Secrets", "Sessions", "Scopes", "UserAttributes", "Users", "Pam", "AuthProviders", "ApiKeys"} {
		if v == g {
			return true
		}
	}
	return false
}
func validRight(v Right) bool { return v == Read || v == Create || v == Update || v == Delete }
func validate(r Request) error {
	if !validName(r.Name) || r.Exp != nil && (*r.Exp < 1719784800 || *r.Exp > maxExpiryUnixSeconds) {
		return ErrInvalid
	}
	if len(r.Access) == 0 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, a := range r.Access {
		if !validGroup(a.Group) || len(a.AccessRights) == 0 || seen[a.Group] {
			return ErrInvalid
		}
		seen[a.Group] = true
		rs := map[Right]bool{}
		for _, x := range a.AccessRights {
			if !validRight(x) || rs[x] {
				return ErrInvalid
			}
			rs[x] = true
		}
	}
	return nil
}
func normalize(v []Access) []Access {
	out := append([]Access(nil), v...)
	for i := range out {
		out[i].AccessRights = append([]Right(nil), out[i].AccessRights...)
		sort.Slice(out[i].AccessRights, func(a, b int) bool { return out[i].AccessRights[a] < out[i].AccessRights[b] })
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Group < out[j].Group })
	return out
}
