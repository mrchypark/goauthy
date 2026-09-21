// Package kv implements namespace-scoped JSON storage, not OAuth API keys.
package kv

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	nameRE          = regexp.MustCompile(`^[A-Za-z0-9-_/,:*\s]{2,64}$`)
	ErrUnauthorized = errors.New("KV unauthorized")
	ErrForbidden    = errors.New("KV forbidden")
	ErrNotFound     = errors.New("KV not found")
	ErrBadRequest   = errors.New("invalid KV request")
	ErrConflict     = errors.New("KV conflict")
	ErrCorrupt      = errors.New("invalid persisted KV state")
)

type Namespace struct {
	Name   string `json:"name"`
	Public bool   `json:"public"`
}
type Access struct {
	ID        string  `json:"id"`
	Namespace string  `json:"ns"`
	Secret    string  `json:"secret,omitempty"`
	Name      *string `json:"name,omitempty"`
	Enabled   bool    `json:"enabled"`
	digest    string
}
type Value struct {
	Key       string          `json:"key"`
	Encrypted bool            `json:"encrypted"`
	Value     json.RawMessage `json:"value"`
}
type Store struct {
	db        *rhiza.DB
	keyring   *oidc.Keyring
	writerKey string
	// Deterministic interposition seam; production leaves this nil.
	beforeMutation func()
}

func NewStore(db *rhiza.DB, keyring *oidc.Keyring) (*Store, error) {
	if db == nil {
		return nil, ErrBadRequest
	}
	k, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return nil, err
	}
	return &Store{db: db, keyring: keyring, writerKey: k}, nil
}
func valid(s string) bool         { return nameRE.MatchString(s) }
func validDisplay(s *string) bool { return s == nil || valid(*s) }
func digest(s string) string {
	d := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(d[:])
}
func randomText(n int) string {
	s := rand.Text()
	for len(s) < n {
		s += rand.Text()
	}
	return s[:n]
}
func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
func accessPurpose(id string) string           { return "kv/access/" + id }
func valuePurpose(identity, key string) string { return "kv/value/" + digest(identity+"\x00"+key) }
func (s *Store) query(ctx context.Context, sql string, args ...any) ([][]any, error) {
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	return r.Rows, err
}
func (s *Store) mutate(ctx context.Context, sql string, args ...any) (rhiza.ExecuteResponse, error) {
	if s.beforeMutation != nil {
		s.beforeMutation()
	}
	// IDs identify operations, not rows or wall-clock instants. A per-key ID
	// would replay the first operation and silently break subsequent updates.
	return storage.ExecuteEnvelope(ctx, s.db, s.writerKey, rhiza.ExecuteRequest{RequestID: "kv/" + rand.Text(), SQL: sql, Args: args})
}
func changed(r rhiza.ExecuteResponse, err, missing error) error {
	if err != nil {
		return err
	}
	if r.RowsAffected == 0 {
		return missing
	}
	return nil
}

// Growing KV lists are keyset paginated: a page holds at most listLimit rows
// and carries the position of its last row so the next page resumes exactly
// after it. Cursors name the listing they came from, so a token cannot be
// replayed against a different list.
const (
	kvListNamespaces = "ns"
	kvListAccess     = "access"
	kvListKeys       = "key"
	kvListValues     = "value"
	// kvValuePageByteBudget bounds one value page. A single accepted value can
	// be 64 KiB, so the documented 1,000-row default can request far more than
	// the engine's per-query result budget in one read.
	kvValuePageByteBudget = 8 << 20
)

type kvListCursor struct {
	Kind     string
	Position string
}

// Stored names may contain whitespace and punctuation, so a continuation token
// is base64url: it stays valid both as a query value and as a header value.
func encodeKVListCursor(c kvListCursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte("e1." + c.Kind + "." + c.Position))
}

// kvListPosition decodes a continuation token and checks that it belongs to the
// listing asking for it. Anything else is a bad request rather than a silent
// restart or skip.
func kvListPosition(kind, cursor string) (string, error) {
	if cursor == "" {
		return "", nil
	}
	if len(cursor) > 256 {
		return "", ErrBadRequest
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", ErrBadRequest
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 || parts[0] != "e1" || parts[1] != kind || !valid(parts[2]) {
		return "", ErrBadRequest
	}
	return parts[2], nil
}

// ListNamespaces returns one bounded keyset page and the continuation token of
// the following page, which is empty when the page ends the listing.
func (s *Store) ListNamespaces(ctx context.Context, limit int, cursor string) ([]Namespace, string, error) {
	limit, err := listLimit(limit, "")
	if err != nil {
		return nil, "", err
	}
	after, err := kvListPosition(kvListNamespaces, cursor)
	if err != nil {
		return nil, "", err
	}
	// One extra row only decides whether a continuation exists; it is never
	// returned, so every continuation has at least one following row.
	rows, err := s.query(ctx, "SELECT name,public FROM kv_namespaces WHERE name>? ORDER BY name LIMIT ?", after, int64(limit)+1)
	if err != nil {
		return nil, "", err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]Namespace, 0, len(rows))
	for _, row := range rows {
		if len(row) != 2 {
			return nil, "", ErrCorrupt
		}
		n, ok := row[0].(string)
		p, pok := row[1].(int64)
		if !ok || !valid(n) || !pok || p < 0 || p > 1 {
			return nil, "", ErrCorrupt
		}
		out = append(out, Namespace{n, p == 1})
	}
	if !more {
		return out, "", nil
	}
	return out, encodeKVListCursor(kvListCursor{Kind: kvListNamespaces, Position: out[len(out)-1].Name}), nil
}
func (s *Store) namespaceIdentity(ctx context.Context, name string) (Namespace, string, error) {
	if !valid(name) {
		return Namespace{}, "", ErrBadRequest
	}
	rows, err := s.query(ctx, "SELECT public,identity FROM kv_namespaces WHERE name=?", name)
	if err != nil {
		return Namespace{}, "", err
	}
	if len(rows) == 0 {
		return Namespace{}, "", ErrNotFound
	}
	if len(rows) != 1 || len(rows[0]) != 2 {
		return Namespace{}, "", ErrCorrupt
	}
	p, ok := rows[0][0].(int64)
	id, iok := rows[0][1].(string)
	if !ok || p < 0 || p > 1 || !iok || id == "" {
		return Namespace{}, "", ErrCorrupt
	}
	return Namespace{name, p == 1}, id, nil
}
func (s *Store) Namespace(ctx context.Context, name string) (Namespace, error) {
	n, _, err := s.namespaceIdentity(ctx, name)
	return n, err
}
func (s *Store) PutNamespace(ctx context.Context, old, name string, public, create bool) error {
	if !valid(name) || !create && !valid(old) {
		return ErrBadRequest
	}
	if create {
		r, err := s.mutate(ctx, "INSERT INTO kv_namespaces(name,identity,public) SELECT ?,?,? WHERE NOT EXISTS(SELECT 1 FROM kv_namespaces WHERE name=?)", name, randomText(16), boolInt(public), name)
		return changed(r, err, ErrConflict)
	}
	// Stable identity keeps row-bound encryption valid across namespace renames.
	r, err := s.mutate(ctx, "UPDATE kv_namespaces SET name=?,public=? WHERE name=? AND NOT EXISTS(SELECT 1 FROM kv_namespaces WHERE name=? AND name<>?)", name, boolInt(public), old, name, old)
	if err != nil {
		return err
	}
	if r.RowsAffected > 0 {
		return nil
	}
	if _, err := s.Namespace(ctx, old); err != nil {
		return err
	}
	return ErrConflict
}
func (s *Store) DeleteNamespace(ctx context.Context, name string) error {
	if !valid(name) {
		return ErrBadRequest
	}
	r, err := s.mutate(ctx, "DELETE FROM kv_namespaces WHERE name=?", name)
	return changed(r, err, ErrNotFound)
}
func (s *Store) decodeAccess(row []any) (Access, error) {
	if len(row) != 6 {
		return Access{}, ErrCorrupt
	}
	id, iok := row[0].(string)
	ns, nok := row[1].(string)
	enc, eok := row[2].([]byte)
	enabled, bok := row[3].(int64)
	d, dok := row[5].(string)
	if !iok || !alphaNum(id, 16) || !nok || !valid(ns) || !eok || !bok || enabled < 0 || enabled > 1 || !dok {
		return Access{}, ErrCorrupt
	}
	var name *string
	if row[4] != nil {
		v, ok := row[4].(string)
		if !ok || !valid(v) {
			return Access{}, ErrCorrupt
		}
		name = &v
	}
	sec, err := s.keyring.OpenEnvelope(accessPurpose(id), enc)
	if err != nil || !alphaNum(string(sec), 48) || subtle.ConstantTimeCompare([]byte(digest(string(sec))), []byte(d)) != 1 {
		return Access{}, ErrCorrupt
	}
	return Access{ID: id, Namespace: ns, Secret: string(sec), Name: name, Enabled: enabled == 1, digest: d}, nil
}

// Accesses returns one bounded keyset page of namespace credentials and the
// continuation token of the following page, which is empty when the listing
// ends.
func (s *Store) Accesses(ctx context.Context, ns string, limit int, cursor string) ([]Access, string, error) {
	if _, err := s.Namespace(ctx, ns); err != nil {
		return nil, "", err
	}
	limit, err := listLimit(limit, "")
	if err != nil {
		return nil, "", err
	}
	after, err := kvListPosition(kvListAccess, cursor)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.query(ctx, "SELECT id,namespace,secret,enabled,name,secret_digest FROM kv_access WHERE namespace=? AND id>? ORDER BY id LIMIT ?", ns, after, int64(limit)+1)
	if err != nil {
		return nil, "", err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]Access, 0, len(rows))
	for _, row := range rows {
		a, err := s.decodeAccess(row)
		if err != nil {
			return nil, "", err
		}
		out = append(out, a)
	}
	if !more {
		return out, "", nil
	}
	return out, encodeKVListCursor(kvListCursor{Kind: kvListAccess, Position: out[len(out)-1].ID}), nil
}
func nullableName(name *string) any {
	if name == nil {
		return nil
	}
	return *name
}
func (s *Store) CreateAccess(ctx context.Context, ns string, enabled bool, name *string) (Access, error) {
	if !valid(ns) || !validDisplay(name) {
		return Access{}, ErrBadRequest
	}
	id, sec := randomText(16), randomText(48)
	enc, err := s.keyring.SealEnvelope(accessPurpose(id), []byte(sec))
	if err != nil {
		return Access{}, err
	}
	r, err := s.mutate(ctx, "INSERT INTO kv_access(id,namespace,secret,secret_digest,enabled,name) SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM kv_namespaces WHERE name=?)", id, ns, enc, digest(sec), boolInt(enabled), nullableName(name), ns)
	if err = changed(r, err, ErrNotFound); err != nil {
		return Access{}, err
	}
	return Access{ID: id, Namespace: ns, Secret: sec, Name: name, Enabled: enabled}, nil
}
func (s *Store) UpdateAccess(ctx context.Context, ns, id string, enabled bool, name *string) error {
	if !valid(ns) || !alphaNum(id, 16) || !validDisplay(name) {
		return ErrBadRequest
	}
	r, err := s.mutate(ctx, "UPDATE kv_access SET enabled=?,name=? WHERE namespace=? AND id=?", boolInt(enabled), nullableName(name), ns, id)
	return changed(r, err, ErrNotFound)
}
func (s *Store) DeleteAccess(ctx context.Context, ns, id string) error {
	if !valid(ns) || !alphaNum(id, 16) {
		return ErrBadRequest
	}
	r, err := s.mutate(ctx, "DELETE FROM kv_access WHERE namespace=? AND id=?", ns, id)
	return changed(r, err, ErrNotFound)
}
func (s *Store) RotateAccess(ctx context.Context, ns, id string) (Access, error) {
	if !valid(ns) || !alphaNum(id, 16) {
		return Access{}, ErrBadRequest
	}
	rows, err := s.query(ctx, "SELECT id,namespace,secret,enabled,name,secret_digest FROM kv_access WHERE namespace=? AND id=?", ns, id)
	if err != nil {
		return Access{}, err
	}
	if len(rows) == 0 {
		return Access{}, ErrNotFound
	}
	if len(rows) != 1 {
		return Access{}, ErrCorrupt
	}
	a, err := s.decodeAccess(rows[0])
	if err != nil {
		return Access{}, err
	}
	sec := randomText(48)
	enc, err := s.keyring.SealEnvelope(accessPurpose(id), []byte(sec))
	if err != nil {
		return Access{}, err
	}
	r, err := s.mutate(ctx, "UPDATE kv_access SET secret=?,secret_digest=? WHERE namespace=? AND id=? AND secret_digest=?", enc, digest(sec), ns, id, a.digest)
	if err = changed(r, err, ErrConflict); err != nil {
		return Access{}, err
	}
	a.Secret = sec
	a.digest = ""
	return a, nil
}
func alphaNum(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func (s *Store) Authenticate(ctx context.Context, header string) (Access, error) {
	if !strings.HasPrefix(header, "Bearer ") || strings.Count(header, " ") != 1 {
		return Access{}, ErrUnauthorized
	}
	id, sec, ok := strings.Cut(strings.TrimPrefix(header, "Bearer "), "$")
	if !ok || !alphaNum(id, 16) || !alphaNum(sec, 48) {
		return Access{}, ErrUnauthorized
	}
	rows, err := s.query(ctx, "SELECT id,namespace,secret,enabled,name,secret_digest FROM kv_access WHERE id=?", id)
	if err != nil {
		return Access{}, err
	}
	if len(rows) != 1 {
		return Access{}, ErrUnauthorized
	}
	a, err := s.decodeAccess(rows[0])
	if err != nil {
		return Access{}, err
	}
	if !a.Enabled || subtle.ConstantTimeCompare([]byte(a.digest), []byte(digest(sec))) != 1 {
		return Access{}, ErrUnauthorized
	}
	a.Secret = ""
	return a, nil
}

// Empty ID is created only by the authenticated browser-admin handler.
// Bearer writes revalidate the exact credential inside the SQL transaction.
func accessGuard(a Access) (string, []any) {
	if a.ID == "" {
		return "1", nil
	}
	return "EXISTS(SELECT 1 FROM kv_access a WHERE a.id=? AND a.namespace=? AND a.secret_digest=? AND a.enabled=1)", []any{a.ID, a.Namespace, a.digest}
}
func (s *Store) Set(ctx context.Context, a Access, v Value) error {
	if !valid(v.Key) || len(v.Value) > 64<<10 || !json.Valid(v.Value) {
		return ErrBadRequest
	}
	_, identity, err := s.namespaceIdentity(ctx, a.Namespace)
	if err != nil {
		return err
	}
	data := []byte(v.Value)
	if v.Encrypted {
		data, err = s.keyring.SealEnvelope(valuePurpose(identity, v.Key), data)
		if err != nil {
			return err
		}
	}
	guard, gargs := accessGuard(a)
	args := append([]any{a.Namespace, v.Key, boolInt(v.Encrypted), data, a.Namespace, identity}, gargs...)
	r, err := s.mutate(ctx, "INSERT INTO kv_values(namespace,key,encrypted,value) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM kv_namespaces WHERE name=? AND identity=?) AND "+guard+" ON CONFLICT(namespace,key) DO UPDATE SET encrypted=excluded.encrypted,value=excluded.value", args...)
	return changed(r, err, ErrUnauthorized)
}
func (s *Store) decodeValue(row []any) (Value, error) {
	if len(row) != 4 {
		return Value{}, ErrCorrupt
	}
	key, kok := row[0].(string)
	encrypted, eok := row[1].(int64)
	data, dok := row[2].([]byte)
	identity, iok := row[3].(string)
	if !kok || !valid(key) || !eok || encrypted < 0 || encrypted > 1 || !dok || !iok || identity == "" {
		return Value{}, ErrCorrupt
	}
	if encrypted == 1 {
		var err error
		data, err = s.keyring.OpenEnvelope(valuePurpose(identity, key), data)
		if err != nil {
			return Value{}, ErrCorrupt
		}
	}
	if len(data) > 64<<10 || !json.Valid(data) {
		return Value{}, ErrCorrupt
	}
	return Value{key, encrypted == 1, json.RawMessage(data)}, nil
}
func (s *Store) Get(ctx context.Context, a Access, key string) (json.RawMessage, error) {
	if !valid(a.Namespace) || !valid(key) {
		return nil, ErrBadRequest
	}
	guard, args := accessGuard(a)
	rows, err := s.query(ctx, "SELECT v.key,v.encrypted,v.value,n.identity FROM kv_values v JOIN kv_namespaces n ON n.name=v.namespace WHERE v.namespace=? AND v.key=? AND "+guard, append([]any{a.Namespace, key}, args...)...)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	if len(rows) != 1 {
		return nil, ErrCorrupt
	}
	v, err := s.decodeValue(rows[0])
	return v.Value, err
}
func (s *Store) PublicGet(ctx context.Context, ns, key string) (json.RawMessage, error) {
	if !valid(ns) || !valid(key) {
		return nil, ErrBadRequest
	}
	// Policy and data are resolved by one linearizable read, so turning a
	// namespace private cannot race a later unguarded value lookup.
	rows, err := s.query(ctx, `SELECT n.public,v.key,v.encrypted,v.value,n.identity FROM kv_namespaces n LEFT JOIN kv_values v ON v.namespace=n.name AND v.key=? WHERE n.name=?`, key, ns)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	if len(rows) != 1 || len(rows[0]) != 5 {
		return nil, ErrCorrupt
	}
	public, ok := rows[0][0].(int64)
	if !ok || public < 0 || public > 1 {
		return nil, ErrCorrupt
	}
	if public == 0 {
		return nil, ErrUnauthorized
	}
	if rows[0][1] == nil {
		return nil, ErrNotFound
	}
	v, err := s.decodeValue(rows[0][1:])
	return v.Value, err
}
func (s *Store) Delete(ctx context.Context, a Access, key string) error {
	if !valid(a.Namespace) || !valid(key) {
		return ErrBadRequest
	}
	guard, args := accessGuard(a)
	r, err := s.mutate(ctx, "DELETE FROM kv_values WHERE namespace=? AND key=? AND "+guard, append([]any{a.Namespace, key}, args...)...)
	return changed(r, err, ErrNotFound)
}
func listLimit(limit int, search string) (int, error) {
	if limit == 0 {
		limit = 1000
	}
	if limit < 1 || limit > 1000 || len(search) > 64 || strings.ContainsRune(search, '\x00') {
		return 0, ErrBadRequest
	}
	return limit, nil
}

// valueRows reads one keyset page of value rows in key order and reports
// whether a further row exists, which is how the caller detects a continuation.
// Pages are bounded by kvValuePageByteBudget: a single accepted value may be
// 64 KiB, so the documented 1,000-row default would otherwise ask one query for
// far more than the engine's result budget and fail for valid stored data.
//
// ponytail: the page boundary is byte-budgeted, not snapshot-isolated, so a
// concurrent write can hide a row inserted behind the cursor. Upgrade path: pin
// the read when the pinned Rhiza API exposes a snapshot handle.
func (s *Store) valueRows(ctx context.Context, a Access, limit int, search, cursor string) ([][]any, bool, error) {
	limit, err := listLimit(limit, search)
	if err != nil || !valid(a.Namespace) {
		return nil, false, ErrBadRequest
	}
	after, err := kvListPosition(kvListValues, cursor)
	if err != nil {
		return nil, false, err
	}
	guard, guardArgs := accessGuard(a)
	args := append(append([]any{a.Namespace, search}, guardArgs...), after, int64(limit)+1)
	rows, err := s.query(ctx, "SELECT "+valueListColumns+",run FROM (SELECT key,encrypted,value,identity,"+valueRowRun+" AS run FROM ("+
		"SELECT v.key AS key,v.encrypted AS encrypted,v.value AS value,n.identity AS identity FROM kv_values v JOIN kv_namespaces n ON n.name=v.namespace "+
		"WHERE v.namespace=? AND instr(v.key,?)>0 AND "+guard+" AND v.key>? ORDER BY v.key LIMIT ?"+
		")) WHERE run<="+strconv.Itoa(kvValuePageByteBudget)+" OR run-"+valueRowCost+"<="+strconv.Itoa(kvValuePageByteBudget)+" ORDER BY key", args...)
	if err != nil {
		return nil, false, err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	if n := len(rows); n > 0 {
		if run, ok := rows[n-1][4].(int64); !ok || run > kvValuePageByteBudget {
			// The trailing row pushes the page past the byte budget; keep the rows
			// that fit and resume from this one on the next page.
			rows = rows[:n-1]
			more = true
		}
	}
	out := make([][]any, 0, len(rows))
	for _, row := range rows {
		if len(row) != 5 {
			return nil, false, ErrCorrupt
		}
		out = append(out, row[:4])
	}
	return out, more, nil
}

// valueListColumns is the projection decodeValue expects. valueRows appends the
// running byte estimate and trims it before returning, so callers keep the
// four-column contract.
const valueListColumns = "key,encrypted,value,identity"

// Every stored byte can expand into a 6-byte JSON escape, so the cost
// over-estimates the encoded row; 64 more bytes cover its quotes and separators.
const valueRowCost = "((COALESCE(octet_length(value),0)+octet_length(key)+octet_length(identity))*6+64)"

// A row is admitted when everything before it already fits the budget, so one
// oversized row cannot end the page early; valueRows then drops the trailing
// row whose running total overruns and resumes from it on the next page.
const valueRowRun = "SUM(" + valueRowCost + ") OVER (ORDER BY key ROWS UNBOUNDED PRECEDING)"

func (s *Store) keyRows(ctx context.Context, a Access, limit int, search, cursor string) ([][]any, error) {
	limit, err := listLimit(limit, search)
	if err != nil || !valid(a.Namespace) {
		return nil, ErrBadRequest
	}
	after, err := kvListPosition(kvListKeys, cursor)
	if err != nil {
		return nil, err
	}
	guard, args := accessGuard(a)
	args = append([]any{a.Namespace, search}, args...)
	args = append(args, after, int64(limit)+1)
	// Key names alone, like valueRows with the same authority predicate: listing
	// names must not read or decrypt payloads, which would spend the storage
	// result budget on data the caller did not ask for.
	return s.query(ctx, "SELECT v.key FROM kv_values v WHERE v.namespace=? AND instr(v.key,?)>0 AND "+guard+" AND v.key>? ORDER BY v.key LIMIT ?", args...)
}

// Keys returns one bounded keyset page of key names and the continuation token
// of the following page, which is empty when the listing ends.
func (s *Store) Keys(ctx context.Context, a Access, limit int, search, cursor string) ([]string, string, error) {
	// The row reader validates the same limit; normalizing here keeps the page
	// boundary and the requested page size the same number.
	limit, err := listLimit(limit, search)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.keyRows(ctx, a, limit, search, cursor)
	if err != nil {
		return nil, "", err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) != 1 {
			return nil, "", ErrCorrupt
		}
		key, ok := row[0].(string)
		if !ok || !valid(key) || strings.ContainsRune(key, '\x00') {
			return nil, "", ErrCorrupt
		}
		out = append(out, key)
	}
	if !more {
		return out, "", nil
	}
	return out, encodeKVListCursor(kvListCursor{Kind: kvListKeys, Position: out[len(out)-1]}), nil
}

// Values returns one bounded keyset page of values and the continuation token
// of the following page, which is empty when the listing ends.
func (s *Store) Values(ctx context.Context, a Access, limit int, search, cursor string) ([]Value, string, error) {
	limit, err := listLimit(limit, search)
	if err != nil {
		return nil, "", err
	}
	rows, more, err := s.valueRows(ctx, a, limit, search, cursor)
	if err != nil {
		return nil, "", err
	}
	out := make([]Value, 0, len(rows))
	for _, row := range rows {
		v, err := s.decodeValue(row)
		if err != nil {
			return nil, "", err
		}
		out = append(out, v)
	}
	if !more {
		return out, "", nil
	}
	return out, encodeKVListCursor(kvListCursor{Kind: kvListValues, Position: out[len(out)-1].Key}), nil
}
