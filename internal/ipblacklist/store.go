// Package ipblacklist provides a deterministic, replicated manual IP blacklist.
// Entries are canonical netip.Prefix values with optional expiry. Check returns
// the longest matching prefix; expiry equality is treated as expired. Storage
// errors fail closed.
package ipblacklist

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrInvalid       = errors.New("invalid IP blacklist input")
	ErrNotFound      = errors.New("IP blacklist entry not found")
	ErrAlreadyExists = errors.New("IP blacklist entry already exists")
	ErrTooMany       = errors.New("IP blacklist entry limit exceeded")
)

const (
	MaxNoteLength     = 256
	DefaultMaxEntries = 10000
)

type Entry struct {
	Prefix          string `json:"prefix"`
	Note            string `json:"note"`
	ExpiresAtUnixMs *int64 `json:"expires_at_unix_ms,omitempty"`
	CreatedAtUnixMs int64  `json:"created_at_unix_ms"`
	UpdatedAtUnixMs int64  `json:"updated_at_unix_ms"`
}

type CheckResult struct {
	Matched bool   `json:"matched"`
	Prefix  string `json:"prefix,omitempty"`
	Entry   *Entry `json:"entry,omitempty"`
}

type Store struct {
	db         *rhiza.DB
	now        func() time.Time
	maxEntries int
}

func NewStore(db *rhiza.DB, maxEntries int) *Store {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	return &Store{db: db, now: time.Now, maxEntries: maxEntries}
}

func (s *Store) timeNow() time.Time { return s.now().UTC() }

func CanonicalPrefix(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix = prefix.Masked()
	addr := prefix.Addr()
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits := prefix.Bits() - 96
		if bits < 0 {
			bits = 0
		}
		prefix = netip.PrefixFrom(addr, bits).Masked()
	}
	return prefix, nil
}

func prefixContains(prefixStr string, addr netip.Addr) (bool, error) {
	p, err := netip.ParsePrefix(prefixStr)
	if err != nil {
		return false, ErrInvalid
	}
	return p.Contains(addr), nil
}

// postQuery classifies a committed zero-row INSERT OR IGNORE receipt. Prefix
// present means the entry exists (ErrAlreadyExists). Prefix absent: query
// count fail-closed. At or above ceiling → ErrTooMany. Below ceiling the only
// valid cause is a concurrent duplicate that was removed between our commit
// and this read, so we also return ErrAlreadyExists. Storage-query errors
// propagate as-is (fail closed).
func (s *Store) postQuery(ctx context.Context, prefixStr string, maxEntries int) error {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT 1 FROM ip_blacklist_entries WHERE prefix = ?`,
		Args:        []any{prefixStr},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	if len(result.Rows) == 1 {
		return ErrAlreadyExists
	}

	count, err := s.count(ctx)
	if err != nil {
		return err
	}
	if count >= int64(maxEntries) {
		return ErrTooMany
	}
	// Prefix absent and count below ceiling: the concurrent duplicate was
	// removed between our commit and this linearizable read.
	return ErrAlreadyExists
}

func (s *Store) count(ctx context.Context) (int64, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM ip_blacklist_entries`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return 0, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return 0, ErrInvalid
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		return 0, ErrInvalid
	}
	return count, nil
}

func (s *Store) Add(ctx context.Context, rawPrefix, note string, expiresAt *time.Time, requestID string) (Entry, error) {
	if s == nil || s.db == nil {
		return Entry{}, ErrInvalid
	}
	prefix, err := CanonicalPrefix(rawPrefix)
	if err != nil {
		return Entry{}, ErrInvalid
	}
	if note != "" && len(note) > MaxNoteLength {
		return Entry{}, ErrInvalid
	}
	if requestID == "" || len(requestID) > 64 {
		return Entry{}, ErrInvalid
	}
	now := s.timeNow().UnixMilli()
	var expiresMs *int64
	if expiresAt != nil {
		e := expiresAt.UTC().Truncate(time.Millisecond).UnixMilli()
		if e <= now {
			return Entry{}, ErrInvalid
		}
		expiresMs = &e
	}
	prefixStr := prefix.String()

	// Convert *int64 to any to avoid Rhiza argument type issues.
	var expiresArg any
	if expiresMs != nil {
		expiresArg = *expiresMs
	}

	// One replicated conditional INSERT OR IGNORE: ceiling + duplicate
	// are both silent zero-row outcomes. The post-query classifies them.
	resp, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: requestID,
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT OR IGNORE INTO ip_blacklist_entries(prefix, note, expires_at_unix_ms, created_at_unix_ms, updated_at_unix_ms)
				SELECT ?, ?, ?, ?, ?
				WHERE (SELECT COUNT(*) FROM ip_blacklist_entries) < ?`,
				Args: []any{prefixStr, note, expiresArg, now, now, int64(s.maxEntries)}},
		},
	})
	if err != nil {
		return Entry{}, err
	}
	if resp.RowsAffected > 0 {
		// Linearizably read the stored row so replays with an advanced clock
		// still return the original timestamps.
		got, qerr := s.Get(ctx, rawPrefix)
		if qerr != nil {
			// Concurrently deleted between insert and read — still a valid
			// linearizable outcome; return the entry as stored.
			if errors.Is(qerr, ErrNotFound) {
				return Entry{Prefix: prefixStr, Note: note, ExpiresAtUnixMs: expiresMs, CreatedAtUnixMs: now, UpdatedAtUnixMs: now}, nil
			}
			return Entry{}, qerr
		}
		return got, nil
	}
	// Zero-row committed receipt: classify via fail-closed linearizable read.
	return Entry{}, s.postQuery(ctx, prefixStr, s.maxEntries)
}

func (s *Store) Update(ctx context.Context, rawPrefix string, note string, expiresAt *time.Time, requestID string) (Entry, error) {
	if s == nil || s.db == nil {
		return Entry{}, ErrInvalid
	}
	prefix, err := CanonicalPrefix(rawPrefix)
	if err != nil {
		return Entry{}, ErrInvalid
	}
	if note != "" && len(note) > MaxNoteLength {
		return Entry{}, ErrInvalid
	}
	if requestID == "" || len(requestID) > 64 {
		return Entry{}, ErrInvalid
	}
	prefixStr := prefix.String()

	now := s.timeNow().UnixMilli()
	var expiresMs *int64
	if expiresAt != nil {
		e := expiresAt.UTC().Truncate(time.Millisecond).UnixMilli()
		if e <= now {
			return Entry{}, ErrInvalid
		}
		expiresMs = &e
	}

	// Convert *int64 to any to avoid Rhiza argument type issues.
	var expiresArg any
	if expiresMs != nil {
		expiresArg = *expiresMs
	}

	// One conditional mutation: UPDATE ... WHERE prefix=?
	resp, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: requestID,
		Statements: []rhiza.SQLStatement{
			{SQL: `UPDATE ip_blacklist_entries SET note=?, expires_at_unix_ms=?, updated_at_unix_ms=?
				WHERE prefix=?`,
				Args: []any{note, expiresArg, now, prefixStr}},
		},
	})
	if err != nil {
		return Entry{}, err
	}
	if resp.RowsAffected > 0 {
		// Return the actual stored row unchanged so concurrent updates cannot
		// cause us to return fabricated stale data.
		got, qerr := s.Get(ctx, rawPrefix)
		if qerr != nil {
			return Entry{}, qerr
		}
		return got, nil
	}
	// Zero-row committed receipt: verify existence, then ErrNotFound.
	result, qerr := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT 1 FROM ip_blacklist_entries WHERE prefix=?`,
		Args:        []any{prefixStr},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if qerr != nil {
		return Entry{}, qerr
	}
	if len(result.Rows) == 1 {
		// Row exists but was not updated — fail closed.
		return Entry{}, fmt.Errorf("ip blacklist update zero-row on existing entry %q", prefixStr)
	}
	return Entry{}, ErrNotFound
}

func (s *Store) Delete(ctx context.Context, rawPrefix string, requestID string) error {
	if s == nil || s.db == nil {
		return ErrInvalid
	}
	prefix, err := CanonicalPrefix(rawPrefix)
	if err != nil {
		return ErrInvalid
	}
	if requestID == "" || len(requestID) > 64 {
		return ErrInvalid
	}
	prefixStr := prefix.String()

	// One DELETE: committed zero-row means prefix did not exist (idempotent).
	resp, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: requestID,
		Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM ip_blacklist_entries WHERE prefix=?`, Args: []any{prefixStr}},
		},
	})
	if err != nil {
		return err
	}
	if resp.RowsAffected > 0 {
		return nil
	}
	// Zero-row: check if it was an idempotent replay or truly absent.
	result, qerr := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT 1 FROM ip_blacklist_entries WHERE prefix=?`,
		Args:        []any{prefixStr},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if qerr != nil {
		return qerr
	}
	if len(result.Rows) == 1 {
		// Row exists but DELETE returned zero — this is an idempotent replay
		// of a previously committed delete. Treat as success.
		return nil
	}
	return nil
}

func (s *Store) Check(ctx context.Context, rawIP string) (CheckResult, error) {
	if s == nil || s.db == nil {
		return CheckResult{}, ErrInvalid
	}
	addr, err := netip.ParseAddr(rawIP)
	if err != nil {
		return CheckResult{}, ErrInvalid
	}
	addr = addr.Unmap()

	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT prefix, note, expires_at_unix_ms, created_at_unix_ms, updated_at_unix_ms FROM ip_blacklist_entries`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return CheckResult{}, err
	}

	now := s.timeNow().UnixMilli()
	var best *Entry
	bestBits := -1

	for _, row := range result.Rows {
		if len(row) != 5 {
			return CheckResult{}, ErrInvalid
		}
		prefixStr, ok := row[0].(string)
		if !ok {
			return CheckResult{}, ErrInvalid
		}
		note, _ := row[1].(string)
		var expiresMs *int64
		if row[2] != nil {
			e, ok := row[2].(int64)
			if !ok {
				return CheckResult{}, ErrInvalid
			}
			expiresMs = &e
		}
		createdMs, ok := row[3].(int64)
		if !ok {
			return CheckResult{}, ErrInvalid
		}
		updatedMs, ok := row[4].(int64)
		if !ok {
			return CheckResult{}, ErrInvalid
		}

		contains, err := prefixContains(prefixStr, addr)
		if err != nil {
			return CheckResult{}, err
		}
		if !contains {
			continue
		}

		p, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			return CheckResult{}, ErrInvalid
		}
		if p.Bits() <= bestBits {
			continue
		}

		if expiresMs != nil && *expiresMs <= now {
			continue
		}

		bestBits = p.Bits()
		best = &Entry{
			Prefix:          prefixStr,
			Note:            note,
			ExpiresAtUnixMs: expiresMs,
			CreatedAtUnixMs: createdMs,
			UpdatedAtUnixMs: updatedMs,
		}
	}

	if best == nil {
		return CheckResult{Matched: false}, nil
	}
	return CheckResult{Matched: true, Prefix: best.Prefix, Entry: best}, nil
}

func (s *Store) List(ctx context.Context) ([]Entry, error) {
	if s == nil || s.db == nil {
		return nil, ErrInvalid
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT prefix, note, expires_at_unix_ms, created_at_unix_ms, updated_at_unix_ms FROM ip_blacklist_entries ORDER BY prefix`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) != 5 {
			return nil, ErrInvalid
		}
		prefixStr, ok := row[0].(string)
		if !ok {
			return nil, ErrInvalid
		}
		note, _ := row[1].(string)
		var expiresMs *int64
		if row[2] != nil {
			e, ok := row[2].(int64)
			if !ok {
				return nil, ErrInvalid
			}
			expiresMs = &e
		}
		createdMs, ok := row[3].(int64)
		if !ok {
			return nil, ErrInvalid
		}
		updatedMs, ok := row[4].(int64)
		if !ok {
			return nil, ErrInvalid
		}
		entries = append(entries, Entry{
			Prefix:          prefixStr,
			Note:            note,
			ExpiresAtUnixMs: expiresMs,
			CreatedAtUnixMs: createdMs,
			UpdatedAtUnixMs: updatedMs,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Prefix < entries[j].Prefix })
	return entries, nil
}

func (s *Store) Get(ctx context.Context, rawPrefix string) (Entry, error) {
	if s == nil || s.db == nil {
		return Entry{}, ErrInvalid
	}
	prefix, err := CanonicalPrefix(rawPrefix)
	if err != nil {
		return Entry{}, ErrInvalid
	}
	prefixStr := prefix.String()

	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT prefix, note, expires_at_unix_ms, created_at_unix_ms, updated_at_unix_ms FROM ip_blacklist_entries WHERE prefix=?`,
		Args:        []any{prefixStr},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return Entry{}, err
	}
	if len(result.Rows) != 1 {
		return Entry{}, ErrNotFound
	}
	row := result.Rows[0]
	if len(row) != 5 {
		return Entry{}, ErrInvalid
	}
	prefixStr2, ok := row[0].(string)
	if !ok {
		return Entry{}, ErrInvalid
	}
	note, _ := row[1].(string)
	var expiresMs *int64
	if row[2] != nil {
		e, ok := row[2].(int64)
		if !ok {
			return Entry{}, ErrInvalid
		}
		expiresMs = &e
	}
	createdMs, ok := row[3].(int64)
	if !ok {
		return Entry{}, ErrInvalid
	}
	updatedMs, ok := row[4].(int64)
	if !ok {
		return Entry{}, ErrInvalid
	}
	return Entry{
		Prefix:          prefixStr2,
		Note:            note,
		ExpiresAtUnixMs: expiresMs,
		CreatedAtUnixMs: createdMs,
		UpdatedAtUnixMs: updatedMs,
	}, nil
}

func (s *Store) Count(ctx context.Context) (int64, error) {
	return s.count(ctx)
}

// SchemaStatements returns the DDL for the IP blacklist tables.
func SchemaStatements() []rhiza.SQLStatement {
	return []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS ip_blacklist_entries (
			prefix TEXT PRIMARY KEY NOT NULL CHECK (length(prefix) > 0),
			note TEXT NOT NULL DEFAULT '' CHECK (length(note) BETWEEN 0 AND 256),
			expires_at_unix_ms INTEGER CHECK (expires_at_unix_ms IS NULL OR expires_at_unix_ms > 0),
			created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
		) STRICT`},
	}
}
