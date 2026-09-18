package ipblacklist

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	// Barrier tests release up to 200 callers, including post-write reads.
	// Size this fixture's read budget for that workload; production retains
	// Rhiza's bounded default. These tests check state races, not admission.
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir(), MaxConcurrentReads: 256})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-ipbl-schema",
		Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE IF NOT EXISTS goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `CREATE TABLE IF NOT EXISTS ip_blacklist_entries (
				prefix TEXT PRIMARY KEY NOT NULL,
				note TEXT NOT NULL DEFAULT '' CHECK (length(note) BETWEEN 0 AND 256),
				expires_at_unix_ms INTEGER CHECK (expires_at_unix_ms IS NULL OR expires_at_unix_ms > 0),
				created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
				updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
			) STRICT`},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return NewStore(db, 100)
}

func newTestStoreWithClock(t *testing.T, now func() time.Time, maxEntries int) *Store {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-ipbl-schema-clock",
		Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE IF NOT EXISTS goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `CREATE TABLE IF NOT EXISTS ip_blacklist_entries (
				prefix TEXT PRIMARY KEY NOT NULL,
				note TEXT NOT NULL DEFAULT '' CHECK (length(note) BETWEEN 0 AND 256),
				expires_at_unix_ms INTEGER CHECK (expires_at_unix_ms IS NULL OR expires_at_unix_ms > 0),
				created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
				updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
			) STRICT`},
		},
	}); err != nil {
		t.Fatal(err)
	}
	s := NewStore(db, maxEntries)
	s.now = now
	return s
}

func fixedTime(ms int64) time.Time {
	return time.UnixMilli(ms).UTC()
}

func TestCanonicalPrefix(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.1.2.3/24", "10.1.2.0/24"},
		{"192.168.1.1/32", "192.168.1.1/32"},
		{"::1/128", "::1/128"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"::ffff:10.0.0.1/128", "10.0.0.1/32"},
		{"::ffff:10.0.0.0/108", "10.0.0.0/12"},
		{"::ffff:c0a8:0001/112", "192.168.0.0/16"},
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"::/0", "::/0"},
		{"10.0.0.5/8", "10.0.0.0/8"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := CanonicalPrefix(tc.input)
			if err != nil {
				t.Fatalf("CanonicalPrefix(%q) error: %v", tc.input, err)
			}
			if got.String() != tc.want {
				t.Errorf("CanonicalPrefix(%q) = %q, want %q", tc.input, got.String(), tc.want)
			}
		})
	}
}

func TestCanonicalPrefixRejectsInvalid(t *testing.T) {
	for _, input := range []string{"", "not-a-prefix", "10.0.0.0", "10.0.0.0/33", "10.0.0.0/-1", "::ffff:10.0.0.1/200"} {
		if _, err := CanonicalPrefix(input); err == nil {
			t.Errorf("CanonicalPrefix(%q) should have failed", input)
		}
	}
}

func TestCheckRejectsMalformedPersistedPrefix(t *testing.T) {
	s := newTestStore(t)
	if _, err := storage.Execute(context.Background(), s.db, rhiza.ExecuteRequest{
		RequestID:  "test-ipbl-malformed-prefix",
		Statements: []rhiza.SQLStatement{{SQL: `INSERT INTO ip_blacklist_entries(prefix, note, created_at_unix_ms, updated_at_unix_ms) VALUES (?, '', 1, 1)`, Args: []any{"not-a-prefix"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Check(context.Background(), "10.0.0.1"); err != ErrInvalid {
		t.Fatalf("Check error=%v, want %v", err, ErrInvalid)
	}
}

func TestAddAndGet(t *testing.T) {
	s := newTestStore(t)
	fixed := fixedTime(1000000)
	s.now = func() time.Time { return fixed }

	entry, err := s.Add(context.Background(), "10.0.0.0/8", "test entry", nil, "req-add-1")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Prefix != "10.0.0.0/8" {
		t.Fatalf("prefix = %q, want %q", entry.Prefix, "10.0.0.0/8")
	}
	if entry.Note != "test entry" {
		t.Fatalf("note = %q, want %q", entry.Note, "test entry")
	}
	if entry.ExpiresAtUnixMs != nil {
		t.Fatalf("expires = %v, want nil", entry.ExpiresAtUnixMs)
	}
	if entry.CreatedAtUnixMs != fixed.UnixMilli() {
		t.Fatalf("created = %d, want %d", entry.CreatedAtUnixMs, fixed.UnixMilli())
	}

	got, err := s.Get(context.Background(), "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if got.Prefix != entry.Prefix || got.Note != entry.Note {
		t.Fatalf("Get mismatch: got=%v entry=%v", got, entry)
	}
}

func TestAddWithExpiry(t *testing.T) {
	s := newTestStore(t)
	fixed := fixedTime(1000000)
	s.now = func() time.Time { return fixed }

	expires := fixed.Add(time.Hour)
	entry, err := s.Add(context.Background(), "192.168.0.0/16", "expires", &expires, "req-add-exp")
	if err != nil {
		t.Fatal(err)
	}
	if entry.ExpiresAtUnixMs == nil || *entry.ExpiresAtUnixMs != expires.UnixMilli() {
		t.Fatalf("expires = %v, want %d", entry.ExpiresAtUnixMs, expires.UnixMilli())
	}
}

func TestAddRejectsExpiredTime(t *testing.T) {
	s := newTestStore(t)
	fixed := fixedTime(1000000)
	s.now = func() time.Time { return fixed }

	expires := fixed.Add(-time.Hour)
	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", &expires, "req-add-exp-past"); err != ErrInvalid {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func TestAddRejectsDuplicate(t *testing.T) {
	s := newTestStore(t)
	fixed := fixedTime(1000000)
	s.now = func() time.Time { return fixed }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req-add-dup-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(context.Background(), "10.0.0.0/8", "different note", nil, "req-add-dup-2"); err != ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestAddCanonicalizesPrefix(t *testing.T) {
	s := newTestStore(t)
	fixed := fixedTime(1000000)
	s.now = func() time.Time { return fixed }

	entry, err := s.Add(context.Background(), "::ffff:10.0.0.1/128", "mapped", nil, "req-add-canonical")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Prefix != "10.0.0.1/32" {
		t.Fatalf("prefix = %q, want %q", entry.Prefix, "10.0.0.1/32")
	}

	got, err := s.Get(context.Background(), "10.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	if got.Prefix != "10.0.0.1/32" {
		t.Fatalf("Get prefix = %q, want %q", got.Prefix, "10.0.0.1/32")
	}
}

func TestUpdate(t *testing.T) {
	s := newTestStore(t)
	now := fixedTime(1000000)
	s.now = func() time.Time { return now }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "old note", nil, "req-upd-add"); err != nil {
		t.Fatal(err)
	}

	now2 := fixedTime(2000000)
	s.now = func() time.Time { return now2 }

	expires := now2.Add(time.Hour)
	entry, err := s.Update(context.Background(), "10.0.0.0/8", "new note", &expires, "req-upd-1")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Note != "new note" {
		t.Fatalf("note = %q, want %q", entry.Note, "new note")
	}
	if entry.UpdatedAtUnixMs != now2.UnixMilli() {
		t.Fatalf("updated = %d, want %d", entry.UpdatedAtUnixMs, now2.UnixMilli())
	}

	got, err := s.Get(context.Background(), "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != "new note" {
		t.Fatalf("Get note = %q, want %q", got.Note, "new note")
	}
}

func TestUpdateNotFound(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Update(context.Background(), "10.0.0.0/8", "note", nil, "req-upd-nf"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req-del-add"); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(context.Background(), "10.0.0.0/8", "req-del-1"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Get(context.Background(), "10.0.0.0/8"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	// Delete is idempotent — deleting a non-existent entry returns nil.
	if err := s.Delete(context.Background(), "10.0.0.0/8", "req-del-nf"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCheckNoMatch(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "192.168.0.0/16", "", nil, "req-chk-add"); err != nil {
		t.Fatal(err)
	}

	result, err := s.Check(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched {
		t.Fatal("expected no match")
	}
}

func TestCheckMatch(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "blocked", nil, "req-chk-m-add"); err != nil {
		t.Fatal(err)
	}

	result, err := s.Check(context.Background(), "10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("expected match")
	}
	if result.Prefix != "10.0.0.0/8" {
		t.Fatalf("prefix = %q, want %q", result.Prefix, "10.0.0.0/8")
	}
	if result.Entry == nil || result.Entry.Note != "blocked" {
		t.Fatalf("entry note = %v, want %q", result.Entry, "blocked")
	}
}

func TestCheckLongestPrefix(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "broad", nil, "req-lp-add-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(context.Background(), "10.1.0.0/16", "specific", nil, "req-lp-add-2"); err != nil {
		t.Fatal(err)
	}

	result, err := s.Check(context.Background(), "10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("expected match")
	}
	if result.Prefix != "10.1.0.0/16" {
		t.Fatalf("prefix = %q, want %q (longest match)", result.Prefix, "10.1.0.0/16")
	}
	if result.Entry == nil || result.Entry.Note != "specific" {
		t.Fatalf("entry note = %v, want %q", result.Entry, "specific")
	}
}

func TestCheckMultiplePrefixes(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "a", nil, "req-mp-add-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(context.Background(), "10.0.0.0/4", "b", nil, "req-mp-add-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(context.Background(), "10.0.0.0/12", "c", nil, "req-mp-add-3"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(context.Background(), "10.0.0.0/20", "d", nil, "req-mp-add-4"); err != nil {
		t.Fatal(err)
	}

	result, err := s.Check(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("expected match")
	}
	if result.Prefix != "10.0.0.0/20" {
		t.Fatalf("prefix = %q, want %q", result.Prefix, "10.0.0.0/20")
	}
}

func TestCheckExpiryEqualIsExpired(t *testing.T) {
	s := newTestStore(t)
	fixed := fixedTime(1000000)
	s.now = func() time.Time { return fixed }

	expires := fixed.Add(time.Millisecond)
	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", &expires, "req-exp-eq-add"); err != nil {
		t.Fatal(err)
	}

	// At exact expiry time, entry is expired
	s.now = func() time.Time { return expires }
	result, err := s.Check(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched {
		t.Fatal("entry should be expired at exact expiry time")
	}

	// Before expiry, entry is active
	s.now = func() time.Time { return expires.Add(-time.Millisecond) }
	result, err = s.Check(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("entry should be active before expiry")
	}
}

func TestCheckIPv4MappedIPv6(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "ipv4-net", nil, "req-ipv6-add"); err != nil {
		t.Fatal(err)
	}

	result, err := s.Check(context.Background(), "::ffff:10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("expected match for IPv4-mapped IPv6")
	}
	if result.Prefix != "10.0.0.0/8" {
		t.Fatalf("prefix = %q, want %q", result.Prefix, "10.0.0.0/8")
	}
}

func TestCheckCanonicalizesIPv4MappedIPv6Prefix(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "::ffff:10.0.0.0/104", "mapped", nil, "req-cmap-add"); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(context.Background(), "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if got.Prefix != "10.0.0.0/8" {
		t.Fatalf("prefix = %q, want %q", got.Prefix, "10.0.0.0/8")
	}

	result, err := s.Check(context.Background(), "10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("expected match for IPv4 address")
	}
}

func TestCheckUnmappedAddress(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req-unmap-add"); err != nil {
		t.Fatal(err)
	}

	result, err := s.Check(context.Background(), "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched {
		t.Fatal("should not match IPv6 address against IPv4 prefix")
	}
}

func TestList(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "192.168.0.0/16", "c", nil, "req-list-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(context.Background(), "10.0.0.0/8", "a", nil, "req-list-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(context.Background(), "172.16.0.0/12", "b", nil, "req-list-3"); err != nil {
		t.Fatal(err)
	}

	entries, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("list len = %d, want 3", len(entries))
	}
	if entries[0].Prefix != "10.0.0.0/8" || entries[1].Prefix != "172.16.0.0/12" || entries[2].Prefix != "192.168.0.0/16" {
		t.Fatalf("list order = %v, want sorted by prefix", []string{entries[0].Prefix, entries[1].Prefix, entries[2].Prefix})
	}
}

func TestListEmpty(t *testing.T) {
	s := newTestStore(t)

	entries, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("list len = %d, want 0", len(entries))
	}
}

func TestCount(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	count, err := s.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0", count)
	}

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req-cnt-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(context.Background(), "192.168.0.0/16", "", nil, "req-cnt-2"); err != nil {
		t.Fatal(err)
	}

	count, err = s.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
}

func TestIdempotentRequestID(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	entry1, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req-idem-1")
	if err != nil {
		t.Fatal(err)
	}

	// Same request ID, same prefix — idempotent replay returns same result.
	entry2, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req-idem-1")
	if err != nil {
		t.Fatal(err)
	}
	if entry1.Prefix != entry2.Prefix || entry1.CreatedAtUnixMs != entry2.CreatedAtUnixMs {
		t.Fatalf("idempotent add returned different entries: %v vs %v", entry1, entry2)
	}

	count, err := s.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1 (idempotent)", count)
	}
}

func TestDeleteIdempotent(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req-idel-add"); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(context.Background(), "10.0.0.0/8", "req-idel-1"); err != nil {
		t.Fatal(err)
	}

	// Same request ID — idempotent replay returns nil.
	if err := s.Delete(context.Background(), "10.0.0.0/8", "req-idel-1"); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentAddDelete(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	var wg sync.WaitGroup
	errs := make(chan error, 200)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			prefix := fmt.Sprintf("10.%d.0.0/16", i)
			_, err := s.Add(context.Background(), prefix, "", nil, fmt.Sprintf("req-conc-add-%d", i))
			if err != nil {
				errs <- fmt.Errorf("add %s: %w", prefix, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	count, err := s.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 100 {
		t.Fatalf("count = %d, want 100", count)
	}

	errs = make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			prefix := fmt.Sprintf("10.%d.0.0/16", i)
			err := s.Delete(context.Background(), prefix, fmt.Sprintf("req-conc-del-%d", i))
			if err != nil {
				errs <- fmt.Errorf("delete %s: %w", prefix, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	count, err = s.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0", count)
	}
}

func TestConcurrentAddDeleteRace(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req-race-add"); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 200)

	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, fmt.Sprintf("req-race-add-%d", i))
			if err != nil && err != ErrAlreadyExists {
				errs <- fmt.Errorf("concurrent add: %w", err)
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			err := s.Delete(context.Background(), "10.0.0.0/8", fmt.Sprintf("req-race-del-%d", i))
			if err != nil {
				errs <- fmt.Errorf("concurrent delete: %w", err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestCheckExpiredEntrySkippedForLongerPrefix(t *testing.T) {
	s := newTestStore(t)
	fixed := fixedTime(1000000)
	s.now = func() time.Time { return fixed }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "broad", nil, "req-skip-add-1"); err != nil {
		t.Fatal(err)
	}

	expires := fixed.Add(time.Millisecond)
	if _, err := s.Add(context.Background(), "10.0.0.0/16", "specific-expired", &expires, "req-skip-add-2"); err != nil {
		t.Fatal(err)
	}

	s.now = func() time.Time { return expires }
	result, err := s.Check(context.Background(), "10.0.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("expected match from broader prefix")
	}
	if result.Prefix != "10.0.0.0/8" {
		t.Fatalf("prefix = %q, want %q (broader, since specific is expired)", result.Prefix, "10.0.0.0/8")
	}
}

func TestCheckRejectsInvalidIP(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.Check(context.Background(), "not-an-ip"); err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.Get(context.Background(), "10.0.0.0/8"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRejectsEmptyPrefix(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "", "", nil, "req-empty-pfx"); err != ErrInvalid {
		t.Fatalf("expected ErrInvalid for empty prefix, got %v", err)
	}
}

func TestRejectsEmptyRequestID(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, ""); err != ErrInvalid {
		t.Fatalf("expected ErrInvalid for empty request ID, got %v", err)
	}
}

func TestRejectsLongNote(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	note := make([]byte, MaxNoteLength+1)
	for i := range note {
		note[i] = 'x'
	}
	if _, err := s.Add(context.Background(), "10.0.0.0/8", string(note), nil, "req-long-note"); err != ErrInvalid {
		t.Fatalf("expected ErrInvalid for long note, got %v", err)
	}
}

func TestRejectsLongRequestID(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	longID := make([]byte, 65)
	for i := range longID {
		longID[i] = 'a'
	}
	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, string(longID)); err != ErrInvalid {
		t.Fatalf("expected ErrInvalid for long request ID, got %v", err)
	}
}

func TestIPv6Prefix(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "2001:db8::/32", "ipv6", nil, "req-v6-add"); err != nil {
		t.Fatal(err)
	}

	result, err := s.Check(context.Background(), "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("expected match for IPv6")
	}
	if result.Prefix != "2001:db8::/32" {
		t.Fatalf("prefix = %q, want %q", result.Prefix, "2001:db8::/32")
	}
}

func TestCheckIPv4MappedIPv6AgainstIPv6Prefix(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "2001:db8::/32", "ipv6", nil, "req-v6-map-add"); err != nil {
		t.Fatal(err)
	}

	result, err := s.Check(context.Background(), "::ffff:10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched {
		t.Fatal("should not match IPv4-mapped IPv6 against IPv6 prefix")
	}
}

func TestPrefixContains(t *testing.T) {
	tests := []struct {
		prefix string
		addr   string
		want   bool
	}{
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "11.0.0.1", false},
		{"192.168.0.0/16", "192.168.1.1", true},
		{"192.168.0.0/16", "192.169.0.1", false},
		{"2001:db8::/32", "2001:db8::1", true},
		{"2001:db8::/32", "2001:db9::1", false},
	}
	for _, tc := range tests {
		p, err := netip.ParsePrefix(tc.prefix)
		if err != nil {
			t.Fatal(err)
		}
		a, err := netip.ParseAddr(tc.addr)
		if err != nil {
			t.Fatal(err)
		}
		got := p.Contains(a)
		if got != tc.want {
			t.Errorf("Contains(%s, %s) = %v, want %v", tc.prefix, tc.addr, got, tc.want)
		}
	}
}

func TestDeleteDecrementsCount(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req-cnt-del-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(context.Background(), "192.168.0.0/16", "", nil, "req-cnt-del-2"); err != nil {
		t.Fatal(err)
	}

	count, _ := s.Count(context.Background())
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}

	if err := s.Delete(context.Background(), "10.0.0.0/8", "req-cnt-del-d"); err != nil {
		t.Fatal(err)
	}

	count, _ = s.Count(context.Background())
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}

	if _, err := s.Add(context.Background(), "172.16.0.0/12", "", nil, "req-cnt-del-3"); err != nil {
		t.Fatal(err)
	}
	count, _ = s.Count(context.Background())
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
}

// --- New tests for deterministic ceiling, replay, and fail-closed ---

func TestAddCeilingDeterministic(t *testing.T) {
	const N = 5
	s := newTestStoreWithClock(t, func() time.Time { return fixedTime(1000000) }, N)

	// Start barrier ensures all goroutines begin concurrently.
	var start sync.WaitGroup
	start.Add(1)
	var successes atomic.Int64
	var wg sync.WaitGroup
	total := 2 * N
	wg.Add(total)
	for i := 0; i < total; i++ {
		go func(i int) {
			defer wg.Done()
			start.Wait()
			p := fmt.Sprintf("10.%d.0.0/16", i)
			_, err := s.Add(context.Background(), p, "", nil, fmt.Sprintf("req-ceiling-%d", i))
			if err == nil {
				successes.Add(1)
			}
		}(i)
	}
	start.Done()
	wg.Wait()

	finalCount, err := s.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if finalCount != N {
		t.Fatalf("final count = %d, want exactly %d", finalCount, N)
	}
	if successes.Load() != int64(N) {
		t.Fatalf("successes = %d, want %d", successes.Load(), N)
	}
}

func TestAddReplaySameRequestID(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	e1, err := s.Add(context.Background(), "10.0.0.0/8", "note", nil, "req-replay-add")
	if err != nil {
		t.Fatal(err)
	}

	// Replay with same request ID — must return identical full Entry.
	e2, err := s.Add(context.Background(), "10.0.0.0/8", "note", nil, "req-replay-add")
	if err != nil {
		t.Fatal(err)
	}
	if e1 != e2 {
		t.Fatalf("replay mismatch:\n  first:  %+v\n  second: %+v", e1, e2)
	}

	count, _ := s.Count(context.Background())
	if count != 1 {
		t.Fatalf("count = %d, want 1 after replay", count)
	}
}

// TestAddReturnsStoredEntry verifies that Add returns the actual stored row.
// It advances the clock after the insert and confirms Get still returns the
// original timestamps — proving Add didn't fabricate from the advanced clock.
//
// Rhiza rejects same RequestID with changed args (ErrRequestConflict), so
// replay-with-advanced-clock is tested separately in TestAddReplaySameRequestID
// where the clock stays constant.
func TestAddReturnsStoredEntry(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	e1, err := s.Add(context.Background(), "10.0.0.0/8", "note", nil, "req-add-stored-1")
	if err != nil {
		t.Fatal(err)
	}

	// Advance clock — Get must still return original timestamps.
	s.now = func() time.Time { return fixedTime(9000000) }

	got, err := s.Get(context.Background(), "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if got.CreatedAtUnixMs != 1000000 {
		t.Fatalf("CreatedAtUnixMs = %d, want 1000000", got.CreatedAtUnixMs)
	}
	if got != e1 {
		t.Fatalf("Get returned different entry than Add:\n  add:   %+v\n  get:   %+v", e1, got)
	}
}

func TestUpdateReplaySameRequestID(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "old", nil, "req-replay-upd-add"); err != nil {
		t.Fatal(err)
	}

	s.now = func() time.Time { return fixedTime(2000000) }
	e1, err := s.Update(context.Background(), "10.0.0.0/8", "new", nil, "req-replay-upd")
	if err != nil {
		t.Fatal(err)
	}

	// Replay — must return the same full Entry.
	e2, err := s.Update(context.Background(), "10.0.0.0/8", "new", nil, "req-replay-upd")
	if err != nil {
		t.Fatal(err)
	}
	if e1 != e2 {
		t.Fatalf("replay returned different entries:\n  first:  %+v\n  second: %+v", e1, e2)
	}

	got, err := s.Get(context.Background(), "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != "new" {
		t.Fatalf("note = %q, want %q", got.Note, "new")
	}
}

// TestUpdateReturnsStoredEntry verifies that Update returns the actual stored
// row. It advances the clock after the update and confirms Get still returns
// the original timestamps — proving Update didn't fabricate from the advanced
// clock.
//
// Rhiza rejects same RequestID with changed args (ErrRequestConflict), so
// replay-with-advanced-clock is tested separately in TestUpdateReplaySameRequestID
// where the clock stays constant.
func TestUpdateReturnsStoredEntry(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "old", nil, "req-upd-stored-add"); err != nil {
		t.Fatal(err)
	}

	s.now = func() time.Time { return fixedTime(2000000) }
	e1, err := s.Update(context.Background(), "10.0.0.0/8", "new", nil, "req-upd-stored-1")
	if err != nil {
		t.Fatal(err)
	}

	// Advance clock — Get must still return original update timestamp.
	s.now = func() time.Time { return fixedTime(9000000) }

	got, err := s.Get(context.Background(), "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if got.UpdatedAtUnixMs != 2000000 {
		t.Fatalf("UpdatedAtUnixMs = %d, want 2000000", got.UpdatedAtUnixMs)
	}
	if got != e1 {
		t.Fatalf("Get returned different entry than Update:\n  update: %+v\n  get:    %+v", e1, got)
	}
}

func TestDeleteReplaySameRequestID(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req-replay-del-add"); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(context.Background(), "10.0.0.0/8", "req-replay-del"); err != nil {
		t.Fatal(err)
	}

	// Replay — must return nil (idempotent).
	if err := s.Delete(context.Background(), "10.0.0.0/8", "req-replay-del"); err != nil {
		t.Fatal(err)
	}
}

func TestStorageClosedFailClosed(t *testing.T) {
	// nil store → ErrInvalid (fail closed).
	s := (*Store)(nil)
	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req"); err != ErrInvalid {
		t.Fatalf("nil store Add: %v", err)
	}
	if _, err := s.Update(context.Background(), "10.0.0.0/8", "", nil, "req"); err != ErrInvalid {
		t.Fatalf("nil store Update: %v", err)
	}
	if err := s.Delete(context.Background(), "10.0.0.0/8", "req"); err != ErrInvalid {
		t.Fatalf("nil store Delete: %v", err)
	}
	if _, err := s.Check(context.Background(), "10.0.0.1"); err != ErrInvalid {
		t.Fatalf("nil store Check: %v", err)
	}
	if _, err := s.List(context.Background()); err != ErrInvalid {
		t.Fatalf("nil store List: %v", err)
	}
	if _, err := s.Get(context.Background(), "10.0.0.0/8"); err != ErrInvalid {
		t.Fatalf("nil store Get: %v", err)
	}
}

func TestNilDBFailClosed(t *testing.T) {
	s := &Store{db: nil, now: time.Now, maxEntries: 100}
	if _, err := s.Add(context.Background(), "10.0.0.0/8", "", nil, "req"); err != ErrInvalid {
		t.Fatalf("nil db Add: %v", err)
	}
	if _, err := s.Update(context.Background(), "10.0.0.0/8", "", nil, "req"); err != ErrInvalid {
		t.Fatalf("nil db Update: %v", err)
	}
	if err := s.Delete(context.Background(), "10.0.0.0/8", "req"); err != ErrInvalid {
		t.Fatalf("nil db Delete: %v", err)
	}
	if _, err := s.Check(context.Background(), "10.0.0.1"); err != ErrInvalid {
		t.Fatalf("nil db Check: %v", err)
	}
}

// TestDBClosedFailClosed constructs a real store, closes the underlying Rhiza
// DB, and verifies every method returns a non-nil error (fail closed). No
// double-close cleanup. No exact error string assertions.
func TestDBClosedFailClosed(t *testing.T) {
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-db-close", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-ipbl-schema-closed",
		Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE IF NOT EXISTS goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `CREATE TABLE IF NOT EXISTS ip_blacklist_entries (
				prefix TEXT PRIMARY KEY NOT NULL,
				note TEXT NOT NULL DEFAULT '' CHECK (length(note) BETWEEN 0 AND 256),
				expires_at_unix_ms INTEGER CHECK (expires_at_unix_ms IS NULL OR expires_at_unix_ms > 0),
				created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
				updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
			) STRICT`},
		},
	}); err != nil {
		t.Fatal(err)
	}
	s := NewStore(db, 100)
	s.now = func() time.Time { return fixedTime(1000000) }

	// Populate the store so reads hit the closed db too.
	if _, err := s.Add(context.Background(), "10.0.0.0/8", "before-close", nil, "req-closed-add"); err != nil {
		t.Fatal(err)
	}

	// Close the db exactly once — no double-close cleanup.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := s.Add(ctx, "192.168.0.0/16", "", nil, "req-closed-add2"); err == nil {
		t.Fatal("Add on closed db should return non-nil error")
	}
	if _, err := s.Update(ctx, "10.0.0.0/8", "gone", nil, "req-closed-upd"); err == nil {
		t.Fatal("Update on closed db should return non-nil error")
	}
	if err := s.Delete(ctx, "10.0.0.0/8", "req-closed-del"); err == nil {
		t.Fatal("Delete on closed db should return non-nil error")
	}
	if _, err := s.Check(ctx, "10.0.0.1"); err == nil {
		t.Fatal("Check on closed db should return non-nil error")
	}
	if _, err := s.List(ctx); err == nil {
		t.Fatal("List on closed db should return non-nil error")
	}
	if _, err := s.Get(ctx, "10.0.0.0/8"); err == nil {
		t.Fatal("Get on closed db should return non-nil error")
	}
	if _, err := s.Count(ctx); err == nil {
		t.Fatal("Count on closed db should return non-nil error")
	}
}
