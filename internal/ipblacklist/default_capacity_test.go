package ipblacklist

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDefaultCapacityWideRows(t *testing.T) {
	if DefaultMaxEntries != 10000 {
		t.Fatalf("documented default changed: %d", DefaultMaxEntries)
	}
	s := benchStore(t, 0)
	if s.maxEntries != 10000 {
		t.Fatalf("default capacity=%d", s.maxEntries)
	}
	now := time.UnixMilli(1800000000000).UTC()
	created := now.UnixMilli()
	s.now = func() time.Time { return now }
	second := NewStore(s.db, 0)
	second.now = s.now
	note := strings.Repeat("\x01", 256) // Non-NUL, one byte/character; JSON escapes each byte.
	expected := map[string]Entry{}
	prefixes := []string{"203.0.113.0/24", "192.0.2.7/32", "198.18.0.0/16", "198.18.7.0/24"}
	for len(prefixes) < 9999 {
		prefixes = append(prefixes, fmt.Sprintf("ffff:ffff:ffff:ffff:ffff:ffff:ffff:%04x/128", 0x1000+len(prefixes)))
	}
	for _, p := range prefixes {
		canonical, err := CanonicalPrefix(p)
		if err != nil || canonical.String() != p {
			t.Fatalf("invalid seed prefix %q: %v", p, err)
		}
		if _, exists := expected[p]; exists {
			t.Fatalf("duplicate seed %q", p)
		}
		expected[p] = Entry{Prefix: p, Note: note, CreatedAtUnixMs: created, UpdatedAtUnixMs: created}
	}
	// Unconditional fixture setup, not admission evidence. Common wide values are bound once.
	for start := 0; start < len(prefixes); start += 500 {
		end := min(start+500, len(prefixes))
		args := make([]any, 0, end-start+3)
		for _, p := range prefixes[start:end] {
			args = append(args, p)
		}
		args = append(args, note, created, created)
		sql := `WITH seed(prefix) AS (VALUES ` + strings.TrimSuffix(strings.Repeat("(?),", end-start), ",") + `) INSERT INTO ip_blacklist_entries(prefix,note,created_at_unix_ms,updated_at_unix_ms) SELECT prefix,?,?,? FROM seed`
		request := rhiza.ExecuteRequest{RequestID: fmt.Sprintf("wide-seed-%d", start), SQL: sql, Args: args}
		encoded, err := json.Marshal(request)
		if err != nil || len(args) > 999 || len(sql) > 256<<10 || len(encoded) > 64<<10 {
			t.Fatalf("seed bounds args=%d sql=%d request=%d err=%v", len(args), len(sql), len(encoded), err)
		}
		if _, err = storage.Execute(t.Context(), s.db, request); err != nil {
			t.Fatal(err)
		}
	}
	count := func(want int64) {
		t.Helper()
		got, err := s.Count(t.Context())
		if err != nil || got != want {
			t.Fatalf("count=%d want=%d err=%v", got, want, err)
		}
	}
	get := func(want Entry) {
		t.Helper()
		got, err := s.Get(t.Context(), want.Prefix)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("stored fields differ for %s: err=%v", want.Prefix, err)
		}
	}
	count(9999)
	expiry := now.Add(time.Second)
	expiryMS := expiry.UnixMilli()
	type result struct {
		entry  Entry
		prefix string
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for i, store := range []*Store{s, second} {
		go func() {
			<-start
			p := fmt.Sprintf("203.0.113.%d/32", 10+i)
			e, err := store.Add(t.Context(), p, note, &expiry, fmt.Sprintf("last-slot-%d", i))
			results <- result{e, p, err}
		}()
	}
	close(start)
	// Both Add calls include their classification reads; no table/clock change until both return.
	a, b := <-results, <-results
	if a.err != nil {
		a, b = b, a
	}
	if a.err != nil || !errors.Is(b.err, ErrTooMany) {
		t.Fatalf("last-slot outcomes=%v/%v", a.err, b.err)
	}
	winner := Entry{Prefix: a.prefix, Note: note, ExpiresAtUnixMs: &expiryMS, CreatedAtUnixMs: created, UpdatedAtUnixMs: created}
	if !reflect.DeepEqual(a.entry, winner) {
		t.Fatal("winner returned incorrect fields")
	}
	expected[a.prefix] = winner
	get(winner)
	count(10000)
	if _, err := s.Get(t.Context(), b.prefix); !errors.Is(err, ErrNotFound) {
		t.Fatalf("loser exists: %v", err)
	}
	if _, err := s.Add(t.Context(), "192.0.2.99/32", note, nil, "overflow"); !errors.Is(err, ErrTooMany) {
		t.Fatalf("overflow=%v", err)
	}
	if _, err := s.Add(t.Context(), a.prefix, note, &expiry, "fresh-duplicate"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate=%v", err)
	}
	now = now.Add(time.Millisecond)
	updated := expected["192.0.2.7/32"]
	updated.Note = strings.Repeat("\t", 256)
	updated.UpdatedAtUnixMs = now.UnixMilli()
	got, err := s.Update(t.Context(), updated.Prefix, updated.Note, nil, "full-update")
	if err != nil || !reflect.DeepEqual(got, updated) {
		t.Fatalf("update fields: %v", err)
	}
	expected[updated.Prefix] = updated
	get(updated)
	count(10000)
	rows, err := s.List(t.Context())
	if err != nil || len(rows) != 10000 {
		t.Fatalf("wide full List rows=%d err=%v", len(rows), err)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		want, ok := expected[row.Prefix]
		if !ok || seen[row.Prefix] || !reflect.DeepEqual(row, want) {
			t.Fatalf("List fields/uniqueness: %s", row.Prefix)
		}
		seen[row.Prefix] = true
	}
	check := func(ip, prefix string) {
		t.Helper()
		r, err := s.Check(t.Context(), ip)
		if err != nil || r.Matched != (prefix != "") || r.Prefix != prefix {
			t.Fatalf("Check(%s) prefix=%s matched=%t err=%v", ip, r.Prefix, r.Matched, err)
		}
		if prefix != "" && (r.Entry == nil || !reflect.DeepEqual(*r.Entry, expected[prefix])) {
			t.Fatalf("Check(%s) fields differ", ip)
		}
	}
	check("192.0.2.7", "192.0.2.7/32")
	check("::ffff:192.0.2.7", "192.0.2.7/32")
	check("198.18.7.9", "198.18.7.0/24")
	check("172.31.0.1", "")
	check(strings.TrimSuffix(prefixes[4], "/128"), prefixes[4])
	winnerIP := strings.TrimSuffix(a.prefix, "/32")
	check(winnerIP, a.prefix)
	now = expiry
	check(winnerIP, "203.0.113.0/24")
	get(winner)
	count(10000)
	if _, err := s.Add(t.Context(), b.prefix, note, nil, "expired-still-full"); !errors.Is(err, ErrTooMany) {
		t.Fatalf("expired entry released slot: %v", err)
	}
	if err := s.Delete(t.Context(), a.prefix, "delete-expired"); err != nil {
		t.Fatal(err)
	}
	count(9999)
	if _, err := s.Get(t.Context(), a.prefix); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted winner remains: %v", err)
	}
	replacement, err := s.Add(t.Context(), b.prefix, note, nil, "reuse-slot")
	want := Entry{Prefix: b.prefix, Note: note, CreatedAtUnixMs: now.UnixMilli(), UpdatedAtUnixMs: now.UnixMilli()}
	if err != nil || !reflect.DeepEqual(replacement, want) {
		t.Fatalf("replacement fields: %v", err)
	}
	get(want)
	count(10000)
}
