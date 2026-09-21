package kv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestStoreRepeatedWritesJSONRenameAndCascade(t *testing.T) {
	s, _ := newHTTPStore(t)
	ctx := context.Background()
	for _, ns := range []string{"alpha", "beta"} {
		if err := s.PutNamespace(ctx, "", ns, false, true); err != nil {
			t.Fatal(err)
		}
	}
	a, err := s.CreateAccess(ctx, "alpha", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	bearer := "Bearer " + a.ID + "$" + a.Secret
	p, err := s.Authenticate(ctx, bearer)
	if err != nil {
		t.Fatal(err)
	}
	for i, text := range []string{`null`, `true`, `false`, `12345678901234567890`, `"<script>text</script>"`, `[1,"two"]`, `{"nested":{"ok":true}}`} {
		for _, encrypted := range []bool{false, true} {
			if err := s.Set(ctx, p, Value{"same/key", encrypted, json.RawMessage(text)}); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get(ctx, p, "same/key")
			if err != nil || string(got) != text {
				t.Fatalf("roundtrip %d encrypted=%v got=%s err=%v", i, encrypted, got, err)
			}
		}
	}
	if _, err := s.Get(ctx, Access{Namespace: "beta"}, "same/key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("isolation=%v", err)
	}
	if err := s.PutNamespace(ctx, "alpha", "renamed", true, false); err != nil {
		t.Fatal(err)
	}
	p, err = s.Authenticate(ctx, bearer)
	if err != nil || p.Namespace != "renamed" {
		t.Fatalf("renamed credential=%+v err=%v", p, err)
	}
	if _, err = s.Get(ctx, p, "same/key"); err != nil {
		t.Fatalf("renamed encrypted value=%v", err)
	}
	if _, err = s.PublicGet(ctx, "renamed", "same/key"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PublicGet(ctx, "renamed", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("public missing=%v", err)
	}
	if _, err = s.PublicGet(ctx, "beta", "same/key"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("private=%v", err)
	}
	if err = s.DeleteNamespace(ctx, "renamed"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authenticate(ctx, bearer); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cascade credential=%v", err)
	}
	if err = s.PutNamespace(ctx, "", "renamed", false, true); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(ctx, Access{Namespace: "renamed"}, "same/key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cascade value=%v", err)
	}
	if err = s.DeleteNamespace(ctx, "renamed"); err != nil {
		t.Fatalf("delete/recreate/delete replay=%v", err)
	}
}

func TestStoreCredentialRevalidationInterposition(t *testing.T) {
	s, _ := newHTTPStore(t)
	ctx := context.Background()
	a, err := s.CreateAccess(ctx, "default", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(ctx, "Bearer "+a.ID+"$"+a.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Set(ctx, p, Value{"record", true, json.RawMessage(`"original"`)}); err != nil {
		t.Fatal(err)
	}
	peer := *s
	s.beforeMutation = func() {
		s.beforeMutation = nil
		if err := peer.UpdateAccess(ctx, "default", a.ID, false, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Set(ctx, p, Value{"record", false, json.RawMessage(`"changed"`)}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked during write=%v", err)
	}
	got, err := s.Get(ctx, Access{Namespace: "default"}, "record")
	if err != nil || string(got) != `"original"` {
		t.Fatalf("guard rollback=%s %v", got, err)
	}
	if err = s.UpdateAccess(ctx, "default", a.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	rotated, err := s.RotateAccess(ctx, "default", a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Secret == a.Secret {
		t.Fatal("secret unchanged")
	}
	if _, err = s.Authenticate(ctx, "Bearer "+a.ID+"$"+a.Secret); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old credential=%v", err)
	}
	if err = s.Set(ctx, p, Value{"record", false, json.RawMessage(`false`)}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale principal write=%v", err)
	}
	if _, err = s.Authenticate(ctx, "Bearer "+rotated.ID+"$"+rotated.Secret); err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"", "KV " + a.ID + "$" + a.Secret, "Bearer  " + a.ID + "$" + a.Secret, "Bearer " + a.ID + "$" + a.Secret + "$extra", "API-Key " + a.ID + "$" + a.Secret} {
		if _, err = s.Authenticate(ctx, header); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("invalid auth accepted: %v", err)
		}
	}
}

func TestStoreValidationAndCiphertextIsolation(t *testing.T) {
	s, _ := newHTTPStore(t)
	ctx := context.Background()
	for _, name := range []string{"x", strings.Repeat("x", 65), "bad.name", "한글"} {
		if err := s.PutNamespace(ctx, "", name, false, true); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("name=%q err=%v", name, err)
		}
	}
	for _, name := range []string{"xx", strings.Repeat("x", 64), "a/b"} {
		if err := s.PutNamespace(ctx, "", name, false, true); err != nil {
			t.Fatal(err)
		}
	}
	for i, raw := range []string{"", `{`, strings.Repeat(" ", 64<<10) + `null`} {
		if err := s.Set(ctx, Access{Namespace: "default"}, Value{"record", false, json.RawMessage(raw)}); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("invalid json %d=%v", i, err)
		}
	}
	for _, ns := range []string{"xx", "a/b"} {
		if err := s.Set(ctx, Access{Namespace: ns}, Value{"record", true, json.RawMessage(fmt.Sprintf("%q", ns))}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "test-copy-ciphertext", SQL: `UPDATE kv_values SET value=(SELECT value FROM kv_values WHERE namespace='xx' AND key='record') WHERE namespace='a/b' AND key='record'`}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, Access{Namespace: "a/b"}, "record"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("row swap=%v", err)
	}
	if _, err := s.Get(ctx, Access{Namespace: "xx"}, "record"); err != nil {
		t.Fatal(err)
	}
}

// Keys must enumerate names without reading or decrypting payloads. Loading
// the value column spends the engine's aggregate result budget on data the
// caller did not ask for, and an unreadable payload must not hide its key.
func TestKeysListsNamesWithoutReadingValues(t *testing.T) {
	s, _ := newHTTPStore(t)
	ctx := context.Background()
	a := Access{Namespace: "default"}
	// A row that claims encryption but holds no valid envelope is individually
	// valid state; only payload readers must reject it.
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "kv-malformed-value", SQL: `INSERT INTO kv_values(namespace,key,encrypted,value) VALUES(?,?,1,?)`, Args: []any{"default", "000-malformed", []byte(`not-an-envelope`)}}); err != nil {
		t.Fatal(err)
	}
	if got, _, err := s.Keys(ctx, a, 0, "", ""); err != nil || len(got) != 1 || got[0] != "000-malformed" {
		t.Fatalf("keys with unreadable neighbor=%v err=%v", got, err)
	}
	if _, _, err := s.Values(ctx, a, 0, "", ""); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("value read with malformed row=%v", err)
	}
	// Individually valid near-limit values whose aggregate far exceeds the
	// storage result budget must still enumerate by name.
	payload := json.RawMessage(fmt.Sprintf("%q", strings.Repeat("x", 60<<10)))
	for i := 0; i < 500; i++ {
		if err := s.Set(ctx, a, Value{"zz-" + strconv.Itoa(i), true, payload}); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	names, _, err := s.Keys(ctx, a, 0, "", "")
	if err != nil || len(names) != 501 {
		t.Fatalf("keys beyond budget=%d err=%v", len(names), err)
	}
	// Keys are ordered lexicographically, so "zz-99" sorts after "zz-499".
	if names[0] != "000-malformed" || names[500] != "zz-99" {
		t.Fatalf("key order=%q..%q", names[0], names[500])
	}
}

// GA-KV-001: 1,000 accepted 64 KiB values are roughly 60 MiB of stored bytes,
// far past the engine's 16 MiB result budget, so a value list must read pages
// inside that budget instead of failing for valid stored data.
func TestValueListPagesInsideResultBudget(t *testing.T) {
	s, _ := newHTTPStore(t)
	ctx := context.Background()
	a := Access{Namespace: "default"}
	// Unencrypted rows keep the stored size equal to the accepted JSON size.
	payload := json.RawMessage(fmt.Sprintf("%q", strings.Repeat("x", 60<<10)))
	const rows = 300
	for i := 0; i < rows; i++ {
		if err := s.Set(ctx, a, Value{"big-" + strconv.Itoa(i), false, payload}); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, next, err := s.Values(ctx, a, 1000, "", cursor)
		if err != nil {
			t.Fatalf("page %d cursor=%q err=%v", pages, cursor, err)
		}
		pages++
		for _, v := range page {
			if seen[v.Key] {
				t.Fatalf("key %q repeated across pages", v.Key)
			}
			seen[v.Key] = true
			if len(v.Value) != len(payload) {
				t.Fatalf("key %q payload=%d want %d", v.Key, len(v.Value), len(payload))
			}
		}
		if next == "" {
			break
		}
		if len(page) == 0 {
			t.Fatal("continuation returned an empty page")
		}
		cursor = next
	}
	if pages < 2 {
		t.Fatalf("pages=%d want at least 2", pages)
	}
	if len(seen) != rows {
		t.Fatalf("enumerated=%d want %d", len(seen), rows)
	}
}

// A continuation token names its listing, so a token from one list cannot be
// replayed against another and a malformed token is refused outright.
func TestListCursorBoundaries(t *testing.T) {
	s, _ := newHTTPStore(t)
	ctx := context.Background()
	for _, ns := range []string{"cursor-a", "cursor-b"} {
		if err := s.PutNamespace(ctx, "", ns, false, true); err != nil {
			t.Fatal(err)
		}
	}
	a, err := s.CreateAccess(ctx, "cursor-a", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Set(ctx, Access{Namespace: "cursor-a"}, Value{"key-" + strconv.Itoa(i), false, json.RawMessage(strconv.Itoa(i))}); err != nil {
			t.Fatal(err)
		}
	}
	names, next, err := s.ListNamespaces(ctx, 1, "")
	if err != nil || len(names) != 1 || next == "" {
		t.Fatalf("namespaces page=%v next=%q err=%v", names, next, err)
	}
	if _, _, err := s.ListNamespaces(ctx, 1, next); err != nil {
		t.Fatalf("namespace continuation=%v", err)
	}
	// A namespace token is not a value token, even though both are valid
	// tokens for their own listing.
	if _, _, err := s.Values(ctx, Access{Namespace: "cursor-a"}, 1, "", next); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("cross-list token=%v", err)
	}
	if _, _, err := s.Keys(ctx, Access{Namespace: "cursor-a"}, 1, "", "not-base64!"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("malformed token=%v", err)
	}
	if _, _, err := s.Keys(ctx, Access{Namespace: "cursor-a"}, 1, "", encodeKVListCursor(kvListCursor{Kind: kvListValues, Position: "key-1"})); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("wrong-kind token=%v", err)
	}
	// Each listing resumes exactly after its last row and ends with no token.
	for _, tc := range []struct {
		name string
		list func(string) (int, string, error)
	}{
		{"keys", func(c string) (int, string, error) {
			v, n, e := s.Keys(ctx, Access{Namespace: "cursor-a"}, 1, "", c)
			return len(v), n, e
		}},
		{"values", func(c string) (int, string, error) {
			v, n, e := s.Values(ctx, Access{Namespace: "cursor-a"}, 1, "", c)
			return len(v), n, e
		}},
		{"accesses", func(c string) (int, string, error) { v, n, e := s.Accesses(ctx, "cursor-a", 1, c); return len(v), n, e }},
		{"namespaces", func(c string) (int, string, error) { v, n, e := s.ListNamespaces(ctx, 1, c); return len(v), n, e }},
	} {
		cursor, seen := "", 0
		for {
			got, nxt, err := tc.list(cursor)
			if err != nil {
				t.Fatalf("%s cursor=%q err=%v", tc.name, cursor, err)
			}
			if got != 1 {
				t.Fatalf("%s page size=%d want 1", tc.name, got)
			}
			seen++
			if nxt == "" {
				break
			}
			cursor = nxt
			if seen > 4 {
				t.Fatalf("%s did not terminate", tc.name)
			}
		}
		want := 3
		if tc.name == "accesses" {
			want = 1
		}
		if tc.name == "namespaces" {
			// The store always seeds `default`, plus the two namespaces above.
			want = 3
		}
		if seen != want {
			t.Fatalf("%s pages=%d want %d", tc.name, seen, want)
		}
	}
	if _, next, err := s.Keys(ctx, Access{Namespace: "cursor-a"}, 1000, "", ""); err != nil || next != "" {
		t.Fatalf("final page token=%q err=%v", next, err)
	}
	_ = a
}
