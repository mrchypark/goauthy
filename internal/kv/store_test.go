package kv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
