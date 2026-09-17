package kv

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestEnvelopeInspectorCountsEncryptedFamilies(t *testing.T) {
	s, _ := newHTTPStore(t)
	ctx := context.Background()
	if err := s.PutNamespace(ctx, "", "test-ns", false, true); err != nil {
		t.Fatal(err)
	}
	a, err := s.CreateAccess(ctx, "test-ns", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, Access{Namespace: a.Namespace}, Value{Key: "secret", Encrypted: true, Value: []byte(`{"ok":true}`)}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAccess(ctx, "test-ns", a.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	status, err := s.InspectEnvelopeReferences(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Safe || status.Access.Total != 1 || status.Values.Total != 1 || status.Access.ByKeyID[status.ActiveMasterKeyID] != 1 || status.Values.ByKeyID[status.ActiveMasterKeyID] != 1 {
		t.Fatalf("status=%+v", status)
	}
}

func TestRewrapBatchRejectsMalformedEnvelope(t *testing.T) {
	s, _ := newHTTPStore(t)
	ctx := context.Background()
	if err := s.PutNamespace(ctx, "", "test-ns", false, true); err != nil {
		t.Fatal(err)
	}
	_, err := s.mutate(ctx, "INSERT INTO kv_access(id,namespace,secret,secret_digest,enabled) VALUES (?,?,?,?,?)", "abcdefghijklmnop", "test-ns", []byte("bad"), digest("x"), int64(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RewrapBatch(ctx, ""); err == nil {
		t.Fatal("malformed envelope accepted")
	}
}

func TestRewrapBatchPaginatesAccessRows(t *testing.T) {
	s, _ := newHTTPStore(t)
	ctx := context.Background()
	if err := s.PutNamespace(ctx, "", "test-ns", false, true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 33; i++ {
		if _, err := s.CreateAccess(ctx, "test-ns", true, nil); err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.RewrapBatch(ctx, "")
	if err != nil || first.Done || first.Cursor == "" {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	second, err := s.RewrapBatch(ctx, first.Cursor)
	if err != nil || !second.Done {
		t.Fatalf("second=%+v err=%v", second, err)
	}
}

func TestRewrapBatchCASInterpositionPaginatesValuesAndPreservesJSON(t *testing.T) {
	ctx := context.Background()
	_, oldStore, newStore := newEnvelopeKeyStores(t)
	if err := oldStore.PutNamespace(ctx, "", "cas-ns", false, true); err != nil {
		t.Fatal(err)
	}
	access, err := oldStore.CreateAccess(ctx, "cas-ns", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 33; i++ {
		if err := oldStore.Set(ctx, Access{Namespace: access.Namespace}, Value{Key: fmt.Sprintf("key-%02d", i), Encrypted: true, Value: []byte(fmt.Sprintf(`{"n":%d}`, i))}); err != nil {
			t.Fatal(err)
		}
	}
	mutations := 0
	newStore.beforeMutation = func() {
		mutations++
		if mutations == 2 {
			newStore.beforeMutation = nil
			if err := oldStore.Set(ctx, Access{Namespace: access.Namespace}, Value{Key: "key-00", Encrypted: true, Value: []byte(`{"n":999,"source":"concurrent"}`)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	var total int
	for cursor := ""; ; {
		batch, err := newStore.RewrapBatch(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		total += batch.Rewrapped
		if batch.Done {
			break
		}
		cursor = batch.Cursor
	}
	if total != 33 || mutations != 2 {
		t.Fatalf("rewrapped=%d mutations=%d, want 33 and 2", total, mutations)
	}
	value, err := newStore.Get(ctx, Access{Namespace: access.Namespace}, "key-00")
	if err != nil || string(value) != `{"n":999,"source":"concurrent"}` {
		t.Fatalf("interposed value=%s err=%v", value, err)
	}
	for i := 1; i < 33; i++ {
		value, err := newStore.Get(ctx, Access{Namespace: access.Namespace}, fmt.Sprintf("key-%02d", i))
		if err != nil || string(value) != fmt.Sprintf(`{"n":%d}`, i) {
			t.Fatalf("value %d=%s err=%v", i, value, err)
		}
	}
	refs, err := newStore.InspectEnvelopeReferences(ctx)
	if err != nil || refs.Safe || refs.Access.ByKeyID["key-b"] != 1 || refs.Values.ByKeyID["key-a"] != 1 || refs.Values.ByKeyID["key-b"] != 32 {
		t.Fatalf("refs=%+v err=%v", refs, err)
	}
}

func newEnvelopeKeyStores(t *testing.T) (*rhiza.DB, *Store, *Store) {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "kv-cas-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, id := range []string{"key-a", "key-b"} {
		if err := os.WriteFile(filepath.Join(dir, id), []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{id[len(id)-1]}, 32))), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldKeyring, err := oidc.LoadKeyring(dir, "key-a")
	if err != nil {
		t.Fatal(err)
	}
	newKeyring, err := oidc.LoadKeyring(dir, "key-b")
	if err != nil {
		t.Fatal(err)
	}
	oldStore, err := NewStore(db, oldKeyring)
	if err != nil {
		t.Fatal(err)
	}
	newStore, err := NewStore(db, newKeyring)
	if err != nil {
		t.Fatal(err)
	}
	return db, oldStore, newStore
}
