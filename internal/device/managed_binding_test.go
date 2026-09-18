package device

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func seedManagedBinding(t *testing.T, ctx context.Context, store *Store, id, generation string, revision int64, enabled int64) {
	t.Helper()
	_, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "managed-binding-" + id + generation, SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json) VALUES(?,?,?,?,0,?)`, Args: []any{id, generation, revision, enabled, `{"confidential":false,"redirect_uris":[],"scopes":["goauthy.read"],"default_scopes":["goauthy.read"],"enabled_flows":["urn:ietf:params:oauth:grant-type:device_code"]}`}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateWithBindingRejectsStaleRevisionAndGeneration(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	seedManagedBinding(t, ctx, store, "managed-device", "gen-a", 1, 1)
	if _, err := store.CreateWithBinding(ctx, "managed-device", []string{"goauthy.read"}, ClientBinding{ID: "managed-device", Generation: "gen-a", Revision: 1}, now); err != nil {
		t.Fatalf("current binding rejected: %v", err)
	}
	_, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "managed-binding-revision", SQL: `UPDATE managed_oauth_clients SET revision=2 WHERE id=?`, Args: []any{"managed-device"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateWithBinding(ctx, "managed-device", []string{"goauthy.read"}, ClientBinding{ID: "managed-device", Generation: "gen-a", Revision: 1}, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stale revision error=%v", err)
	}
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "managed-binding-replace", SQL: `UPDATE managed_oauth_clients SET generation=?,revision=1 WHERE id=?`, Args: []any{"gen-b", "managed-device"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateWithBinding(ctx, "managed-device", []string{"goauthy.read"}, ClientBinding{ID: "managed-device", Generation: "gen-a", Revision: 1}, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stale generation error=%v", err)
	}
	if _, err := store.CreateWithBinding(ctx, "managed-device", []string{"goauthy.read"}, ClientBinding{ID: "other", Generation: "gen-b", Revision: 1}, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched ID error=%v", err)
	}
	for _, binding := range []ClientBinding{{ID: "managed-device", Generation: "", Revision: 1}, {ID: "managed-device", Generation: "gen-b", Revision: 0}} {
		if _, err := store.CreateWithBinding(ctx, "managed-device", []string{"goauthy.read"}, binding, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("incomplete binding=%+v error=%v", binding, err)
		}
	}
}

func TestCreateWithoutBindingRejectsManagedID(t *testing.T) {
	ctx, store, _ := testStore(t)
	seedManagedBinding(t, ctx, store, "managed-device", "gen-a", 1, 1)
	if _, err := store.Create(ctx, "managed-device", []string{"goauthy.read"}, time.UnixMilli(1_700_000_000_000).UTC()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbound managed creation error=%v", err)
	}
}
