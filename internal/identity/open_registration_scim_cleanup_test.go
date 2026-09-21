package identity

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/scim"
	"github.com/mrchypark/rhiza"
)

type cleanupReconciler func(context.Context, scim.Request) (scim.Result, error)

func (f cleanupReconciler) Reconcile(ctx context.Context, request scim.Request) (scim.Result, error) {
	return f(ctx, request)
}

func TestCleanupExpiredOpenRegistrationSnapshotsSCIMDelete(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, credential.DefaultRules())
	base := time.UnixMilli(2_000_000).UTC()
	store.now = func() time.Time { return base }
	if err := store.ConfigureSCIMTombstoneProviders([]SCIMTombstoneProvider{{ID: "provider", DeletePolicy: scim.UnlinkRemote}}); err != nil {
		t.Fatal(err)
	}
	created, err := store.RegisterOpenUser(context.Background(), OpenRegistration{Email: "orphan@example.test", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupExpiredOpenRegistrations(context.Background(), base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	rows, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT hard_delete,provider_snapshot_complete,generation FROM scim_user_tombstones WHERE local_external_id=?`, Args: []any{created.Subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) || rows.Rows[0][1] != int64(1) || rows.Rows[0][2] == "" {
		t.Fatalf("tombstone rows=%#v err=%v", rows.Rows, err)
	}
	providers, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT delete_policy FROM scim_user_tombstone_providers WHERE local_external_id=?`, Args: []any{created.Subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(providers.Rows) != 1 || providers.Rows[0][0] != int64(scim.DeleteRemote) {
		t.Fatalf("provider rows=%#v err=%v", providers.Rows, err)
	}
}

func TestExpiredOpenRegistrationSCIMDeleteClosesDeliveredProjection(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, credential.DefaultRules())
	base := time.UnixMilli(2_000_000).UTC()
	store.now = func() time.Time { return base }
	if err := store.ConfigureSCIMTombstoneProviders([]SCIMTombstoneProvider{{ID: "provider", DeletePolicy: scim.UnlinkRemote}}); err != nil {
		t.Fatal(err)
	}
	created, err := store.RegisterOpenUser(context.Background(), OpenRegistration{Email: "delivered@example.test", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	deleted := false
	remoteExists := false
	mappings := scim.NewUserMappingStore(store.db)
	outbox := scim.NewOutbox(store.db, func(context.Context, string) (scim.Reconciler, error) {
		return cleanupReconciler(func(_ context.Context, request scim.Request) (scim.Result, error) {
			if request.User.ExternalID != created.Subject || request.User.UserName != "delivered@example.test" || request.User.Active {
				t.Fatal("unexpected pending identity projection")
			}
			if request.Delete {
				if !remoteExists || request.DeletePolicy != scim.DeleteRemote {
					t.Fatal("delete must remove the previously delivered remote identity")
				}
				deleted = true
				remoteExists = false
				return scim.Result{Action: scim.ActionDeleted}, nil
			}
			remoteExists = true
			return scim.Result{Action: scim.ActionCreated, RemoteID: "remote-user-1"}, nil
		}), nil
	}, scim.OutboxConfig{Mapping: mappings, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 512))})
	if _, err := outbox.EnqueueUser(context.Background(), "provider", scim.User{ExternalID: created.Subject, UserName: "delivered@example.test", Active: false}, base); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Step(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if remoteID, found, err := mappings.Lookup(context.Background(), "provider", created.Subject); err != nil || !found || remoteID != "remote-user-1" || !remoteExists {
		t.Fatalf("pending mapping found=%t remoteExists=%t err=%v", found, remoteExists, err)
	}
	if err := store.CleanupExpiredOpenRegistrations(context.Background(), base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	row, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT generation FROM scim_user_tombstones WHERE local_external_id=?`, Args: []any{created.Subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("tombstone=%#v err=%v", row.Rows, err)
	}
	generation := row.Rows[0][0].(string)
	if _, admitted, err := outbox.EnqueueTombstoneDelete(context.Background(), "provider", scim.User{ExternalID: created.Subject, UserName: "delivered@example.test"}, scim.DeleteRemote, generation, base.Add(2*time.Minute)); err != nil || !admitted {
		t.Fatalf("delete enqueue admitted=%v err=%v", admitted, err)
	}
	if err := outbox.Step(context.Background(), base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !deleted || remoteExists {
		t.Fatal("remote delete was not delivered")
	}
	if _, found, err := mappings.Lookup(context.Background(), "provider", created.Subject); err != nil || found {
		t.Fatalf("deleted mapping found=%t err=%v", found, err)
	}
	if _, err := store.CleanupSCIMDeletedUsers(context.Background(), 64); err != nil {
		t.Fatal(err)
	}
	row, err = store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id=?`, Args: []any{created.Subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || row.Rows[0][0] != int64(0) {
		t.Fatalf("tombstone remained=%#v err=%v", row.Rows, err)
	}
}

func TestExpiredOpenRegistrationCleanupRandomFailurePreservesState(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, credential.DefaultRules())
	base := time.UnixMilli(2_000_000).UTC()
	store.now = func() time.Time { return base }
	if err := store.ConfigureSCIMTombstoneProviders([]SCIMTombstoneProvider{{ID: "provider", DeletePolicy: scim.DeleteRemote}}); err != nil {
		t.Fatal(err)
	}
	created, err := store.RegisterOpenUser(context.Background(), OpenRegistration{Email: "rng-failure@example.test", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	store.random = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	if err := store.CleanupExpiredOpenRegistrations(context.Background(), base.Add(time.Minute)); err == nil {
		t.Fatal("accepted entropy failure")
	}
	for _, table := range []string{"identity_users", "identity_password_reset_tokens"} {
		rows, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM ` + table + ` WHERE subject=?`, Args: []any{created.Subject}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || rows.Rows[0][0] != int64(1) {
			t.Fatalf("%s rows=%#v err=%v", table, rows.Rows, err)
		}
	}
}
