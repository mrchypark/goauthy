package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDeleteUserPurgesOwnedAuthCollectionConnections(t *testing.T) {
	t.Parallel()
	store := testConversionStore(t)
	ctx := context.Background()
	bootstrapPassword(t, store, "collection-owner", "owner", []byte("CurrentPassword1"))
	bootstrapPassword(t, store, "other-owner", "other", []byte("CurrentPassword1"))
	_, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "auth-collection-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json) VALUES (?,?,?,?,?,?,?)`, Args: []any{"admin-defined", "Admin collection", "oauth2", int64(1), int64(1), "generation", "[]"}},
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{"owned", "admin-defined", "collection-owner", "draft", int64(1), int64(1), "{}", "owned-generation"}},
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{"other", "admin-defined", "other-owner", "draft", int64(1), int64(1), "{}", "other-generation"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUserWithGuard(ctx, "collection-owner", "1=1", nil); err != nil {
		t.Fatal(err)
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,owner_subject FROM auth_collection_connections ORDER BY id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "other" || rows.Rows[0][1] != "other-owner" {
		t.Fatalf("connections=%v err=%v", rows.Rows, err)
	}
	defs, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id FROM auth_collection_definitions`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(defs.Rows) != 1 {
		t.Fatalf("definitions=%v err=%v", defs.Rows, err)
	}
}

func TestDeleteUserUnauthorizedDoesNotPurgeAuthCollectionConnections(t *testing.T) {
	t.Parallel()
	store := testConversionStore(t)
	ctx := context.Background()
	bootstrapPassword(t, store, "collection-owner-guard", "owner-guard", []byte("CurrentPassword1"))
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "auth-collection-guard-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{"guarded", "admin-defined", "collection-owner-guard", "draft", int64(1), int64(1), "{}", "guarded-generation"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUserWithGuard(ctx, "collection-owner-guard", "0=1", nil); !errors.Is(err, ErrDeleteUnauthorized) {
		t.Fatalf("err=%v", err)
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id FROM auth_collection_connections WHERE owner_subject=?`, Args: []any{"collection-owner-guard"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("connections=%v err=%v", rows.Rows, err)
	}
}
