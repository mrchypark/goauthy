package saas

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAPIKeyStorePutStatusRotateRevoke(t *testing.T) {
	t.Parallel()
	ctx, store, db, b := credentialStoreFixture(t)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "saas-api-key-method", SQL: `UPDATE auth_collection_definitions SET auth_method='api_key',providers_json='[]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	status, err := store.APIKeyStatus(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || status != (APIKeyStatus{}) {
		t.Fatalf("initial status=%+v err=%v", status, err)
	}
	status, err = store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "api-key-secret", credentialAuthority())
	if err != nil || status != (APIKeyStatus{Registered: true, Version: 1}) {
		t.Fatalf("put=%+v err=%v", status, err)
	}
	status, err = store.APIKeyStatus(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || status != (APIKeyStatus{Registered: true, Version: 1}) {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || bytes.Contains(row.Rows[0][0].([]byte), []byte("api-key-secret")) {
		t.Fatalf("plaintext credential row=%v err=%v", row.Rows, err)
	}
	status, err = store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, "api-key-secret-2", credentialAuthority())
	if err != nil || status.Version != 2 {
		t.Fatalf("rotate=%+v err=%v", status, err)
	}
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, "stale", credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("stale rotate=%v", err)
	}
	if err := store.RevokeAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 2, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	status, err = store.APIKeyStatus(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || status != (APIKeyStatus{Registered: false, Version: 2}) {
		t.Fatalf("revoked status=%+v err=%v", status, err)
	}
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 2, "new", credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("revoked replacement=%v", err)
	}
}

func TestAPIKeyStoreRejectsWrongOwnerAndMethodAndKey(t *testing.T) {
	t.Parallel()
	ctx, store, db, b := credentialStoreFixture(t)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "saas-api-key-method", SQL: `UPDATE auth_collection_definitions SET auth_method='api_key',providers_json='[]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutAPIKey(ctx, "owner-2", b.CollectionID, b.ConnectionID, 0, "key", credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("wrong owner=%v", err)
	}
	if _, err := store.APIKeyStatus(ctx, "owner-2", b.CollectionID, b.ConnectionID, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("wrong owner status=%v", err)
	}
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "bad\nkey", credentialAuthority()); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("newline key err=%v", err)
	}
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "", credentialAuthority()); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("empty key err=%v", err)
	}
	if err := store.RevokeAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, credentialAuthority()); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("invalid revoke version=%v", err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "saas-oauth-method", SQL: `UPDATE auth_collection_definitions SET auth_method='oauth2' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "key", credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("oauth method=%v", err)
	}
}
