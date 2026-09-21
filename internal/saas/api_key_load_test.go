package saas

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestLoadAPIKeyEnforcesCurrentParentAndReturnsLatest(t *testing.T) {
	t.Parallel()
	ctx, store, db, b := credentialStoreFixture(t)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "saas-api-key-load-method", SQL: `UPDATE auth_collection_definitions SET auth_method='api_key',providers_json='[]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("missing=%v", err)
	}
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "first", credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	gotBinding, got, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || gotBinding.TokenVersion != 1 || got.APIKey != "first" || got.AccessToken != "" {
		t.Fatalf("first binding=%+v value=%+v err=%v", gotBinding, got, err)
	}
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, "second", credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	gotBinding, got, err = store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || gotBinding.TokenVersion != 2 || got.APIKey != "second" {
		t.Fatalf("rotated binding=%+v value=%+v err=%v", gotBinding, got, err)
	}
	if _, _, err := store.loadAPIKey(ctx, "wrong-owner", b.CollectionID, b.ConnectionID, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("wrong owner=%v", err)
	}
	if _, _, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, func() (string, []any) { return "0", nil }); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("authority denial=%v", err)
	}
	if err := store.RevokeAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 2, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("revoked=%v", err)
	}
}

func TestLoadAPIKeyFailsClosedForDisabledAndCorruptCiphertext(t *testing.T) {
	t.Parallel()
	ctx, store, db, b := credentialStoreFixture(t)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "saas-api-key-load-method-2", SQL: `UPDATE auth_collection_definitions SET auth_method='api_key',providers_json='[]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "secret", credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "saas-api-key-load-corrupt", SQL: `UPDATE saas_connection_credentials SET credential=?`, Args: []any{[]byte("corrupt")}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority()); !errors.Is(err, errCredential) {
		t.Fatalf("corrupt=%v", err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "saas-api-key-load-disabled", SQL: `UPDATE auth_collection_definitions SET enabled=0`, Args: nil}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("disabled=%v", err)
	}
}
