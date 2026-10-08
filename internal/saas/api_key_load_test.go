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

func TestLoadAPIKeyForDispatchUsesOneSnapshotAndFencesResolvedBinding(t *testing.T) {
	t.Parallel()
	ctx, store, db, b, connector := registeredAPIKeyFixture(t, "provider")
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	resolved, err := store.APIKeyConnector(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	// One linearizable read builds exactly one authority predicate, so this is
	// the snapshot count for the dispatch load: provider metadata and the ready
	// credential must be read together.
	reads := 0
	binding, value, err := store.loadAPIKeyForDispatch(ctx, b.Owner, b.CollectionID, b.ConnectionID, func() (string, []any) { reads++; return "1", nil }, &resolved.registered)
	if err != nil || reads != 1 || binding.TokenVersion != 1 || binding.ProviderID != "provider" || value.APIKey != "synthetic-key" {
		t.Fatalf("snapshot binding=%+v value=%+v reads=%d err=%v", binding, value, reads, err)
	}
	// A provider revision change invalidates the caller's resolved binding even
	// though the connector config and credential are otherwise unchanged.
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "load-dispatch-revision", SQL: `UPDATE saas_providers SET revision=revision+1 WHERE id='provider'`}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAPIKeyForDispatch(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority(), &resolved.registered); !errors.Is(err, ErrCredentialUnauthorized) {
		t.Fatalf("stale resolved binding err=%v", err)
	}
}

func TestLoadAPIKeyForDispatchFailsClosedOnConnectionGenerationChange(t *testing.T) {
	t.Parallel()
	ctx, store, db, b, connector := registeredAPIKeyFixture(t, "provider")
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	// A reconnect changes the connection generation and orphans the credential
	// stored under the previous generation in the same merged read.
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "load-dispatch-generation", SQL: `UPDATE auth_collection_connections SET generation='generation-2' WHERE id=?`, Args: []any{b.ConnectionID}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("connection generation change err=%v", err)
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
