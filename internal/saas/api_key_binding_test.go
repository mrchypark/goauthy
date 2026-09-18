package saas

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestBoundAPIKeyConsentAndCustodyRotation(t *testing.T) {
	ctx, store, db, b := credentialStoreFixture(t)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "saas-api-key-binding-method", SQL: `UPDATE auth_collection_definitions SET auth_method='api_key',providers_json='[]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	connector, err := NewAPIKeyConnector(validAPIKeyConnectorConfig())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "legacy", credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	_, legacy, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || legacy.ConnectorDigest != "" {
		t.Fatalf("legacy digest=%q err=%v", legacy.ConnectorDigest, err)
	}

	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, "bound", connector, "wrong", credentialAuthority()); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("mismatch=%v", err)
	}
	status, err := store.APIKeyStatus(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || status.Version != 1 {
		t.Fatalf("mismatch changed status=%+v err=%v", status, err)
	}
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, "bound", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	_, got, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || got.ConnectorDigest != connector.Digest() {
		t.Fatalf("bound digest=%q err=%v", got.ConnectorDigest, err)
	}
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 2, "bound-2", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	_, got, err = store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || got.ConnectorDigest != connector.Digest() {
		t.Fatalf("bound rotation digest=%q err=%v", got.ConnectorDigest, err)
	}
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 3, "custody", credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("legacy rotation of bound key=%v", err)
	}
	_, got, err = store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || got.ConnectorDigest != connector.Digest() || got.APIKey != "bound-2" {
		t.Fatalf("legacy rotation changed bound credential: %v", err)
	}
	if err := store.RevokeAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 3, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 3, "resurrect", connector, connector.Digest(), credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("revoked replacement=%v", err)
	}
}

func TestPutAPIKeyRejectsMaxInt64Version(t *testing.T) {
	ctx, store, _, b := credentialStoreFixture(t)
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1<<63-1, "key", credentialAuthority()); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("max version=%v", err)
	}
}
