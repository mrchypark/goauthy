package saas

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func registeredAPIKeyFixture(t *testing.T, id string) (context.Context, *CredentialStore, *rhiza.DB, credentialBinding, *APIKeyConnector) {
	t.Helper()
	ctx, store, db, b := credentialStoreFixture(t)
	connector := validAPIKeyConnectorConfig()
	connector.ID = id
	providers, err := NewProviderStore(db, store.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := providers.Create(ctx, ProviderInput{ID: id, Name: "Provider", Kind: "api_key", Enabled: true, Connector: &connector}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "registered-api-key-method-" + id, SQL: `UPDATE auth_collection_definitions SET auth_method='api_key',providers_json=? WHERE id=?`, Args: []any{"[\"" + id + "\"]", b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	bound, err := NewAPIKeyConnector(connector)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, store, db, b, bound
}

func TestRegisteredAPIKeyBindsProviderAndFailsClosedWhenDisabled(t *testing.T) {
	t.Parallel()
	ctx, store, db, b, registered := registeredAPIKeyFixture(t, "provider")
	registered, err := store.APIKeyConnector(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || registered.Digest() == "" {
		t.Fatalf("connector=%v err=%v", registered, err)
	}
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "unbound", credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("unbound put=%v", err)
	}
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "bound", registered, registered.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT provider_id FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{b.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != "provider" {
		t.Fatalf("provider binding=%v err=%v", row.Rows, err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "registered-api-key-disable", SQL: `UPDATE saas_providers SET enabled=0,revision=revision+1 WHERE id=?`, Args: []any{"provider"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("disabled load=%v", err)
	}
	if err := store.RevokeAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, credentialAuthority()); err != nil {
		t.Fatalf("disabled revoke=%v", err)
	}
}

func TestRegisteredAPIKeyProviderIDMayBeSentinel(t *testing.T) {
	t.Parallel()
	ctx, store, db, b, connector := registeredAPIKeyFixture(t, apiKeyProviderID)
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "bound", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT provider_id FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{b.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != apiKeyProviderID {
		t.Fatalf("provider binding=%v err=%v", row.Rows, err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "registered-api-key-sentinel-disable", SQL: `UPDATE saas_providers SET enabled=0 WHERE id=?`, Args: []any{apiKeyProviderID}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("disabled sentinel load=%v", err)
	}
}

func TestRegisteredAPIKeyRejectsChangedConnector(t *testing.T) {
	t.Parallel()
	ctx, store, db, b, connector := registeredAPIKeyFixture(t, "provider")
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "bound", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	changed := validAPIKeyConnectorConfig()
	changed.ID = "provider"
	changed.Operations[0].URL = "https://api.example.com/changed"
	encoded, _ := json.Marshal(changed)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "registered-api-key-connector-change", SQL: `UPDATE saas_providers SET connector_json=?,revision=revision+1 WHERE id=?`, Args: []any{string(encoded), "provider"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority()); !errors.Is(err, ErrCredentialUnauthorized) {
		t.Fatalf("changed connector load=%v", err)
	}
}

func TestRegisteredAPIKeyPutRevisionFence(t *testing.T) {
	t.Parallel()
	ctx, store, db, b, connector := registeredAPIKeyFixture(t, "provider")
	calls := 0
	authority := func() (string, []any) {
		calls++
		if calls == 2 {
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "registered-api-key-race", SQL: `UPDATE saas_providers SET revision=revision+1 WHERE id=?`, Args: []any{"provider"}}); err != nil {
				t.Fatal(err)
			}
		}
		return "1", nil
	}
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "race", connector, connector.Digest(), authority); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("revision race=%v", err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{b.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(0) {
		t.Fatalf("credential persisted rows=%v err=%v", row.Rows, err)
	}
}
