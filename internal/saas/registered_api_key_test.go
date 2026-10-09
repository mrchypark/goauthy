package saas

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func registeredAPIKeyFixture(t testing.TB, id string) (context.Context, *CredentialStore, *rhiza.DB, credentialBinding, *APIKeyConnector) {
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

func benchmarkConnectorHasCurrentBinding(connector *APIKeyConnector, store *CredentialStore, db *rhiza.DB, id string, revision int64) bool {
	want := providerHTTPBinding{db: db, id: id, kind: "api_key", revision: revision}
	if connector == nil || store == nil || connector.client == nil || connector.registered != want {
		return false
	}
	transport, ok := connector.client.Transport.(*providerHTTPTransport)
	return ok && transport.owner == &store.http && transport.binding == want
}

// BenchmarkRegisteredAPIKeyRebuild separates connector reconstruction from
// the guarded database lookup that supplies the row. Both cases use a local
// fixture and synthetic authority predicate; neither dispatches an operation.
func BenchmarkRegisteredAPIKeyRebuild(b *testing.B) {
	b.Run("row-rebuild", func(b *testing.B) {
		ctx, store, db, binding, _ := registeredAPIKeyFixture(b, "bench-provider")
		b.Cleanup(store.CloseConnections)
		config := validAPIKeyConnectorConfig()
		config.ID = "bench-provider"
		configJSON, err := json.Marshal(config)
		if err != nil {
			b.Fatal(err)
		}
		row := []any{binding.Generation, config.ID, "api_key", int64(1), int64(1), string(configJSON)}
		want, err := store.APIKeyConnector(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, credentialAuthority())
		if err != nil {
			b.Fatal(err)
		}

		b.ReportAllocs()
		b.ResetTimer()
		var got registeredAPIKey
		var generation string
		for i := 0; i < b.N; i++ {
			got, generation, err = store.registeredAPIKeyFromRow(row)
			if err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()

		if generation != binding.Generation || got.ID != config.ID || got.Revision != 1 || !got.Enabled ||
			!benchmarkConnectorHasCurrentBinding(got.Connector, store, db, config.ID, 1) ||
			!got.Connector.HasOperation("account") || !got.Connector.HasOperation("balance") ||
			!reflect.DeepEqual(got.Connector.Info(), want.Info()) {
			b.Fatalf("row rebuild contract mismatch: generation=%q provider=%#v", generation, got)
		}
	})

	b.Run("guarded-lookup", func(b *testing.B) {
		ctx, store, db, binding, _ := registeredAPIKeyFixture(b, "bench-provider")
		b.Cleanup(store.CloseConnections)
		want, generation, err := store.registeredAPIKeyInfo(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, credentialAuthority())
		if err != nil || generation != binding.Generation || want.ID != "bench-provider" || want.Revision != 1 || !want.Enabled ||
			!benchmarkConnectorHasCurrentBinding(want.Connector, store, db, "bench-provider", 1) {
			b.Fatalf("guarded lookup fixture contract mismatch: generation=%q provider=%#v err=%v", generation, want, err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		var got *APIKeyConnector
		for i := 0; i < b.N; i++ {
			got, err = store.APIKeyConnector(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, credentialAuthority())
			if err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()

		if !benchmarkConnectorHasCurrentBinding(got, store, db, "bench-provider", 1) ||
			!got.HasOperation("account") || !got.HasOperation("balance") || !reflect.DeepEqual(got.Info(), want.Connector.Info()) {
			b.Fatalf("guarded lookup contract mismatch: connector=%#v", got)
		}
	})
}

func TestRegisteredAPIKeyBenchmarkBindingCheckRejectsStaleTransport(t *testing.T) {
	ctx, store, db, binding, expected := registeredAPIKeyFixture(t, "provider")
	t.Cleanup(store.CloseConnections)
	connector, err := store.APIKeyConnector(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}

	// Reproduce the previous assertions: they accept stale dispatch provenance
	// because the connector metadata and public Info remain unchanged.
	oldAssertionsAccept := connector.registered.id == "provider" && connector.registered.kind == "api_key" && connector.registered.revision == 1 &&
		connector.HasOperation("account") && connector.HasOperation("balance") && reflect.DeepEqual(connector.Info(), expected.Info())
	if !oldAssertionsAccept {
		t.Fatal("control setup did not satisfy the previous benchmark assertions")
	}
	transport, ok := connector.client.Transport.(*providerHTTPTransport)
	if !ok || transport.binding.revision != 1 {
		t.Fatalf("unexpected control transport: %#v", connector.client.Transport)
	}
	transport.binding.revision++
	if benchmarkConnectorHasCurrentBinding(connector, store, db, "provider", 1) {
		t.Fatal("current-binding assertion accepted a stale dispatch transport")
	}
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
