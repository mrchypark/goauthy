package saas

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUseGrantStatusReturnsStoredStateAndCurrentConnectionGeneration(t *testing.T) {
	t.Parallel()
	ctx, store, db, b := credentialStoreFixture(t)
	providers, err := NewProviderStore(db, store.keys)
	if err != nil {
		t.Fatal(err)
	}
	provider := providerInputForTest("0123456789012345")
	provider.ID = b.ProviderID
	if _, err := providers.Create(ctx, provider, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, credentialBinding{Owner: b.Owner, CollectionID: b.CollectionID, ConnectionID: b.ConnectionID, ProviderID: b.ProviderID, Generation: b.Generation, TokenVersion: 1}, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	consumer := clients.NewStore(db, store.keys)
	if _, err := consumer.CreateWithGuard(ctx, clients.NewRequest{ID: "status-consumer", Confidential: true, RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://status.example/active", "https://status.example/revoked", "https://status.example/expired"}}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	active, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://status.example/active", UseGrantInput{ConsumerClientID: "status-consumer", Mode: "proxy", Purpose: "active", ExpiresAt: store.now() + 60_000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://status.example/revoked", UseGrantInput{ConsumerClientID: "status-consumer", Mode: "proxy", Purpose: "revoked", ExpiresAt: store.now() + 60_000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	expired, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://status.example/expired", UseGrantInput{ConsumerClientID: "status-consumer", Mode: "proxy", Purpose: "expired", ExpiresAt: store.now() + 60_000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, revoked.ID, revoked.Revision, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "status-expire", SQL: `UPDATE saas_use_grants SET expires_at_unix_ms=? WHERE id=?`, Args: []any{store.now() - 1, expired.ID}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		grant    UseGrant
		resource string
		revoked  bool
	}{
		{"active", active, active.Resource, false},
		{"revoked", revoked, revoked.Resource, true},
		{"expired", expired, expired.Resource, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.GetUseGrantStatus(ctx, b.Owner, b.CollectionID, b.ConnectionID, tc.grant.ID, tc.resource, credentialAuthority())
			if err != nil || got.Grant.ID != tc.grant.ID || got.Grant.Revoked != tc.revoked || got.Grant.Purpose != tc.name || got.ConnectionGeneration != b.Generation {
				t.Fatalf("status=%+v err=%v", got, err)
			}
		})
	}
	for name, args := range map[string][5]string{
		"owner":      {"other", b.CollectionID, b.ConnectionID, active.ID, active.Resource},
		"collection": {b.Owner, "other", b.ConnectionID, active.ID, active.Resource},
		"connection": {b.Owner, b.CollectionID, "other", active.ID, active.Resource},
		"grant":      {b.Owner, b.CollectionID, b.ConnectionID, "missing", active.Resource},
		"resource":   {b.Owner, b.CollectionID, b.ConnectionID, active.ID, "https://status.example/other"},
	} {
		t.Run("wrong-"+name, func(t *testing.T) {
			if _, err := store.GetUseGrantStatus(ctx, args[0], args[1], args[2], args[3], args[4], credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if _, err := store.GetUseGrantStatus(ctx, b.Owner, b.CollectionID, b.ConnectionID, active.ID, active.Resource, nil); !errors.Is(err, ErrCredentialUnauthorized) {
		t.Fatalf("nil authority=%v", err)
	}
	if _, err := store.GetUseGrantStatus(ctx, b.Owner, b.CollectionID, b.ConnectionID, active.ID, active.Resource, func() (string, []any) { return "0", nil }); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("denied authority=%v", err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "status-reconnect", SQL: `UPDATE auth_collection_connections SET generation=? WHERE id=?`, Args: []any{"generation-current", b.ConnectionID}}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetUseGrantStatus(ctx, b.Owner, b.CollectionID, b.ConnectionID, active.ID, active.Resource, credentialAuthority())
	if err != nil || got.Grant.ID != active.ID || got.ConnectionGeneration != "generation-current" || got.Grant.Generation == got.ConnectionGeneration {
		t.Fatalf("reconnected status=%+v err=%v", got, err)
	}
}
