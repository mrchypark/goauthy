package saas

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUseGrantAPIKeyCreateListAuthorizeRevoke(t *testing.T) {
	t.Parallel()
	ctx, store, db, b := credentialStoreFixture(t)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "use-grant-api-key", SQL: `UPDATE auth_collection_definitions SET auth_method='api_key',providers_json='[]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	connector, err := NewAPIKeyConnector(validAPIKeyConnectorConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "bound-api-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	meta := `{"name":"consumer","confidential":true,"redirect_uris":[],"scopes":["goauthy.connections.use"],"default_scopes":["goauthy.connections.use"],"enabled_flows":["client_credentials"],"audience":["https://resource.example/api"]}`
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "use-grant-client", SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json) VALUES(?,?,?,?,?,?)`, Args: []any{"consumer", "consumer-generation", 1, 1, 0, meta}}); err != nil {
		t.Fatal(err)
	}
	g, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://resource.example/api", UseGrantInput{ConsumerClientID: "consumer", Mode: "proxy", Purpose: "sync", ExpiresAt: store.now() + 60_000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if g.Revision != 1 || g.ConsumerClientID != "consumer" {
		t.Fatalf("grant=%+v", g)
	}
	listed, err := store.ListUseGrants(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || len(listed) != 1 {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	got, guard, err := store.AuthorizeUseGrant(ctx, b.Owner, "consumer", g.ID, g.Resource, g.Mode, credentialAuthority())
	if err != nil || got.ID != g.ID || guard == nil {
		t.Fatalf("authorize=%+v err=%v", got, err)
	}
	if _, err := store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, "unbound-rotation", credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("bound consent downgraded by legacy rotation: %v", err)
	}
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, "rotated-api-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	sql, args := guard()
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 0 {
		t.Fatalf("old credential snapshot survived rotation: rows=%v err=%v", q.Rows, err)
	}
	got, _, err = store.AuthorizeUseGrant(ctx, b.Owner, "consumer", g.ID, g.Resource, g.Mode, credentialAuthority())
	if err != nil || got.ID != g.ID || got.Revision != g.Revision {
		t.Fatalf("same-connector rotation invalidated consent: grant=%+v err=%v", got, err)
	}
	if err := store.RevokeUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, g.ID, g.Revision, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthorizeUseGrant(ctx, b.Owner, "consumer", g.ID, g.Resource, g.Mode, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("revoked=%v", err)
	}
}

func TestUseGrantWrongConsumerExpiryAndStaleCAS(t *testing.T) {
	t.Parallel()
	ctx, store, db, b := credentialStoreFixture(t)
	connector, err := NewAPIKeyConnector(validAPIKeyConnectorConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "use-grant-api-method", SQL: `UPDATE auth_collection_definitions SET auth_method='api_key',providers_json='[]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "bound", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	meta := `{"confidential":true,"scopes":["goauthy.connections.use"],"audience":["https://resource.example"]}`
	if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "use-grant-client-2", SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json) VALUES(?,?,?,?,?,?)`, Args: []any{"consumer-2", "consumer-generation", 1, 1, 0, meta}}); err != nil {
		t.Fatal(err)
	}
	g, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://resource.example", UseGrantInput{ConsumerClientID: "consumer-2", Mode: "credential_delivery", Purpose: "x", ExpiresAt: store.now() + 1000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.AuthorizeUseGrant(ctx, b.Owner, "other", g.ID, g.Resource, g.Mode, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("wrong consumer=%v", err)
	}
	if err = store.RevokeUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, g.ID, g.Revision+1, credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("stale revoke=%v", err)
	}
	store.now = func() int64 { return g.ExpiresAt }
	if _, _, err = store.AuthorizeUseGrant(ctx, b.Owner, g.ConsumerClientID, g.ID, g.Resource, g.Mode, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("expired=%v", err)
	}
}

func TestUseGrantGuards(t *testing.T) {
	t.Parallel()
	ctx, store, _, b := credentialStoreFixture(t)
	if _, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://resource.example", UseGrantInput{ConsumerClientID: "missing", Mode: "proxy", Purpose: "x", ExpiresAt: store.now() + 1000}, nil); !errors.Is(err, ErrCredentialUnauthorized) {
		t.Fatalf("nil authority=%v", err)
	}
	if _, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "http://resource.example", UseGrantInput{ConsumerClientID: "missing", Mode: "proxy", Purpose: "x", ExpiresAt: store.now() + 1000}, credentialAuthority()); !errors.Is(err, ErrUseGrantInvalid) {
		t.Fatalf("resource=%v", err)
	}
}
