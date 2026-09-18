package saas

import (
	"errors"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUseGrantReviewedConnectorDigest(t *testing.T) {
	ctx, store, db, b, connector := registeredAPIKeyFixture(t, "review-provider")
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "bound", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	consumer, err := clients.NewStore(db, store.keys).CreateWithGuard(ctx, clients.NewRequest{ID: "review-consumer", RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://resource.example"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	input := func(digest *string) UseGrantInput {
		return UseGrantInput{ConsumerClientID: consumer.ID, Mode: "proxy", Purpose: "review", ExpiresAt: store.now() + 60000, ReviewedConnectorDigest: digest}
	}
	digest := connector.Digest()
	grant, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://resource.example", input(&digest), credentialAuthority())
	if err != nil || grant.ConnectorDigest != digest {
		t.Fatalf("reviewed create=%+v err=%v", grant, err)
	}
	for name, reviewed := range map[string]string{"mismatch": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "invalid": "bad"} {
		t.Run(name, func(t *testing.T) {
			want := ErrUseGrantInvalid
			if name == "mismatch" {
				want = ErrUseGrantConflict
			}
			if _, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://resource.example", input(&reviewed), credentialAuthority()); !errors.Is(err, want) {
				t.Fatalf("err=%v", err)
			}
			q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_use_grants`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 1 || q.Rows[0][0].(int64) != 1 {
				t.Fatalf("grant count=%v err=%v", q.Rows, err)
			}
		})
	}
}

func TestUseGrantReviewedConnectorDigestProviderFence(t *testing.T) {
	ctx, store, db, b, connector := registeredAPIKeyFixture(t, "review-fence-provider")
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "bound", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	consumer, err := clients.NewStore(db, store.keys).CreateWithGuard(ctx, clients.NewRequest{ID: "review-fence-consumer", RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://resource.example"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	digest := connector.Digest()
	calls := 0
	authority := func() (string, []any) {
		calls++
		if calls == 2 {
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "review-fence-bump", SQL: `UPDATE saas_providers SET revision=revision+1 WHERE id=?`, Args: []any{"review-fence-provider"}}); err != nil {
				t.Fatalf("provider bump: %v", err)
			}
		}
		return "1", nil
	}
	_, err = store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://resource.example", UseGrantInput{ConsumerClientID: consumer.ID, Mode: "proxy", Purpose: "review", ExpiresAt: store.now() + 60000, ReviewedConnectorDigest: &digest}, authority)
	if !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("fenced create err=%v calls=%d", err, calls)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_use_grants`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || q.Rows[0][0].(int64) != 0 {
		t.Fatalf("grant count=%v err=%v", q.Rows, err)
	}
}

func TestUseGrantReviewedConnectorDigestOAuth(t *testing.T) {
	ctx, store, db, b := credentialStoreFixture(t)
	providers, err := NewProviderStore(db, store.keys)
	if err != nil {
		t.Fatal(err)
	}
	provider := providerInputForTest("review-oauth-secret")
	provider.ID = b.ProviderID
	if _, err := providers.Create(ctx, provider, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, b, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	consumer, err := clients.NewStore(db, store.keys).CreateWithGuard(ctx, clients.NewRequest{ID: "review-oauth-consumer", RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://resource.example"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	provided := strings.Repeat("A", 43)
	input := UseGrantInput{ConsumerClientID: consumer.ID, Mode: "proxy", Purpose: "review", ExpiresAt: store.now() + 60000, ReviewedConnectorDigest: &provided}
	if _, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://resource.example", input, credentialAuthority()); !errors.Is(err, ErrUseGrantInvalid) {
		t.Fatalf("oauth reviewed digest err=%v", err)
	}
	input.ReviewedConnectorDigest = nil
	if _, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://resource.example", input, credentialAuthority()); err != nil {
		t.Fatalf("oauth omitted digest err=%v", err)
	}
}
