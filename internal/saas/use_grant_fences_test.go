package saas

import (
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUseGrantOAuthRefreshAndPolicyFences(t *testing.T) {
	for _, change := range []string{"provider", "consumer", "connection", "authority", "expiry"} {
		t.Run(change, func(t *testing.T) {
			ctx, s, db, b := credentialStoreFixture(t)
			providers, err := NewProviderStore(db, s.keys)
			if err != nil {
				t.Fatal(err)
			}
			in := providerInputForTest("synthetic-provider-secret")
			in.ID = b.ProviderID
			if _, err := providers.Create(ctx, in, credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			if err := s.Install(ctx, b, testCredential(), credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			const resource = "https://resource.example/api"
			consumer, err := clients.NewStore(db, s.keys).CreateWithGuard(ctx, clients.NewRequest{ID: "grant-consumer", RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{resource}}, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			allowed := true
			authority := func() (string, []any) {
				if !allowed {
					return "0", nil
				}
				return "1", nil
			}
			g, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, resource, UseGrantInput{ConsumerClientID: consumer.ID, Mode: "proxy", Purpose: "sync", ExpiresAt: s.now() + 60000}, authority)
			if err != nil {
				t.Fatal(err)
			}
			_, oldGuard, err := s.AuthorizeUseGrant(ctx, b.Owner, consumer.ID, g.ID, resource, "proxy", authority)
			if err != nil {
				t.Fatal(err)
			}
			check := func(guard func() (string, []any), want int) {
				t.Helper()
				sql, args := guard()
				q, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
				if err != nil || len(q.Rows) != want {
					t.Fatalf("guard rows=%v err=%v", q.Rows, err)
				}
			}
			check(oldGuard, 1)
			claim, err := s.ClaimRefresh(ctx, b, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			if err := s.CompleteRefresh(ctx, b, claim, testCredential(), credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			check(oldGuard, 0)
			_, guard, err := s.AuthorizeUseGrant(ctx, b.Owner, consumer.ID, g.ID, resource, "proxy", authority)
			if err != nil {
				t.Fatalf("refresh invalidated consent: %v", err)
			}
			check(guard, 1)
			switch change {
			case "authority":
				allowed = false
			case "expiry":
				s.now = func() int64 { return g.ExpiresAt }
			default:
				sql := map[string]string{"provider": `UPDATE saas_providers SET revision=revision+1 WHERE id='provider'`, "consumer": `UPDATE managed_oauth_clients SET generation='replacement' WHERE id='grant-consumer'`, "connection": `UPDATE auth_collection_connections SET generation='replacement' WHERE id='connection'`}[change]
				if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "use-grant-fence-" + change, SQL: sql}); err != nil {
					t.Fatal(err)
				}
			}
			check(guard, 0)
			if _, _, err := s.AuthorizeUseGrant(ctx, b.Owner, consumer.ID, g.ID, resource, "proxy", authority); err == nil {
				t.Fatal("stale grant authorized")
			}
		})
	}
}
