package saas

import (
	"testing"

	"github.com/mrchypark/goauthy/internal/authcollection"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUseGrantRegisteredAPIKeyPolicy(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"disable", "revision", "remove"} {
		t.Run(change, func(t *testing.T) {
			ctx, s, db, b := credentialStoreFixture(t)
			providers, err := NewProviderStore(db, s.keys)
			if err != nil {
				t.Fatal(err)
			}
			cfg := validAPIKeyConnectorConfig()
			cfg.ID = "registered-key"
			p, err := providers.Create(ctx, ProviderInput{ID: cfg.ID, Name: "Registered", Kind: "api_key", Enabled: true, Connector: &cfg}, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			collections := authcollection.NewStore(db)
			d, err := collections.CreateDefinition(ctx, authcollection.DefinitionInput{ID: "registered-collection", Name: "Registered", AuthMethod: "api_key", Enabled: true, ProviderIDs: []string{p.ID}}, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			c, err := collections.CreateConnection(ctx, b.Owner, d.ID, d.Revision, []byte(`{}`), credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			connector, err := s.APIKeyConnector(ctx, b.Owner, d.ID, c.ID, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.PutBoundAPIKey(ctx, b.Owner, d.ID, c.ID, 0, "synthetic-key", connector, connector.Digest(), credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			const resource = "https://consumer.example/resource"
			consumer, err := clients.NewStore(db, s.keys).CreateWithGuard(ctx, clients.NewRequest{ID: "registered-consumer", RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{resource}}, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			g, err := s.CreateUseGrant(ctx, b.Owner, d.ID, c.ID, resource, UseGrantInput{ConsumerClientID: consumer.ID, Mode: "proxy", Purpose: "sync", ExpiresAt: s.now() + 60000}, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			if g.ProviderID != p.ID || g.ProviderRevision != p.Revision || g.ConnectorDigest != connector.Digest() {
				t.Fatal("grant lost registered provider binding")
			}
			_, guard, err := s.AuthorizeUseGrant(ctx, b.Owner, consumer.ID, g.ID, resource, "proxy", credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			// Deterministically interleave a policy change after authorization.
			sql := map[string]string{"disable": `UPDATE saas_providers SET enabled=0 WHERE id='registered-key'`, "revision": `UPDATE saas_providers SET revision=revision+1 WHERE id='registered-key'`, "remove": `UPDATE auth_collection_definitions SET providers_json='[]' WHERE id='registered-collection'`}[change]
			if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "registered-grant-" + change, SQL: sql}); err != nil {
				t.Fatal(err)
			}
			predicate, args := guard()
			q, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + predicate, Args: args, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 0 {
				t.Fatalf("old guard survived: rows=%v err=%v", q.Rows, err)
			}
			if _, _, err = s.AuthorizeUseGrant(ctx, b.Owner, consumer.ID, g.ID, resource, "proxy", credentialAuthority()); err == nil {
				t.Fatal("changed provider authorized")
			}
		})
	}
}
