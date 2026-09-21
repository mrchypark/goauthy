package saas

import (
	"errors"
	"fmt"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func credentialStatusFixture(t *testing.T) (*refreshFixture, clients.Client, UseGrant) {
	t.Helper()
	f := newRefreshFixture(t, "account-1")
	consumer, err := clients.NewStore(f.s.db, f.s.keys).CreateWithGuard(f.ctx, clients.NewRequest{
		ID: "status-consumer", Confidential: true,
		RedirectURIs: []string{"https://consumer.example/callback"},
		Scopes:       []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"},
		GrantTypes: []string{"authorization_code"}, Audiences: []string{useRefreshResource},
	}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.s.CreateUseGrant(f.ctx, f.b.Owner, f.b.CollectionID, f.b.ConnectionID, useRefreshResource, UseGrantInput{
		ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "status", ExpiresAt: f.s.now() + 60000,
	}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	return f, consumer, grant
}

func TestOAuth2UseGrantStatusShowsMetadataForEveryCredentialState(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"ready", "refreshing", "uncertain", "revoked"} {
		t.Run(state, func(t *testing.T) {
			f, consumer, grant := credentialStatusFixture(t)
			claim := any(nil)
			if state == "refreshing" {
				claim = "status-claim"
			}
			if _, err := storage.Execute(f.ctx, f.s.db, rhiza.ExecuteRequest{RequestID: "status-state-" + state, SQL: `UPDATE saas_connection_credentials SET state=?,refresh_claim=? WHERE connection_id=?`, Args: []any{state, claim, f.b.ConnectionID}}); err != nil {
				t.Fatal(err)
			}
			before := credentialStatusRow(t, f)
			got, err := f.s.OAuth2UseGrantStatus(f.ctx, f.b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority())
			after := credentialStatusRow(t, f)
			if err != nil || got.State != state || got.Version != 1 || got.ProviderID != f.b.ProviderID || got.AccountID != "account-1" || len(got.Scopes) != 2 || f.tokenCalls.Load() != 0 || f.identityCalls.Load() != 0 {
				t.Fatalf("status=%+v err=%v provider=%d identity=%d", got, err, f.tokenCalls.Load(), f.identityCalls.Load())
			}
			if before != after {
				t.Fatalf("credential row changed before=%v after=%v", before, after)
			}
		})
	}
}

func TestOAuth2UseGrantStatusAllowsExpiredAccessAndRejectsFences(t *testing.T) {
	t.Parallel()
	f, consumer, grant := credentialStatusFixture(t)
	old := credentialBinding{Owner: f.b.Owner, CollectionID: f.b.CollectionID, ConnectionID: f.b.ConnectionID, ProviderID: f.b.ProviderID, Generation: f.b.Generation, TokenVersion: 1}
	env, err := sealCredential(f.s.keys, old, credential{AccountID: "account-1", AccessToken: "expired", RefreshToken: "refresh-old", ExpiresAtUnixMS: f.s.now() - 1, Scopes: []string{"openid", "profile"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(f.ctx, f.s.db, rhiza.ExecuteRequest{RequestID: "status-expired-access", SQL: `UPDATE saas_connection_credentials SET credential=? WHERE connection_id=?`, Args: []any{env, f.b.ConnectionID}}); err != nil {
		t.Fatal(err)
	}
	got, err := f.s.OAuth2UseGrantStatus(f.ctx, f.b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority())
	if err != nil || got.AccountID != "account-1" || got.State != "ready" {
		t.Fatalf("expired status=%+v err=%v", got, err)
	}

	for _, name := range []string{"expired grant", "provider changed", "client disabled", "reconnected generation"} {
		t.Run(name, func(t *testing.T) {
			// Each mutation is intentionally applied to a fresh fixture so the
			// stored grant and credential remain otherwise unchanged.
			ff, cc, gg := credentialStatusFixture(t)
			var err error
			switch name {
			case "expired grant":
				_, err = storage.Execute(ff.ctx, ff.s.db, rhiza.ExecuteRequest{RequestID: "status-expire-grant", SQL: `UPDATE saas_use_grants SET expires_at_unix_ms=? WHERE id=?`, Args: []any{ff.s.now() - 1, gg.ID}})
			case "provider changed":
				_, err = storage.Execute(ff.ctx, ff.s.db, rhiza.ExecuteRequest{RequestID: "status-provider-change", SQL: `UPDATE saas_providers SET revision=revision+1 WHERE id=?`, Args: []any{ff.b.ProviderID}})
			case "client disabled":
				_, err = storage.Execute(ff.ctx, ff.s.db, rhiza.ExecuteRequest{RequestID: "status-client-disable", SQL: `UPDATE managed_oauth_clients SET enabled=0 WHERE id=?`, Args: []any{cc.ID}})
			case "reconnected generation":
				_, err = storage.Execute(ff.ctx, ff.s.db, rhiza.ExecuteRequest{RequestID: "status-reconnect", SQL: `UPDATE auth_collection_connections SET generation='new-generation' WHERE id=?`, Args: []any{ff.b.ConnectionID}})
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ff.s.OAuth2UseGrantStatus(ff.ctx, ff.b.Owner, cc.ID, gg.ID, gg.Resource, credentialAuthority()); !statusDenied(err) {
				t.Fatalf("err=%v", err)
			}
			if ff.tokenCalls.Load() != 0 || ff.identityCalls.Load() != 0 {
				t.Fatal("status performed provider I/O")
			}
		})
	}
	for _, name := range []string{"wrong owner", "wrong consumer", "wrong resource"} {
		t.Run(name, func(t *testing.T) {
			ff, cc, gg := credentialStatusFixture(t)
			owner, client, resource := ff.b.Owner, cc.ID, gg.Resource
			switch name {
			case "wrong owner":
				owner = "other"
			case "wrong consumer":
				client = "other"
			case "wrong resource":
				resource = "https://other.example/resource"
			}
			if _, err := ff.s.OAuth2UseGrantStatus(ff.ctx, owner, client, gg.ID, resource, credentialAuthority()); !statusDenied(err) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func statusDenied(err error) bool {
	return errors.Is(err, ErrUseGrantNotFound) || errors.Is(err, ErrCredentialNotFound)
}

func TestOAuth2UseGrantStatusRejectsRevokedGrantAndAPIKey(t *testing.T) {
	t.Parallel()
	f, consumer, grant := credentialStatusFixture(t)
	if _, err := storage.Execute(f.ctx, f.s.db, rhiza.ExecuteRequest{RequestID: "status-revoke-grant", SQL: `UPDATE saas_use_grants SET revoked=1 WHERE id=?`, Args: []any{grant.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.OAuth2UseGrantStatus(f.ctx, f.b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority()); !statusDenied(err) {
		t.Fatalf("revoked grant err=%v", err)
	}

	ctx, store, db, b, connector := registeredAPIKeyFixture(t, "status-api-key")
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	consumer2, err := clients.NewStore(db, store.keys).CreateWithGuard(ctx, clients.NewRequest{ID: "status-api-consumer", Confidential: true, RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{useRefreshResource}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"proxy", "credential_delivery"} {
		apiGrant, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, useRefreshResource, UseGrantInput{ConsumerClientID: consumer2.ID, Mode: mode, Purpose: "status", ExpiresAt: store.now() + 60000}, credentialAuthority())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.OAuth2UseGrantStatus(ctx, b.Owner, consumer2.ID, apiGrant.ID, apiGrant.Resource, credentialAuthority()); !statusDenied(err) {
			t.Fatalf("API-key %s grant err=%v", mode, err)
		}
	}
}

func credentialStatusRow(t *testing.T, f *refreshFixture) string {
	t.Helper()
	q, err := f.s.db.Query(f.ctx, rhiza.QueryRequest{SQL: `SELECT state,token_version,COALESCE(refresh_claim,'') FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{f.b.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 {
		t.Fatalf("credential row=%v err=%v", q.Rows, err)
	}
	return fmt.Sprint(q.Rows[0])
}

func TestOAuth2UseGrantStatusRechecksAuthority(t *testing.T) {
	t.Parallel()
	f, consumer, grant := credentialStatusFixture(t)
	calls := 0
	authority := func() (string, []any) {
		calls++
		// Stored consent and the credential query must both succeed. Revoke
		// only at the post-decryption check, not before metadata was read.
		if calls < 3 {
			return "1", nil
		}
		return "0", nil
	}
	if _, err := f.s.OAuth2UseGrantStatus(f.ctx, f.b.Owner, consumer.ID, grant.ID, grant.Resource, authority); !statusDenied(err) {
		t.Fatalf("authority loss err=%v", err)
	}
	if calls != 3 {
		t.Fatalf("final authority check calls=%d", calls)
	}
	if f.tokenCalls.Load() != 0 || f.identityCalls.Load() != 0 {
		t.Fatal("status performed provider I/O")
	}
}

func TestOAuth2UseGrantStatusRejectsChangedSnapshot(t *testing.T) {
	t.Parallel()
	f, consumer, grant := credentialStatusFixture(t)
	calls := 0
	authority := func() (string, []any) {
		calls++
		if calls == 3 {
			if _, err := storage.Execute(f.ctx, f.s.db, rhiza.ExecuteRequest{RequestID: "status-changed-after-read", SQL: `UPDATE saas_connection_credentials SET state='uncertain' WHERE connection_id=?`, Args: []any{f.b.ConnectionID}}); err != nil {
				t.Fatal(err)
			}
		}
		return "1", nil
	}
	if _, err := f.s.OAuth2UseGrantStatus(f.ctx, f.b.Owner, consumer.ID, grant.ID, grant.Resource, authority); !statusDenied(err) {
		t.Fatalf("changed snapshot err=%v", err)
	}
	if calls != 3 || f.tokenCalls.Load() != 0 || f.identityCalls.Load() != 0 {
		t.Fatal("snapshot check did not remain read-only")
	}
}
