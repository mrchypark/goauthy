package saas

import (
	"errors"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const useRefreshResource = "https://consumer.example/resource"

func useRefreshFixture(t *testing.T) (*refreshFixture, clients.Client, UseGrant) {
	t.Helper()
	f := newRefreshFixture(t, "account-1")
	consumer, err := clients.NewStore(f.s.db, f.s.keys).CreateWithGuard(f.ctx, clients.NewRequest{
		ID: "refresh-consumer", Confidential: true,
		RedirectURIs: []string{"https://consumer.example/callback"},
		Scopes:       []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"},
		GrantTypes: []string{"authorization_code"}, Audiences: []string{useRefreshResource},
	}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.s.CreateUseGrant(f.ctx, f.b.Owner, f.b.CollectionID, f.b.ConnectionID, useRefreshResource, UseGrantInput{
		ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "refresh", ExpiresAt: f.s.now() + 60000, AllowRefresh: true,
	}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	return f, consumer, grant
}

func TestUseGrantRefreshSuccessAndExpiredAccessToken(t *testing.T) {
	t.Parallel()
	f, consumer, grant := useRefreshFixture(t)
	// Refresh is based on the durable refresh token, not the current access expiry.
	expired := sealCredentialForTest(t, f, credentialBinding{Owner: f.b.Owner, CollectionID: f.b.CollectionID, ConnectionID: f.b.ConnectionID, ProviderID: f.b.ProviderID, Generation: f.b.Generation, TokenVersion: 1}, credential{AccountID: "account-1", AccessToken: "expired", RefreshToken: "refresh-old", ExpiresAtUnixMS: f.s.now() - 1, RefreshExpiresAtUnixMS: f.s.now() + 60000, Scopes: []string{"openid", "profile"}})
	if _, err := storage.Execute(f.ctx, f.s.db, rhiza.ExecuteRequest{RequestID: "use-refresh-expired-access", SQL: `UPDATE saas_connection_credentials SET credential=? WHERE connection_id=?`, Args: []any{expired, f.b.ConnectionID}}); err != nil {
		t.Fatal(err)
	}
	g, guard, err := f.s.authorizeUseRefresh(f.ctx, f.b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority())
	if err != nil || !g.AllowRefresh {
		t.Fatalf("authorize grant=%+v err=%v", g, err)
	}
	status, err := f.s.refreshOAuth2(f.ctx, f.o, credentialBinding{Owner: g.Owner, CollectionID: g.CollectionID, ConnectionID: g.ConnectionID, ProviderID: g.ProviderID, Generation: g.Generation, TokenVersion: 1}, guard)
	if err != nil || !status.Connected || status.Version != 2 || f.tokenCalls.Load() != 1 || f.identityCalls.Load() != 1 {
		t.Fatalf("status=%+v err=%v token=%d identity=%d", status, err, f.tokenCalls.Load(), f.identityCalls.Load())
	}
}

func TestUseGrantRefreshRejectsOptInAndBoundaryCases(t *testing.T) {
	t.Parallel()
	f, consumer, grant := useRefreshFixture(t)
	defaultGrant, err := f.s.CreateUseGrant(f.ctx, f.b.Owner, f.b.CollectionID, f.b.ConnectionID, grant.Resource, UseGrantInput{ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "default", ExpiresAt: f.s.now() + 60000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RefreshOAuth2UseGrant(f.ctx, f.p, f.b.Owner, consumer.ID, defaultGrant.ID, defaultGrant.Resource, 1, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) || f.tokenCalls.Load() != 0 {
		t.Fatalf("default grant err=%v calls=%d", err, f.tokenCalls.Load())
	}
	if _, err := f.s.CreateUseGrant(f.ctx, f.b.Owner, f.b.CollectionID, f.b.ConnectionID, grant.Resource, UseGrantInput{ConsumerClientID: consumer.ID, Mode: "proxy", Purpose: "proxy", ExpiresAt: f.s.now() + 60000, AllowRefresh: true}, credentialAuthority()); !errors.Is(err, ErrUseGrantInvalid) {
		t.Fatalf("proxy opt-in err=%v", err)
	}
	for name, version := range map[string]int64{"stale": 2, "zero": 0, "max": 1<<63 - 1} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.s.RefreshOAuth2UseGrant(f.ctx, f.p, f.b.Owner, consumer.ID, grant.ID, grant.Resource, version, credentialAuthority()); !errors.Is(err, ErrUseGrantInvalid) && !(name == "stale" && errors.Is(err, ErrCredentialNotFound)) {
				t.Fatalf("version=%d err=%v", version, err)
			}
			if f.tokenCalls.Load() != 0 {
				t.Fatal("stale/invalid version performed provider I/O")
			}
		})
	}
	if _, err := storage.Execute(f.ctx, f.s.db, rhiza.ExecuteRequest{RequestID: "use-refresh-revoke-grant", SQL: `UPDATE saas_use_grants SET revoked=1 WHERE id=?`, Args: []any{grant.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RefreshOAuth2UseGrant(f.ctx, f.p, f.b.Owner, consumer.ID, grant.ID, grant.Resource, 1, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("revoked grant err=%v", err)
	}

	apiCtx, apiStore, apiDB, apiBinding, connector := registeredAPIKeyFixture(t, "refresh-api")
	if _, err := apiStore.PutBoundAPIKey(apiCtx, apiBinding.Owner, apiBinding.CollectionID, apiBinding.ConnectionID, 0, "key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	apiConsumer, err := clients.NewStore(apiDB, apiStore.keys).CreateWithGuard(apiCtx, clients.NewRequest{ID: "refresh-api-consumer", Confidential: true, RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{useRefreshResource}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apiStore.CreateUseGrant(apiCtx, apiBinding.Owner, apiBinding.CollectionID, apiBinding.ConnectionID, useRefreshResource, UseGrantInput{ConsumerClientID: apiConsumer.ID, Mode: "credential_delivery", Purpose: "refresh", ExpiresAt: apiStore.now() + 60000, AllowRefresh: true}, credentialAuthority()); !errors.Is(err, ErrUseGrantInvalid) {
		t.Fatalf("API-key opt-in err=%v", err)
	}
}

func TestUseGrantRefreshGrantAndCredentialRevocationAreUncertain(t *testing.T) {
	t.Parallel()
	for _, revokeCredential := range []bool{false, true} {
		t.Run(map[bool]string{false: "grant", true: "credential"}[revokeCredential], func(t *testing.T) {
			f, consumer, grant := useRefreshFixture(t)
			f.beforeTokenReply = func() {
				if revokeCredential {
					_, err := storage.Execute(f.ctx, f.s.db, rhiza.ExecuteRequest{RequestID: "use-refresh-revoke-credential", SQL: `UPDATE saas_connection_credentials SET state='revoked',refresh_claim=NULL WHERE connection_id=?`, Args: []any{f.b.ConnectionID}})
					if err != nil {
						t.Error(err)
					}
				} else {
					_, err := storage.Execute(f.ctx, f.s.db, rhiza.ExecuteRequest{RequestID: "use-refresh-revoke-grant-race", SQL: `UPDATE saas_use_grants SET revoked=1 WHERE id=?`, Args: []any{grant.ID}})
					if err != nil {
						t.Error(err)
					}
				}
			}
			g, guard, err := f.s.authorizeUseRefresh(f.ctx, f.b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.s.refreshOAuth2(f.ctx, f.o, credentialBinding{Owner: g.Owner, CollectionID: g.CollectionID, ConnectionID: g.ConnectionID, ProviderID: g.ProviderID, Generation: g.Generation, TokenVersion: 1}, guard)
			if !errors.Is(err, errRefreshUncertain) {
				t.Fatalf("refresh err=%v", err)
			}
			if f.tokenCalls.Load() != 1 {
				t.Fatalf("provider calls=%d", f.tokenCalls.Load())
			}
			q, err := f.s.db.Query(f.ctx, rhiza.QueryRequest{SQL: `SELECT state,token_version,refresh_claim FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{f.b.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 1 || q.Rows[0][1] != int64(1) || q.Rows[0][2] != nil {
				t.Fatalf("row=%v err=%v", q.Rows, err)
			}
			want := "uncertain"
			if revokeCredential {
				want = "revoked"
			}
			if q.Rows[0][0] != want {
				t.Fatalf("state=%v want=%s", q.Rows[0][0], want)
			}
		})
	}
}

func TestUseGrantRefreshConcurrentClaimOneProviderCall(t *testing.T) {
	t.Parallel()
	f, consumer, grant := useRefreshFixture(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, guard, err := f.s.authorizeUseRefresh(f.ctx, f.b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority())
			if err == nil {
				_, err = f.s.refreshOAuth2(f.ctx, f.o, credentialBinding{Owner: g.Owner, CollectionID: g.CollectionID, ConnectionID: g.ConnectionID, ProviderID: g.ProviderID, Generation: g.Generation, TokenVersion: 1}, guard)
			}
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if f.tokenCalls.Load() != 1 {
		t.Fatalf("provider calls=%d errs=%v", f.tokenCalls.Load(), errs)
	}
}

func sealCredentialForTest(t *testing.T, f *refreshFixture, b credentialBinding, value credential) []byte {
	t.Helper()
	env, err := sealCredential(f.s.keys, b, value)
	if err != nil {
		t.Fatal(err)
	}
	return env
}
