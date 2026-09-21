package saas

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUseGrantInvokeRegisteredAPIKeySequence(t *testing.T) {
	t.Parallel()
	ctx, store, _, b, grant, calls, server := useGrantInvokeFixture(t, nil)
	defer server.Close()

	_, guard, err := store.AuthorizeUseGrant(ctx, b.Owner, grant.ConsumerClientID, grant.ID, grant.Resource, "proxy", credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	connector, err := store.APIKeyConnector(ctx, grant.Owner, grant.CollectionID, grant.ConnectionID, guard)
	if err != nil {
		t.Fatal(err)
	}
	if connector.Digest() != grant.ConnectorDigest {
		t.Fatalf("connector digest=%q grant=%q", connector.Digest(), grant.ConnectorDigest)
	}
	connector.client = apiKeyConnectorTLSClient(t, server)
	result, err := store.CallAPIKey(ctx, grant.Owner, grant.CollectionID, grant.ConnectionID, connector, "account", guard)
	if err != nil || string(result["id"]) != `"account-1"` || string(result["active"]) != "true" || len(result) != 2 {
		t.Fatalf("result=%v err=%v", result, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls=%d want=1", calls.Load())
	}
}

func TestUseGrantInvokeRejectsInvalidGrantsBeforeProvider(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		consumer string
		grantID  string
		resource string
		mode     string
	}{
		{name: "wrong-consumer", consumer: "other-consumer"},
		{name: "no-grant", consumer: "invoke-consumer", grantID: "missing"},
		{name: "wrong-mode", consumer: "invoke-consumer", mode: "credential_delivery"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, store, _, b, grant, calls, server := useGrantInvokeFixture(t, nil)
			defer server.Close()
			consumer, id, resource, mode := tc.consumer, tc.grantID, tc.resource, tc.mode
			if id == "" {
				id = grant.ID
			}
			if resource == "" {
				resource = grant.Resource
			}
			if mode == "" {
				mode = grant.Mode
			}
			if _, _, err := store.AuthorizeUseGrant(ctx, b.Owner, consumer, id, resource, mode, credentialAuthority()); err == nil {
				t.Fatal("invalid grant authorized")
			}
			if calls.Load() != 0 {
				t.Fatalf("provider calls=%d want=0", calls.Load())
			}
		})
	}

	t.Run("revoked-before-zero-calls", func(t *testing.T) {
		ctx, store, _, b, grant, calls, server := useGrantInvokeFixture(t, nil)
		defer server.Close()
		if err := store.RevokeUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, grant.ID, grant.Revision, credentialAuthority()); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.AuthorizeUseGrant(ctx, b.Owner, grant.ConsumerClientID, grant.ID, grant.Resource, "proxy", credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
			t.Fatalf("err=%v", err)
		}
		if calls.Load() != 0 {
			t.Fatalf("provider calls=%d want=0", calls.Load())
		}
	})
}

func TestUseGrantInvokeRevokedDuringProviderDiscardsResponse(t *testing.T) {
	t.Parallel()
	var store *CredentialStore
	var grant UseGrant
	var during func()
	ctx, s, _, b, g, calls, server := useGrantInvokeFixture(t, &during)
	defer server.Close()
	store, grant = s, g
	during = func() {
		if err := store.RevokeUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, grant.ID, grant.Revision, credentialAuthority()); err != nil {
			t.Error(err)
		}
	}
	_, guard, err := store.AuthorizeUseGrant(ctx, b.Owner, grant.ConsumerClientID, grant.ID, grant.Resource, "proxy", credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	connector, err := store.APIKeyConnector(ctx, grant.Owner, grant.CollectionID, grant.ConnectionID, guard)
	if err != nil {
		t.Fatal(err)
	}
	connector.client = apiKeyConnectorTLSClient(t, server)
	result, err := store.CallAPIKey(ctx, grant.Owner, grant.CollectionID, grant.ConnectionID, connector, "account", guard)
	if err == nil || result != nil {
		t.Fatalf("result=%v err=%v", result, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls=%d want=1", calls.Load())
	}
}

func TestUseGrantInvokeProviderPolicyChangesBetweenAuthorizeAndCredentialRead(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"disable", "rotation"} {
		t.Run(change, func(t *testing.T) {
			ctx, store, db, b, grant, calls, server := useGrantInvokeFixture(t, nil)
			defer server.Close()
			_, guard, err := store.AuthorizeUseGrant(ctx, b.Owner, grant.ConsumerClientID, grant.ID, grant.Resource, "proxy", credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			sql := `UPDATE saas_providers SET enabled=0 WHERE id=?`
			args := []any{grant.ProviderID}
			if change == "rotation" {
				sql = `UPDATE saas_providers SET revision=revision+1 WHERE id=?`
			}
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "invoke-provider-" + change, SQL: sql, Args: args}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.APIKeyConnector(ctx, grant.Owner, grant.CollectionID, grant.ConnectionID, guard); err == nil {
				t.Fatal("changed provider returned connector")
			}
			if calls.Load() != 0 {
				t.Fatalf("provider calls=%d want=0", calls.Load())
			}
		})
	}
}

func useGrantInvokeFixture(t *testing.T, during *func()) (context.Context, *CredentialStore, *rhiza.DB, credentialBinding, UseGrant, *atomic.Int64, *httptest.Server) {
	t.Helper()
	calls := new(atomic.Int64)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-key" {
			t.Errorf("authorization=%q", r.Header.Get("Authorization"))
		}
		if during != nil && *during != nil {
			(*during)()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"account-1","active":true,"access_token":"should-not-leak","api_key":"should-not-leak"}`)
	}))
	ctx, store, db, b, connector := registeredAPIKeyFixture(t, "billing")
	connector.client = apiKeyConnectorTLSClient(t, server)
	consumer, err := clients.NewStore(db, store.keys).CreateWithGuard(ctx, clients.NewRequest{ID: "invoke-consumer", RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	grant, err := store.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", UseGrantInput{ConsumerClientID: consumer.ID, Mode: "proxy", Purpose: "invoke", ExpiresAt: store.now() + 60000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	return ctx, store, db, b, grant, calls, server
}
