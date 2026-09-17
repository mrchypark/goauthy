package oauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestDPoPPolicyExchangeRebindsSourceCutoff(t *testing.T) {
	server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
	client, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{
		ClientID: "dpop-exchange-cutoff", GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "exchange",
	})
	if err != nil {
		t.Fatal(err)
	}
	dynamic, err := server.store.GetClient(context.Background(), client.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	source, sourceExpiry := exchangeSource(t, server)
	policy := context.WithValue(context.Background(), dpopPolicyContextKey{}, dpopPolicySnapshot{clientID: client.ClientID})
	txCtx, err := server.store.BeginTokenExchangeTX(policy, source, sourceExpiry)
	if err != nil {
		t.Fatal(err)
	}
	target := "dpop-exchange-cutoff-target"
	if err := server.store.CreateAccessTokenSession(txCtx, target, dynamicExchangeRequest(dynamic, target)); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); err != nil {
		t.Fatalf("optional bearer exchange failed: %v", err)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), target, &fosite.DefaultSession{}); err != nil {
		t.Fatalf("optional bearer target missing: %v", err)
	}
	server.store.now = func() time.Time { return sourceExpiry.Add(time.Second) }
	txCtx, err = server.store.BeginTokenExchangeTX(policy, source, sourceExpiry)
	if err != nil {
		t.Fatal(err)
	}
	target = "dpop-exchange-cutoff-expired"
	if err := server.store.CreateAccessTokenSession(txCtx, target, dynamicExchangeRequest(dynamic, target)); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); !errors.Is(err, fosite.ErrSerializationFailure) {
		t.Fatalf("expired source accepted or wrong error: %v", err)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), target, &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("expired source created target: %v", err)
	}
	assertDPoPExchangeNoArtifacts(t, server, target)
}

func TestDPoPPolicyActorExchangeRebindsBothCutoffs(t *testing.T) {
	server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
	client, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{
		ClientID: "dpop-actor-exchange-cutoff", GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "actor-exchange",
	})
	if err != nil {
		t.Fatal(err)
	}
	dynamic, err := server.store.GetClient(context.Background(), client.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	source, sourceExpiry := exchangeSource(t, server)
	actor, actorExpiry := exchangeSource(t, server)
	actorExpiry = sourceExpiry.Add(-time.Minute)
	if _, err := storage.Execute(t.Context(), server.store.db, rhiza.ExecuteRequest{RequestID: "dpop-actor-earlier-expiry", SQL: `UPDATE oauth_access_tokens SET expires_at_unix_ms=? WHERE signature=?`, Args: []any{actorExpiry.UnixMilli(), actor}}); err != nil {
		t.Fatal(err)
	}
	policy := context.WithValue(context.Background(), dpopPolicyContextKey{}, dpopPolicySnapshot{clientID: client.ClientID})
	txCtx, err := server.store.BeginTokenExchangeActorTX(policy, source, sourceExpiry, actor, actorExpiry)
	if err != nil {
		t.Fatal(err)
	}
	target := "dpop-actor-exchange-cutoff-target"
	if err := server.store.CreateAccessTokenSession(txCtx, target, dynamicExchangeRequest(dynamic, target)); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); err != nil {
		t.Fatalf("optional bearer actor exchange failed: %v", err)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), target, &fosite.DefaultSession{}); err != nil {
		t.Fatalf("optional bearer actor target missing: %v", err)
	}
	// Expire only the actor, exactly at its boundary; the source remains valid.
	server.store.now = func() time.Time { return actorExpiry }
	txCtx, err = server.store.BeginTokenExchangeActorTX(policy, source, sourceExpiry, actor, actorExpiry)
	if err != nil {
		t.Fatal(err)
	}
	target = "dpop-actor-exchange-cutoff-expired"
	if err := server.store.CreateAccessTokenSession(txCtx, target, dynamicExchangeRequest(dynamic, target)); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); !errors.Is(err, fosite.ErrSerializationFailure) {
		t.Fatalf("expired source/actor accepted or wrong error: %v", err)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), target, &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("expired source/actor created target: %v", err)
	}
	assertDPoPExchangeNoArtifacts(t, server, target)
}

func assertDPoPExchangeNoArtifacts(t *testing.T, server *Server, target string) {
	t.Helper()
	rows, err := server.store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?), (SELECT COUNT(*) FROM oauth_token_requests WHERE signature=?)`, Args: []any{target, target}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 2 || rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != int64(0) {
		t.Fatalf("exchange left token artifacts: rows=%v err=%v", rows.Rows, err)
	}
}

func dynamicExchangeRequest(client fosite.Client, target string) fosite.Requester {
	request := fosite.NewRequest()
	request.ID, request.Client, request.RequestedAt = target, client, time.Now().UTC()
	request.RequestedScope = fosite.Arguments{"goauthy.read"}
	request.GrantedScope = fosite.Arguments{"goauthy.read"}
	request.Session = &fosite.DefaultSession{Subject: "subject"}
	request.Session.SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(time.Hour))
	return request
}
