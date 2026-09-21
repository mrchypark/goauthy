package oauth

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestDynamicClientLastUsedIsMonotonicForSuccessfulTokenArtifacts(t *testing.T) {
	ctx := context.Background()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	registered, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: "dynamic-last-used", GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "Last used",
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := server.store.dynamicClients.GetClient(ctx, registered.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	clock := int64(0)
	server.store.now = func() time.Time { return time.UnixMilli(clock) }
	for i, issuanceAt := range []int64{2000, 1000, 3000} {
		suffix := []string{"a", "b", "c"}[i]
		clock = issuanceAt
		request := dynamicLastUsedRequest(client, "last-used-request-"+suffix, time.UnixMilli(1))
		if err := server.store.CreateAccessTokenSession(ctx, "last-used-token-"+suffix, request); err != nil {
			t.Fatal(err)
		}
	}
	if got := dynamicLastUsed(t, db, registered.ClientID); got != 3000 {
		t.Fatalf("last_used_at_unix_ms=%d, want 3000", got)
	}
}

func TestDynamicClientLastUsedRequiresSuccessfulCodeGuard(t *testing.T) {
	ctx := context.Background()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	registered, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: "dynamic-last-used-code", RedirectURIs: []string{"https://rp.example.test/callback"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, Name: "Last used code",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "seed-last-used-code", SQL: `UPDATE dynamic_oauth_clients SET last_used_at_unix_ms = ? WHERE client_id = ?`, Args: []any{5000, registered.ClientID}}); err != nil {
		t.Fatal(err)
	}
	client, err := server.store.dynamicClients.GetClient(ctx, registered.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	server.store.now = func() time.Time { return time.UnixMilli(6000) }
	txCtx, err := server.store.BeginTX(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.InvalidateAuthorizeCodeSession(txCtx, "missing-code"); err != nil {
		t.Fatal(err)
	}
	request := dynamicLastUsedRequest(client, "failed-code-request", time.UnixMilli(1))
	request.GetRequestForm().Set("grant_type", "authorization_code")
	if err := server.store.CreateAccessTokenSession(txCtx, "failed-code-token", request); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); !errors.Is(err, fosite.ErrSerializationFailure) {
		t.Fatalf("Commit error=%v", err)
	}
	if got := dynamicLastUsed(t, db, registered.ClientID); got != 5000 {
		t.Fatalf("failed code exchange changed last_used_at_unix_ms=%d", got)
	}
}

func TestDynamicClientLastUsedForSuccessfulCodeExchange(t *testing.T) {
	ctx := context.Background()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	registered, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: "dynamic-last-used-code-ok", RedirectURIs: []string{"https://rp.example.test/callback"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, Name: "Last used code ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "seed-last-used-code-ok", SQL: `INSERT INTO oauth_authorize_codes (signature, request_json, expires_at_unix_ms) VALUES (?, ?, ?)`, Args: []any{"code-ok", `{}`, int64(10000)}}); err != nil {
		t.Fatal(err)
	}
	client, err := server.store.dynamicClients.GetClient(ctx, registered.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	server.store.now = func() time.Time { return time.UnixMilli(7000) }
	txCtx, err := server.store.BeginTX(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.InvalidateAuthorizeCodeSession(txCtx, "code-ok"); err != nil {
		t.Fatal(err)
	}
	request := dynamicLastUsedRequest(client, "code-ok-request", time.UnixMilli(1))
	request.GetSession().(*fosite.DefaultSession).Subject = "code-user"
	request.GetRequestForm().Set("grant_type", "authorization_code")
	if err := server.store.CreateAccessTokenSession(txCtx, "code-ok-token", request); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); err != nil {
		t.Fatal(err)
	}
	if got := dynamicLastUsed(t, db, registered.ClientID); got != 7000 {
		t.Fatalf("last_used_at_unix_ms=%d, want 7000", got)
	}
}

func TestDynamicClientLastUsedDoesNotChangeOnFailedTokenInsert(t *testing.T) {
	ctx := context.Background()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	registered, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: "dynamic-last-used-failed", GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "Last used failed",
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := server.store.dynamicClients.GetClient(ctx, registered.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	clock := int64(2000)
	server.store.now = func() time.Time { return time.UnixMilli(clock) }
	if err := server.store.CreateAccessTokenSession(ctx, "duplicate-token", dynamicLastUsedRequest(client, "first-request", time.UnixMilli(2000))); err != nil {
		t.Fatal(err)
	}
	clock = 4000
	if err := server.store.CreateAccessTokenSession(ctx, "duplicate-token", dynamicLastUsedRequest(client, "second-request", time.UnixMilli(4000))); err == nil {
		t.Fatal("duplicate access token insert succeeded")
	}
	if got := dynamicLastUsed(t, db, registered.ClientID); got != 2000 {
		t.Fatalf("failed token insert changed last_used_at_unix_ms=%d", got)
	}
}

func dynamicLastUsedRequest(client fosite.Client, id string, requestedAt time.Time) fosite.Requester {
	session := &fosite.DefaultSession{}
	session.SetExpiresAt(fosite.AccessToken, time.UnixMilli(4_000_000_000_000))
	request := fosite.NewRequest()
	request.ID, request.Client, request.RequestedAt = id, client, requestedAt
	request.Form = url.Values{"grant_type": {"client_credentials"}}
	request.Session = session
	request.SetRequestedScopes(fosite.Arguments{"goauthy.read"})
	request.GrantScope("goauthy.read")
	return request
}

func dynamicLastUsed(t *testing.T, db *rhiza.DB, clientID string) int64 {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT last_used_at_unix_ms FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("last-used row=%#v err=%v", result.Rows, err)
	}
	value, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("last-used value=%#v", result.Rows[0][0])
	}
	return value
}

func TestDynamicClientLastUsedPasswordCredentialFence(t *testing.T) {
	db := oauthTestDB(t)
	s := oauthTestServer(t, db, randomSecret(t)).store
	// This exercises storage with an actual password-enabled registration.
	registered, err := s.dynamicClients.Create(t.Context(), dcr.CreateRequest{ClientID: "password-last-used", Name: "Password last used", GrantTypes: []string{"password"}, Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic})
	if err != nil {
		t.Fatal(err)
	}
	client, err := s.dynamicClients.GetClient(t.Context(), registered.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "password-last-used-user", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users(subject,username,password_phc,password_generation) VALUES('password-user','password-user','phc',1)`},
		{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES('password-user','password',1,0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	for i, at := range []int64{2000, 1000, 3000} {
		s.now = func() time.Time { return time.UnixMilli(at) }
		ctx, err := s.beginPasswordTX(t.Context(), "password-user", 1, 1, loginpolicy.AccountStuffingDigest("password-user"))
		if err != nil {
			t.Fatal(err)
		}
		suffix := []string{"first", "older", "denied"}[i]
		r := dynamicLastUsedRequest(client, suffix, time.UnixMilli(at))
		r.GetSession().(*fosite.DefaultSession).Subject = "password-user"
		r.GetRequestForm().Set("grant_type", "password")
		if err := s.CreateAccessTokenSession(ctx, "password-last-used-"+suffix, r); err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "password-last-used-change", SQL: `UPDATE identity_users SET password_generation=2 WHERE subject='password-user'`}); err != nil {
				t.Fatal(err)
			}
		}
		err = s.Commit(ctx)
		if i == 2 {
			if !errors.Is(err, fosite.ErrSerializationFailure) {
				t.Fatalf("changed credentials: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if got := dynamicLastUsed(t, db, registered.ClientID); got != 2000 {
			t.Fatalf("iteration=%d last_used=%d", i, got)
		}
	}
}
