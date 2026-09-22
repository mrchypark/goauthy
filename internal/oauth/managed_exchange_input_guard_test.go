package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestTokenExchangeManagedInputGenerationGuard(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		actor   bool
		disable bool
	}{
		{name: "source-generation"},
		{name: "source-disabled", disable: true},
		{name: "actor-generation", actor: true},
		{name: "actor-disabled", actor: true, disable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, db := crossClientExchangeServer(t)
			inputID, inputSecret := "managed-exchange-input-"+tc.name, "managed-exchange-input-secret-"+tc.name
			seedCrossExchangeManagedClient(t, db, inputID, inputSecret, true, []string{"client_credentials"}, nil, nil, 1)
			inputSignature, inputExpiry := managedExchangeInput(t, server, inputID, inputSecret)

			sourceSignature, sourceExpiry := inputSignature, inputExpiry
			actorSignature, actorExpiry := "", time.Time{}
			if tc.actor {
				source := crossExchangeSource(t, server, "managed-input-source")
				sourceSignature = server.accessTokens.AccessTokenSignature(t.Context(), source)
				request, err := server.store.GetAccessTokenSession(t.Context(), sourceSignature, &fosite.DefaultSession{})
				if err != nil {
					t.Fatal(err)
				}
				sourceExpiry = request.GetSession().GetExpiresAt(fosite.AccessToken)
				actorSignature, actorExpiry = inputSignature, inputExpiry
			}
			var (
				txCtx context.Context
				err   error
			)
			if tc.actor {
				txCtx, err = server.store.BeginTokenExchangeActorTX(t.Context(), sourceSignature, sourceExpiry, actorSignature, actorExpiry)
			} else {
				txCtx, err = server.store.BeginTokenExchangeTX(t.Context(), sourceSignature, sourceExpiry)
			}
			if err != nil {
				t.Fatal(err)
			}
			mutation := rhiza.ExecuteRequest{RequestID: "managed-input-change-" + tc.name, SQL: `UPDATE managed_oauth_clients SET generation=?,revision=revision+1 WHERE id=?`, Args: []any{"revoked-" + tc.name, inputID}}
			if tc.disable {
				mutation.SQL = `UPDATE managed_oauth_clients SET enabled=0,revision=revision+1 WHERE id=?`
				mutation.Args = []any{inputID}
			}
			if _, err := storage.Execute(t.Context(), db, mutation); err != nil {
				t.Fatal(err)
			}
			target := "managed-input-target-" + tc.name
			if err := server.store.CreateAccessTokenSession(txCtx, target, exchangeRequest(server.store, target)); err != nil {
				t.Fatal(err)
			}
			if err := server.store.Commit(txCtx); !errors.Is(err, fosite.ErrSerializationFailure) {
				t.Fatalf("Commit error=%v", err)
			}
			assertManagedExchangeInputNoArtifacts(t, db, target)
		})
	}
}

func TestTokenExchangeManagedInputCosmeticRevisionStillIssues(t *testing.T) {
	t.Parallel()
	server, db := crossClientExchangeServer(t)
	for _, input := range []struct{ id, secret string }{{"managed-input-positive-source", "managed-input-positive-source-secret"}, {"managed-input-positive-actor", "managed-input-positive-actor-secret"}} {
		seedCrossExchangeManagedClient(t, db, input.id, input.secret, true, []string{"client_credentials"}, nil, nil, 1)
	}
	source, sourceExpiry := managedExchangeInput(t, server, "managed-input-positive-source", "managed-input-positive-source-secret")
	actor, actorExpiry := managedExchangeInput(t, server, "managed-input-positive-actor", "managed-input-positive-actor-secret")
	txCtx, err := server.store.BeginTokenExchangeActorTX(t.Context(), source, sourceExpiry, actor, actorExpiry)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"managed-input-positive-source", "managed-input-positive-actor"} {
		if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "managed-input-cosmetic-" + id, SQL: `UPDATE managed_oauth_clients SET revision=revision+1 WHERE id=?`, Args: []any{id}}); err != nil {
			t.Fatal(err)
		}
	}
	target := "managed-input-positive-target"
	if err := server.store.CreateAccessTokenSession(txCtx, target, exchangeRequest(server.store, target)); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); err != nil {
		t.Fatalf("cosmetic managed input revision rejected: %v", err)
	}
	if _, err := server.store.GetAccessTokenSession(t.Context(), target, &fosite.DefaultSession{}); err != nil {
		t.Fatalf("cosmetic managed input target missing: %v", err)
	}
}

func TestTokenExchangeDynamicInputDeletionGuard(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		actor bool
	}{
		{name: "source"},
		{name: "actor", actor: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, db := crossClientExchangeServer(t)
			input, signature, expiry := dynamicExchangeInput(t, server, "dynamic-input-"+tc.name)
			source, sourceExpiry := signature, expiry
			actor, actorExpiry := "", time.Time{}
			if tc.actor {
				access := crossExchangeSource(t, server, "dynamic-input-source")
				source = server.accessTokens.AccessTokenSignature(t.Context(), access)
				request, err := server.store.GetAccessTokenSession(t.Context(), source, &fosite.DefaultSession{})
				if err != nil {
					t.Fatal(err)
				}
				sourceExpiry = request.GetSession().GetExpiresAt(fosite.AccessToken)
				actor, actorExpiry = signature, expiry
			}
			var (
				txCtx context.Context
				err   error
			)
			if tc.actor {
				txCtx, err = server.store.BeginTokenExchangeActorTX(t.Context(), source, sourceExpiry, actor, actorExpiry)
			} else {
				txCtx, err = server.store.BeginTokenExchangeTX(t.Context(), source, sourceExpiry)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := server.store.dynamicClients.DeleteRegistration(t.Context(), input.ClientID, input.RegistrationAccessToken); err != nil {
				t.Fatal(err)
			}
			target := "dynamic-input-target-" + tc.name
			if err := server.store.CreateAccessTokenSession(txCtx, target, exchangeRequest(server.store, target)); err != nil {
				t.Fatal(err)
			}
			if err := server.store.Commit(txCtx); !errors.Is(err, fosite.ErrSerializationFailure) {
				t.Fatalf("Commit error=%v", err)
			}
			assertManagedExchangeInputNoArtifacts(t, db, target)
		})
	}
}

func TestTokenExchangeDynamicInputUnchangedStillIssues(t *testing.T) {
	t.Parallel()
	server, db := crossClientExchangeServer(t)
	_, source, sourceExpiry := dynamicExchangeInput(t, server, "dynamic-input-positive-source")
	_, actor, actorExpiry := dynamicExchangeInput(t, server, "dynamic-input-positive-actor")
	txCtx, err := server.store.BeginTokenExchangeActorTX(t.Context(), source, sourceExpiry, actor, actorExpiry)
	if err != nil {
		t.Fatal(err)
	}
	target := "dynamic-input-positive-target"
	if err := server.store.CreateAccessTokenSession(txCtx, target, exchangeRequest(server.store, target)); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); err != nil {
		t.Fatalf("unchanged dynamic inputs rejected: %v", err)
	}
	if _, err := server.store.GetAccessTokenSession(t.Context(), target, &fosite.DefaultSession{}); err != nil {
		t.Fatalf("dynamic input target request is unreadable: %v", err)
	}
	assertManagedExchangeInputArtifacts(t, db, target, 1)
}

func managedExchangeInput(t *testing.T, server *Server, clientID, secret string) (string, time.Time) {
	t.Helper()
	response := postCrossExchange(server, clientID, secret, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}})
	if response.Code != http.StatusOK {
		t.Fatalf("managed input issuance status=%d", response.Code)
	}
	access := decodeToken(t, response).AccessToken
	signature := server.accessTokens.AccessTokenSignature(t.Context(), access)
	request, err := server.store.GetAccessTokenSession(t.Context(), signature, &fosite.DefaultSession{})
	if err != nil {
		t.Fatal(err)
	}
	return signature, request.GetSession().GetExpiresAt(fosite.AccessToken)
}

func dynamicExchangeInput(t *testing.T, server *Server, clientID string) (dcr.Registration, string, time.Time) {
	t.Helper()
	registration, err := server.store.dynamicClients.Create(t.Context(), dcr.CreateRequest{ClientID: clientID, GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: clientID})
	if err != nil {
		t.Fatal(err)
	}
	response := postCrossExchange(server, registration.ClientID, registration.ClientSecret, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}})
	if response.Code != http.StatusOK {
		t.Fatalf("dynamic input issuance status=%d", response.Code)
	}
	access := decodeToken(t, response).AccessToken
	signature := server.accessTokens.AccessTokenSignature(t.Context(), access)
	request, err := server.store.GetAccessTokenSession(t.Context(), signature, &fosite.DefaultSession{})
	if err != nil {
		t.Fatal(err)
	}
	return registration, signature, request.GetSession().GetExpiresAt(fosite.AccessToken)
}

func assertManagedExchangeInputNoArtifacts(t *testing.T, db *rhiza.DB, target string) {
	assertManagedExchangeInputArtifacts(t, db, target, 0)
}

func assertManagedExchangeInputArtifacts(t *testing.T, db *rhiza.DB, target string, want int64) {
	t.Helper()
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?), (SELECT COUNT(*) FROM oauth_token_requests WHERE signature=?)`, Args: []any{target, target}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 2 || rows.Rows[0][0] != want || rows.Rows[0][1] != want {
		t.Fatalf("exchange target artifacts want=%d rows=%v err=%v", want, rows.Rows, err)
	}
}
