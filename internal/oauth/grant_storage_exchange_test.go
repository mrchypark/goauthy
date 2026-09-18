package oauth

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestTokenExchangeSourceRevocationPreventsTargetIssue(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	sourceSignature, sourceExpiry := exchangeSource(t, server)
	txCtx, err := server.store.BeginTokenExchangeTX(context.Background(), sourceSignature, sourceExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.DeleteAccessTokenSession(context.Background(), sourceSignature); err != nil {
		t.Fatal(err)
	}
	target := "exchange-target-revoked"
	if err := server.store.CreateAccessTokenSession(txCtx, target, exchangeRequest(server.store, target)); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); !errors.Is(err, fosite.ErrSerializationFailure) {
		t.Fatalf("Commit error=%v", err)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), target, &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("revoked source issued target: %v", err)
	}
}

func TestTokenExchangeConcurrentIndependentTargets(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	sourceSignature, sourceExpiry := exchangeSource(t, server)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, target := range []string{"exchange-target-one", "exchange-target-two"} {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			txCtx, err := server.store.BeginTokenExchangeTX(context.Background(), sourceSignature, sourceExpiry)
			if err == nil {
				<-start
				err = server.store.CreateAccessTokenSession(txCtx, target, exchangeRequest(server.store, target))
			}
			if err == nil {
				err = server.store.Commit(txCtx)
			}
			errs <- err
		}(target)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"exchange-target-one", "exchange-target-two"} {
		if _, err := server.store.GetAccessTokenSession(context.Background(), target, &fosite.DefaultSession{}); err != nil {
			t.Fatalf("target %s missing: %v", target, err)
		}
	}
}

func TestTokenExchangeRejectsRefreshArtifact(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	sourceSignature, sourceExpiry := exchangeSource(t, server)
	txCtx, err := server.store.BeginTokenExchangeTX(context.Background(), sourceSignature, sourceExpiry)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.store.Rollback(txCtx) }()
	request := exchangeRequest(server.store, "exchange-refresh-rejected")
	if err := server.store.CreateRefreshTokenSession(txCtx, "exchange-refresh", "exchange-access", request); err == nil {
		t.Fatal("token exchange accepted a refresh artifact")
	}
}

func TestTokenExchangeCommitCutoffRejectsSourceThatExpiresWhileQueued(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	sourceSignature, _ := exchangeSource(t, server)
	futureExpiry := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "exchange-source-future-expiry", SQL: `UPDATE oauth_access_tokens SET expires_at_unix_ms = ? WHERE signature = ?`, Args: []any{futureExpiry.UnixMilli(), sourceSignature}}); err != nil {
		t.Fatal(err)
	}
	txCtx, err := server.store.BeginTokenExchangeTX(context.Background(), sourceSignature, futureExpiry)
	if err != nil {
		t.Fatal(err)
	}
	pastExpiry := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "exchange-source-expire-before-commit", SQL: `UPDATE oauth_access_tokens SET expires_at_unix_ms = ? WHERE signature = ?`, Args: []any{pastExpiry.UnixMilli(), sourceSignature}}); err != nil {
		t.Fatal(err)
	}
	target := "exchange-target-expired-queued"
	if err := server.store.CreateAccessTokenSession(txCtx, target, exchangeRequest(server.store, target)); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); !errors.Is(err, fosite.ErrSerializationFailure) {
		t.Fatalf("Commit error=%v", err)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), target, &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("expired source issued target: %v", err)
	}
}

func TestTokenExchangeActorRevocationPreventsTargetIssueAtCommit(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	sourceSignature, sourceExpiry := exchangeSource(t, server)
	actorSignature, actorExpiry := exchangeSource(t, server)
	txCtx, err := server.store.BeginTokenExchangeActorTX(context.Background(), sourceSignature, sourceExpiry, actorSignature, actorExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.DeleteAccessTokenSession(context.Background(), actorSignature); err != nil {
		t.Fatal(err)
	}
	target := "exchange-target-actor-revoked"
	if err := server.store.CreateAccessTokenSession(txCtx, target, exchangeRequest(server.store, target)); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); !errors.Is(err, fosite.ErrSerializationFailure) {
		t.Fatalf("Commit error=%v", err)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), target, &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("revoked actor issued target: %v", err)
	}
}

func exchangeSource(t *testing.T, server *Server) (string, time.Time) {
	t.Helper()
	issued := decodeToken(t, postToken(server, mapForm("grant_type", "client_credentials")))
	signature := server.accessTokens.AccessTokenSignature(context.Background(), issued.AccessToken)
	request, err := server.store.GetAccessTokenSession(context.Background(), signature, &fosite.DefaultSession{})
	if err != nil {
		t.Fatal(err)
	}
	expires := request.GetSession().GetExpiresAt(fosite.AccessToken)
	if expires.IsZero() {
		t.Fatal("source access token lacks expiry")
	}
	return signature, expires
}

func exchangeRequest(store *Store, target string) fosite.Requester {
	request := fosite.NewRequest()
	request.ID = target
	request.Client = store.client
	request.RequestedAt = time.Now().UTC()
	request.RequestedScope = fosite.Arguments{"goauthy.read"}
	request.GrantedScope = fosite.Arguments{"goauthy.read"}
	request.Session = &fosite.DefaultSession{Subject: "subject"}
	request.Session.SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(time.Hour))
	return request
}

func mapForm(key, value string) url.Values { return url.Values{key: {value}} }
