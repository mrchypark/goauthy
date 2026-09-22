package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestOIDCAuthorizationCodeIssueIsGuardedByBrowserSession(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, sessions *browser.Store, issued browser.IssuedSession, db *rhiza.DB)
	}{
		{name: "revoked", mutate: func(t *testing.T, sessions *browser.Store, issued browser.IssuedSession, _ *rhiza.DB) {
			t.Helper()
			if err := sessions.RevokeSession(context.Background(), issued.Token); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "absolutely expired", mutate: func(t *testing.T, _ *browser.Store, issued browser.IssuedSession, db *rhiza.DB) {
			t.Helper()
			if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "expire-browser-session", SQL: `UPDATE browser_sessions SET expires_at_unix_ms = ? WHERE token_digest = ?`, Args: []any{time.Unix(1, 0).UTC().UnixMilli(), issued.ID}}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "idle expired", mutate: func(t *testing.T, _ *browser.Store, issued browser.IssuedSession, db *rhiza.DB) {
			t.Helper()
			if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "idle-browser-session", SQL: `UPDATE browser_sessions SET last_seen_at_unix_ms = ? WHERE token_digest = ?`, Args: []any{time.Unix(1, 0).UTC().UnixMilli(), issued.ID}}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := oauthTestDB(t)
			seedDeviceUser(t, db, "user-1", nil)
			sessions, err := browser.NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			issued, err := sessions.CreateSession(context.Background(), "user-1", oidcAuthMethodPwd, time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "")
			if err != nil {
				t.Fatal(err)
			}
			store := oauthTestServer(t, db, randomSecret(t)).store
			ctx, err := store.BeginTX(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			request := guardedOIDCRequest(t, store, issued.ID)
			signature := "guarded-" + test.name
			if err := store.CreatePKCERequestSession(ctx, signature, request); err != nil {
				t.Fatal(err)
			}
			if err := store.CreateAuthorizeCodeSession(ctx, signature, request); err != nil {
				t.Fatal(err)
			}
			// The authorization flow loaded this session before logout. The final
			// replicated issuance transaction must observe the later state.
			test.mutate(t, sessions, issued, db)
			if err := store.Commit(ctx); !errors.Is(err, fosite.ErrSerializationFailure) {
				t.Fatalf("Commit error = %v, want serialization failure", err)
			}
			result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_authorize_codes), (SELECT COUNT(*) FROM oauth_pkce_requests)`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) || result.Rows[0][1] != int64(0) {
				t.Fatalf("guarded issuance persisted state: rows=%#v err=%v", result.Rows, err)
			}
		})
	}
}

func TestOIDCIssueGuardHonorsConfiguredBrowserIdleTimeout(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	seedDeviceUser(t, db, "user-1", nil)
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateSession(context.Background(), "user-1", oidcAuthMethodPwd, time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil }, BrowserSessionIdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := server.store.BeginTX(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request := guardedOIDCRequest(t, server.store, issued.ID)
	if err := server.store.CreatePKCERequestSession(ctx, "configured-idle", request); err != nil {
		t.Fatal(err)
	}
	if err := server.store.CreateAuthorizeCodeSession(ctx, "configured-idle", request); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "configured-idle-expire", SQL: `UPDATE browser_sessions SET last_seen_at_unix_ms = ? WHERE token_digest = ?`, Args: []any{time.Unix(1, 0).UTC().UnixMilli(), issued.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(ctx); !errors.Is(err, fosite.ErrSerializationFailure) {
		t.Fatalf("Commit error = %v, want serialization failure", err)
	}
}

func TestAtomicOIDCSessionRevocationWinsAgainstInFlightCodeIssue(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	seedDeviceUser(t, db, "user-1", nil)
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateSession(context.Background(), "user-1", oidcAuthMethodPwd, time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil })
	ctx, err := server.store.BeginTX(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request := guardedOIDCRequest(t, server.store, issued.ID)
	if err := server.store.CreatePKCERequestSession(ctx, "atomic-revoke", request); err != nil {
		t.Fatal(err)
	}
	if err := server.store.CreateAuthorizeCodeSession(ctx, "atomic-revoke", request); err != nil {
		t.Fatal(err)
	}
	if err := server.RevokeOIDCSession(context.Background(), issued.ID); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(ctx); !errors.Is(err, fosite.ErrSerializationFailure) {
		t.Fatalf("Commit error = %v, want serialization failure", err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT
		(SELECT revoked_at_unix_ms IS NOT NULL FROM browser_sessions WHERE token_digest = ?),
		(SELECT COUNT(*) FROM oauth_authorize_codes),
		(SELECT COUNT(*) FROM oauth_pkce_requests),
		(SELECT COUNT(*) FROM oauth_access_tokens),
		(SELECT COUNT(*) FROM oauth_refresh_tokens WHERE active = 1)`, Args: []any{issued.ID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) || result.Rows[0][1] != int64(0) || result.Rows[0][2] != int64(0) || result.Rows[0][3] != int64(0) || result.Rows[0][4] != int64(0) {
		t.Fatalf("atomic revoke state: rows=%#v err=%v", result.Rows, err)
	}
}

func TestNonOIDCAuthorizationCodeIssueDoesNotRequireBrowserSession(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	seedDeviceUser(t, db, "user-1", nil)
	store := oauthTestServer(t, db, randomSecret(t)).store
	ctx, err := store.BeginTX(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request := guardedOIDCRequest(t, store, "")
	if err := store.CreatePKCERequestSession(ctx, "oauth-code", request); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthorizeCodeSession(ctx, "oauth-code", request); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx); err != nil {
		t.Fatalf("non-OIDC Commit error = %v", err)
	}
}

func TestMalformedOIDCBrowserSessionIDCannotPersistAuthorizationCode(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil })
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO0123456789"
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+oidcAuthorizationValues(verifier, "nonce").Encode(), nil), "user-1", []string{"openid", "goauthy.read", "offline_access"}, time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "not-a-browser-session-id", oidcAuthMethodPwd)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") != "" {
		t.Fatalf("malformed OIDC session issued code: status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_authorize_codes), (SELECT COUNT(*) FROM oauth_pkce_requests)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) || result.Rows[0][1] != int64(0) {
		t.Fatalf("malformed OIDC session persisted state: rows=%#v err=%v", result.Rows, err)
	}
}

func TestOIDCBrowserSessionIDRequiresCanonicalBase64URL(t *testing.T) {
	t.Parallel()
	if validOIDCSessionID(strings.Repeat("A", 42) + "B") {
		t.Fatal("noncanonical base64url browser session ID accepted")
	}
}

func guardedOIDCRequest(t *testing.T, store *Store, sid string) fosite.Requester {
	t.Helper()
	client, err := store.GetClient(context.Background(), testClientID)
	if err != nil {
		t.Fatal(err)
	}
	session := &fosite.DefaultSession{Subject: "user-1"}
	scopes := []string{"goauthy.read"}
	if sid != "" {
		session.Extra = map[string]interface{}{oidcSessionIDExtra: sid}
		scopes = append(scopes, openidScope)
	}
	session.SetExpiresAt(fosite.AuthorizeCode, time.Date(2100, time.January, 1, 0, 1, 0, 0, time.UTC))
	request := fosite.NewRequest()
	request.ID, request.Client, request.RequestedAt, request.Form, request.Session = "request-1", client, time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), url.Values{"scope": {strings.Join(scopes, " ")}}, session
	request.SetRequestedScopes(scopes)
	for _, scope := range scopes {
		request.GrantScope(scope)
	}
	return request
}
