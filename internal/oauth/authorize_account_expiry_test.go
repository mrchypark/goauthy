package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestAuthorizationAccountExpiryStorageMatrix(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, tc := range []struct {
		name     string
		deadline any
		want     time.Time
	}{
		{"NULL retains configured expiry", nil, now.Add(5 * time.Minute)},
		{"shorter account expiry", now.Add(2 * time.Minute), now.Add(2 * time.Minute)},
		{"shorter configured expiry", now.Add(time.Hour), now.Add(5 * time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := oauthTestDB(t)
			server := oauthTestServer(t, db, randomSecret(t))
			server.store.now = func() time.Time { return now }
			seedAccountExpiry(t, db, tc.deadline)
			ctx, err := server.store.accountContext(context.Background(), "user-1")
			if err != nil {
				t.Fatal(err)
			}
			ctx, err = server.store.BeginTX(ctx)
			if err != nil {
				t.Fatal(err)
			}
			request := fosite.NewRequest()
			request.ID, request.Client, request.RequestedAt = "code-account", server.store.client, now
			request.Session = &fosite.DefaultSession{Subject: "user-1"}
			request.Session.SetExpiresAt(fosite.AuthorizeCode, now.Add(5*time.Minute))
			if err := server.store.CreateAuthorizeCodeSession(ctx, "capped-code", request); err != nil {
				t.Fatal(err)
			}
			// Fosite may hand PKCE a separate sanitized session. Both storage
			// writes must enforce the cap, not rely on mutation of the first clone.
			request.Session.SetExpiresAt(fosite.AuthorizeCode, now.Add(5*time.Minute))
			if err := server.store.CreatePKCERequestSession(ctx, "capped-code", request); err != nil {
				t.Fatal(err)
			}
			if err := server.store.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT expires_at_unix_ms,json_extract(request_json,'$.expires_at_unix_ms.authorize_code') FROM oauth_authorize_codes WHERE signature='capped-code' UNION ALL SELECT expires_at_unix_ms,json_extract(request_json,'$.expires_at_unix_ms.authorize_code') FROM oauth_pkce_requests WHERE signature='capped-code'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 2 {
				t.Fatalf("rows=%v err=%v", rows.Rows, err)
			}
			for _, row := range rows.Rows {
				if row[0] != tc.want.UnixMilli() || row[1] != tc.want.UnixMilli() {
					t.Fatalf("expiry=%v want=%d", row, tc.want.UnixMilli())
				}
			}
		})
	}
}

func TestAuthorizationAccountExpiryCapsStoredCodeAndPKCE(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	now := time.Now().UTC().Truncate(time.Second)
	server.store.now = func() time.Time { return now }
	deadline := now.Add(2 * time.Minute)
	seedAccountExpiry(t, db, deadline)
	code := issueCode(t, server, strings.Repeat("a", 43))
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT c.expires_at_unix_ms,p.expires_at_unix_ms FROM oauth_authorize_codes c JOIN oauth_pkce_requests p ON p.signature=c.signature WHERE c.signature=?`, Args: []any{server.authorizeCodes.AuthorizeCodeSignature(context.Background(), code)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != deadline.UnixMilli() || rows.Rows[0][1] != deadline.UnixMilli() {
		t.Fatalf("stored expiry=%#v err=%v want=%d", rows.Rows, err, deadline.UnixMilli())
	}
}

func TestAuthorizationAccountExpiryRejectsExpiredDeadlineWithoutArtifacts(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	now := time.Unix(1_900_000_000, 0).UTC()
	server.store.now = func() time.Time { return now }
	seedAccountExpiry(t, db, now)
	response := httptest.NewRecorder()
	verifier := strings.Repeat("z", 43)
	digest := sha256.Sum256([]byte(verifier))
	values := url.Values{"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI}, "scope": {"goauthy.read"}, "state": {strings.Repeat("s", 32)}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
	server.WriteAuthorization(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"goauthy.read"})
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_authorize_codes),(SELECT COUNT(*) FROM oauth_pkce_requests)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != int64(0) || response.Header().Get("Location") == "" {
		t.Fatalf("expired authorization response=%q rows=%#v err=%v", response.Header().Get("Location"), rows.Rows, err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "authorization-expiry-null", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=NULL WHERE subject='user-1'`}); err != nil {
		t.Fatal(err)
	}
	if issueCode(t, server, verifier) == "" {
		t.Fatal("nullable authorization did not issue a code")
	}
}

func TestAuthorizationAccountExpirySnapshotRejectsDeadlineChange(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, tc := range []struct {
		name             string
		initial, changed any
	}{
		{"finite to NULL", now.Add(time.Hour), nil},
		{"future shortened", now.Add(time.Hour), now.Add(30 * time.Minute).UnixMilli()},
		{"NULL to finite", nil, now.Add(30 * time.Minute).UnixMilli()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := oauthTestDB(t)
			server := oauthTestServer(t, db, randomSecret(t))
			server.store.now = func() time.Time { return now }
			seedAccountExpiry(t, db, tc.initial)
			hookCalled := false
			server.beforeAuthorizationIssue = func() {
				hookCalled = true
				server.beforeAuthorizationIssue = nil
				if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "authorization-expiry-snapshot", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject='user-1'`, Args: []any{tc.changed}}); err != nil {
					t.Fatal(err)
				}
			}
			response := httptest.NewRecorder()
			values := authorizationValues(strings.Repeat("x", 43), "")
			values.Del("resource")
			server.WriteAuthorization(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"goauthy.read"})
			if !hookCalled {
				t.Fatal("authorization did not reach snapshot hook")
			}
			location, err := url.Parse(response.Header().Get("Location"))
			if err != nil || location.Query().Get("code") != "" || location.Query().Get("error") == "" {
				t.Fatalf("stale snapshot response=%q err=%v", response.Header().Get("Location"), err)
			}
			assertNoAuthorizationState(t, db)
			if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "restore-authorize-neighbor", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=NULL WHERE subject='user-1'`}); err != nil {
				t.Fatal(err)
			}
			if issueCode(t, server, strings.Repeat("x", 43)) == "" {
				t.Fatal("valid neighbor did not issue")
			}
		})
	}
}
