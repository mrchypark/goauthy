package oauth

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestClientCredentialsCleanupDoesNotMaskGuardFailure(t *testing.T) {
	t.Parallel()
	server, db := clientCredentialsClaimsServer(t, `{"department":"ops"}`, false)

	// Seed expired access tokens and orphaned token requests so the cleanup
	// DELETEs inside CreateAccessTokenSession will affect at least 2 rows.
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "seed-expired-for-cleanup-guard-test",
		Statements: []rhiza.SQLStatement{
			{SQL: "INSERT INTO oauth_access_tokens (signature, request_id, client_id, requested_at_unix_ms, expires_at_unix_ms, requested_scopes, granted_scopes, requested_audience, granted_audience) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
				Args: []any{"expired-access-1", "req-1", testClientID, int64(0), int64(0), "[]", "[]", "[]", "[]"}},
			{SQL: "INSERT INTO oauth_token_requests (signature, request_json) VALUES (?, ?)",
				Args: []any{"expired-access-1", "{}"}},
			{SQL: "INSERT INTO oauth_access_tokens (signature, request_id, client_id, requested_at_unix_ms, expires_at_unix_ms, requested_scopes, granted_scopes, requested_audience, granted_audience) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
				Args: []any{"expired-access-2", "req-2", testClientID, int64(0), int64(0), "[]", "[]", "[]", "[]"}},
			{SQL: "INSERT INTO oauth_token_requests (signature, request_json) VALUES (?, ?)",
				Args: []any{"expired-access-2", "{}"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	// Expire the seeded tokens so the cleanup DELETEs will remove them.
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "expire-seeded-tokens",
		SQL:       "UPDATE oauth_access_tokens SET expires_at_unix_ms = 0",
	}); err != nil {
		t.Fatal(err)
	}

	// Bump the claims revision at the issuance barrier so both guarded INSERTs
	// are rejected by their WHERE clause.
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
			RequestID: "claims-revision-bump-guard-test",
			SQL:       "UPDATE bootstrap_client_credentials_claims SET revision=revision+1 WHERE client_id=?",
			Args:      []any{testClientID},
		}); err != nil {
			t.Fatal(err)
		}
	}

	if response := postToken(server, url.Values{"grant_type": {"client_credentials"}}); response.Code == http.StatusOK {
		t.Fatalf("cleanup-masked guard failure issued token: %s", response.Body.String())
	}
	assertClientCredentialsTokenRows(t, db, 0)
}
