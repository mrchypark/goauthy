package oauth

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func seedManagedClient(t *testing.T, db *rhiza.DB, revision int64, generation string, enabled bool) *clients.Client {
	t.Helper()
	meta, _ := json.Marshal(map[string]any{"id": "managed-test", "redirect_uris": []string{"https://rp.example.test/callback"}, "scopes": []string{"goauthy.read"}, "default_scopes": []string{"goauthy.read"}, "enabled_flows": []string{"authorization_code", "refresh_token", "client_credentials"}})
	en := int64(0)
	if enabled {
		en = 1
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "seed-managed-" + generation, SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json,secret_hash) VALUES(?,?,?,?,0,?,?)`, Args: []any{"managed-test", generation, revision, en, string(meta), []byte("hash")}}); err != nil {
		t.Fatal(err)
	}
	return &clients.Client{ID: "managed-test", Revision: revision, Generation: generation, Enabled: enabled, Confidential: true, RedirectURIs: []string{"https://rp.example.test/callback"}, Scopes: []string{"goauthy.read"}, DefaultScopes: []string{"goauthy.read"}, GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"}}
}

func TestManagedClientIssuanceGuardsRevisionAndGeneration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := oauthTestDB(t)
	client := seedManagedClient(t, db, 1, "generation-one", true)
	store := &Store{db: db, now: time.Now}
	session := &fosite.DefaultSession{ExpiresAt: map[fosite.TokenType]time.Time{fosite.AuthorizeCode: time.Now().Add(time.Hour), fosite.AccessToken: time.Now().Add(time.Hour), fosite.RefreshToken: time.Now().Add(time.Hour)}}
	request := fosite.NewRequest()
	request.ID, request.Client, request.RequestedAt, request.Session = "managed-request", client, time.Now(), session
	request.GrantScope("goauthy.read")
	request.Form = url.Values{"grant_type": {"client_credentials"}}
	if err := store.CreateAccessTokenSession(ctx, "managed-cc", request); err != nil {
		t.Fatal(err)
	}
	ccRows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, Args: []any{"managed-cc"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || ccRows.Rows[0][0] != int64(1) {
		t.Fatalf("managed client-credentials token missing: %#v err=%v", ccRows.Rows, err)
	}
	request.Form = nil
	txCtx, err := store.BeginTX(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthorizeCodeSession(txCtx, "managed-code", request); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(txCtx); err != nil {
		t.Fatalf("normal managed authorization code: %v", err)
	}
	codeRows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature=?`, Args: []any{"managed-code"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || codeRows.Rows[0][0] != int64(1) {
		t.Fatalf("normal code missing: %#v err=%v", codeRows.Rows, err)
	}
	txCtx, err = store.BeginTX(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthorizeCodeSession(txCtx, "managed-code-stale", request); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "managed-revision-bump", SQL: `UPDATE managed_oauth_clients SET revision=2 WHERE id=?`, Args: []any{"managed-test"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(txCtx); err == nil {
		t.Fatal("stale managed client issuance committed")
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature=?`, Args: []any{"managed-code-stale"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(0) {
		t.Fatalf("stale code persisted: %#v err=%v", rows.Rows, err)
	}
	request.Form = url.Values{"grant_type": {"client_credentials"}}
	if err := store.CreateAccessTokenSession(ctx, "managed-stale-cc", request); err == nil {
		t.Fatal("stale managed client-credentials issuance committed")
	}
	staleRows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, Args: []any{"managed-stale-cc"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || staleRows.Rows[0][0] != int64(0) {
		t.Fatalf("stale cc persisted: %#v err=%v", staleRows.Rows, err)
	}

}
