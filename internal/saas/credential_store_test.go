package saas

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func credentialStoreFixture(t *testing.T) (context.Context, *CredentialStore, *rhiza.DB, credentialBinding) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "saas-credential-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "saas-credential-fence", SQL: `INSERT INTO master_key_retirement_barrier(barrier_id,epoch,old_key_id,replacement_key_id,membership_digest,state,prepared_at_unix_ms) VALUES (1,1,'old','master',?,'prepared',1)`, Args: []any{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(dir, "master"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := oidc.LoadKeyring(dir, "master")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewCredentialStore(db, keys)
	if err != nil {
		t.Fatal(err)
	}
	b := credentialBinding{"owner", "collection", "connection", "provider", "generation", 1}
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "saas-credential-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users(subject,username,password_phc,user_expires_at_unix_ms) VALUES(?,?,?,?)`, Args: []any{"owner", "owner", "phc", nil}},
		{SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"collection", "Collection", "oauth2", 1, 1, "definition-generation", "[]", `["provider"]`}},
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"connection", "collection", "owner", "draft", 1, 1, "{}", "generation"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() int64 { return time.Unix(1_800_000_000, 0).UnixMilli() }
	return ctx, store, db, b
}

func credentialAuthority() func() (string, []any) { return func() (string, []any) { return "1", nil } }

func testCredential() credential {
	return credential{AccessToken: "access", RefreshToken: "refresh", Scopes: []string{"scope"}}
}

func TestCredentialStoreInstallLoadAndPlaintextProtection(t *testing.T) {
	ctx, store, db, b := credentialStoreFixture(t)
	if err := store.Install(ctx, b, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(ctx, b, credentialAuthority())
	if err != nil || got.AccessToken != "access" {
		t.Fatalf("load=%#v err=%v", got, err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("credential rows=%#v err=%v", rows.Rows, err)
	}
	if bytes.Contains(rows.Rows[0][0].([]byte), []byte("access")) || bytes.Contains(rows.Rows[0][0].([]byte), []byte("refresh")) {
		t.Fatal("plaintext credential stored")
	}
}

func TestCredentialStoreClaimCompleteAndOldVersionReject(t *testing.T) {
	ctx, store, _, b := credentialStoreFixture(t)
	if err := store.Install(ctx, b, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimRefresh(ctx, b, credentialAuthority())
	if err != nil || claim == "" {
		t.Fatalf("claim=%q err=%v", claim, err)
	}
	if _, err := store.ClaimRefresh(ctx, b, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("second claim=%v", err)
	}
	if err := store.CompleteRefresh(ctx, b, claim, credential{AccessToken: "new-access"}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, b, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("old version load=%v", err)
	}
	next := b
	next.TokenVersion = 2
	if got, err := store.Load(ctx, next, credentialAuthority()); err != nil || got.AccessToken != "new-access" {
		t.Fatalf("new version load=%#v err=%v", got, err)
	}
}

func TestCredentialStoreRevokePreventsRefreshCommit(t *testing.T) {
	ctx, store, _, b := credentialStoreFixture(t)
	if err := store.Install(ctx, b, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimRefresh(ctx, b, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, b, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteRefresh(ctx, b, claim, testCredential(), credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("revoked completion=%v", err)
	}
}
