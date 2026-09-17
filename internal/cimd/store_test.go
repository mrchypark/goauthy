package cimd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestStoreLookupHitAndExactExpiry(t *testing.T) {
	ctx, store, _ := testStore(t)
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	clientID, policy := "https://client.example.test/cimd.json", testPolicy("one")
	want := testMetadata(clientID, "one")
	if got, err := store.PutFirstWinner(ctx, clientID, policy, want, now, time.Minute); err != nil || !sameMetadata(got, want) {
		t.Fatalf("put=%#v err=%v", got, err)
	}
	got, found, err := store.Lookup(ctx, clientID, policy, now.Add(59*time.Second+999*time.Millisecond))
	if err != nil || !found || !sameMetadata(got, want) {
		t.Fatalf("lookup=%#v found=%v err=%v", got, found, err)
	}
	got.RedirectURIs[0] = "https://attacker.example.test/callback"
	again, found, err := store.Lookup(ctx, clientID, policy, now)
	if err != nil || !found || !sameMetadata(again, want) {
		t.Fatalf("defensive lookup=%#v found=%v err=%v", again, found, err)
	}
	if got, found, err := store.Lookup(ctx, clientID, policy, now.Add(time.Minute)); err != nil || found || got.ID != "" {
		t.Fatalf("exact expiry=%#v found=%v err=%v", got, found, err)
	}
}

func TestStoreRoundTripsKnownGrantTypes(t *testing.T) {
	ctx, store, _ := testStore(t)
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	clientID, policy := "https://client.example.test/cimd.json", testPolicy("grant-types")
	want := testMetadata(clientID, "known")
	want.GrantTypes = []string{"authorization_code", "refresh_token", "client_credentials"}
	if _, err := store.PutFirstWinner(ctx, clientID, policy, want, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.Lookup(ctx, clientID, policy, now)
	if err != nil || !found || !sameMetadata(got, want) {
		t.Fatalf("lookup=%#v found=%v err=%v", got, found, err)
	}
}

func TestStoreRoundTripsAllowedResourcesAndExplicitDeny(t *testing.T) {
	ctx, store, _ := testStore(t)
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	clientID, policy := "https://client.example.test/cimd.json", testPolicy("resources")
	for _, want := range []Metadata{
		{ID: clientID, Name: "allow", RedirectURIs: []string{"https://client.example.test/callback"}, Scopes: []string{"openid"}, AllowedResources: []string{"https://resource.example.test/api"}, AllowedResourcesPresent: true},
		{ID: clientID, Name: "deny", RedirectURIs: []string{"https://client.example.test/callback"}, Scopes: []string{"openid"}, AllowedResources: []string{}, AllowedResourcesPresent: true},
	} {
		entryPolicy := testPolicy(policy + want.Name)
		if _, err := store.PutFirstWinner(ctx, clientID, entryPolicy, want, now, time.Hour); err != nil {
			t.Fatalf("put %s: %v", want.Name, err)
		}
		got, found, err := store.Lookup(ctx, clientID, entryPolicy, now)
		if err != nil || !found || !sameMetadata(got, want) {
			t.Fatalf("lookup=%#v found=%v err=%v want=%#v", got, found, err, want)
		}
	}
}

func TestStoreSeparatesPoliciesAndKeepsFirstWinner(t *testing.T) {
	ctx, store, _ := testStore(t)
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	clientID := "https://client.example.test/cimd.json"
	first := testMetadata(clientID, "first")
	second := testMetadata(clientID, "second")
	policyOne, policyTwo := testPolicy("one"), testPolicy("two")
	if _, err := store.PutFirstWinner(ctx, clientID, policyOne, first, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := store.PutFirstWinner(ctx, clientID, policyOne, second, now, time.Hour); err != nil || !sameMetadata(got, first) {
		t.Fatalf("winner=%#v err=%v", got, err)
	}
	if got, err := store.PutFirstWinner(ctx, clientID, policyTwo, second, now, time.Hour); err != nil || !sameMetadata(got, second) {
		t.Fatalf("other policy=%#v err=%v", got, err)
	}
	if got, found, err := store.Lookup(ctx, clientID, policyOne, now); err != nil || !found || !sameMetadata(got, first) {
		t.Fatalf("policy one=%#v found=%v err=%v", got, found, err)
	}
}

func TestStoreTamperFailsClosed(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	clientID, policy := "https://client.example.test/cimd.json", testPolicy("one")
	if _, err := store.PutFirstWinner(ctx, clientID, policy, testMetadata(clientID, "safe"), now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cimd-test-tamper", SQL: `UPDATE cimd_client_documents SET metadata_digest = ? WHERE client_id = ? AND policy_digest = ?`, Args: []any{"bad", clientID, policy}}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Lookup(ctx, clientID, policy, now); !errors.Is(err, ErrInvalidCache) || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

func TestStoreTamperedDuplicateListFailsClosed(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	clientID, policy := "https://client.example.test/cimd.json", testPolicy("one")
	if _, err := store.PutFirstWinner(ctx, clientID, policy, testMetadata(clientID, "safe"), now, time.Hour); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(storedMetadata{ID: clientID, Name: "safe", RedirectURIs: []string{"https://client.example.test/callback", "https://client.example.test/callback"}, Scopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cimd-test-duplicate-tamper", SQL: `UPDATE cimd_client_documents SET metadata_json = ?, metadata_digest = ? WHERE client_id = ? AND policy_digest = ?`, Args: []any{string(encoded), base64.RawURLEncoding.EncodeToString(sum[:]), clientID, policy}}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Lookup(ctx, clientID, policy, now); !errors.Is(err, ErrInvalidCache) || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

func TestStoreRejectsWhenActiveCacheIsFull(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	for start := 0; start < storeActiveCacheCap; start += 64 {
		statements := make([]rhiza.SQLStatement, 0, 64)
		for i := start; i < start+64; i++ {
			statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO cimd_client_documents
				(client_id,policy_digest,metadata_json,metadata_digest,fetched_at_unix_ms,expires_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?)`,
				Args: []any{fmt.Sprintf("https://cached-%04d.example.test/cimd.json", i), testPolicy(fmt.Sprint(i)), `{}`, strings.Repeat("d", 43), now.UnixMilli(), now.Add(time.Hour).UnixMilli()}})
		}
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("cimd-test-fill-%d", start), Statements: statements}); err != nil {
			t.Fatal(err)
		}
	}
	clientID := "https://client.example.test/cimd.json"
	if _, err := store.PutFirstWinner(ctx, clientID, testPolicy("new"), testMetadata(clientID, "new"), now, time.Hour); !errors.Is(err, ErrCacheFull) {
		t.Fatalf("err=%v", err)
	}
}

func TestStorePutFirstWinnerDoesNotAcceptWinnerAfterBeforeAckCommitUnknown(t *testing.T) {
	ctx := context.Background()
	objectStoreDir := filepath.Join(t.TempDir(), "objects")
	db, err := rhiza.Open(ctx, rhiza.Config{
		ClusterID: "cimd-before-ack-test", NodeID: "cimd-before-ack-test", DataDir: t.TempDir(),
		ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: objectStoreDir,
		ObjStoreDurability:   rhiza.ObjectStoreDurabilityBeforeAck,
		ObjStoreSyncInterval: time.Hour, CheckpointInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cimd-before-ack-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE cimd_client_documents (
			client_id TEXT NOT NULL, policy_digest TEXT NOT NULL, metadata_json TEXT NOT NULL,
			metadata_digest TEXT NOT NULL, fetched_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL, PRIMARY KEY(client_id, policy_digest)
		) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}

	offlineDir := objectStoreDir + "-offline"
	if err := os.Rename(objectStoreDir, offlineDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectStoreDir, []byte("offline"), 0o600); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		if err := os.Remove(objectStoreDir); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Rename(offlineDir, objectStoreDir); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		restored = true
	}
	t.Cleanup(restore)

	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	clientID, policy := "https://client.example.test/cimd.json", testPolicy("before-ack")
	want := testMetadata(clientID, "before-ack")
	if got, err := store.PutFirstWinner(ctx, clientID, policy, want, now, time.Hour); !errors.Is(err, rhiza.ErrCommitUnknown) || got.ID != "" {
		t.Fatalf("offline put=%#v err=%v, want commit unknown without winner", got, err)
	}
	other := testMetadata(clientID, "before-ack-other")
	if got, err := store.PutFirstWinner(ctx, clientID, policy, other, now.Add(time.Millisecond), time.Hour); !errors.Is(err, rhiza.ErrCommitUnknown) || got.ID != "" {
		t.Fatalf("offline competing put=%#v err=%v, want commit unknown without winner", got, err)
	}

	restore()
	if got, err := store.PutFirstWinner(ctx, clientID, policy, want, now, time.Hour); err != nil || !sameMetadata(got, want) {
		t.Fatalf("recovered put=%#v err=%v", got, err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM cimd_client_documents WHERE client_id = ? AND policy_digest = ?`, Args: []any{clientID, policy}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) {
		t.Fatalf("rows=%#v err=%v, want one record", rows.Rows, err)
	}
}

func testStore(t *testing.T) (context.Context, *Store, *rhiza.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cimd-store-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cimd-test-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE cimd_client_documents (
			client_id TEXT NOT NULL CHECK(length(client_id) <= 2048),
			policy_digest TEXT NOT NULL,
			metadata_json TEXT NOT NULL CHECK(length(metadata_json) <= 8192),
			metadata_digest TEXT NOT NULL,
			fetched_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms > fetched_at_unix_ms),
			PRIMARY KEY(client_id, policy_digest)
		) STRICT`},
		{SQL: `CREATE INDEX cimd_client_documents_expiry ON cimd_client_documents(expires_at_unix_ms,client_id,policy_digest)`},
	}}); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, store, db
}

func testMetadata(id, name string) Metadata {
	return Metadata{ID: id, Name: name, RedirectURIs: []string{"https://client.example.test/callback"}, Scopes: []string{"openid", "profile"}}
}

func testPolicy(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func sameMetadata(a, b Metadata) bool {
	if a.ID != b.ID || a.Name != b.Name || a.AllowedResourcesPresent != b.AllowedResourcesPresent || len(a.RedirectURIs) != len(b.RedirectURIs) || len(a.Scopes) != len(b.Scopes) || len(a.GrantTypes) != len(b.GrantTypes) || len(a.AllowedResources) != len(b.AllowedResources) {
		return false
	}
	for i := range a.RedirectURIs {
		if a.RedirectURIs[i] != b.RedirectURIs[i] {
			return false
		}
	}
	for i := range a.Scopes {
		if a.Scopes[i] != b.Scopes[i] {
			return false
		}
	}
	for i := range a.AllowedResources {
		if a.AllowedResources[i] != b.AllowedResources[i] {
			return false
		}
	}
	for i := range a.GrantTypes {
		if a.GrantTypes[i] != b.GrantTypes[i] {
			return false
		}
	}
	return true
}
