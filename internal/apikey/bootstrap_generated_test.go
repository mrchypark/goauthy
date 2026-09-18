package apikey

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generatedBootstrapFiles(t *testing.T, name string, deadline time.Time) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	keyDir := filepath.Join(root, "keys")
	if err := os.Mkdir(keyDir, 0700); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 17)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "dev-1"), []byte(base64.RawURLEncoding.EncodeToString(master)), 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "bootstrap.json")
	if err := os.WriteFile(config, []byte(`[{"name":"`+name+`","secret":"generate","access":[{"group":"Clients","access_rights":["read"]}]}]`), 0600); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(root, "generated.secrets")
	return config, keyDir, artifact
}

func TestBootstrapGeneratedImportAuthenticatesAndRetriesSameArtifact(t *testing.T) {
	now := time.Unix(2_100_000_000, 0).UTC()
	config, keyDir, artifact := generatedBootstrapFiles(t, "runner", now.Add(time.Hour))
	db := bootstrapTestDB(t, "bootstrap-generated-import")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	if err := store.BootstrapWithGeneratedSecrets(context.Background(), config, keyDir, artifact, "dev-1", now.Add(time.Hour)); err != nil {
		t.Fatalf("generated import: %v", err)
	}
	entries, err := ReadGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", now)
	if err != nil || len(entries) != 1 {
		t.Fatalf("read generated artifact count=%d err=%v", len(entries), err)
	}
	if entries[0].Kind != "api-key" || entries[0].ID != "runner" || entries[0].Field != "token" {
		t.Fatal("unexpected artifact entry metadata or token")
	}
	if _, err := store.Authenticate(context.Background(), "API-Key "+entries[0].Value); err != nil {
		t.Fatalf("artifact token did not authenticate: %v", err)
	}
	before, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now.Add(10 * time.Minute) }
	if err := store.BootstrapWithGeneratedSecrets(context.Background(), config, keyDir, artifact, "dev-1", now.Add(2*time.Hour)); err != nil {
		t.Fatalf("idempotent generated import: %v", err)
	}
	after, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("retry rewrote generated artifact")
	}
	entriesAfter, err := ReadGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", now.Add(10*time.Minute))
	if err != nil || len(entriesAfter) != 1 || entriesAfter[0].Value != entries[0].Value {
		t.Fatalf("retry changed artifact secret count=%d err=%v", len(entriesAfter), err)
	}
	if _, err := ReadGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", now.Add(time.Hour)); err == nil {
		t.Fatal("retry extended the original artifact deadline")
	}
	assertBootstrapCount(t, db, 1)
}

func TestBootstrapGeneratedPrewrittenArtifactImportsAfterDBCrash(t *testing.T) {
	now := time.Unix(2_100_000_000, 0).UTC()
	config, keyDir, artifact := generatedBootstrapFiles(t, "crash-safe", now.Add(time.Hour))
	secret := bootstrapTestSecret
	if err := WriteGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", []BootstrapSecretEntry{{Kind: "api-key", ID: "crash-safe", Field: "token", Value: "crash-safe$" + secret}}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	db := bootstrapTestDB(t, "bootstrap-generated-crash")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	if err := store.BootstrapWithGeneratedSecrets(context.Background(), config, keyDir, artifact, "dev-1", now.Add(time.Hour)); err != nil {
		t.Fatalf("import prewritten artifact: %v", err)
	}
	if _, err := store.Authenticate(context.Background(), "API-Key crash-safe$"+secret); err != nil {
		t.Fatalf("prewritten artifact token did not authenticate: %v", err)
	}
	assertBootstrapCount(t, db, 1)
}

func TestBootstrapGeneratedRejectsInvalidArtifactWithoutPartialDB(t *testing.T) {
	cases := []struct {
		name string
		prep func(t *testing.T, artifact, keyDir string, now time.Time)
	}{
		{"malformed", func(t *testing.T, artifact, _ string, _ time.Time) {
			if err := os.WriteFile(artifact, []byte("not-an-artifact"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"tampered", func(t *testing.T, artifact, keyDir string, now time.Time) {
			if err := WriteGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", []BootstrapSecretEntry{{Kind: "api-key", ID: "runner", Field: "token", Value: "runner$" + bootstrapTestSecret}}, now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(artifact)
			if err != nil {
				t.Fatal(err)
			}
			data[len(data)-1] ^= 1
			if err := os.WriteFile(artifact, data, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"expired", func(t *testing.T, artifact, keyDir string, now time.Time) {
			if err := WriteGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", []BootstrapSecretEntry{{Kind: "api-key", ID: "runner", Field: "token", Value: "runner$" + bootstrapTestSecret}}, now.Add(-time.Minute)); err != nil {
				t.Fatal(err)
			}
		}},
		{"mismatch", func(t *testing.T, artifact, keyDir string, now time.Time) {
			if err := WriteGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", []BootstrapSecretEntry{{Kind: "api-key", ID: "other", Field: "token", Value: "other$" + bootstrapTestSecret}}, now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(2_100_000_000, 0).UTC()
			config, keyDir, artifact := generatedBootstrapFiles(t, "runner", now.Add(time.Hour))
			tc.prep(t, artifact, keyDir, now)
			db := bootstrapTestDB(t, "bootstrap-generated-invalid-"+tc.name)
			store, err := NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			store.now = func() time.Time { return now }
			if err := store.BootstrapWithGeneratedSecrets(context.Background(), config, keyDir, artifact, "dev-1", now.Add(time.Hour)); err == nil {
				t.Fatal("invalid artifact accepted")
			}
			assertBootstrapCount(t, db, 0)
		})
	}
	now := time.Unix(2_100_000_000, 0).UTC()
	config, keyDir, _ := generatedBootstrapFiles(t, "missing", now.Add(time.Hour))
	db := bootstrapTestDB(t, "bootstrap-generated-missing-path")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	if err := store.BootstrapWithGeneratedSecrets(context.Background(), config, keyDir, "", "dev-1", now.Add(time.Hour)); err == nil {
		t.Fatal("missing artifact path accepted")
	}
	assertBootstrapCount(t, db, 0)
}
