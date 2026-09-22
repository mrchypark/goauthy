package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestGeneratedBootstrapConfiguration(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, path, ttl string
		valid           bool
		duration        time.Duration
	}{
		{"disabled", "", "", true, 0},
		{"no expiry", "/data/bootstrap.secrets.enc", "0", true, 0},
		{"expiring", "/data/bootstrap.secrets.enc", "3600", true, time.Hour},
		{"uint32 max", "/data/bootstrap.secrets.enc", "4294967295", true, 4294967295 * time.Second},
		{"missing ttl", "/data/bootstrap.secrets.enc", "", false, 0},
		{"missing path", "", "3600", false, 0},
		{"negative", "/data/bootstrap.secrets.enc", "-1", false, 0},
		{"overflow", "/data/bootstrap.secrets.enc", "4294967296", false, 0},
		{"units", "/data/bootstrap.secrets.enc", "1h", false, 0},
		{"whitespace ttl", "/data/bootstrap.secrets.enc", " 1", false, 0},
		{"whitespace path", " /data/bootstrap.secrets.enc", "1", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := generatedBootstrapConfigFromEnv(func(key string) string {
				if key == "GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_FILE" {
					return tc.path
				}
				if key == "GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_TTL_SECONDS" {
					return tc.ttl
				}
				return ""
			})
			if (err == nil) != tc.valid {
				t.Fatalf("config=%+v err=%v", cfg, err)
			}
			if tc.valid && (cfg.artifact != tc.path || cfg.ttl != tc.duration) {
				t.Fatalf("config=%+v", cfg)
			}
		})
	}
}

func TestBootstrapAPIKeysSharedStartupAndRetry(t *testing.T) {
	t.Parallel()
	db := retirementCmdDB(t, true)
	store, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keyDir, "dev-1"), []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))), 0600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(keyDir, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	input := filepath.Join(root, "api_keys.json")
	if err := os.WriteFile(input, []byte(`[{"name":"startup-runner","secret":"generate","access":[{"group":"Clients","access_rights":["read"]}]}]`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := generatedBootstrapConfig{artifact: filepath.Join(root, "bootstrap.secrets.enc"), ttl: time.Hour}
	now := time.Now().UTC()
	if err := bootstrapAPIKeys(t.Context(), store, keyring, input, keyDir, cfg, now); err != nil {
		t.Fatal(err)
	}
	entries, err := apikey.ReadGeneratedBootstrapSecrets(cfg.artifact, keyDir, "dev-1", now)
	if err != nil || len(entries) != 1 {
		t.Fatalf("generated export unavailable: %v", err)
	}
	if _, err := store.Authenticate(t.Context(), "API-Key "+entries[0].Value); err != nil {
		t.Fatal("exported startup key did not authenticate")
	}
	original, err := os.ReadFile(cfg.artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrapAPIKeys(t.Context(), store, keyring, input, keyDir, cfg, now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cfg.artifact)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("startup retry replaced original artifact")
	}
	if _, err := apikey.ReadGeneratedBootstrapSecrets(cfg.artifact, keyDir, "dev-1", now.Add(time.Hour)); err == nil {
		t.Fatal("startup retry extended export expiry")
	}
}

func TestGeneratedBootstrapPurgeWorkerExpiresBothCopiesAndStops(t *testing.T) {
	t.Parallel()
	db := retirementCmdDB(t, true)
	store, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keyDir, "dev-1"), []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))), 0600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(keyDir, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(-time.Hour)
	artifact := filepath.Join(t.TempDir(), "expired.enc")
	if err := apikey.WriteGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", []apikey.BootstrapSecretEntry{}, deadline); err != nil {
		t.Fatal(err)
	}
	envelope, err := keyring.SealEnvelope(oidc.GeneratedAPIKeyBootstrapEnvelopePurpose, []byte(fmt.Sprintf(`{"version":1,"deadline":%d,"entries":[]}`, deadline.Unix())))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.ExecuteEnvelope(t.Context(), db, "dev-1", rhiza.ExecuteRequest{RequestID: "purge-worker-seed", SQL: `INSERT INTO generated_api_key_bootstrap(singleton,config_digest,payload_envelope,deadline_unix_s,created_at_unix_ms) VALUES(1,?,?,?,?)`, Args: []any{"digest", envelope, deadline.Unix(), deadline.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	failures := make(chan error, 1)
	go func() {
		defer close(done)
		runGeneratedBootstrapPurge(ctx, store, keyring, generatedBootstrapConfig{artifact: artifact}, keyDir, func(err error) {
			select {
			case failures <- err:
			default:
			}
		})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("purge worker did not stop")
		}
	}()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case err := <-failures:
			t.Fatal(err)
		case <-timeout.C:
			t.Fatal("immediate purge did not expire both copies")
		case <-poll.C:
			result, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT payload_envelope FROM generated_api_key_bootstrap WHERE singleton=1`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Rows) == 1 && result.Rows[0][0] == nil {
				if _, err := os.Stat(artifact); !os.IsNotExist(err) {
					t.Fatal("shared tombstone exists but expired local export remains")
				}
				return
			}
		}
	}
}
