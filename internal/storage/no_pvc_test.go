package storage_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// The filesystem object-store adapter is the deterministic external boundary.
// Separate processes and fresh DataDirs prevent reuse of the writer's local WAL.
// Archive-only cases skip Close; checkpoint cases explicitly publish on Close.
// This is not an S3/network or HA qualification.
func TestNoPVCRejectsCorruptArchiveAndRecovers(t *testing.T) {
	t.Parallel()
	for _, fault := range []string{"malformed-head", "missing-blocks", "corrupt-blocks", "checkpoint-pointer", "checkpoint-root", "checkpoint-blocks"} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir()
			checkpointed := strings.HasPrefix(fault, "checkpoint-")
			run := func(phase string) {
				t.Helper()
				ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNoPVCAccountAndSigningKeyRecovery$")
				// This test owns a filesystem fixture, even when an outer E2E selected S3/GCS.
				cmd.Env = append(os.Environ(), "GOAUTHY_RECOVERY_TEST_ROOT="+root,
					"GOAUTHY_RECOVERY_TEST_PHASE="+phase, "GOAUTHY_RECOVERY_S3_ENDPOINT=", "GOAUTHY_RECOVERY_GCS_BUCKET=")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s failed: %v\n%s", phase, err, out)
				}
			}
			if checkpointed {
				run("write-checkpoint")
			} else {
				run("write")
			}
			var heads, checkpoints []string
			err := filepath.WalkDir(filepath.Join(root, "objects"), func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !entry.IsDir() && entry.Name() == "CURRENT" {
					checkpoints = append(checkpoints, path)
				}
				if !entry.IsDir() && entry.Name() == "head.bin" {
					heads = append(heads, path)
				}
				return nil
			})
			if err != nil || len(heads) != 1 {
				t.Fatalf("expected one archive head: count=%d error=%v", len(heads), err)
			}
			target := heads[0]
			if checkpointed {
				if len(checkpoints) != 1 {
					t.Fatal("expected one certified checkpoint pointer")
				}
				target = checkpoints[0]
			} else if len(checkpoints) != 0 {
				t.Fatal("unexpected checkpoint: test requires archive-only recovery")
			}
			var pointerOriginal []byte
			if fault == "checkpoint-root" || fault == "checkpoint-blocks" {
				pointerOriginal, err = os.ReadFile(checkpoints[0])
				if err != nil {
					t.Fatal(err)
				}
				var pointer struct {
					Index    uint64 `json:"index"`
					RootHash string `json:"root_hash"`
				}
				if err := json.Unmarshal(pointerOriginal, &pointer); err != nil {
					t.Fatal(err)
				}
				hash, err := hex.DecodeString(pointer.RootHash)
				if err != nil || len(hash) != 32 || pointer.Index == 0 {
					t.Fatal("invalid original checkpoint pointer", err)
				}
				target = filepath.Join(filepath.Dir(checkpoints[0]), "roots", fmt.Sprintf("%020d_%x.json", pointer.Index, hash))
			}
			original, err := os.ReadFile(target)
			if err != nil || len(original) == 0 {
				t.Fatal("archive head missing or empty", err)
			}
			if fault == "missing-blocks" || fault == "corrupt-blocks" || fault == "checkpoint-blocks" {
				blocks := filepath.Join(filepath.Dir(heads[0]), "blocks")
				if fault == "checkpoint-blocks" {
					blocks = filepath.Join(filepath.Dir(checkpoints[0]), "blocks")
				}
				entries, err := os.ReadDir(blocks)
				if err != nil || len(entries) == 0 {
					t.Fatal("archive blocks missing before fault injection", err)
				}
				saved := filepath.Join(root, "saved-blocks")
				if err := os.Rename(blocks, saved); err != nil {
					t.Fatal(err)
				}
				if fault != "missing-blocks" {
					if err := os.Mkdir(blocks, 0700); err != nil {
						t.Fatal(err)
					}
					for _, entry := range entries {
						if !entry.Type().IsRegular() {
							t.Fatal("unexpected archive block entry type")
						}
						corrupt, err := os.ReadFile(filepath.Join(saved, entry.Name()))
						if err != nil || len(corrupt) == 0 {
							t.Fatal("empty or unreadable original block", err)
						}
						corrupt[0] ^= 1 // Preserve size so only content/hash validation can reject it.
						if err := os.WriteFile(filepath.Join(blocks, entry.Name()), corrupt, 0600); err != nil {
							t.Fatal(err)
						}
					}
					if fault == "checkpoint-blocks" {
						run("reject-checkpoint-blocks")
					} else {
						run("reject-corrupt-blocks")
					}
					for _, entry := range entries {
						path := filepath.Join(blocks, entry.Name())
						expected, err := os.ReadFile(filepath.Join(saved, entry.Name()))
						if err != nil || len(expected) == 0 {
							t.Fatal("saved block unavailable", err)
						}
						expected[0] ^= 1
						if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, expected) {
							t.Fatal("failed recovery modified a corrupt block", err)
						}
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.Remove(blocks); err != nil {
						t.Fatal("failed recovery added unexpected archive blocks", err)
					}
				} else {
					run("reject-missing-blocks")
					if _, err := os.Stat(blocks); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("failed recovery recreated missing archive blocks", err)
					}
				}
				if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, original) {
					t.Fatal("failed recovery modified the intact archive head", err)
				}
				if err := os.Rename(saved, blocks); err != nil {
					t.Fatal(err)
				}
			} else {
				corrupt := []byte("deliberately invalid archive head")
				rejectPhase := "reject-corrupt"
				if fault == "checkpoint-pointer" {
					corrupt = []byte(`{"index":1,"root_hash":"broken"}`)
					rejectPhase = "reject-checkpoint"
				} else if fault == "checkpoint-root" {
					corrupt = []byte(`{"corrupt":"checkpoint root"}`)
					rejectPhase = "reject-checkpoint-root"
				}
				if err := os.WriteFile(target, corrupt, 0600); err != nil {
					t.Fatal(err)
				}
				run(rejectPhase)
				if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, corrupt) {
					t.Fatal("failed recovery modified the corrupt object", err)
				}
				if fault == "checkpoint-root" {
					if got, err := os.ReadFile(checkpoints[0]); err != nil || !bytes.Equal(got, pointerOriginal) {
						t.Fatal("failed recovery changed original checkpoint pointer", err)
					}
				}
				if err := os.WriteFile(target, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if pointerOriginal != nil {
				if got, err := os.ReadFile(checkpoints[0]); err != nil || !bytes.Equal(got, pointerOriginal) {
					t.Fatal("checkpoint pointer changed during failed recovery", err)
				}
			}
			run("recover")
		})
	}
}

// seedNoPVCv98v102 inserts v98-v102 non-default fixture data for recovery testing.
func seedNoPVCv98v102(t *testing.T, ctx context.Context, db *rhiza.DB) {
	t.Helper()
	batch := []rhiza.SQLStatement{
		{SQL: "INSERT INTO scim_client_config(client_id,endpoint,enabled,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)",
			Args: []any{"nrc-scim", "https://scim.test", int64(1), int64(1000), int64(1000)}},
		{SQL: "INSERT INTO managed_oauth_clients(id,generation,revision,enabled,metadata_json) VALUES(?,?,?,?,?)",
			Args: []any{"nrc-mc", "g1", int64(1), int64(1), "{}"}},
		{SQL: "UPDATE managed_oauth_clients SET force_mfa=1 WHERE id='nrc-mc'"},
		{SQL: "INSERT INTO system_lockdown(id,enabled,reason,until_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(1,0,'recovery-test',9999,1000,1000)"},
		{SQL: "INSERT INTO identity_email_otp(code_digest,subject,expires_at_unix_ms) VALUES(?,?,?)",
			Args: []any{"nrc-otp-digest", "user@example.com", int64(5000)}},
		{SQL: "INSERT INTO identity_email_otp_rate_limits(subject_digest,window_start_unix_seconds,count) VALUES(?,?,?)",
			Args: []any{"nrc-rate-subj", int64(100), int64(5)}},
		{SQL: "INSERT INTO event_log(id,timestamp,level,typ,text) VALUES(?,?,?,?,?)",
			Args: []any{strings.Repeat("C", 43), int64(2000), int64(0), "Test", "nrc-seed"}},
		{SQL: "UPDATE event_log SET prev_hash='prev-nrc',integrity_hash='int-nrc' WHERE id=?",
			Args: []any{strings.Repeat("C", 43)}},
	}
	for i, s := range batch {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("no-pvc-schema-seed-%d", i), SQL: s.SQL, Args: s.Args}); err != nil {
			t.Fatal("v98-v102 seed:", err)
		}
	}
}

// assertNoPVCv98v102 verifies v98-v102 non-default fixture data survived recovery.
func assertNoPVCv98v102(t *testing.T, ctx context.Context, db *rhiza.DB) {
	t.Helper()
	type check struct {
		sql  string
		args []any
		desc string
		want func(rhiza.QueryResponse) error
	}
	checks := []check{
		{"SELECT client_id,enabled,endpoint FROM scim_client_config WHERE client_id='nrc-scim'", nil, "scim",
			func(r rhiza.QueryResponse) error {
				if len(r.Rows) != 1 || r.Rows[0][0] != "nrc-scim" || r.Rows[0][1] != int64(1) || r.Rows[0][2] != "https://scim.test" {
					return fmt.Errorf("scim enabled/endpoint: %v", r.Rows)
				}
				return nil
			}},
		{"SELECT force_mfa FROM managed_oauth_clients WHERE id='nrc-mc'", nil, "force_mfa",
			func(r rhiza.QueryResponse) error {
				if len(r.Rows) != 1 || r.Rows[0][0] != int64(1) {
					return fmt.Errorf("force_mfa: %v", r.Rows)
				}
				return nil
			}},
		{"SELECT enabled,reason,until_unix_ms FROM system_lockdown WHERE id=1", nil, "lockdown",
			func(r rhiza.QueryResponse) error {
				if len(r.Rows) != 1 || r.Rows[0][0] != int64(0) || r.Rows[0][1] != "recovery-test" || r.Rows[0][2] != int64(9999) {
					return fmt.Errorf("lockdown enabled/reason/until: %v", r.Rows)
				}
				return nil
			}},
		{"SELECT subject,expires_at_unix_ms FROM identity_email_otp WHERE code_digest='nrc-otp-digest'", nil, "otp",
			func(r rhiza.QueryResponse) error {
				if len(r.Rows) != 1 || r.Rows[0][0] != "user@example.com" || r.Rows[0][1] != int64(5000) {
					return fmt.Errorf("otp: %v", r.Rows)
				}
				return nil
			}},
		{"SELECT count FROM identity_email_otp_rate_limits WHERE subject_digest='nrc-rate-subj'", nil, "rate",
			func(r rhiza.QueryResponse) error {
				if len(r.Rows) != 1 || r.Rows[0][0] != int64(5) {
					return fmt.Errorf("rate: %v", r.Rows)
				}
				return nil
			}},
		{"SELECT prev_hash,integrity_hash FROM event_log WHERE id=?", []any{strings.Repeat("C", 43)}, "event_hash",
			func(r rhiza.QueryResponse) error {
				if len(r.Rows) != 1 || r.Rows[0][0] != "prev-nrc" || r.Rows[0][1] != "int-nrc" {
					return fmt.Errorf("event_hash: %v", r.Rows)
				}
				return nil
			}},
	}
	for _, c := range checks {
		r, err := db.Query(ctx, rhiza.QueryRequest{SQL: c.sql, Args: c.args, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			t.Fatal(c.desc, err)
		}
		if err := c.want(r); err != nil {
			t.Fatal(c.desc, err)
		}
	}
}

func TestNoPVCAccountAndSigningKeyRecovery(t *testing.T) {
	t.Parallel()
	root := os.Getenv("GOAUTHY_RECOVERY_TEST_ROOT")
	if root == "" {
		root = t.TempDir()
		for _, phase := range []string{"write", "recover"} {
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNoPVCAccountAndSigningKeyRecovery$")
			cmd.Env = append(os.Environ(), "GOAUTHY_RECOVERY_TEST_ROOT="+root, "GOAUTHY_RECOVERY_TEST_PHASE="+phase)
			out, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("%s failed: %v\n%s", phase, err, out)
			}
		}
		return
	}
	phase := os.Getenv("GOAUTHY_RECOVERY_TEST_PHASE")
	writing := phase == "write" || phase == "write-checkpoint"
	ctx := t.Context()
	dataDir := os.Getenv("GOAUTHY_RECOVERY_DATA_DIR")
	if dataDir == "" {
		dataDir = filepath.Join(root, phase)
	}
	env := map[string]string{
		"GOAUTHY_RHIZA_PROFILE": "standalone", "GOAUTHY_CLUSTER_ID": "ternal-auth-test",
		"GOAUTHY_NODE_ID": "auth-0", "GOAUTHY_DATA_DIR": dataDir,
		"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET": "test", "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX": "ternal-auth",
	}
	cfg, err := storage.RhizaConfigFromEnv(func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	cfg.ObjStoreProvider, cfg.ObjStoreDir = "filesystem", filepath.Join(root, "objects")
	if endpoint := os.Getenv("GOAUTHY_RECOVERY_S3_ENDPOINT"); endpoint != "" {
		cfg.ObjStoreProvider, cfg.ObjStoreDir = "s3", ""
		cfg.ObjStoreEndpoint = endpoint
		cfg.ObjStoreBucket = os.Getenv("GOAUTHY_RECOVERY_S3_BUCKET")
		cfg.ObjStoreRegion = "us-east-1"
		cfg.ObjStoreAccessKey = os.Getenv("GOAUTHY_RECOVERY_S3_ACCESS_KEY")
		cfg.ObjStoreSecretKey = os.Getenv("GOAUTHY_RECOVERY_S3_SECRET_KEY")
		cfg.ObjStoreInsecure = true // Loopback-only disposable MinIO test fixture.
	}
	if bucket := os.Getenv("GOAUTHY_RECOVERY_GCS_BUCKET"); bucket != "" {
		if os.Getenv("GOAUTHY_RECOVERY_S3_ENDPOINT") != "" {
			t.Fatal("select exactly one recovery backend")
		}
		cfg.ObjStoreProvider, cfg.ObjStoreDir = "gcs", ""
		cfg.ObjStoreBucket = bucket
		cfg.ObjStorePrefix = os.Getenv("GOAUTHY_RECOVERY_GCS_PREFIX")
		if cfg.ObjStorePrefix == "" {
			t.Fatal("a dedicated GCS test prefix is required")
		}
	}
	cfg.CheckpointInterval = time.Hour
	db, err := rhiza.Open(ctx, cfg)
	if phase == "reject-checkpoint" || phase == "reject-checkpoint-root" || phase == "reject-checkpoint-blocks" {
		if err == nil {
			db.Close()
			t.Fatal("invalid checkpoint accepted on a fresh local data directory")
		}
		expected := "load checkpoint manifest: invalid CURRENT:"
		if phase == "reject-checkpoint-root" {
			expected = "load checkpoint manifest: checkpoint root integrity mismatch"
		} else if phase == "reject-checkpoint-blocks" {
			expected = "restore checkpoint recovery base: checkpoint block integrity mismatch"
		}
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("unexpected checkpoint recovery failure: %v", err)
		}
		return
	}
	if phase == "reject-corrupt" || phase == "reject-missing-blocks" || phase == "reject-corrupt-blocks" {
		if err == nil {
			db.Close()
			t.Fatal("corrupt archive accepted on a fresh local data directory")
		}
		if !strings.Contains(err.Error(), "load shared decision archive:") {
			t.Fatalf("failure did not originate in archive recovery: %v", err)
		}
		if phase == "reject-missing-blocks" && !errors.Is(err, os.ErrNotExist) ||
			phase == "reject-corrupt" && !strings.Contains(err.Error(), "invalid archive head header") ||
			phase == "reject-corrupt-blocks" && !strings.Contains(err.Error(), "archive extent integrity mismatch") {
			t.Fatalf("unexpected recovery failure: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if phase == "recover" {
		defer db.Close()
	}
	keyDir := filepath.Join(root, "keys")
	if writing {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			t.Fatal(err)
		}
		// Disposable test fixture, never a deployment master key.
		if err := os.WriteFile(filepath.Join(keyDir, "test-key"), []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))), 0600); err != nil {
			t.Fatal(err)
		}
		if err := storage.Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
		seedNoPVCv98v102(t, ctx, db)
	}
	keyring, err := oidc.LoadKeyring(keyDir, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyNoPVCGeneratedAPIKey(ctx, db, keyring, root, dataDir, writing); err != nil {
		t.Fatal(err)
	}
	users, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://ternal-auth.example.test"
	if writing {
		phc, err := credential.Hash([]byte("Disposable recovery test password 7!"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := users.BootstrapUser(ctx, "test-user", "test@example.test", phc); err != nil {
			t.Fatal(err)
		}
		key, err := oidc.EnsureSigningKey(ctx, db, keyring, issuer, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "public-kid"), []byte(key.PublicJWK.KeyID), 0600); err != nil {
			t.Fatal(err)
		}
		verifyNoPVCPasswordRefresh(t, db, users, keyring, root, issuer, true)
		if _, err := users.AuthenticatePasswordGrant(ctx, "test@example.test", []byte("wrong"), nil); !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Fatal("failure fixture authentication", err)
		}
		if phase == "write-checkpoint" {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			return
		}
		os.Exit(0) // Intentionally skip Close and all defers, like losing the pod.
	}
	assertNoPVCv98v102(t, ctx, db)
	failure, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT failed_login_attempts,last_failed_login_at_unix_ms FROM identity_users WHERE subject='test-user'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(failure.Rows) != 1 || failure.Rows[0][0] != int64(1) {
		t.Fatalf("recovered failure count: %+v %v", failure, err)
	}
	if stamp, ok := failure.Rows[0][1].(int64); !ok || stamp <= 0 {
		t.Fatal("recovered failure timestamp missing")
	}
	user, err := users.Authenticate(ctx, "test@example.test", []byte("Disposable recovery test password 7!"))
	if err != nil || user.Subject != "test-user" {
		t.Fatal("recovered account authentication failed", err)
	}
	if _, err := users.Authenticate(ctx, "test@example.test", []byte("wrong")); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatal("wrong password not rejected", err)
	}
	key, err := oidc.LoadActiveSigningKey(ctx, db, keyring, issuer)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(root, "public-kid"))
	if err != nil || key.PublicJWK.KeyID != string(want) {
		t.Fatal("signing key changed after losing local storage", err)
	}
	verifyNoPVCPasswordRefresh(t, db, users, keyring, root, issuer, false)
	if _, err := oidc.LoadKeyring(filepath.Join(root, "absent-keys"), "test-key"); err == nil {
		t.Fatal("missing external master keys accepted")
	}
	wrongDir := filepath.Join(root, "wrong-keys")
	if err := os.MkdirAll(wrongDir, 0700); err != nil {
		t.Fatal(err)
	}
	wrong := make([]byte, 32)
	wrong[0] = 1
	if err := os.WriteFile(filepath.Join(wrongDir, "test-key"), []byte(base64.RawURLEncoding.EncodeToString(wrong)), 0600); err != nil {
		t.Fatal(err)
	}
	wrongRing, err := oidc.LoadKeyring(wrongDir, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oidc.EnsureSigningKey(ctx, db, wrongRing, issuer, time.Now()); err == nil {
		t.Fatal("wrong master key accepted or signing key silently regenerated")
	}
}
