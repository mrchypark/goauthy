package storage_test

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestNoPVCLoginRevokeRecovery(t *testing.T) {
	const s3OptIn = "GOAUTHY_LOGIN_REVOKE_RECOVERY_S3"
	root := os.Getenv("GOAUTHY_LOGIN_REVOKE_RECOVERY_ROOT")
	if root == "" {
		root = t.TempDir()
		useS3 := os.Getenv(s3OptIn) == "1"
		if useS3 {
			for _, name := range []string{"GOAUTHY_RECOVERY_S3_ENDPOINT", "GOAUTHY_RECOVERY_S3_BUCKET", "GOAUTHY_RECOVERY_S3_ACCESS_KEY", "GOAUTHY_RECOVERY_S3_SECRET_KEY"} {
				if os.Getenv(name) == "" {
					t.Fatalf("S3 opt-in requires %s; runnable command: %s=1 GOAUTHY_RECOVERY_S3_ENDPOINT=127.0.0.1:<port> GOAUTHY_RECOVERY_S3_BUCKET=<bucket> GOAUTHY_RECOVERY_S3_ACCESS_KEY=<access-key> GOAUTHY_RECOVERY_S3_SECRET_KEY=<secret-key> go test -race ./internal/storage -run '^TestNoPVCLoginRevokeRecovery$' -count=1 -timeout=3m", name, s3OptIn)
				}
			}
		}
		run := func(dataDir, phase string) {
			t.Helper()
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNoPVCLoginRevokeRecovery$")
			cmd.Env = append(os.Environ(),
				"GOAUTHY_LOGIN_REVOKE_RECOVERY_ROOT="+root,
				"GOAUTHY_LOGIN_REVOKE_RECOVERY_DATA_DIR="+dataDir,
				"GOAUTHY_LOGIN_REVOKE_RECOVERY_PHASE="+phase,
			)
			if !useS3 {
				cmd.Env = append(cmd.Env, "GOAUTHY_RECOVERY_S3_ENDPOINT=", "GOAUTHY_RECOVERY_S3_BUCKET=", "GOAUTHY_RECOVERY_S3_ACCESS_KEY=", "GOAUTHY_RECOVERY_S3_SECRET_KEY=")
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s failed: %v\n%s", phase, err, out)
			}
		}
		run(filepath.Join(root, "writer"), "write")
		if _, err := os.Stat(filepath.Join(root, "login-revoke-code")); err != nil {
			t.Fatal("writer did not persist the recovery fixture", err)
		}
		run(filepath.Join(root, "fresh"), "recover")
		return
	}

	phase := os.Getenv("GOAUTHY_LOGIN_REVOKE_RECOVERY_PHASE")
	if phase != "write" && phase != "recover" {
		t.Fatalf("invalid recovery phase %q", phase)
	}
	if os.Getenv(s3OptIn) != "1" {
		for _, name := range []string{"GOAUTHY_RECOVERY_S3_ENDPOINT", "GOAUTHY_RECOVERY_S3_BUCKET", "GOAUTHY_RECOVERY_S3_ACCESS_KEY", "GOAUTHY_RECOVERY_S3_SECRET_KEY"} {
			t.Setenv(name, "")
		}
	}
	dataDir := os.Getenv("GOAUTHY_LOGIN_REVOKE_RECOVERY_DATA_DIR")
	config := noPVCExportConfig(t, root, dataDir, filepath.Join(root, "objects"))
	ctx := t.Context()
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if phase == "recover" {
		defer db.Close()
	}

	const subject = "no-pvc-login-revoke-user"
	keyDir := filepath.Join(root, "keys")
	if phase == "write" {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keyDir, "test-key"), []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))), 0600); err != nil {
			t.Fatal(err)
		}
		if err := storage.Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.Ready(ctx, db); phase == "recover" && err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(keyDir, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	users, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}

	if phase == "write" {
		phc, err := credential.Hash([]byte("Disposable login revoke recovery password 7!"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := users.BootstrapUser(ctx, subject, "no-pvc-login-revoke@example.test", phc); err != nil {
			t.Fatal(err)
		}
		code, err := users.FindOrCreateLoginRevokeCode(ctx, keyring, subject)
		if err != nil {
			t.Fatal(err)
		}
		codeBytes := []byte(code)
		if err := os.WriteFile(filepath.Join(root, "login-revoke-code"), codeBytes, 0600); err != nil {
			clear(codeBytes)
			t.Fatal(err)
		}
		clear(codeBytes)
		for _, location := range []struct {
			browser, ip, agent, place string
		}{
			{"browser-one", "192.0.2.10", "Browser One", "Seoul"},
			{"browser-two", "192.0.2.11", "Browser Two", "Busan"},
		} {
			inserted, err := users.RecordBrowserLoginLocation(ctx, subject, location.browser, location.ip, location.agent, &location.place)
			if err != nil || !inserted {
				t.Fatal("schema 91 login location was not persisted", err)
			}
		}
		os.Exit(0) // Exercise object-store recovery after an abrupt writer exit.
	}

	stored, err := os.ReadFile(filepath.Join(root, "login-revoke-code"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stored)
	recoveredCode, err := users.FindOrCreateLoginRevokeCode(ctx, keyring, subject)
	if err != nil {
		t.Fatal(err)
	}
	if subtle.ConstantTimeCompare([]byte(recoveredCode), stored) != 1 {
		t.Fatal("recovered shared login revoke code changed")
	}

	envelope, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT code_envelope FROM identity_login_revoke WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(envelope.Rows) != 1 || len(envelope.Rows[0]) != 1 {
		t.Fatalf("recovered encrypted login revoke row unavailable: %v", err)
	}
	if value, ok := envelope.Rows[0][0].([]byte); !ok || len(value) == 0 || bytes.Contains(value, stored) {
		t.Fatal("recovered login revoke code was not stored as encrypted data")
	}
	locations, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT ip_address,browser_id,user_agent,location FROM identity_login_locations WHERE subject=? ORDER BY browser_id`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(locations.Rows) != 2 || len(locations.Rows[0]) != 4 || len(locations.Rows[1]) != 4 {
		t.Fatalf("restored schema 91 login locations=%v err=%v", locations.Rows, err)
	}
	wantLocations := [][]any{{"192.0.2.10", "browser-one", "Browser One", "Seoul"}, {"192.0.2.11", "browser-two", "Browser Two", "Busan"}}
	for i := range wantLocations {
		if !sameLoginRevokeLocation(locations.Rows[i], wantLocations[i]) {
			t.Fatal("restored schema 91 login location changed")
		}
	}

	if err := users.RevokeLogin(ctx, keyring, subject, recoveredCode, netip.MustParseAddr("203.0.113.7"), nil); err != nil {
		t.Fatal(err)
	}
	for query, want := range map[string]int64{
		`SELECT COUNT(*) FROM identity_login_revoke WHERE subject=?`:    0,
		`SELECT COUNT(*) FROM identity_login_locations WHERE subject=?`: 0,
	} {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: query, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != want {
			t.Fatalf("post-redeem query=%q rows=%v err=%v", query, result.Rows, err)
		}
	}
	if err := users.RevokeLogin(ctx, keyring, subject, recoveredCode, netip.MustParseAddr("203.0.113.7"), nil); !errors.Is(err, identity.ErrInvalidLoginRevokeCode) {
		t.Fatalf("replayed login revoke code error=%v", err)
	}
}

func sameLoginRevokeLocation(got, want []any) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
