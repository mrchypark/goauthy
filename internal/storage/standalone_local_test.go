package storage

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
	"github.com/mrchypark/rhiza/pkg/recovery"
)

func standaloneLocalTestEnv(dataDir string) map[string]string {
	return map[string]string{
		"GOAUTHY_RHIZA_PROFILE":                 "standalone-local",
		"GOAUTHY_CLUSTER_ID":                    "local-app-recovery",
		"GOAUTHY_NODE_ID":                       "local-node",
		"GOAUTHY_DATA_DIR":                      dataDir,
		"GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE":    "true",
		"GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER":   "s3",
		"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET":     "local-test",
		"GOAUTHY_RHIZA_OBJECT_STORE_PREFIX":     "app",
		"GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT":   "127.0.0.1:9000",
		"GOAUTHY_RHIZA_OBJECT_STORE_INSECURE":   "true",
		"GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY": "test",
		"GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY": "test",
	}
}

func TestStandaloneLocalConfigurationBoundaries(t *testing.T) {
	env := standaloneLocalTestEnv(t.TempDir())
	config, err := RhizaConfigFromEnv(envMap(env))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Local || len(config.Members) != 0 || config.PeerAddr != "" || config.PeerToken != "" || config.AdminToken != "" || config.ObjStoreDurability != rhiza.ObjectStoreDurabilityBeforeAck {
		t.Fatalf("invalid embedded Local profile: %+v", config)
	}
	if config.ObjStoreGCInterval != time.Hour || config.ObjStoreGCGracePeriod != 24*time.Hour || config.CheckpointRetainCount != 3 {
		t.Fatal("Local profile did not retain its documented native GC defaults")
	}
	gcs := copyEnv(env)
	gcs["GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER"] = "gcs"
	for _, name := range []string{"GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT", "GOAUTHY_RHIZA_OBJECT_STORE_INSECURE", "GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY", "GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY"} {
		delete(gcs, name)
	}
	if configured, err := RhizaConfigFromEnv(envMap(gcs)); err != nil || !configured.Local || configured.ObjStoreProvider != "gcs" || configured.ObjStoreDurability != rhiza.ObjectStoreDurabilityBeforeAck {
		t.Fatalf("GCS Local configuration=%+v err=%v", configured, err)
	}
	for name, value := range map[string]string{
		"GOAUTHY_RHIZA_CHECKPOINT_INTERVAL":     "1s",
		"GOAUTHY_RHIZA_PEER_ADDR":               ":8444",
		"GOAUTHY_RHIZA_MEMBERS":                 "[]",
		"GOAUTHY_RHIZA_ADMIN_TOKEN":             "test-admin",
		"GOAUTHY_RHIZA_OBJECT_STORE_DURABILITY": "async",
	} {
		t.Run(name, func(t *testing.T) {
			invalid := copyEnv(env)
			invalid[name] = value
			if _, err := RhizaConfigFromEnv(envMap(invalid)); err == nil {
				t.Fatalf("accepted unsupported Local setting %s", name)
			}
		})
	}
	for _, name := range []string{"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET", "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX"} {
		invalid := copyEnv(env)
		delete(invalid, name)
		if _, err := RhizaConfigFromEnv(envMap(invalid)); err == nil {
			t.Fatalf("accepted incomplete Local object storage without %s", name)
		}
	}
	for _, interval := range []string{"15m", "1h"} {
		invalid := copyEnv(env)
		invalid["GOAUTHY_RHIZA_CHECKPOINT_INTERVAL"] = interval
		if _, err := RhizaConfigFromEnv(envMap(invalid)); err == nil {
			t.Fatalf("accepted Local checkpoint override %q", interval)
		}
	}
	cluster, err := RhizaConfigFromEnv(envMap(clusterEnv()))
	if err != nil || cluster.Local {
		t.Fatalf("existing cluster changed Local mode: Local=%v err=%v", cluster.Local, err)
	}
	for _, profile := range []string{RhizaProfileStandalone, RhizaProfileDev} {
		original, err := RhizaConfigFromEnv(envMap(map[string]string{
			"GOAUTHY_RHIZA_PROFILE": profile, "GOAUTHY_CLUSTER_ID": "existing", "GOAUTHY_NODE_ID": "node", "GOAUTHY_DATA_DIR": t.TempDir(),
		}))
		if err != nil || original.Local {
			t.Fatalf("existing profile %s changed Local mode: Local=%v err=%v", profile, original.Local, err)
		}
	}
}

// Exercise the real application migrations with archiving enabled from the first
// Open. The writer exits without Close before its entire DataDir is removed.
func TestStandaloneLocalArchiveApplicationRecovery(t *testing.T) {
	root := os.Getenv("GOAUTHY_STANDALONE_LOCAL_TEST_ROOT")
	if root == "" {
		var err error
		root, err = filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"write", "recover"} {
			if phase == "recover" {
				if err := os.RemoveAll(filepath.Join(root, "data")); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(root, "data")); !os.IsNotExist(err) {
					t.Fatalf("local directory loss was incomplete: %v", err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStandaloneLocalArchiveApplicationRecovery$", "-test.v")
			cmd.Env = append(os.Environ(), "GOAUTHY_STANDALONE_LOCAL_TEST_ROOT="+root, "GOAUTHY_STANDALONE_LOCAL_TEST_PHASE="+phase)
			out, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("%s failed: %v\n%s", phase, err, out)
			}
		}
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	config, err := RhizaConfigFromEnv(envMap(standaloneLocalTestEnv(filepath.Join(root, "data"))))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Local {
		t.Fatal("standalone-local did not select embedded Local mode")
	}
	// Substitute only the external provider with isolated filesystem objects.
	config.ObjStoreProvider, config.ObjStoreDir = rhiza.ObjectStoreProviderFilesystem, filepath.Join(root, "objects")
	config.ObjStoreEndpoint, config.ObjStoreAccessKey, config.ObjStoreSecretKey, config.ObjStoreRegion = "", "", "", ""
	config.ObjStoreInsecure = false
	phase := os.Getenv("GOAUTHY_STANDALONE_LOCAL_TEST_PHASE")
	if phase != "write" && phase != "recover" {
		t.Fatalf("invalid subprocess phase %q", phase)
	}
	if _, err := os.Stat(config.DataDir); !os.IsNotExist(err) {
		t.Fatalf("expected fresh init DataDir: %v", err)
	}
	initDB, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := initDB.Close(); err != nil {
		t.Fatal(err)
	}
	readBinding := func() recovery.LocalBinding {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(config.DataDir, "local-backup.json"))
		if err != nil {
			t.Fatal(err)
		}
		var binding recovery.LocalBinding
		if err := json.Unmarshal(data, &binding); err != nil {
			t.Fatal(err)
		}
		return binding
	}
	initializedBinding := readBinding()
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close recovery verifier: %v", err)
		}
	})
	for !db.Ready() {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !reflect.DeepEqual(initializedBinding, readBinding()) {
		t.Fatal("main Open changed the identity established by init")
	}
	verifySchema := func() {
		t.Helper()
		rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT MAX(version) FROM goauthy_schema_migrations", Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(schemaVersion) {
			t.Fatalf("recovered schema=%v err=%v; want version %d", rows.Rows, err, schemaVersion)
		}
	}
	if phase == "recover" {
		verifySchema() // Do not let migration recreate missing recovered schema.
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("archive-enabled application migration: %v", err)
	}
	verifySchema()
	request := rhiza.ExecuteRequest{RequestID: "ack-before-loss", SQL: "INSERT INTO local_application_proof VALUES (1, 'remote-before-ack')"}
	if phase == "write" {
		if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "local-proof-schema", SQL: "CREATE TABLE local_application_proof (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)"}); err != nil {
			t.Fatal(err)
		}
		response, err := Execute(ctx, db, request)
		if err != nil || response.Status != rhiza.MutationCommitted || response.RowsAffected != 1 {
			t.Fatalf("original receipt=%+v err=%v", response.MutationReceipt, err)
		}
		data, err := json.Marshal(response.MutationReceipt)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "ack.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		os.Exit(0) // Simulate process loss without graceful archive publication.
	}
	verifyRow := func() {
		t.Helper()
		rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT id, payload FROM local_application_proof", Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) || rows.Rows[0][1] != "remote-before-ack" {
			t.Fatalf("recovered rows=%v err=%v", rows.Rows, err)
		}
	}
	verifyRow()
	data, err := os.ReadFile(filepath.Join(root, "ack.json"))
	if err != nil {
		t.Fatal(err)
	}
	var original rhiza.MutationReceipt
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatal(err)
	}
	replayed, err := Execute(ctx, db, request)
	if err != nil || replayed.MutationReceipt != original {
		t.Fatalf("replayed=%+v original=%+v err=%v", replayed.MutationReceipt, original, err)
	}
	verifyRow()
}
