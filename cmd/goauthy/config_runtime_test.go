package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func applicationConfigTestEnv(t *testing.T, overrides map[string]string) func(string) string {
	t.Helper()
	values := map[string]string{
		"GOAUTHY_RHIZA_PROFILE": "dev",
		"GOAUTHY_CLUSTER_ID":    "test-cluster",
		"GOAUTHY_NODE_ID":       "test-node",
		"GOAUTHY_DATA_DIR":      filepath.Join(t.TempDir(), "data"),
	}
	for name, value := range overrides {
		values[name] = value
	}
	return func(name string) string { return values[name] }
}

func TestRunConfigCommandCheckValidatesWithoutStartingRuntime(t *testing.T) {
	var out bytes.Buffer
	if err := runConfigCommand([]string{"check"}, applicationConfigTestEnv(t, nil), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "configuration valid\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestRunConfigCommandRejectsInvalidRuntimeConfig(t *testing.T) {
	var out bytes.Buffer
	err := runConfigCommand([]string{"check"}, applicationConfigTestEnv(t, map[string]string{
		"GOAUTHY_RHIZA_PROFILE": "invalid",
	}), &out)
	if err == nil || !strings.Contains(err.Error(), "GOAUTHY_RHIZA_PROFILE") {
		t.Fatalf("error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("unexpected output = %q", out.String())
	}
}

func TestRunConfigCommandDumpEffectiveRedactsStorageCredentials(t *testing.T) {
	getenv := applicationConfigTestEnv(t, map[string]string{
		"GOAUTHY_RHIZA_PROFILE":                 "standalone",
		"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET":     "test-bucket",
		"GOAUTHY_RHIZA_OBJECT_STORE_PREFIX":     "goauthy/test",
		"GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY": "access-secret",
		"GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY": "storage-secret",
	})
	var out bytes.Buffer
	if err := runConfigCommand([]string{"dump-effective"}, getenv, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "access-secret") || strings.Contains(out.String(), "storage-secret") {
		t.Fatalf("effective configuration exposed storage credentials: %s", out.String())
	}
	var decoded effectiveConfig
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Storage.Profile != "standalone" || decoded.Storage.ObjectStoreBucket != "test-bucket" || !decoded.Storage.StaticCredentials {
		t.Fatalf("unexpected storage summary: %+v", decoded.Storage)
	}
}

func TestRunConfigCommandRejectsUnknownAction(t *testing.T) {
	var out bytes.Buffer
	if err := runConfigCommand([]string{"unknown"}, applicationConfigTestEnv(t, nil), &out); err == nil {
		t.Fatal("unknown config action accepted")
	}
}
