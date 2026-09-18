package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/mrchypark/rhiza"
)

func TestCreateArgumentsFailBeforeConfiguration(t *testing.T) {
	for _, args := range [][]string{
		{"create"},
		{"create", "-recipient-file", "recipients", "-signing-key-file", "signing", "-catalog-prefix", "catalog", "-work-dir", "work", "-max-files", "0"},
	} {
		if err := run(context.Background(), args, func(string) string {
			t.Fatal("read configuration for invalid create arguments")
			return ""
		}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestCreateRecipientFileFailsBeforeConfiguration(t *testing.T) {
	root := t.TempDir()
	recipients := filepath.Join(root, "recipients")
	if err := os.WriteFile(recipients, []byte("not-a-recipient\n"), 0644); err != nil {
		t.Fatal(err)
	}
	args := []string{"create", "-recipient-file", recipients, "-signing-key-file", filepath.Join(root, "signing"), "-catalog-prefix", "catalog", "-work-dir", root}
	if err := run(context.Background(), args, func(string) string {
		t.Fatal("read configuration for invalid create key files")
		return ""
	}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted malformed recipient file")
	}
}

func TestCreateSigningKeyFailsBeforeConfiguration(t *testing.T) {
	root := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipients := filepath.Join(root, "recipients")
	signing := filepath.Join(root, "signing")
	if err := os.WriteFile(recipients, []byte(identity.Recipient().String()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signing, []byte("not-a-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"create", "-recipient-file", recipients, "-signing-key-file", signing, "-catalog-prefix", "catalog", "-work-dir", root}
	if err := run(context.Background(), args, func(string) string {
		t.Fatal("read configuration for invalid create signing key")
		return ""
	}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted malformed signing key")
	}
}

func TestBackupDestinationConfigDoesNotInheritSourceCredentials(t *testing.T) {
	source := rhiza.Config{ObjStoreBucket: "source", ObjStoreAccessKey: "source-access", ObjStoreSecretKey: "source-secret"}
	env := map[string]string{
		"GOAUTHY_RHIZA_PROFILE":                  "standalone",
		"GOAUTHY_CLUSTER_ID":                     "test",
		"GOAUTHY_NODE_ID":                        "node",
		"GOAUTHY_DATA_DIR":                       "/private/test",
		"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET":      "source",
		"GOAUTHY_RHIZA_OBJECT_STORE_PREFIX":      "source-prefix",
		"GOAUTHY_BACKUP_OBJECT_STORE_BUCKET":     "destination",
		"GOAUTHY_BACKUP_OBJECT_STORE_ACCESS_KEY": "",
		"GOAUTHY_BACKUP_OBJECT_STORE_SECRET_KEY": "",
	}
	getenv := func(name string) string { return env[name] }
	destination, separate, err := backupDestinationConfig(getenv, source)
	if err != nil {
		t.Fatal(err)
	}
	if !separate || destination.ObjStoreBucket != "destination" || destination.ObjStoreAccessKey != "" || destination.ObjStoreSecretKey != "" {
		t.Fatalf("destination reused source settings: %+v separate=%v", destination, separate)
	}
}

func TestBackupDestinationConfigRejectsNamespaceOverride(t *testing.T) {
	_, _, err := backupDestinationConfig(func(name string) string {
		if name == "GOAUTHY_BACKUP_OBJECT_STORE_PREFIX" {
			return "wrong"
		}
		return ""
	}, rhiza.Config{})
	if err == nil {
		t.Fatal("accepted destination prefix override")
	}
}
