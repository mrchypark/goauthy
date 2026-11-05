package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
)

func TestStandaloneLocalBackupCommandsRejectBeforeObjectAccess(t *testing.T) {
	root := t.TempDir()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identityFile, recipientFile, signingFile := filepath.Join(root, "identity"), filepath.Join(root, "recipient"), filepath.Join(root, "signing")
	if err := os.WriteFile(identityFile, []byte(identity.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recipientFile, []byte(identity.Recipient().String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signingFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	trustFile := filepath.Join(root, "trust")
	if err := os.WriteFile(trustFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"GOAUTHY_RHIZA_PROFILE": "standalone-local", "GOAUTHY_CLUSTER_ID": "unsupported-backup", "GOAUTHY_NODE_ID": "local", "GOAUTHY_DATA_DIR": filepath.Join(root, "data"),
		"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET": "test", "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX": "test-prefix", "GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER": "s3",
		"GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT": strings.TrimPrefix(server.URL, "http://"), "GOAUTHY_RHIZA_OBJECT_STORE_INSECURE": "true",
		"GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY": "test", "GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY": "test",
	}
	artifact := filepath.Join(root, "artifact.age")
	for _, args := range [][]string{
		{"export", "-file", artifact, "-key-file", recipientFile, "-work-dir", root, "-timeout", "1s"},
		{"restore", "-file", artifact, "-key-file", identityFile, "-work-dir", root, "-sha256", strings.Repeat("0", 64), "-timeout", "1s"},
		{"create", "-recipient-file", recipientFile, "-signing-key-file", signingFile, "-catalog-prefix", "catalog", "-work-dir", root, "-timeout", "1s"},
		{"publish", "-catalog-prefix", "catalog", "-key-file", signingFile, "-file", artifact, "-timeout", "1s"},
		{"list", "-catalog-prefix", "catalog", "-key-file", trustFile, "-timeout", "1s"},
		{"fetch", "-catalog-prefix", "catalog", "-key-file", trustFile, "-file", artifact, "-id", "requested-artifact", "-work-dir", root, "-timeout", "1s"},
		{"prune", "-catalog-prefix", "catalog", "-key-file", trustFile, "-apply", "-timeout", "1s"},
	} {
		t.Run(args[0], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var output bytes.Buffer
			err := run(ctx, args, func(name string) string { return env[name] }, &output)
			if err == nil || !strings.Contains(err.Error(), "Local archive") || output.Len() != 0 {
				t.Fatalf("output=%q err=%v", output.String(), err)
			}
			if requests.Load() != 0 {
				t.Fatal("unsupported Local backup touched object storage")
			}
		})
	}
	for _, name := range []string{artifact, env["GOAUTHY_DATA_DIR"]} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("unsupported backup created %s: %v", name, err)
		}
	}
}
