package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mrchypark/rhiza/pkg/checkpoint"
)

func TestCatalogPEMTrustBoundary(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secretDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	secret := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: secretDER})
	trust := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	file := filepath.Join(t.TempDir(), "key.pem")
	for _, test := range []struct {
		name    string
		data    []byte
		mode    os.FileMode
		private bool
		valid   bool
	}{
		{"private", secret, 0600, true, true}, {"public", trust, 0644, false, true},
		{"readable-private", secret, 0644, true, false}, {"private-as-trust", secret, 0600, false, false},
		{"trust-as-private", trust, 0600, true, false}, {"multiple", append(append([]byte(nil), trust...), trust...), 0600, false, false},
		{"malformed", []byte("invalid"), 0600, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(file, test.data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(file, test.mode); err != nil {
				t.Fatal(err)
			}
			_, _, err := readCatalogKey(file, test.private)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
}

func TestBackupFailureMessagesDoNotExposeProviderErrors(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{errors.New("https://user:private-password@example.test/private"), "operation failed"},
		{checkpoint.ErrPublisherBusy, "checkpoint publisher is active"},
		{checkpoint.ErrPublisherFenced, "checkpoint recovery pin ownership was lost"},
		{errors.New("conflicting capture"), "snapshot captured conflicting object versions"},
		{errors.New("catalog timestamp is in the future"), "catalog contains a future timestamp"},
		{errors.Join(errors.New("conflicting capture"), errors.New("private-password")), "operation failed"},
		{errors.New("shared archive head changed during chain load"), "source archive changed during snapshot acquisition"},
		{errors.Join(context.DeadlineExceeded, errors.New("private-password")), "operation timed out"},
	} {
		if got := backupFailureMessage(test.err); got != test.want {
			t.Fatalf("unexpected fixed classification %q", got)
		}
	}
}
