package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
)

func TestReadAndPurgeGeneratedSecretsAtDeadline(t *testing.T) {
	dir, keys := t.TempDir(), t.TempDir()
	key := bytes.Repeat([]byte{9}, 32)
	if err := os.WriteFile(filepath.Join(keys, "test-1"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "generated.enc")
	now := time.Unix(2_000_000_000, 0)
	entries := []apikey.BootstrapSecretEntry{{Kind: "api-key", ID: "test", Field: "token", Value: "test$" + string(bytes.Repeat([]byte("a"), 64))}}
	if err := apikey.WriteGeneratedBootstrapSecrets(path, keys, "test-1", entries, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := apikey.WriteGeneratedBootstrapSecrets(path, keys, "test-1", entries, now.Add(2*time.Hour)); !os.IsExist(err) {
		t.Fatal("preexisting artifact publication was not rejected")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preexisting artifact was changed")
	}
	args := []string{"-file", path, "-key-dir", keys}
	var out bytes.Buffer
	if err := run(args, &out, now); err != nil {
		t.Fatal(err)
	}
	var decoded []apikey.BootstrapSecretEntry
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil || len(decoded) != 1 || decoded[0] != entries[0] {
		t.Fatal("retrieval did not match artifact")
	}
	out.Reset()
	if err := run(append(args, "-purge-expired"), &out, now); err != nil || out.String() != "{\"removed\":false}\n" {
		t.Fatal("unexpired artifact was purged")
	}
	out.Reset()
	if err := run(args, &out, now.Add(time.Hour)); !errors.Is(err, apikey.ErrGeneratedBootstrapExpired) || out.Len() != 0 {
		t.Fatal("expired secret exposed")
	}
	if err := run(append(args, "-purge-expired"), &out, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expired artifact remains")
	}
	out.Reset()
	if err := run(append(args, "-purge-expired"), &out, now.Add(time.Hour)); err != nil || out.String() != "{\"removed\":false}\n" {
		t.Fatalf("repeated purge: output=%q err=%v", out.String(), err)
	}
}

func TestPurgeDoesNotMistakeKeyNameForExpiry(t *testing.T) {
	keys, dir := t.TempDir(), t.TempDir()
	keyPath := filepath.Join(keys, "expired-1")
	key := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "generated.enc")
	now := time.Unix(2_000_000_000, 0)
	if err := apikey.WriteGeneratedBootstrapSecrets(path, keys, "expired-1", []apikey.BootstrapSecretEntry{}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(keyPath, filepath.Join(keys, "other-1")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"-file", path, "-key-dir", keys, "-purge-expired"}, &out, now); err == nil {
		t.Fatal("unknown key accepted as expiry")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("unreadable artifact deleted")
	}
}

func TestPurgeMissingKeysDoesNotTreatExistingArtifactAsAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "generated.enc")
	if err := os.WriteFile(path, []byte("not authenticated"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"-file", path, "-key-dir", filepath.Join(dir, "missing-keys"), "-purge-expired"}, &out, time.Unix(2_000_000_000, 0)); err == nil || out.Len() != 0 {
		t.Fatalf("missing keys suppressed: %v output=%q", err, out.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("artifact removed: %v", err)
	}
}
