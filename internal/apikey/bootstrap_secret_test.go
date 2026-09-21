package apikey

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func cryptrTestValue(t *testing.T, id string, key, plain []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	headerLen := 6 + len(id)
	header := make([]byte, headerLen)
	header[0], header[1] = 1, 1
	binary.BigEndian.PutUint16(header[2:4], uint16(headerLen))
	binary.BigEndian.PutUint16(header[4:6], 0)
	copy(header[6:], id)
	return append(header, append(nonce, aead.Seal(nil, nonce, plain, nil)...)...)
}

func TestEncryptedBootstrapImportsIntoRhizaAndRejectsWrongKeyAtomically(t *testing.T) {
	t.Parallel()
	db := bootstrapTestDB(t, "bootstrap-encrypted")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xa0 + i)
	}
	keyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keyDir, "dev-1"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	secret := []byte(bootstrapTestSecret)
	envelope := cryptrTestValue(t, "dev-1", key, secret)
	path := filepath.Join(t.TempDir(), "encrypted.json")
	content := `[{"name":"encrypted","secret":{"Encrypted":"` + base64.StdEncoding.EncodeToString(envelope) + `"},"access":[{"group":"Clients","access_rights":["read"]}]}]`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapWithMasterKeyDir(context.Background(), path, keyDir); err != nil {
		t.Fatal(err)
	}
	p, err := store.Authenticate(context.Background(), "API-Key encrypted$"+bootstrapTestSecret)
	if err != nil {
		t.Fatalf("encrypted key did not authenticate: %v", err)
	}
	if err := store.Authorize(context.Background(), p, "Clients", Read); err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapWithMasterKeyDir(context.Background(), path, keyDir); err != nil {
		t.Fatalf("idempotent import: %v", err)
	}
	badDir := t.TempDir()
	wrong := make([]byte, 32)
	if err := os.WriteFile(filepath.Join(badDir, "dev-1"), []byte(base64.RawURLEncoding.EncodeToString(wrong)), 0600); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "bad.json")
	badEnvelope := append([]byte(nil), envelope...)
	badEnvelope[len(badEnvelope)-1] ^= 1
	badContent := `[{"name":"second","secret":{"Encrypted":"` + base64.StdEncoding.EncodeToString(badEnvelope) + `"},"access":[{"group":"Clients","access_rights":["read"]}]}]`
	if err := os.WriteFile(badPath, []byte(badContent), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapWithMasterKeyDir(context.Background(), badPath, badDir); err == nil {
		t.Fatal("wrong/tampered envelope accepted")
	}
	assertBootstrapCount(t, db, 1)
}

func TestDecryptCryptrValueAuthenticatesAndUsesKeyID(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plain := []byte("secret")
	envelope := cryptrTestValue(t, "dev-1", key, plain)
	got, err := decryptCryptrValue(envelope, map[string][]byte{"dev-1": key})
	if err != nil || string(got) != string(plain) {
		t.Fatalf("got %q err=%v", got, err)
	}
	envelope[len(envelope)-1] ^= 1
	if _, err := decryptCryptrValue(envelope, map[string][]byte{"dev-1": key}); err == nil {
		t.Fatal("tampered envelope decrypted")
	}
	if _, err := decryptCryptrValue(cryptrTestValue(t, "dev-1", key, plain), map[string][]byte{"other": key}); err == nil {
		t.Fatal("unknown key ID accepted")
	}
}

func TestLoadBootstrapMasterKeysStrict(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key := make([]byte, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)
	if err := os.WriteFile(filepath.Join(dir, "dev-1"), []byte(encoded+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadBootstrapMasterKeys(dir)
	if err != nil || len(got) != 1 || len(got["dev-1"]) != 32 {
		t.Fatalf("keys=%v err=%v", got, err)
	}
	wipeBootstrapMasterKeys(got)
	if len(got) != 0 {
		t.Fatal("master keys not wiped")
	}
}

func TestLoadBootstrapMasterKeysRejectsInvalidFiles(t *testing.T) {
	t.Parallel()
	for name, value := range map[string][]byte{
		"bad id!": []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		"bad-key": []byte("not-base64"),
		"short":   []byte(base64.RawURLEncoding.EncodeToString([]byte("short"))),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), value, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadBootstrapMasterKeys(dir); err == nil {
				t.Fatal("accepted invalid master-key file")
			}
		})
	}
}

func TestBootstrapWithMasterKeyDirEmptyPathRemainsNoOp(t *testing.T) {
	t.Parallel()
	db := bootstrapTestDB(t, "bootstrap-empty-path")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapWithMasterKeyDir(t.Context(), "", filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("empty path must be a no-op: %v", err)
	}
}

func TestBootstrapGeneratedArtifactRoundTripExpiryAndTamper(t *testing.T) {
	t.Parallel()
	dir, path := t.TempDir(), filepath.Join(t.TempDir(), "bootstrap.secrets.enc")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	if err := os.WriteFile(filepath.Join(dir, "dev-1"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	entries := []BootstrapSecretEntry{{Kind: "api-key", ID: "runner", Field: "token", Value: "runner$" + bootstrapTestSecret}}
	if err := WriteGeneratedBootstrapSecrets(path, dir, "dev-1", entries, time.Unix(2000000100, 0)); err != nil {
		t.Fatal(err)
	}
	got, err := ReadGeneratedBootstrapSecrets(path, dir, "dev-1", time.Unix(2000000000, 0))
	if err != nil || len(got) != 1 || got[0].Value != entries[0].Value {
		t.Fatalf("artifact entries mismatch count=%d err=%v", len(got), err)
	}
	if mode := fileMode(t, path); mode != 0600 {
		t.Fatalf("mode=%o", mode)
	}
	data, _ := os.ReadFile(path)
	data[len(data)-1] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadGeneratedBootstrapSecrets(path, dir, "dev-1", time.Unix(2000000000, 0)); err == nil {
		t.Fatal("tampered artifact accepted")
	}
}

func fileMode(t *testing.T, path string) uint32 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(info.Mode().Perm())
}
