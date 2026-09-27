package oidc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestNormalizeIssuer(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
		ok    bool
	}{
		{"https://id.example.com/tenant/", "", false},
		{"https://id.example.com/tenant", "https://id.example.com/tenant", true},
		{"https://id.example.com/tenant%2Fchild", "", false},
		{"https://id.example.com/tenant/../other", "", false},
		{"https://id.example.com/tenant//child", "", false},
		{"http://localhost:8080/", "http://localhost:8080", true},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080", true},
		{"http://id.example.com", "", false},
		{"https://user@id.example.com", "", false},
		{"https://id.example.com?query=yes", "", false},
	} {
		got, err := NormalizeIssuer(test.input)
		if (err == nil) != test.ok || got != test.want {
			t.Fatalf("NormalizeIssuer(%q) = %q, %v", test.input, got, err)
		}
	}
}

func TestSigningKeyBootstrapConvergesAndSigns(t *testing.T) {
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0)

	const workers = 3
	keys := make([]SigningKey, workers)
	errs := make([]error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			keys[index], errs[index] = EnsureSigningKey(context.Background(), db, keyring, issuer, now)
		}()
	}
	wait.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", index, err)
		}
		if keys[index].PublicJWK.KeyID != keys[0].PublicJWK.KeyID || !bytes.Equal(keys[index].Private, keys[0].Private) {
			t.Fatal("bootstrap workers did not converge on one key")
		}
	}

	publicJSON, err := json.Marshal(keys[0].PublicJWK)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(publicJSON, []byte(`"d"`)) {
		t.Fatal("public JWK contains private key material")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: keys[0].Private}, &jose.SignerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign([]byte("goauthy"))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := parsed.Verify(keys[0].PublicJWK.Key)
	if err != nil || string(payload) != "goauthy" {
		t.Fatalf("verify payload=%q err=%v", payload, err)
	}
}

func TestLoadActiveSigningKeyCacheRejectsStoredRowChanges(t *testing.T) {
	for _, test := range []struct {
		name, column, value string
	}{
		{name: "envelope", column: "private_envelope", value: base64.RawURLEncoding.EncodeToString([]byte("tampered"))},
		{name: "public JWK", column: "public_jwk", value: `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := testDB(t)
			keyring := fixedKeyring("master-a")
			issuer := "https://id.example.com"
			key, err := EnsureSigningKey(context.Background(), db, keyring, issuer, time.Unix(1_800_000_000, 0))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := LoadActiveSigningKey(context.Background(), db, keyring, issuer); err != nil {
				t.Fatal("warm signing material:", err)
			}
			keyring.mu.RLock()
			cachedPrivate := keyring.signing.key.Private
			keyring.mu.RUnlock()
			_, err = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
				RequestID: "tamper-cached-signing-key-" + test.name,
				SQL:       `UPDATE oidc_signing_keys SET ` + test.column + ` = ? WHERE kid = ?`,
				Args:      []any{test.value, key.PublicJWK.KeyID},
			})
			if err != nil {
				t.Fatal("tamper signing-key row:", err)
			}
			if _, err := LoadActiveSigningKey(context.Background(), db, keyring, issuer); err == nil {
				t.Fatal("changed active signing-key row was accepted from cache")
			}
			keyring.mu.RLock()
			cached := keyring.signing != nil
			keyring.mu.RUnlock()
			if cached {
				t.Fatal("tampered active row retained cached private material")
			}
			if !bytes.Equal(cachedPrivate, make([]byte, len(cachedPrivate))) {
				t.Fatal("evicted private material was not wiped")
			}
		})
	}
}

func TestLoadActiveSigningKeyWithoutActiveRow(t *testing.T) {
	db := testDB(t)
	emptyDB := testDB(t)
	keyring := fixedKeyring("master-a")
	issuer := "https://id.example.com"
	_, err := EnsureSigningKey(context.Background(), db, keyring, issuer, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal("create active key:", err)
	}
	if _, err := LoadActiveSigningKey(context.Background(), db, keyring, issuer); err != nil {
		t.Fatal("warm active key:", err)
	}
	keyring.mu.RLock()
	cachedPrivate := keyring.signing.key.Private
	keyring.mu.RUnlock()
	if _, err := LoadActiveSigningKey(context.Background(), emptyDB, keyring, issuer); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("load without active key err=%v", err)
	}
	keyring.mu.RLock()
	cached := keyring.signing != nil
	keyring.mu.RUnlock()
	if cached {
		t.Fatal("no-active result retained cached private material")
	}
	if !bytes.Equal(cachedPrivate, make([]byte, len(cachedPrivate))) {
		t.Fatal("no-active result did not wipe cached private material")
	}
}

func TestLoadActiveSigningKeyCacheRejectsRemovedMasterKey(t *testing.T) {
	db := testDB(t)
	issuer := "https://id.example.com"
	oldKeyring := fixedKeyring("master-a")
	if _, err := EnsureSigningKey(context.Background(), db, oldKeyring, issuer, time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal("create active key:", err)
	}
	rotated := fixedKeyring("master-b")
	if _, err := LoadActiveSigningKey(context.Background(), db, rotated, issuer); err != nil {
		t.Fatal("warm key under rotated keyring:", err)
	}
	cachedPrivate := rotated.signing.key.Private
	if err := rotated.RemoveKey("master-a"); err != nil {
		t.Fatal("remove signing envelope master key:", err)
	}
	if rotated.signing != nil || !bytes.Equal(cachedPrivate, make([]byte, len(cachedPrivate))) {
		t.Fatal("removal did not immediately detach and wipe cached private material")
	}
	if _, err := LoadActiveSigningKey(context.Background(), db, rotated, issuer); err == nil {
		t.Fatal("cached signing key survived master-key removal")
	}
	rotated.mu.RLock()
	cached := rotated.signing != nil
	rotated.mu.RUnlock()
	if cached {
		t.Fatal("removed master key left cached private material")
	}
}

func TestLoadActiveSigningKeyCacheReturnsDefensiveCopiesConcurrently(t *testing.T) {
	db := testDB(t)
	keyring := fixedKeyring("master-a")
	issuer := "https://id.example.com"
	want, err := EnsureSigningKey(context.Background(), db, keyring, issuer, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	const workers = 8
	var wait sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, err := LoadActiveSigningKey(context.Background(), db, keyring, issuer)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got.Private, want.Private) {
				errs <- errors.New("loaded private key changed")
				return
			}
			got.Private[0] ^= 0xff
			got.PublicJWK.Key.(ed25519.PublicKey)[0] ^= 0xff
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	got, err := LoadActiveSigningKey(context.Background(), db, keyring, issuer)
	if err != nil || !bytes.Equal(got.Private, want.Private) || !bytes.Equal(got.PublicJWK.Key.(ed25519.PublicKey), want.PublicJWK.Key.(ed25519.PublicKey)) {
		t.Fatalf("caller mutation affected cached key: err=%v", err)
	}
}

func TestSigningMaterialGenerationFence(t *testing.T) {
	key, _, _, err := signingKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize), time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"invalidate empty", "invalidate populated", "replace", "remove master"} {
		t.Run(change, func(t *testing.T) {
			kr := fixedKeyring("master-b")
			if change != "invalidate empty" {
				kr.cacheSigningMaterial(kr.signingGeneration, "issuer", "old", "public", "envelope", 1, "master-a", key)
			}
			// Model a load paused after taking its pre-query generation and row snapshot.
			stale := kr.signingGeneration
			var evicted ed25519.PrivateKey
			if kr.signing != nil {
				evicted = kr.signing.key.Private
			}
			switch change {
			case "replace":
				kr.cacheSigningMaterial(stale, "issuer", "new", "public", "new-envelope", 2, "master-b", key)
			case "remove master":
				if err := kr.RemoveKey("master-a"); err != nil {
					t.Fatal(err)
				}
			default:
				kr.clearSigningMaterial(stale)
			}
			if !bytes.Equal(evicted, make([]byte, len(evicted))) {
				t.Fatal("superseded private material was not wiped")
			}
			want, generation := kr.signing, kr.signingGeneration
			if _, hit := kr.cachedSigningMaterial(&stale, "issuer", "old", "public", "envelope", 1); hit {
				t.Fatal("stale lookup hit")
			}
			if kr.signing != want || kr.signingGeneration != generation {
				t.Fatal("stale mismatch evicted newer state")
			}
			ok := kr.cacheSigningMaterial(stale, "issuer", "old", "public", "envelope", 1, "master-a", key)
			if ok != (change != "remove master") {
				t.Fatal("superseded load did not preserve removed-master failure")
			}
			if kr.signing != want || kr.signingGeneration != generation {
				t.Fatal("stale publication replaced newer state")
			}
			kr.clearSigningMaterial(stale)
			if kr.signing != want || kr.signingGeneration != generation {
				t.Fatal("stale error cleared newer state")
			}
			if want != nil && !bytes.Equal(want.key.Private, key.Private) {
				t.Fatal("newer private material was wiped")
			}
		})
	}

	t.Run("current mismatch can publish replacement", func(t *testing.T) {
		kr := fixedKeyring("master-a")
		kr.cacheSigningMaterial(kr.signingGeneration, "issuer", "old", "public", "envelope", 1, "master-a", key)
		old := kr.signing
		generation := kr.signingGeneration
		if _, hit := kr.cachedSigningMaterial(&generation, "issuer", "new", "public", "new-envelope", 2); hit {
			t.Fatal("changed row hit cache")
		}
		if generation != kr.signingGeneration || kr.signing != nil || !bytes.Equal(old.key.Private, make([]byte, len(old.key.Private))) {
			t.Fatal("current mismatch did not wipe cache and advance its own generation")
		}
		if !kr.cacheSigningMaterial(generation, "issuer", "new", "public", "new-envelope", 2, "master-a", key) || kr.signing == nil || kr.signing.kid != "new" {
			t.Fatal("current load could not publish after its own eviction")
		}
	})
}

func TestLoadSigningKeyCacheFailureBoundaries(t *testing.T) {
	db := testDB(t)
	kr := fixedKeyring("master-a")
	ctx := context.Background()
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0)
	if _, err := EnsureSigningKey(ctx, db, kr, issuer, now); err != nil {
		t.Fatal(err)
	}
	pending, err := PrepareSigningKey(ctx, db, kr, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	want, generation := kr.signing, kr.signingGeneration
	wantPrivate := append(ed25519.PrivateKey(nil), want.key.Private...)
	if _, err := loadSigningKey(ctx, db, kr, issuer, pending.PendingKID, "pending"); err != nil {
		t.Fatal(err)
	}
	if kr.signing != want || kr.signingGeneration != generation {
		t.Fatal("pending success changed active cache")
	}
	if _, err := loadSigningKey(ctx, db, kr, "https://wrong.example.com", pending.PendingKID, "pending"); err == nil {
		t.Fatal("invalid pending envelope accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := loadSigningKey(canceled, db, kr, issuer, pending.PendingKID, "pending"); err == nil {
		t.Fatal("pending query failure accepted")
	}
	if kr.signing != want || kr.signingGeneration != generation || !bytes.Equal(want.key.Private, wantPrivate) {
		t.Fatal("pending failure changed active cache")
	}
	private := want.key.Private
	if _, err := LoadActiveSigningKey(canceled, db, kr, issuer); err == nil {
		t.Fatal("active query failure fell back to cache")
	}
	if kr.signing != nil || !bytes.Equal(private, make([]byte, len(private))) {
		t.Fatal("active query failure did not detach and wipe cache")
	}
}

func TestSigningKeyEnvelopeRejectsWrongContextAndTampering(t *testing.T) {
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	key, err := EnsureSigningKey(context.Background(), db, keyring, issuer, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadActiveSigningKey(context.Background(), db, keyring, "https://other.example.com"); err == nil {
		t.Fatal("wrong issuer decrypted signing key")
	}
	if _, err := LoadActiveSigningKey(context.Background(), db, testKeyring(t, "master-1"), issuer); err == nil {
		t.Fatal("wrong master key decrypted signing key")
	}

	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "tamper-signing-key-envelope",
		SQL:       `UPDATE oidc_signing_keys SET private_envelope = ? WHERE kid = ?`,
		Args:      []any{base64.RawURLEncoding.EncodeToString([]byte("not-an-envelope")), key.PublicJWK.KeyID},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadActiveSigningKey(context.Background(), db, keyring, issuer); err == nil {
		t.Fatal("tampered signing key envelope was accepted")
	}
}

func TestPurposeEnvelopeRejectsWrongPurposeAndTampering(t *testing.T) {
	keyring := testKeyring(t, "master-1")
	plaintext := []byte("one-use credential response")
	envelope, err := keyring.SealEnvelope("dcr/response", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := keyring.OpenEnvelope("dcr/response", envelope)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("open plaintext=%q err=%v", opened, err)
	}
	if _, err := keyring.OpenEnvelope("upstream/transaction", envelope); err == nil {
		t.Fatal("purpose envelope opened under a different purpose")
	}
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 1
	if _, err := keyring.OpenEnvelope("dcr/response", tampered); err == nil {
		t.Fatal("tampered purpose envelope was accepted")
	}
}

func TestPurposeEnvelopeRewrapsAcrossMasterKeys(t *testing.T) {
	plaintext := []byte("client-secret-and-registration-token")
	oldKeyring := fixedKeyring("master-a")
	envelope, err := oldKeyring.SealEnvelope("dcr/response", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), envelope...)

	rotated := fixedKeyring("master-b")
	id, err := rotated.PurposeEnvelopeKeyID("dcr/response", envelope)
	if err != nil || id != "master-a" {
		t.Fatalf("old envelope key ID=%q err=%v", id, err)
	}
	rewrapped, err := rotated.RewrapEnvelope("dcr/response", envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(envelope, original) {
		t.Fatal("rewrap modified the source envelope")
	}
	id, err = rotated.PurposeEnvelopeKeyID("dcr/response", rewrapped)
	if err != nil || id != "master-b" {
		t.Fatalf("rewrapped envelope key ID=%q err=%v", id, err)
	}
	opened, err := rotated.OpenEnvelope("dcr/response", rewrapped)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("rewrapped plaintext=%q err=%v", opened, err)
	}

	delete(rotated.keys, "master-a")
	if _, err := rotated.OpenEnvelope("dcr/response", envelope); err == nil {
		t.Fatal("old-key envelope opened after old key removal")
	}
	if _, err := rotated.OpenEnvelope("dcr/response", rewrapped); err != nil {
		t.Fatalf("rewrapped envelope did not survive old key removal: %v", err)
	}
}

func TestPurposeEnvelopeRewrapRejectsWrongContextAndTampering(t *testing.T) {
	keyring := fixedKeyring("master-a")
	envelope, err := keyring.SealEnvelope("dcr/response", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.PurposeEnvelopeKeyID("upstream/transaction", envelope); err == nil {
		t.Fatal("wrong purpose authenticated a purpose envelope")
	}
	if _, err := keyring.RewrapEnvelope("upstream/transaction", envelope); err == nil {
		t.Fatal("wrong purpose rewrapped a purpose envelope")
	}
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 1
	if _, err := keyring.PurposeEnvelopeKeyID("dcr/response", tampered); err == nil {
		t.Fatal("tampered purpose envelope authenticated")
	}
	if _, err := keyring.RewrapEnvelope("dcr/response", tampered); err == nil {
		t.Fatal("tampered purpose envelope rewrapped")
	}
	badVersion := append([]byte(nil), envelope...)
	badVersion[4]++
	if _, err := keyring.PurposeEnvelopeKeyID("dcr/response", badVersion); err == nil {
		t.Fatal("unsupported purpose envelope version accepted")
	}
}

func TestSigningKeyEnvelopeRewrapsAcrossMasterKeys(t *testing.T) {
	issuer := "https://id.example.com"
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	_, _, kid, err := signingKeyFromSeed(seed, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	oldKeyring := fixedKeyring("master-a")
	envelope, err := sealEnvelope(oldKeyring, issuer, kid, seed)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), envelope...)
	rotated := fixedKeyring("master-b")
	id, err := rotated.SigningKeyEnvelopeKeyID(issuer, kid, envelope)
	if err != nil || id != "master-a" {
		t.Fatalf("old signing envelope key ID=%q err=%v", id, err)
	}
	rewrapped, err := rotated.RewrapSigningKeyEnvelope(issuer, kid, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(envelope, original) {
		t.Fatal("signing rewrap modified the source envelope")
	}
	id, err = rotated.SigningKeyEnvelopeKeyID(issuer, kid, rewrapped)
	if err != nil || id != "master-b" {
		t.Fatalf("rewrapped signing envelope key ID=%q err=%v", id, err)
	}
	opened, err := openEnvelope(rotated, issuer, kid, rewrapped)
	if err != nil || !bytes.Equal(opened, seed) {
		t.Fatalf("rewrapped signing seed=%x err=%v", opened, err)
	}
	delete(rotated.keys, "master-a")
	if _, err := openEnvelope(rotated, issuer, kid, envelope); err == nil {
		t.Fatal("old-key signing envelope opened after old key removal")
	}
	if _, err := openEnvelope(rotated, issuer, kid, rewrapped); err != nil {
		t.Fatalf("rewrapped signing envelope did not survive old key removal: %v", err)
	}
}

func TestSigningKeyEnvelopeRewrapRejectsWrongAADAndTampering(t *testing.T) {
	issuer := "https://id.example.com"
	seed := bytes.Repeat([]byte{9}, ed25519.SeedSize)
	_, _, kid, err := signingKeyFromSeed(seed, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	keyring := fixedKeyring("master-a")
	envelope, err := sealEnvelope(keyring, issuer, kid, seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.SigningKeyEnvelopeKeyID("https://other.example.com", kid, envelope); err == nil {
		t.Fatal("wrong issuer authenticated signing envelope")
	}
	if _, err := keyring.RewrapSigningKeyEnvelope(issuer, "other-kid", envelope); err == nil {
		t.Fatal("wrong signing kid rewrapped signing envelope")
	}
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 1
	if _, err := keyring.SigningKeyEnvelopeKeyID(issuer, kid, tampered); err == nil {
		t.Fatal("tampered signing envelope authenticated")
	}
	badVersion := append([]byte(nil), envelope...)
	badVersion[4]++
	if _, err := keyring.SigningKeyEnvelopeKeyID(issuer, kid, badVersion); err == nil {
		t.Fatal("unsupported signing envelope version accepted")
	}
}

func TestLoadKeyringRejectsInvalidKeys(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "master-1"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(directory, "master-1"); err == nil {
		t.Fatal("invalid master key was accepted")
	}
}

func TestActiveMasterKeyID(t *testing.T) {
	if id, err := (*Keyring)(nil).ActiveMasterKeyID(); err == nil || id != "" {
		t.Fatalf("nil keyring returned id=%q err=%v", id, err)
	}
	missing := &Keyring{active: "master-missing", keys: map[string][32]byte{}}
	if id, err := missing.ActiveMasterKeyID(); err == nil || id != "" {
		t.Fatalf("missing active key returned id=%q err=%v", id, err)
	}
	invalid := &Keyring{active: "bad key", keys: map[string][32]byte{"bad key": {}}}
	if id, err := invalid.ActiveMasterKeyID(); err == nil || id != "" {
		t.Fatalf("invalid active key ID returned id=%q err=%v", id, err)
	}
	keyring := fixedKeyring("master-b")
	if id, err := keyring.ActiveMasterKeyID(); err != nil || id != "master-b" {
		t.Fatalf("active key ID=%q err=%v", id, err)
	}
}

func testDB(t *testing.T) *rhiza.DB {
	t.Helper()
	tmpl := buildOIDCTemplate(t)
	dir := t.TempDir()
	cpDir(t, tmpl, dir)
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func testKeyring(t *testing.T, active string) *Keyring {
	t.Helper()
	directory := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	if err := os.WriteFile(filepath.Join(directory, active), []byte(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := LoadKeyring(directory, active)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func fixedKeyring(active string) *Keyring {
	var oldKey, newKey [32]byte
	for i := range oldKey {
		oldKey[i] = byte(i + 1)
		newKey[i] = byte(i + 33)
	}
	return &Keyring{active: active, keys: map[string][32]byte{"master-a": oldKey, "master-b": newKey}}
}

func TestRemoveKeyRaceAndFileError(t *testing.T) {
	// (b) Injected unlink failure: RemoveKey returns error and keeps the key
	// when os.Remove fails, making cleanup retryable.
	directory := t.TempDir()
	for _, id := range []string{"key-old", "key-active"} {
		encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		if err := os.WriteFile(filepath.Join(directory, id), []byte(encoded), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keyring, err := LoadKeyring(directory, "key-active")
	if err != nil {
		t.Fatal(err)
	}
	// Block the unlink with a non-empty directory at the key path so the failure
	// is a genuine filesystem error rather than an already-absent file.
	blocked := t.TempDir()
	if err := os.MkdirAll(filepath.Join(blocked, "key-old"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "key-old", "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring.directory = blocked
	if err := keyring.RemoveKey("key-old"); err == nil {
		t.Fatal("expected error from failed unlink")
	}
	if !keyring.HasKey("key-old") {
		t.Fatal("key should remain in map after failed unlink")
	}
	// Restore directory; the original file still exists on disk.
	keyring.directory = directory
	if err := keyring.RemoveKey("key-old"); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if keyring.HasKey("key-old") {
		t.Fatal("key should be gone after successful removal")
	}
	if _, err := os.Stat(filepath.Join(directory, "key-old")); !os.IsNotExist(err) {
		t.Fatal("key file should be removed from disk")
	}

	// A second instance loaded from the same directory must still complete its
	// own in-memory removal after another process deleted the file.
	shared := t.TempDir()
	for _, id := range []string{"key-old", "key-active"} {
		encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
		if err := os.WriteFile(filepath.Join(shared, id), []byte(encoded), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := LoadKeyring(shared, "key-active")
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadKeyring(shared, "key-active")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.RemoveKey("key-old"); err != nil {
		t.Fatalf("first removal: %v", err)
	}
	if err := second.RemoveKey("key-old"); err != nil {
		t.Fatalf("removal after external unlink: %v", err)
	}
	if second.HasKey("key-old") {
		t.Fatal("second keyring should drop a key whose file is already gone")
	}

	// (a) Race test: concurrent seal/open with removal of both the same and a
	// different key. The -race flag catches unsynchronized map access.
	dir := t.TempDir()
	for _, id := range []string{"key-a", "key-b", "key-active"} {
		encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{id[4]}, 32))
		if err := os.WriteFile(filepath.Join(dir, id), []byte(encoded), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kr, err := LoadKeyring(dir, "key-active")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("concurrent-race-payload")
	env, err := kr.SealEnvelope("test/purpose", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	// Concurrent seal and open readers.
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					if _, err := kr.SealEnvelope("test/purpose", plaintext); err != nil {
						t.Error(err)
						return
					}
					if got, err := kr.OpenEnvelope("test/purpose", env); err != nil || !bytes.Equal(got, plaintext) {
						t.Errorf("open: got=%x err=%v", got, err)
						return
					}
				}
			}
		}()
	}
	// Concurrent removal of a different key and the same key (idempotent).
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = kr.RemoveKey("key-a")
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = kr.RemoveKey("key-a")
		}()
	}
	// Removal of a non-existent key while readers run.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = kr.RemoveKey("key-b")
	}()
	close(done)
	wg.Wait()
	// Active key must survive all concurrent operations.
	if _, err := kr.ActiveMasterKeyID(); err != nil {
		t.Fatalf("active key lost after concurrent removal: %v", err)
	}
}
func TestRemoveKeyDeletesFromMap(t *testing.T) {
	keyring := fixedKeyring("master-b")
	if _, ok := keyring.keys["master-a"]; !ok {
		t.Fatal("master-a not in keyring before removal")
	}
	if err := keyring.RemoveKey("master-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := keyring.keys["master-a"]; ok {
		t.Fatal("master-a still in keyring after removal")
	}
	if _, ok := keyring.keys["master-b"]; !ok {
		t.Fatal("master-b removed unexpectedly")
	}
}

func TestRemoveKeyDeletesFile(t *testing.T) {
	directory := t.TempDir()
	for _, id := range []string{"key-old", "key-active"} {
		encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		if err := os.WriteFile(filepath.Join(directory, id), []byte(encoded), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keyring, err := LoadKeyring(directory, "key-active")
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.RemoveKey("key-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "key-old")); !os.IsNotExist(err) {
		t.Fatal("old key file still exists after removal")
	}
	if _, err := os.Stat(filepath.Join(directory, "key-active")); err != nil {
		t.Fatal("active key file removed")
	}
}

func TestRemoveKeyRejectsActiveKey(t *testing.T) {
	keyring := fixedKeyring("master-a")
	if err := keyring.RemoveKey("master-a"); err == nil {
		t.Fatal("removing active key did not error")
	}
}

func TestRemoveKeyIsIdempotent(t *testing.T) {
	keyring := fixedKeyring("master-b")
	if err := keyring.RemoveKey("master-a"); err != nil {
		t.Fatal(err)
	}
	if err := keyring.RemoveKey("master-a"); err != nil {
		t.Fatalf("second removal errored: %v", err)
	}
}

func TestRemoveKeyNilKeyring(t *testing.T) {
	if err := (*Keyring)(nil).RemoveKey("master-a"); err == nil {
		t.Fatal("nil keyring removal did not error")
	}
}
