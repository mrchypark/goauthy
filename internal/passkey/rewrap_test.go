package passkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func testPasskeyKeyring(t *testing.T, active string) *oidc.Keyring {
	t.Helper()
	dir := t.TempDir()
	for name, value := range map[string]byte{"master-a": 0x11, "master-b": 0x22} {
		key := bytes.Repeat([]byte{value}, 32)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keyring, err := oidc.LoadKeyring(dir, active)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func testPasskeyKeyringOnly(t *testing.T, active string) *oidc.Keyring {
	t.Helper()
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x22}, 32)
	if err := os.WriteFile(filepath.Join(dir, active), []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(dir, active)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func newRewrapServices(t *testing.T) (context.Context, *rhiza.DB, *Service, *Service) {
	t.Helper()
	old, db, now := newTestService(t)
	rotated, err := New(db, Config{RPID: "example.test", RPDisplayName: "Example", Origins: []string{"https://example.test"}, CookieKey: []byte(strings.Repeat("k", 32)), Keyring: testPasskeyKeyring(t, "master-b")})
	if err != nil {
		t.Fatal(err)
	}
	rotated.now = func() time.Time { return now }
	rotated.random = &deterministicReader{}
	return context.Background(), db, old, rotated
}

func TestDurablePasskeyWritesRespectMasterKeyFence(t *testing.T) {
	ctx, db, old, replacement := newRewrapServices(t)
	now := old.now()
	staleDigest := challengeDigest("stale-ceremony")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "passkey-fence-stale", SQL: `INSERT INTO identity_webauthn_ceremonies (code_digest,purpose,subject,session_digest,passkey_name,session_json,expires_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{staleDigest, "register", "subject", digestForTest('s'), "stale", "stale-envelope", int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "master-a", ReplacementKeyID: "master-b", MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	old.random = &deterministicReader{}
	if _, _, err := old.saveCeremony(ctx, "register", "subject", "new-key", digestForTest('s'), "", "", &wa.SessionData{Challenge: strings.Repeat("d", 43)}); err == nil {
		t.Fatal("fenced old writer was accepted")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_webauthn_ceremonies`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("fenced transaction was not rolled back: rows=%v err=%v", result.Rows, err)
	}

	replacement.random = &deterministicReader{n: 100}
	code, _, err := replacement.saveCeremony(ctx, "register", "subject", "new-key", digestForTest('r'), "", "", &wa.SessionData{Challenge: strings.Repeat("e", 43)})
	if err != nil {
		t.Fatal("replacement writer rejected: ", err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT session_json FROM identity_webauthn_ceremonies WHERE code_digest=?`, Args: []any{challengeDigest(code)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("replacement ceremony rows=%v err=%v", result.Rows, err)
	}
	envelope, err := base64.RawURLEncoding.DecodeString(result.Rows[0][0].(string))
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := replacement.keyring.PurposeEnvelopeKeyID(ceremonyEnvelopePurpose("register", "subject", challengeDigest(code)), envelope)
	if err != nil || keyID != "master-b" {
		t.Fatalf("replacement envelope key=%q err=%v", keyID, err)
	}
}

func TestPasskeyEnvelopeWriteUsesAuthenticatedSealedKeyAsWriter(t *testing.T) {
	ctx, db, _, replacement := newRewrapServices(t)
	now := time.UnixMilli(1_900_000_000_000).UTC()
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "master-a", ReplacementKeyID: "master-b", MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	replacement.keyring = &interposedPasskeyKeyring{EnvelopeKeyring: replacement.keyring, active: "master-a"}
	replacement.random = &deterministicReader{}
	code, _, err := replacement.saveCeremony(ctx, "register", "subject", "new-key", digestForTest('r'), "", "", &wa.SessionData{Challenge: strings.Repeat("e", 43)})
	if err != nil {
		t.Fatalf("sealed replacement writer rejected: %v", err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT session_json FROM identity_webauthn_ceremonies WHERE code_digest=?`, Args: []any{challengeDigest(code)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("replacement ceremony rows=%v err=%v", result.Rows, err)
	}
	envelope, err := base64.RawURLEncoding.DecodeString(result.Rows[0][0].(string))
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := replacement.keyring.PurposeEnvelopeKeyID(ceremonyEnvelopePurpose("register", "subject", challengeDigest(code)), envelope)
	if err != nil || keyID != "master-b" {
		t.Fatalf("replacement envelope key=%q err=%v", keyID, err)
	}
}

type interposedPasskeyKeyring struct {
	EnvelopeKeyring
	active string
}

func (k *interposedPasskeyKeyring) ActiveMasterKeyID() (string, error) { return k.active, nil }

func TestPasskeyRewrapUsesMasterKeyFence(t *testing.T) {
	ctx, db, old, replacement := newRewrapServices(t)
	now := old.now()
	credentialID := testCredentialID("fenced-rewrap")
	original := insertPasskeyCredential(t, ctx, db, old, credentialID, "subject", true)
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "master-a", ReplacementKeyID: "master-b", MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := old.RewrapBatch(ctx, ""); err == nil {
		t.Fatal("fenced old rewrap writer was accepted")
	}
	if got := credentialEnvelopeText(t, ctx, db, credentialID); got != original {
		t.Fatal("fenced rewrap changed the credential")
	}
	if got := drainPasskeyRewrap(t, replacement); got != 1 {
		t.Fatalf("replacement rewrapped=%d, want 1", got)
	}
}

func drainPasskeyRewrap(t *testing.T, service *Service) int {
	t.Helper()
	ctx := context.Background()
	cursor := ""
	total := 0
	for i := 0; i < 20; i++ {
		result, err := service.RewrapBatch(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		total += result.Rewrapped
		if result.Done {
			return total
		}
		cursor = result.Cursor
	}
	t.Fatal("passkey rewrap did not complete")
	return 0
}

func testCredentialID(label string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(label))
}

func insertPasskeyCredential(t *testing.T, ctx context.Context, db *rhiza.DB, service *Service, id, subject string, legacy bool) string {
	t.Helper()
	credentialBytes, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(wa.Credential{ID: credentialBytes, PublicKey: []byte("public-key")})
	if err != nil {
		t.Fatal(err)
	}
	var envelope []byte
	if legacy {
		envelope, err = service.encrypt(plain, credentialAAD(subject))
	} else {
		envelope, _, err = service.encryptDB(plain, credentialEnvelopePurpose(subject))
	}
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(envelope)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "pk-cred-" + id, SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,credential_version,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?)`, Args: []any{id, subject, id, encoded, int64(0), int64(0), int64(0), int64(1), int64(1)}}); err != nil {
		t.Fatal(err)
	}
	return encoded
}

func insertPasskeyCeremony(t *testing.T, ctx context.Context, db *rhiza.DB, service *Service, digest, subject string, legacy bool) string {
	t.Helper()
	plain, err := json.Marshal(sealedState{Session: wa.SessionData{Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'c'}, 32))}})
	if err != nil {
		t.Fatal(err)
	}
	var envelope []byte
	if legacy {
		envelope, err = service.encrypt(plain, ceremonyAAD("register", subject, digest))
	} else {
		envelope, _, err = service.encryptDB(plain, ceremonyEnvelopePurpose("register", subject, digest))
	}
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(envelope)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "pk-ceremony-" + digest, SQL: `INSERT INTO identity_webauthn_ceremonies (code_digest,purpose,subject,session_digest,passkey_name,session_json,expires_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{digest, "register", subject, digest, "new-key", encoded, int64(2)}}); err != nil {
		t.Fatal(err)
	}
	return encoded
}

func insertPasskeyMFACeremony(t *testing.T, ctx context.Context, db *rhiza.DB, service *Service, digest, subject string, legacy bool) string {
	t.Helper()
	plain, err := json.Marshal(modificationSealedState{Session: wa.SessionData{Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'c'}, 32))}, Proof: strings.Repeat("p", 48)})
	if err != nil {
		t.Fatal(err)
	}
	var envelope []byte
	if legacy {
		envelope, err = service.encrypt(plain, mfaCeremonyAAD(subject, digest))
	} else {
		envelope, _, err = service.encryptDB(plain, mfaCeremonyEnvelopePurpose(subject, digest))
	}
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(envelope)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "pk-mfa-" + digest, SQL: `INSERT INTO identity_webauthn_mfa_ceremonies (code_digest,subject,session_digest,session_json,expires_at_unix_ms,proof_expires_at_unix_ms) VALUES (?,?,?,?,?,?)`, Args: []any{digest, subject, digest, encoded, int64(2), int64(3)}}); err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestRewrapBatchConvertsLegacyRowsAndSurvivesOldKeyRemoval(t *testing.T) {
	ctx, db, old, rotated := newRewrapServices(t)
	subject := "subject-legacy"
	credentialID := testCredentialID("credential-legacy")
	credentialOld := insertPasskeyCredential(t, ctx, db, old, credentialID, subject, true)
	digest := challengeDigest("legacy-ceremony")
	ceremonyOld := insertPasskeyCeremony(t, ctx, db, old, digest, subject, true)
	mfaDigest := challengeDigest("legacy-mfa")
	mfaOld := insertPasskeyMFACeremony(t, ctx, db, old, mfaDigest, subject, true)
	if got := drainPasskeyRewrap(t, rotated); got != 3 {
		t.Fatalf("rewrapped=%d, want 3", got)
	}
	rotatedOnly := rotated
	rotatedOnly.keyring = testPasskeyKeyringOnly(t, "master-b")
	for _, tc := range []struct {
		name, encoded, purpose string
		oldPlain               []byte
	}{
		{name: "credential", encoded: credentialOld, purpose: credentialEnvelopePurpose(subject), oldPlain: mustOpenLegacy(t, old, credentialOld, credentialAAD(subject))},
		{name: "ceremony", encoded: ceremonyOld, purpose: ceremonyEnvelopePurpose("register", subject, digest), oldPlain: mustOpenLegacy(t, old, ceremonyOld, ceremonyAAD("register", subject, digest))},
		{name: "mfa", encoded: mfaOld, purpose: mfaCeremonyEnvelopePurpose(subject, mfaDigest), oldPlain: mustOpenLegacy(t, old, mfaOld, mfaCeremonyAAD(subject, mfaDigest))},
	} {
		_ = tc.encoded
		var query string
		var arg string
		switch tc.name {
		case "credential":
			query, arg = `SELECT credential_json FROM identity_webauthn_credentials WHERE credential_id=?`, credentialID
		case "ceremony":
			query, arg = `SELECT session_json FROM identity_webauthn_ceremonies WHERE code_digest=?`, digest
		default:
			query, arg = `SELECT session_json FROM identity_webauthn_mfa_ceremonies WHERE code_digest=?`, mfaDigest
		}
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: query, Args: []any{arg}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(result.Rows) != 1 {
			t.Fatalf("%s query rows=%v err=%v", tc.name, result.Rows, err)
		}
		encoded := result.Rows[0][0].(string)
		envelope, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := rotatedOnly.keyring.PurposeEnvelopeKeyID(tc.purpose, envelope)
		if err != nil || keyID != "master-b" {
			t.Fatalf("%s key=%q err=%v", tc.name, keyID, err)
		}
		plain, err := rotatedOnly.keyring.OpenEnvelope(tc.purpose, envelope)
		if err != nil || !bytes.Equal(plain, tc.oldPlain) {
			t.Fatalf("%s plaintext changed: err=%v", tc.name, err)
		}
	}
}

func mustOpenLegacy(t *testing.T, service *Service, encoded string, aad []byte) []byte {
	t.Helper()
	envelope, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := service.decrypt(envelope, aad)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func TestRewrapBatchConvertsOldGAOPAndRejectsWrongContextOrTamper(t *testing.T) {
	ctx, db, old, rotated := newRewrapServices(t)
	validID := testCredentialID("credential-valid")
	validSubject := "subject-valid"
	original := insertPasskeyCredential(t, ctx, db, old, validID, validSubject, false)
	wrongID := testCredentialID("credential-wrong")
	wrongCredentialBytes, _ := base64.RawURLEncoding.DecodeString(wrongID)
	wrongPlain, _ := json.Marshal(wa.Credential{ID: wrongCredentialBytes, PublicKey: []byte("public-key")})
	wrongEnvelope, _, err := old.encryptDB(wrongPlain, credentialEnvelopePurpose("different-subject"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "passkey-test-wrong-context", SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,credential_version,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?)`, Args: []any{wrongID, "subject-wrong", wrongID, base64.RawURLEncoding.EncodeToString(wrongEnvelope), int64(0), int64(0), int64(0), int64(1), int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := rotated.openStoredEnvelope(original, credentialEnvelopePurpose(validSubject), credentialAAD(validSubject)); err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.RewrapBatch(ctx, ""); err == nil {
		t.Fatal("wrong-context GAOP was accepted")
	}
	if got := credentialEnvelopeText(t, ctx, db, validID); got != original {
		t.Fatal("valid row changed after wrong-context preflight failure")
	}

	// A fresh database proves authenticated tampering also leaves earlier rows untouched.
	ctx, db, old, rotated = newRewrapServices(t)
	firstID := testCredentialID("credential-first")
	secondID := testCredentialID("credential-second")
	first := insertPasskeyCredential(t, ctx, db, old, firstID, "subject-first", false)
	second := insertPasskeyCredential(t, ctx, db, old, secondID, "subject-second", false)
	tampered, err := base64.RawURLEncoding.DecodeString(second)
	if err != nil {
		t.Fatal(err)
	}
	tampered[len(tampered)-1] ^= 1
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "passkey-test-tamper", SQL: `UPDATE identity_webauthn_credentials SET credential_json=? WHERE credential_id=?`, Args: []any{base64.RawURLEncoding.EncodeToString(tampered), secondID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.RewrapBatch(ctx, ""); err == nil {
		t.Fatal("tampered GAOP was accepted")
	}
	if got := credentialEnvelopeText(t, ctx, db, firstID); got != first {
		t.Fatal("valid row changed after tamper preflight failure")
	}
}

func TestRewrapBatchConcurrentWorkersAreZeroOrN(t *testing.T) {
	ctx, db, old, rotated := newRewrapServices(t)
	for i := 0; i < 3; i++ {
		insertPasskeyCredential(t, ctx, db, old, testCredentialID(fmt.Sprintf("credential-worker-%d", i)), fmt.Sprintf("subject-worker-%d", i), false)
	}
	results := make([]RewrapBatchResult, 3)
	errs := make([]error, 3)
	var wait sync.WaitGroup
	for i := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errs[index] = rotated.RewrapBatch(ctx, "")
		}(i)
	}
	wait.Wait()
	var total int
	for i, result := range results {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if result.Rewrapped != 0 && result.Rewrapped != 3 {
			t.Fatalf("worker %d partial result=%+v", i, result)
		}
		total += result.Rewrapped
	}
	if total != 3 {
		t.Fatalf("total rewrapped=%d, want 3", total)
	}
	for i := 0; i < 3; i++ {
		encoded := credentialEnvelopeText(t, ctx, db, testCredentialID(fmt.Sprintf("credential-worker-%d", i)))
		envelope, _ := base64.RawURLEncoding.DecodeString(encoded)
		keyID, err := rotated.keyring.PurposeEnvelopeKeyID(credentialEnvelopePurpose(fmt.Sprintf("subject-worker-%d", i)), envelope)
		if err != nil || keyID != "master-b" {
			t.Fatalf("worker row key=%q err=%v", keyID, err)
		}
	}
}

func TestRewrapBatchIsBoundedAcrossAllPhases(t *testing.T) {
	ctx, db, old, rotated := newRewrapServices(t)
	for i := 0; i < 33; i++ {
		insertPasskeyCredential(t, ctx, db, old, testCredentialID(fmt.Sprintf("credential-%03d", i)), fmt.Sprintf("subject-%03d", i), true)
	}
	first, err := rotated.RewrapBatch(ctx, "")
	if err != nil || first.Rewrapped != 32 || first.Done || first.Cursor == "" {
		t.Fatalf("first batch=%+v err=%v", first, err)
	}
	second, err := rotated.RewrapBatch(ctx, first.Cursor)
	if err != nil || second.Rewrapped != 1 || second.Done || second.Cursor == "" {
		t.Fatalf("second batch=%+v err=%v", second, err)
	}
	if got := drainFromCursor(t, rotated, second.Cursor); got != 0 {
		t.Fatalf("remaining rewrapped=%d, want 0", got)
	}
}

func drainFromCursor(t *testing.T, service *Service, cursor string) int {
	t.Helper()
	total := 0
	for i := 0; i < 10; i++ {
		result, err := service.RewrapBatch(context.Background(), cursor)
		if err != nil {
			t.Fatal(err)
		}
		total += result.Rewrapped
		if result.Done {
			return total
		}
		cursor = result.Cursor
	}
	t.Fatal("cursor drain did not complete")
	return 0
}

type blockingPasskeyKeyring struct {
	EnvelopeKeyring
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (k *blockingPasskeyKeyring) SealEnvelope(purpose string, plaintext []byte) ([]byte, error) {
	k.once.Do(func() { close(k.entered) })
	<-k.release
	return k.EnvelopeKeyring.SealEnvelope(purpose, plaintext)
}

func TestRewrapBatchRetriesConcurrentCredentialVersionAndCeremonyConsume(t *testing.T) {
	ctx, db, old, rotated := newRewrapServices(t)
	credentialID := testCredentialID("credential-version")
	insertPasskeyCredential(t, ctx, db, old, credentialID, "subject-version", false)
	blocking := &blockingPasskeyKeyring{EnvelopeKeyring: rotated.keyring, entered: make(chan struct{}), release: make(chan struct{})}
	rotated.keyring = blocking
	resultCh := make(chan RewrapBatchResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := rotated.RewrapBatch(ctx, "")
		resultCh <- result
		errCh <- err
	}()
	<-blocking.entered
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "passkey-test-version-interpose", SQL: `UPDATE identity_webauthn_credentials SET credential_version=credential_version+1 WHERE credential_id=?`, Args: []any{credentialID}}); err != nil {
		t.Fatal(err)
	}
	close(blocking.release)
	result := <-resultCh
	err := <-errCh
	if err != nil || result.Rewrapped != 0 || result.Cursor == "" {
		t.Fatalf("version interposition result=%+v err=%v", result, err)
	}
	retried, err := rotated.RewrapBatch(ctx, result.Cursor)
	if err != nil || retried.Rewrapped != 1 {
		t.Fatalf("version retry result=%+v err=%v", retried, err)
	}

	// Ceremonies use the same exact-row CAS, including consumed state.
	rotated.keyring = testPasskeyKeyring(t, "master-b")
	digest := challengeDigest("consume-interpose")
	insertPasskeyCeremony(t, ctx, db, old, digest, "subject-consume", false)
	blocking = &blockingPasskeyKeyring{EnvelopeKeyring: rotated.keyring, entered: make(chan struct{}), release: make(chan struct{})}
	rotated.keyring = blocking
	resultCh = make(chan RewrapBatchResult, 1)
	errCh = make(chan error, 1)
	go func() {
		// Skip the credential phase and transition into ceremonies.
		cursor := encodeRewrapCursor(passkeyPhaseCeremonies, "")
		result, err := rotated.RewrapBatch(ctx, cursor)
		resultCh <- result
		errCh <- err
	}()
	<-blocking.entered
	attempt := strings.Repeat("a", 22)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "passkey-test-consume-interpose", SQL: `UPDATE identity_webauthn_ceremonies SET consumed_attempt=?,consumed_at_unix_ms=? WHERE code_digest=?`, Args: []any{attempt, int64(4), digest}}); err != nil {
		t.Fatal(err)
	}
	close(blocking.release)
	result = <-resultCh
	err = <-errCh
	if err != nil || result.Rewrapped != 0 || result.Cursor == "" {
		t.Fatalf("consume interposition result=%+v err=%v", result, err)
	}
	retried, err = rotated.RewrapBatch(ctx, result.Cursor)
	if err != nil || retried.Rewrapped != 1 {
		t.Fatalf("consume retry result=%+v err=%v", retried, err)
	}
}

func credentialEnvelopeText(t *testing.T, ctx context.Context, db *rhiza.DB, id string) string {
	t.Helper()
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential_json FROM identity_webauthn_credentials WHERE credential_id=?`, Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("credential query rows=%v err=%v", result.Rows, err)
	}
	return result.Rows[0][0].(string)
}
