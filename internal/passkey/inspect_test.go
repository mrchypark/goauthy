package passkey

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestInspectEnvelopeReferencesCountsLegacyAndAuthenticatedKeys(t *testing.T) {
	ctx, db, old, rotated := newRewrapServices(t)
	credentialID := testCredentialID("inspect-old")
	insertPasskeyCredential(t, ctx, db, old, credentialID, "inspect-subject", false)
	legacyID := testCredentialID("inspect-legacy")
	insertPasskeyCredential(t, ctx, db, old, legacyID, "inspect-legacy-subject", true)
	digest := challengeDigest("inspect-ceremony")
	insertPasskeyCeremony(t, ctx, db, old, digest, "inspect-ceremony-subject", false)
	mfaDigest := challengeDigest("inspect-mfa")
	insertPasskeyMFACeremony(t, ctx, db, old, mfaDigest, "inspect-mfa-subject", true)

	before := credentialEnvelopeText(t, ctx, db, credentialID)
	status, err := rotated.InspectEnvelopeReferences(ctx)
	if err != nil || status.Safe || status.ActiveMasterKeyID != "master-b" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if status.Credentials.ByKeyID["master-a"] != 1 || status.Credentials.Legacy != 1 || status.Credentials.Total != 2 {
		t.Fatalf("credentials=%+v", status.Credentials)
	}
	if status.Ceremonies.ByKeyID["master-a"] != 1 || status.Ceremonies.Total != 1 {
		t.Fatalf("ceremonies=%+v", status.Ceremonies)
	}
	if status.MFACeremonies.Legacy != 1 || status.MFACeremonies.Total != 1 {
		t.Fatalf("MFA ceremonies=%+v", status.MFACeremonies)
	}
	if got := credentialEnvelopeText(t, ctx, db, credentialID); got != before {
		t.Fatal("inspection mutated credential envelope")
	}

	if got := drainPasskeyRewrap(t, rotated); got != 4 {
		t.Fatalf("rewrapped=%d, want 4", got)
	}
	status, err = rotated.InspectEnvelopeReferences(ctx)
	if err != nil || !status.Safe || status.Credentials.ByKeyID["master-b"] != 2 || status.Credentials.Legacy != 0 || status.Ceremonies.ByKeyID["master-b"] != 1 || status.MFACeremonies.ByKeyID["master-b"] != 1 {
		t.Fatalf("post-rewrap status=%+v err=%v", status, err)
	}
}

func TestInspectEnvelopeReferencesFailsClosedForTamperAndUnknownKey(t *testing.T) {
	ctx, db, old, rotated := newRewrapServices(t)
	id := testCredentialID("inspect-unknown")
	insertPasskeyCredential(t, ctx, db, old, id, "inspect-unknown-subject", false)
	knownOnly := rotated
	knownOnly.keyring = testPasskeyKeyringOnly(t, "master-b")
	status, err := knownOnly.InspectEnvelopeReferences(ctx)
	if !errors.Is(err, ErrUnsafeEnvelopeReferences) || status.Safe {
		t.Fatalf("unknown key status=%+v err=%v", status, err)
	}

	ctx, db, _, rotated = newRewrapServices(t)
	id = testCredentialID("inspect-tamper")
	insertPasskeyCredential(t, ctx, db, rotated, id, "inspect-tamper-subject", false)
	encoded := credentialEnvelopeText(t, ctx, db, id)
	envelope, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	envelope[len(envelope)-1] ^= 1
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "passkey-inspect-tamper", SQL: `UPDATE identity_webauthn_credentials SET credential_json=? WHERE credential_id=?`, Args: []any{base64.RawURLEncoding.EncodeToString(envelope), id}}); err != nil {
		t.Fatal(err)
	}
	status, err = rotated.InspectEnvelopeReferences(ctx)
	if !errors.Is(err, ErrUnsafeEnvelopeReferences) || status.Safe {
		t.Fatalf("tamper status=%+v err=%v", status, err)
	}
}

func TestInspectEnvelopeReferencesScansDeterministicBoundedPages(t *testing.T) {
	ctx, db, _, rotated := newRewrapServices(t)
	for i := 0; i < passkeyReferenceScanLimit+1; i++ {
		id := testCredentialID("inspect-page-" + strings.Repeat("0", 2) + string(rune('a'+i)))
		insertPasskeyCredential(t, ctx, db, rotated, id, "inspect-page-subject-"+string(rune('a'+i)), false)
	}
	first, err := rotated.InspectEnvelopeReferences(ctx)
	if err != nil || !first.Safe || first.Credentials.Total != passkeyReferenceScanLimit+1 || first.Credentials.ByKeyID["master-b"] != passkeyReferenceScanLimit+1 {
		t.Fatalf("status=%+v err=%v", first, err)
	}
	second, err := rotated.InspectEnvelopeReferences(ctx)
	if err != nil || second.Credentials.Total != first.Credentials.Total || second.Credentials.ByKeyID["master-b"] != first.Credentials.ByKeyID["master-b"] || !bytes.Equal([]byte(second.ActiveMasterKeyID), []byte(first.ActiveMasterKeyID)) {
		t.Fatalf("non-deterministic status first=%+v second=%+v err=%v", first, second, err)
	}
}

func TestIncompleteAuthenticatedCredentialFailsRewrapAndInspection(t *testing.T) {
	ctx, db, old, rotated := newRewrapServices(t)
	id := testCredentialID("inspect-incomplete")
	idBytes, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(wa.Credential{ID: idBytes})
	if err != nil {
		t.Fatal(err)
	}
	envelope, _, err := old.encryptDB(plain, credentialEnvelopePurpose("inspect-incomplete-subject"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "passkey-incomplete-credential", SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,credential_version,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?)`, Args: []any{id, "inspect-incomplete-subject", "incomplete", base64.RawURLEncoding.EncodeToString(envelope), int64(0), int64(0), int64(0), int64(1), int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.RewrapBatch(ctx, ""); err == nil {
		t.Fatal("incomplete authenticated credential rewrapped")
	}
	status, err := rotated.InspectEnvelopeReferences(ctx)
	if !errors.Is(err, ErrUnsafeEnvelopeReferences) || status.Safe {
		t.Fatalf("incomplete status=%+v err=%v", status, err)
	}
}
