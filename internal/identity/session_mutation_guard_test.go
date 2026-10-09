package identity

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

const guardTestPeer = "192.0.2.14"

func createIdentityGuardSession(t *testing.T, store *Store, subject string) (*browser.Store, browser.Session, string, []any) {
	t.Helper()
	ctx := context.Background()
	browserStore, err := browser.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := browserStore.CreateSession(ctx, subject, "mfa", time.Now().Add(time.Hour), guardTestPeer)
	if err != nil {
		t.Fatal(err)
	}
	guard, args := browserStore.SessionAuthorizationGuard(issued.Session, guardTestPeer)
	return browserStore, issued.Session, guard, args
}

func seedGuardedPasskeyConversion(t *testing.T, store *Store) {
	t.Helper()
	ctx := context.Background()
	bootstrapPassword(t, store, "subject-guard", "guard-user", []byte("CurrentPassword1"))
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "guarded-conversion-credential",
		SQL:       `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,credential_version,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?)`,
		Args:      []any{"guard-credential", "subject-guard", "primary", "ciphertext", int64(0), int64(0), int64(1), time.Now().UnixMilli(), time.Now().UnixMilli()},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConvertToPasskeyOnlyWithGuardRejectsRevokedSessionAndAllowsCurrentSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testConversionStore(t)
	seedGuardedPasskeyConversion(t, store)
	browserStore, session, guard, args := createIdentityGuardSession(t, store, "subject-guard")
	if err := browserStore.RevokeSessionID(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.ConvertToPasskeyOnlyWithGuard(ctx, "subject-guard", guard, args); err == nil {
		t.Fatal("conversion succeeded after the authorizing browser session was revoked")
	}
	if passkeyOnly, err := store.IsPasskeyOnly(ctx, "subject-guard"); err != nil || passkeyOnly {
		t.Fatalf("revoked-session conversion changed authentication mode: passkeyOnly=%v err=%v", passkeyOnly, err)
	}
	if got := passwordPHC(t, store, "guard-user"); got == "" {
		t.Fatal("revoked-session conversion removed the password")
	}

	current := testConversionStore(t)
	seedGuardedPasskeyConversion(t, current)
	_, _, currentGuard, currentArgs := createIdentityGuardSession(t, current, "subject-guard")
	if err := current.ConvertToPasskeyOnlyWithGuard(ctx, "subject-guard", currentGuard, currentArgs); err != nil {
		t.Fatalf("current-session conversion failed: %v", err)
	}
	if passkeyOnly, err := current.IsPasskeyOnly(ctx, "subject-guard"); err != nil || !passkeyOnly {
		t.Fatalf("current-session conversion did not commit: passkeyOnly=%v err=%v", passkeyOnly, err)
	}
}

func TestUnlinkExternalWithGuardRejectsRevokedSessionIncludingAbsentMapping(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	bootstrapPassword(t, store, "subject-guard", "guard-user", []byte("CurrentPassword1"))
	external := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "guarded-external"}
	if _, err := store.LinkExternal(ctx, "subject-guard", external, time.Now()); err != nil {
		t.Fatal(err)
	}
	browserStore, session, guard, args := createIdentityGuardSession(t, store, "subject-guard")
	if err := browserStore.RevokeSessionID(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.UnlinkExternalWithGuard(ctx, "subject-guard", external.ProviderID, time.Now(), "revoked-existing", guard, args); err == nil {
		t.Fatal("unlink succeeded after the authorizing browser session was revoked")
	}
	if _, found, err := store.FindExternalLink(ctx, external); err != nil || !found {
		t.Fatalf("revoked-session unlink changed the mapping: found=%v err=%v", found, err)
	}

	if err := store.UnlinkExternal(ctx, "subject-guard", external.ProviderID, time.Now(), "trusted-absent"); err != nil {
		t.Fatal(err)
	}
	if err := store.UnlinkExternalWithGuard(ctx, "subject-guard", external.ProviderID, time.Now(), "revoked-absent", guard, args); err == nil {
		t.Fatal("revoked session was accepted because the mapping was already absent")
	}

	_, _, currentGuard, currentArgs := createIdentityGuardSession(t, store, "subject-guard")
	if err := store.UnlinkExternalWithGuard(ctx, "subject-guard", external.ProviderID, time.Now(), "current-absent", currentGuard, currentArgs); err != nil {
		t.Fatalf("current-session unlink of absent mapping should remain idempotent: %v", err)
	}
	if _, err := store.LinkExternal(ctx, "subject-guard", external, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.UnlinkExternalWithGuard(ctx, "subject-guard", external.ProviderID, time.Now(), "current-existing", currentGuard, currentArgs); err != nil {
		t.Fatalf("current-session unlink failed: %v", err)
	}
	if _, found, err := store.FindExternalLink(ctx, external); err != nil || found {
		t.Fatalf("current-session unlink did not remove the mapping: found=%v err=%v", found, err)
	}
}
