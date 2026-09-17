package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"golang.org/x/crypto/argon2"
)

func TestBootstrapConcurrentAndNeverResetsCredential(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	first, err := credential.Hash([]byte("first password"))
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.BootstrapUser(ctx, "subject-1", "alice", first)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	second, err := credential.Hash([]byte("second password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapUser(ctx, "subject-1", "alice", second); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Authenticate(ctx, "alice", []byte("first password")); err != nil || got.Subject != "subject-1" {
		t.Fatalf("original authentication=%#v err=%v", got, err)
	}
	if _, err := store.Authenticate(ctx, "alice", []byte("second password")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("credential was reset: %v", err)
	}
	if revision, _ := principalVersion(t, store, "subject-1"); revision != 1 {
		t.Fatalf("principal revision=%d", revision)
	}
}

func TestBootstrapCreatesPrincipalVersionWithoutReset(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	first := time.UnixMilli(1_000)
	store.now = func() time.Time { return first }
	password, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapUser(ctx, "subject-1", "alice", password); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return first.Add(time.Hour) }
	if _, err := store.BootstrapUser(ctx, "subject-1", "alice", password); err != nil {
		t.Fatal(err)
	}
	if revision, updatedAt := principalVersion(t, store, "subject-1"); revision != 1 || updatedAt != first.UnixMilli() {
		t.Fatalf("principal version=(%d,%d)", revision, updatedAt)
	}
}

func TestAuthenticateHidesUnknownDisabledAndBadPassword(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	password, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapUser(ctx, "subject-1", "alice", password); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "identity-test-disable",
		SQL:       `UPDATE identity_users SET disabled = 1 WHERE username = ?`,
		Args:      []any{"alice"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, username, password string
	}{
		{"unknown", "nobody", "correct password"},
		{"disabled", "alice", "correct password"},
		{"bad password", "alice", "wrong password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.Authenticate(ctx, tc.username, []byte(tc.password)); err != ErrInvalidCredentials {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestUserBySubjectAndVerifyPassword(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	password := []byte("CurrentPassword1")
	bootstrapPassword(t, store, "subject-1", "alice", password)

	user, err := store.UserBySubject(ctx, "subject-1")
	if err != nil || user != (User{Subject: "subject-1", Username: "alice"}) {
		t.Fatalf("user=%#v err=%v", user, err)
	}
	before := passwordPHC(t, store, "alice")
	if err := store.VerifyPassword(ctx, "subject-1", password); err != nil {
		t.Fatalf("valid password err=%v", err)
	}
	if after := passwordPHC(t, store, "alice"); after != before {
		t.Fatal("password verification changed the credential")
	}
	for _, tc := range []struct {
		name, subject, password string
	}{
		{"wrong", "subject-1", "wrong password"},
		{"missing", "subject-missing", "CurrentPassword1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.VerifyPassword(ctx, tc.subject, []byte(tc.password)); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-test-verify-password-disable", SQL: `UPDATE identity_users SET disabled = 1 WHERE subject = ?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UserBySubject(ctx, "subject-1"); !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("disabled user err=%v", err)
	}
	if err := store.VerifyPassword(ctx, "subject-1", password); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled password err=%v", err)
	}
}

func TestAccountProfileBySubjectIsActiveAndUsesSafeEmailFallbacks(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	bootstrapPassword(t, store, "subject-1", "alice@example.test", []byte("CurrentPassword1"))
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "identity-profile-test",
		SQL:       `INSERT INTO identity_user_profiles (subject,email,email_verified,preferred_username,given_name,family_name) VALUES (?,?,?,?,?,?)`,
		Args:      []any{"subject-1", "profile@example.test", int64(1), "Alice", "Alice", "Example"},
	}); err != nil {
		t.Fatal(err)
	}
	profile, err := store.AccountProfileBySubject(ctx, "subject-1")
	if err != nil || profile != (AccountProfile{Subject: "subject-1", Username: "alice@example.test", Email: "profile@example.test", EmailVerified: true, PreferredUsername: "Alice", GivenName: "Alice", FamilyName: "Example"}) {
		t.Fatalf("profile=%#v err=%v", profile, err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-profile-delete", SQL: `DELETE FROM identity_user_profiles WHERE subject = ?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	profile, err = store.AccountProfileBySubject(ctx, "subject-1")
	if err != nil || profile.Email != "alice@example.test" {
		t.Fatalf("username email fallback=%#v err=%v", profile, err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-profile-invalid", SQL: `UPDATE identity_users SET username = ? WHERE subject = ?`, Args: []any{"not-an-email", "subject-1"}}); err != nil {
		t.Fatal(err)
	}
	profile, err = store.AccountProfileBySubject(ctx, "subject-1")
	if err != nil || profile.Email != "" {
		t.Fatalf("missing email must fail closed profile=%#v err=%v", profile, err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-profile-disable", SQL: `UPDATE identity_users SET disabled = 1 WHERE subject = ?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AccountProfileBySubject(ctx, "subject-1"); !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("disabled profile err=%v", err)
	}
}

func TestVerifyPasswordRejectsExpiredPassword(t *testing.T) {
	rules := testRules(1)
	rules.ValidDays = 1
	store := testStoreWithRules(t, rules)
	base := time.UnixMilli(1_000)
	store.now = func() time.Time { return base }
	password := []byte("CurrentPassword1")
	bootstrapPassword(t, store, "subject-1", "alice", password)
	store.now = func() time.Time { return base.Add(24*time.Hour + time.Millisecond) }
	if err := store.VerifyPassword(context.Background(), "subject-1", password); !errors.Is(err, ErrPasswordExpired) {
		t.Fatalf("expired password err=%v", err)
	}
}

func TestConvertToPasskeyOnlyErasesPasswordAdmissionAndArtifacts(t *testing.T) {
	store := testConversionStore(t)
	ctx := context.Background()
	now := time.UnixMilli(17_000)
	store.now = func() time.Time { return now }
	seedDeterministicRandom(store)
	password := []byte("CurrentPassword1")
	bootstrapPassword(t, store, "subject-1", "alice", password)
	if err := store.ChangePassword(ctx, "subject-1", password, []byte("ChangedPassword2")); err != nil {
		t.Fatal(err)
	}
	token, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "conversion-uv-credential", SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,credential_version,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?)`, Args: []any{"credential-id", "subject-1", "primary", "ciphertext", int64(0), int64(0), int64(1), now.UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	mfaToken := strings.Repeat("a", 43)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "conversion-mfa", SQL: `INSERT INTO identity_mfa_mod_tokens (token_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{mfaToken, "subject-1", strings.Repeat("b", 43), now.Add(time.Minute).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "conversion-mfa-factor", SQL: `INSERT INTO identity_mfa_mod_token_factors (token_digest,proof_kind) VALUES (?,?)`, Args: []any{mfaToken, "password"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "conversion-webauthn-ceremony", SQL: `INSERT INTO identity_webauthn_ceremonies (code_digest,purpose,subject,session_digest,interaction_digest,passkey_name,session_json,expires_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{strings.Repeat("g", 43), "register", "subject-1", strings.Repeat("s", 43), nil, "pending", "ciphertext", now.Add(time.Minute).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "conversion-mfa-ceremony", SQL: `INSERT INTO identity_webauthn_mfa_ceremonies (code_digest,subject,session_digest,session_json,expires_at_unix_ms,proof_expires_at_unix_ms) VALUES (?,?,?,?,?,?)`, Args: []any{strings.Repeat("h", 43), "subject-1", strings.Repeat("s", 43), "ciphertext", now.Add(time.Minute).UnixMilli(), now.Add(2 * time.Minute).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "conversion-mfa-ceremony-purpose", SQL: `INSERT INTO identity_webauthn_service_ceremony_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{strings.Repeat("h", 43), "MfaModToken"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "conversion-mfa-proof", SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{strings.Repeat("p", 43), "subject-1", strings.Repeat("s", 43), now.Add(2 * time.Minute).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "conversion-mfa-proof-purpose", SQL: `INSERT INTO identity_webauthn_service_proof_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{strings.Repeat("p", 43), "MfaModToken"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ConvertToPasskeyOnly(ctx, "subject-1"); err != nil {
		t.Fatal(err)
	}
	passkeyOnly, err := store.IsPasskeyOnly(ctx, "subject-1")
	if err != nil || !passkeyOnly {
		t.Fatalf("passkeyOnly=%v err=%v", passkeyOnly, err)
	}
	generation, changed := passwordMetadata(t, store, "subject-1")
	if generation != 3 || changed != now.UnixMilli() || passwordPHC(t, store, "alice") != "" {
		t.Fatalf("password state generation=%d changed=%d phc=%q", generation, changed, passwordPHC(t, store, "alice"))
	}
	for _, sql := range []string{
		`SELECT count(*) FROM identity_password_history WHERE subject = 'subject-1'`,
		`SELECT count(*) FROM identity_password_reset_tokens WHERE subject = 'subject-1'`,
		`SELECT count(*) FROM identity_mfa_mod_tokens WHERE subject = 'subject-1'`,
		`SELECT count(*) FROM identity_mfa_mod_token_factors WHERE token_digest = '` + mfaToken + `'`,
		`SELECT count(*) FROM identity_webauthn_ceremonies WHERE subject = 'subject-1'`,
		`SELECT count(*) FROM identity_webauthn_service_ceremony_purposes WHERE code_digest = '` + strings.Repeat("h", 43) + `'`,
		`SELECT count(*) FROM identity_webauthn_mfa_ceremonies WHERE subject = 'subject-1'`,
		`SELECT count(*) FROM identity_webauthn_service_proof_purposes WHERE code_digest = '` + strings.Repeat("p", 43) + `'`,
		`SELECT count(*) FROM identity_webauthn_mfa_proofs WHERE subject = 'subject-1'`,
		`SELECT count(*) FROM identity_users WHERE subject = 'subject-1' AND password_phc <> ''`,
	} {
		assertCount(t, store, sql, 0)
	}
	if _, err := store.Authenticate(ctx, "alice", []byte("ChangedPassword2")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("authenticate err=%v", err)
	}
	if err := store.VerifyPassword(ctx, "subject-1", []byte("ChangedPassword2")); !errors.Is(err, ErrPasswordAuthenticationDisabled) {
		t.Fatalf("verify err=%v", err)
	}
	if err := store.ChangePassword(ctx, "subject-1", []byte("ChangedPassword2"), []byte("NewPassword3")); !errors.Is(err, ErrPasswordAuthenticationDisabled) {
		t.Fatalf("change err=%v", err)
	}
	if _, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("issue reset err=%v", err)
	}
	if _, err := store.BeginPasswordReset(ctx, "subject-1", token); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("begin reset err=%v", err)
	}
}

func TestConvertToPasskeyOnlyRequiresVerifiedCredentialAndHasOneWinner(t *testing.T) {
	store := testConversionStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(19_000) }
	seedDeterministicRandom(store)
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	if err := store.ConvertToPasskeyOnly(ctx, "subject-1"); !errors.Is(err, ErrPasswordAuthenticationDisabled) {
		t.Fatalf("without credential err=%v", err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "conversion-no-uv", SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,credential_version,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?)`, Args: []any{"credential-id", "subject-1", "primary", "ciphertext", int64(0), int64(0), int64(0), int64(0), int64(0)}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ConvertToPasskeyOnly(ctx, "subject-1"); !errors.Is(err, ErrPasswordAuthenticationDisabled) {
		t.Fatalf("without UV err=%v", err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "conversion-add-uv", SQL: `UPDATE identity_webauthn_credentials SET user_verified = 1 WHERE credential_id = ?`, Args: []any{"credential-id"}}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; errs <- store.ConvertToPasskeyOnly(ctx, "subject-1") }()
	}
	close(start)
	wg.Wait()
	close(errs)
	winners := 0
	for err := range errs {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrPasswordAuthenticationDisabled) {
			t.Fatalf("conversion err=%v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners=%d", winners)
	}
	if err := store.ConvertToPasskeyOnly(ctx, "subject-1"); !errors.Is(err, ErrPasswordAuthenticationDisabled) {
		t.Fatalf("repeat err=%v", err)
	}
}

func TestSetPasswordWithWebAuthnProofRequiresFreshPasswordNewProof(t *testing.T) {
	store := testConversionStore(t)
	ctx := context.Background()
	now := time.UnixMilli(31_000)
	store.now = func() time.Time { return now }
	seedDeterministicRandom(store)
	makePasskeyOnly(t, store, "subject-1", "alice")
	session := digestForTest("session-1")
	proof := strings.Repeat("A", 48)
	seedServiceProof(t, store, proof, "subject-1", session, "PasswordNew", now.Add(time.Minute))

	if err := store.SetPasswordWithWebAuthnProof(ctx, "subject-1", digestForTest("wrong-session"), proof, []byte("RecoveredPassword2")); !errors.Is(err, ErrPasswordAuthenticationDisabled) {
		t.Fatalf("wrong session err=%v", err)
	}
	assertProofUnconsumed(t, store, proof)
	if err := store.SetPasswordWithWebAuthnProof(ctx, "subject-2", session, proof, []byte("RecoveredPassword2")); !errors.Is(err, ErrPasswordAuthenticationDisabled) {
		t.Fatalf("wrong subject err=%v", err)
	}
	assertProofUnconsumed(t, store, proof)
	if err := store.SetPasswordWithWebAuthnProof(ctx, "subject-1", session, proof, []byte("short1A")); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("policy err=%v", err)
	}
	assertProofUnconsumed(t, store, proof)

	wrongPurpose := strings.Repeat("B", 48)
	seedServiceProof(t, store, wrongPurpose, "subject-1", session, "MfaModToken", now.Add(time.Minute))
	if err := store.SetPasswordWithWebAuthnProof(ctx, "subject-1", session, wrongPurpose, []byte("RecoveredPassword2")); !errors.Is(err, ErrPasswordAuthenticationDisabled) {
		t.Fatalf("wrong purpose err=%v", err)
	}
	assertProofUnconsumed(t, store, wrongPurpose)
	expired := strings.Repeat("D", 48)
	seedServiceProof(t, store, expired, "subject-1", session, "PasswordNew", now)
	if err := store.SetPasswordWithWebAuthnProof(ctx, "subject-1", session, expired, []byte("RecoveredPassword2")); !errors.Is(err, ErrPasswordAuthenticationDisabled) {
		t.Fatalf("expired proof err=%v", err)
	}
	assertProofUnconsumed(t, store, expired)

	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "reverse-mfa-token", SQL: `INSERT INTO identity_mfa_mod_tokens (token_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{digestForTest("token"), "subject-1", session, now.Add(time.Minute).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPasswordWithWebAuthnProof(ctx, "subject-1", session, proof, []byte("RecoveredPassword2")); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyPassword(ctx, "subject-1", []byte("RecoveredPassword2")); err != nil {
		t.Fatalf("password authentication err=%v", err)
	}
	if passkeyOnly, err := store.IsPasskeyOnly(ctx, "subject-1"); err != nil || passkeyOnly {
		t.Fatalf("passkey-only=%t err=%v", passkeyOnly, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE subject = 'subject-1'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_history WHERE subject = 'subject-1'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_mfa_mod_tokens WHERE subject = 'subject-1'`, 0)
	if err := store.SetPasswordWithWebAuthnProof(ctx, "subject-1", session, proof, []byte("AnotherPassword3")); !errors.Is(err, ErrPasswordAuthenticationDisabled) {
		t.Fatalf("replay err=%v", err)
	}
}

func TestSetPasswordWithWebAuthnProofDisabledAndConcurrentExactlyOneWinner(t *testing.T) {
	store := testConversionStore(t)
	policy := credential.DefaultPolicy()
	policy.MaxConcurrency = 8
	var err error
	store.hasher, err = credential.NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.UnixMilli(32_000)
	store.now = func() time.Time { return now }
	seedDeterministicRandom(store)
	makePasskeyOnly(t, store, "subject-1", "alice")
	session := digestForTest("session-1")
	proof := strings.Repeat("C", 48)
	seedServiceProof(t, store, proof, "subject-1", session, "PasswordNew", now.Add(time.Minute))
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "reverse-disable", SQL: `UPDATE identity_users SET disabled=1 WHERE subject=?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPasswordWithWebAuthnProof(ctx, "subject-1", session, proof, []byte("RecoveredPassword2")); !errors.Is(err, ErrPasswordAuthenticationDisabled) {
		t.Fatalf("disabled err=%v", err)
	}
	assertProofUnconsumed(t, store, proof)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "reverse-enable", SQL: `UPDATE identity_users SET disabled=0 WHERE subject=?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- store.SetPasswordWithWebAuthnProof(ctx, "subject-1", session, proof, []byte("RecoveredPassword2"))
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	winners := 0
	for err := range errs {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrPasswordAuthenticationDisabled) {
			t.Fatalf("conversion err=%v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners=%d", winners)
	}
	if err := store.VerifyPassword(ctx, "subject-1", []byte("RecoveredPassword2")); err != nil {
		t.Fatalf("password authentication err=%v", err)
	}
}

func TestMissingAuthenticationModeFailsClosedForEveryPasswordPath(t *testing.T) {
	store := testConversionStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(23_000) }
	seedDeterministicRandom(store)
	password := []byte("CurrentPassword1")
	bootstrapPassword(t, store, "subject-1", "alice", password)
	token, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	challenge := beginPasswordReset(t, store, "subject-1", token)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "delete-auth-mode", SQL: `DELETE FROM identity_authentication_modes WHERE subject = ?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, "alice", password); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("authenticate err=%v", err)
	}
	if err := store.VerifyPassword(ctx, "subject-1", password); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("verify err=%v", err)
	}
	if err := store.ChangePassword(ctx, "subject-1", password, []byte("ChangedPassword2")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("change err=%v", err)
	}
	if _, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("issue reset err=%v", err)
	}
	if _, err := store.BeginPasswordReset(ctx, "subject-1", token); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("begin reset err=%v", err)
	}
	if _, err := store.ResetPassword(ctx, "subject-1", token, challenge.CookieToken, challenge.CSRFToken, []byte("ChangedPassword2"), ""); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("reset err=%v", err)
	}
}

func TestBootstrapRejectsMalformedInput(t *testing.T) {
	store := testStore(t)
	valid, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{"", "Alice", "alice ", "álîce", "-alice", "a!"} {
		if _, err := store.BootstrapUser(context.Background(), "subject-1", username, valid); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("username %q err=%v", username, err)
		}
	}
	if _, err := store.BootstrapUser(context.Background(), " subject-1", "alice", valid); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("subject err=%v", err)
	}
	if _, err := store.BootstrapUser(context.Background(), "subject-1", "alice", "not-a-phc"); !errors.Is(err, ErrInvalidPasswordCredential) {
		t.Fatalf("PHC err=%v", err)
	}
	if _, err := store.Authenticate(context.Background(), "Alice", []byte("password")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("authentication username err=%v", err)
	}
}

func TestBootstrapConflictingIdentityFails(t *testing.T) {
	store := testStore(t)
	password, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapUser(context.Background(), "subject-1", "alice", password); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapUser(context.Background(), "subject-2", "alice", password); !errors.Is(err, ErrBootstrapConflict) {
		t.Fatalf("username collision err=%v", err)
	}
	if _, err := store.BootstrapUser(context.Background(), "subject-1", "bob", password); !errors.Is(err, ErrBootstrapConflict) {
		t.Fatalf("subject collision err=%v", err)
	}
}

func TestBootstrapUsesInjectedHasherPolicy(t *testing.T) {
	policy := credential.DefaultPolicy()
	policy.MemoryKiB = 20 * 1024
	hasher, err := credential.NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	password, err := hasher.Hash(context.Background(), []byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	store := testStoreWithHasher(t, hasher)
	if _, err := store.BootstrapUser(context.Background(), "subject-1", "alice", password); err != nil {
		t.Fatalf("bootstrap with injected policy: %v", err)
	}
}

func TestAuthenticateUpgradesLegacyCredentialAfterSuccess(t *testing.T) {
	store := testStore(t)
	password := []byte("correct password")
	salt := []byte("1234567890abcdef")
	legacy := "$argon2id$v=19$m=8192,t=1,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(argon2.IDKey(password, salt, 1, 8192, 1, 32))
	if _, err := store.BootstrapUser(context.Background(), "subject-1", "alice", legacy); !errors.Is(err, ErrInvalidPasswordCredential) {
		t.Fatalf("bootstrap legacy credential err=%v", err)
	}
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
		RequestID: "identity-test-import-legacy",
		SQL:       `INSERT INTO identity_users (subject, username, password_phc) VALUES (?, ?, ?)`,
		Args:      []any{"subject-1", "alice", legacy},
	}); err != nil {
		t.Fatal(err)
	}
	ensureTestPasswordMode(t, store, "subject-1")
	got, err := store.Authenticate(context.Background(), "alice", password)
	if err != nil || got.Subject != "subject-1" || got.NeedsRehash {
		t.Fatalf("authentication=%#v err=%v", got, err)
	}
	if err := credential.ValidateCurrentPHC(passwordPHC(t, store, "alice")); err != nil {
		t.Fatalf("legacy credential was not upgraded: %v", err)
	}
	if got, err := store.Authenticate(context.Background(), "alice", []byte("wrong password")); !errors.Is(err, ErrInvalidCredentials) || got.NeedsRehash {
		t.Fatalf("failed authentication=%#v err=%v", got, err)
	}
}

func TestExistingBootstrapSurvivesPolicyRolloutAndUpgradesOnLogin(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	password := []byte("correct password")
	oldPHC, err := credential.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapUser(ctx, "subject-1", "alice", oldPHC); err != nil {
		t.Fatal(err)
	}

	policy := credential.DefaultPolicy()
	policy.MemoryKiB = 32 * 1024
	policy.Iterations = 3
	policy.Parallelism = 2
	hasher, err := credential.NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	rolled, err := NewStoreWithHasher(store.db, hasher)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rolled.BootstrapUser(ctx, "subject-1", "alice", oldPHC); err != nil {
		t.Fatalf("existing bootstrap under new policy: %v", err)
	}
	if _, err := rolled.Authenticate(ctx, "alice", password); err != nil {
		t.Fatalf("authenticate after policy rollout: %v", err)
	}
	if err := hasher.ValidateCurrentPHC(passwordPHC(t, rolled, "alice")); err != nil {
		t.Fatalf("credential was not upgraded: %v", err)
	}
}

func TestAuthenticateDoesNotDowngradeStrongerOrMixedCredentials(t *testing.T) {
	ctx := context.Background()
	password := []byte("correct password")
	policy := credential.DefaultPolicy()
	policy.MemoryKiB = 20 * 1024
	hasher, err := credential.NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	store := testStoreWithHasher(t, hasher)
	for _, tc := range []struct {
		name, username, phc string
	}{
		{"stronger", "alice", testPHC(password, 24*1024, 2, 1)},
		{"mixed", "bob", testPHC(password, 19*1024, 3, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
				RequestID: "identity-test-import-" + tc.username,
				SQL:       `INSERT INTO identity_users (subject, username, password_phc) VALUES (?, ?, ?)`,
				Args:      []any{"subject-" + tc.username, tc.username, tc.phc},
			}); err != nil {
				t.Fatal(err)
			}
			ensureTestPasswordMode(t, store, "subject-"+tc.username)
			if got, err := store.Authenticate(ctx, tc.username, password); err != nil || got.NeedsRehash {
				t.Fatalf("authentication=%#v err=%v", got, err)
			}
			if got := passwordPHC(t, store, tc.username); got != tc.phc {
				t.Fatal("credential was downgraded or rewritten")
			}
		})
	}
}

func TestAuthenticateDoesNotRehashWrongOrDisabledCredential(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	legacy := testPHC([]byte("correct password"), 8*1024, 1, 1)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "identity-test-import-legacy-no-mutation",
		SQL:       `INSERT INTO identity_users (subject, username, password_phc) VALUES (?, ?, ?)`,
		Args:      []any{"subject-1", "alice", legacy},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, "alice", []byte("wrong password")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password err=%v", err)
	}
	if got := passwordPHC(t, store, "alice"); got != legacy {
		t.Fatal("wrong password mutated credential")
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "identity-test-disable-before-rehash",
		SQL:       `UPDATE identity_users SET disabled = 1 WHERE username = ?`,
		Args:      []any{"alice"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, "alice", []byte("correct password")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled err=%v", err)
	}
	if got := passwordPHC(t, store, "alice"); got != legacy {
		t.Fatal("disabled credential mutated")
	}
}

func TestAuthenticateConcurrentLegacyUpgradeIsSafe(t *testing.T) {
	ctx := context.Background()
	policy := credential.DefaultPolicy()
	policy.MaxConcurrency = 3
	hasher, err := credential.NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	store := testStoreWithHasher(t, hasher)
	password := []byte("correct password")
	legacy := testPHC(password, 8*1024, 1, 1)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "identity-test-import-concurrent-legacy",
		SQL:       `INSERT INTO identity_users (subject, username, password_phc) VALUES (?, ?, ?)`,
		Args:      []any{"subject-1", "alice", legacy},
	}); err != nil {
		t.Fatal(err)
	}
	ensureTestPasswordMode(t, store, "subject-1")
	start := make(chan struct{})
	errs := make(chan error, 3)
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.Authenticate(ctx, "alice", password)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent authentication: %v", err)
		}
	}
	if err := hasher.ValidateCurrentPHC(passwordPHC(t, store, "alice")); err != nil {
		t.Fatalf("final credential is not current: %v", err)
	}
	if _, err := store.Authenticate(ctx, "alice", password); err != nil {
		t.Fatalf("upgraded credential does not authenticate: %v", err)
	}
}

func TestChangePasswordRulesHistoryAndMetadata(t *testing.T) {
	ctx := context.Background()
	rules := testRules(3)
	store := testStoreWithRules(t, rules)
	store.now = func() time.Time { return time.UnixMilli(1000) }
	current := []byte("CurrentPassword1")
	bootstrapPassword(t, store, "subject-1", "alice", current)

	store.now = func() time.Time { return time.UnixMilli(2000) }
	first := []byte("FirstPassword2")
	if err := store.ChangePassword(ctx, "subject-1", current, first); err != nil {
		t.Fatal(err)
	}
	if generation, changed := passwordMetadata(t, store, "subject-1"); generation != 2 || changed != 2000 {
		t.Fatalf("generation=%d changed=%d", generation, changed)
	}
	if got := passwordHistory(t, store, "subject-1"); len(got) != 1 {
		t.Fatalf("history=%#v", got)
	}
	if err := store.ChangePassword(ctx, "subject-1", first, []byte("short1A")); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("weak password err=%v", err)
	}
	if err := store.ChangePassword(ctx, "subject-1", first, current); !errors.Is(err, ErrPasswordReuse) {
		t.Fatalf("current history reuse err=%v", err)
	}
}

func TestChangePasswordHistoryDepthThree(t *testing.T) {
	ctx := context.Background()
	store := testStoreWithRules(t, testRules(3))
	passwords := [][]byte{[]byte("PasswordZero1"), []byte("PasswordOne2"), []byte("PasswordTwo3"), []byte("PasswordThree4")}
	bootstrapPassword(t, store, "subject-1", "alice", passwords[0])
	for i := 1; i < len(passwords); i++ {
		store.now = func() time.Time { return time.UnixMilli(int64(1000 + i)) }
		if err := store.ChangePassword(ctx, "subject-1", passwords[i-1], passwords[i]); err != nil {
			t.Fatalf("change %d: %v", i, err)
		}
	}
	if err := store.ChangePassword(ctx, "subject-1", passwords[3], passwords[1]); !errors.Is(err, ErrPasswordReuse) {
		t.Fatalf("recent password err=%v", err)
	}
	if err := store.ChangePassword(ctx, "subject-1", passwords[3], passwords[0]); err != nil {
		t.Fatalf("oldest password should be pruned: %v", err)
	}
}

func TestChangePasswordHistoryZeroStoresNoHistory(t *testing.T) {
	store := testStoreWithRules(t, testRules(0))
	current := []byte("CurrentPassword1")
	next := []byte("NextPassword2")
	bootstrapPassword(t, store, "subject-1", "alice", current)
	if err := store.ChangePassword(context.Background(), "subject-1", current, next); err != nil {
		t.Fatal(err)
	}
	if got := passwordHistory(t, store, "subject-1"); len(got) != 0 {
		t.Fatalf("history=%#v", got)
	}
	if err := store.ChangePassword(context.Background(), "subject-1", next, next); !errors.Is(err, ErrPasswordReuse) {
		t.Fatalf("current reuse err=%v", err)
	}
}

func TestChangePasswordDoesNotMutateInvalidCurrentOrDisabled(t *testing.T) {
	ctx := context.Background()
	store := testStoreWithRules(t, testRules(3))
	current := []byte("CurrentPassword1")
	next := []byte("NextPassword2")
	bootstrapPassword(t, store, "subject-1", "alice", current)
	beforePHC := passwordPHC(t, store, "alice")
	beforeGeneration, beforeChanged := passwordMetadata(t, store, "subject-1")
	for _, tc := range []struct {
		name, subject string
		current       []byte
		disable       bool
	}{
		{"unknown", "unknown", current, false},
		{"wrong", "subject-1", []byte("WrongPassword1"), false},
		{"disabled", "subject-1", current, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disable {
				if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "disable-change-password", SQL: `UPDATE identity_users SET disabled = 1 WHERE subject = ?`, Args: []any{"subject-1"}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.ChangePassword(ctx, tc.subject, tc.current, next); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if got := passwordPHC(t, store, "alice"); got != beforePHC {
		t.Fatal("failed change rewrote credential")
	}
	if generation, changed := passwordMetadata(t, store, "subject-1"); generation != beforeGeneration || changed != beforeChanged {
		t.Fatalf("failed change metadata generation=%d changed=%d", generation, changed)
	}
}

func TestChangePasswordConcurrentExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	store := testStoreWithRules(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(2000) }
	current := []byte("CurrentPassword1")
	bootstrapPassword(t, store, "subject-1", "alice", current)
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, next := range [][]byte{[]byte("FirstPassword2"), []byte("SecondPassword3")} {
		go func(next []byte) {
			<-start
			errs <- store.ChangePassword(ctx, "subject-1", current, next)
		}(next)
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-errs; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes=%d", successes)
	}
	if generation, _ := passwordMetadata(t, store, "subject-1"); generation != 2 {
		t.Fatalf("generation=%d", generation)
	}
}

func TestAuthenticateRehashPreservesPasswordMetadata(t *testing.T) {
	rules := credential.DefaultRules()
	rules.ValidDays = 0
	store := testStoreWithRules(t, rules)
	password := []byte("CurrentPassword1")
	legacy := testPHC(password, 8*1024, 1, 1)
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
		RequestID: "identity-test-import-legacy-metadata",
		SQL:       `INSERT INTO identity_users (subject, username, password_phc, password_changed_at_unix_ms, password_generation) VALUES (?, ?, ?, ?, ?)`,
		Args:      []any{"subject-1", "alice", legacy, int64(777), int64(9)},
	}); err != nil {
		t.Fatal(err)
	}
	ensureTestPasswordMode(t, store, "subject-1")
	if auth, err := store.Authenticate(context.Background(), "alice", password); err != nil || auth.PasswordGeneration != 9 || auth.AuthenticationGeneration != 1 {
		t.Fatalf("rehash snapshot=%+v err=%v", auth, err)
	}
	if generation, changed := passwordMetadata(t, store, "subject-1"); generation != 9 || changed != 777 {
		t.Fatalf("rehash changed metadata generation=%d changed=%d", generation, changed)
	}
}

func TestAuthenticatePasswordExpiryUsesStrictBoundary(t *testing.T) {
	rules := testRules(1)
	rules.ValidDays = 1
	store := testStoreWithRules(t, rules)
	base := time.UnixMilli(1_000)
	store.now = func() time.Time { return base }
	password := []byte("CurrentPassword1")
	bootstrapPassword(t, store, "subject-1", "alice", password)
	store.now = func() time.Time { return base.Add(24 * time.Hour) }
	if _, err := store.Authenticate(context.Background(), "alice", password); err != nil {
		t.Fatalf("expiry equality err=%v", err)
	}
	store.now = func() time.Time { return base.Add(24*time.Hour + time.Millisecond) }
	auth, err := store.Authenticate(context.Background(), "alice", password)
	if !errors.Is(err, ErrPasswordExpired) || auth.Subject != "subject-1" {
		t.Fatalf("expired auth=%#v err=%v", auth, err)
	}
}

func TestPasswordResetConsumesExactlyOnceAndAppliesHistory(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(3))
	base := time.UnixMilli(1_000)
	store.now = func() time.Time { return base }
	seedDeterministicRandom(store)
	current := []byte("CurrentPassword1")
	next := []byte("NextPassword2")
	bootstrapPassword(t, store, "subject-1", "alice", current)
	token, expiry, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute)
	if err != nil || !expiry.Equal(base.Add(time.Minute)) || !validResetToken(token) {
		t.Fatalf("issue expiry=%v err=%v", expiry, err)
	}
	challenge := beginPasswordReset(t, store, "subject-1", token)
	if _, err := store.ResetPassword(ctx, "subject-1", token, challenge.CookieToken, challenge.CSRFToken, next, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, "alice", current); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password err=%v", err)
	}
	if _, err := store.Authenticate(ctx, "alice", next); err != nil {
		t.Fatalf("new password err=%v", err)
	}
	if generation, changed := passwordMetadata(t, store, "subject-1"); generation != 2 || changed != base.UnixMilli() {
		t.Fatalf("generation=%d changed=%d", generation, changed)
	}
	if got := passwordHistory(t, store, "subject-1"); len(got) != 1 {
		t.Fatalf("history=%#v", got)
	}
	if _, err := store.ResetPassword(ctx, "subject-1", token, challenge.CookieToken, challenge.CSRFToken, []byte("OtherPassword3"), ""); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("replay err=%v", err)
	}
}

func TestPasswordResetBrowserBindingLastChallengeWins(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(1_000) }
	seedDeterministicRandom(store)
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	token, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	first := beginPasswordReset(t, store, "subject-1", token)
	second := beginPasswordReset(t, store, "subject-1", token)
	if first.CookieToken == second.CookieToken || first.CSRFToken == second.CSRFToken {
		t.Fatal("reset browser binding was not replaced")
	}
	if _, err := store.ResetPassword(ctx, "subject-1", token, "", second.CSRFToken, []byte("ResetPassword2"), ""); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("missing cookie err=%v", err)
	}
	if _, err := store.ResetPassword(ctx, "subject-1", token, second.CookieToken, "", []byte("ResetPassword2"), ""); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("missing csrf err=%v", err)
	}
	if _, err := store.ResetPassword(ctx, "subject-1", token, first.CookieToken, first.CSRFToken, []byte("ResetPassword2"), ""); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("superseded binding err=%v", err)
	}
	wrongCookie := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if _, err := store.ResetPassword(ctx, "subject-1", token, wrongCookie, second.CSRFToken, []byte("ResetPassword2"), ""); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("wrong cookie err=%v", err)
	}
	wrongCSRF := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	if _, err := store.ResetPassword(ctx, "subject-1", token, second.CookieToken, wrongCSRF, []byte("ResetPassword2"), ""); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("wrong csrf err=%v", err)
	}
	if _, err := store.ResetPassword(ctx, "subject-1", token, second.CookieToken, second.CSRFToken, []byte("ResetPassword2"), ""); err != nil {
		t.Fatal(err)
	}
}

func TestBeginPasswordResetRejectsExactExpiry(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	base := time.UnixMilli(1_000)
	store.now = func() time.Time { return base }
	seedDeterministicRandom(store)
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	token, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return base.Add(time.Minute) }
	if _, err := store.BeginPasswordReset(ctx, "subject-1", token); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("exact expiry begin err=%v", err)
	}
}

func TestPasswordResetStaleGenerationAndConcurrentConsumer(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(1_000) }
	seedDeterministicRandom(store)
	current := []byte("CurrentPassword1")
	bootstrapPassword(t, store, "subject-1", "alice", current)
	stale, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	staleChallenge := beginPasswordReset(t, store, "subject-1", stale)
	if err := store.ChangePassword(ctx, "subject-1", current, []byte("ChangedPassword2")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResetPassword(ctx, "subject-1", stale, staleChallenge.CookieToken, staleChallenge.CSRFToken, []byte("ResetPassword3"), ""); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("stale token err=%v", err)
	}
	token, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	challenge := beginPasswordReset(t, store, "subject-1", token)
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, next := range [][]byte{[]byte("FirstResetPassword3"), []byte("SecondResetPassword4")} {
		go func(next []byte) {
			<-start
			_, err := store.ResetPassword(ctx, "subject-1", token, challenge.CookieToken, challenge.CSRFToken, next, "")
			errs <- err
		}(next)
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-errs; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes=%d", successes)
	}
}

func TestPasswordResetRevokesOnlyBoundSubjectArtifacts(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(1_000) }
	seedDeterministicRandom(store)
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-reset-artifacts", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO browser_sessions (token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES (?,?,?,?,?)`, Args: []any{"sid-target", "subject-1", int64(1), int64(999999), int64(1)}},
		{SQL: `INSERT INTO browser_sessions (token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES (?,?,?,?,?)`, Args: []any{"sid-deleted", "subject-1", int64(1), int64(999999), int64(1)}},
		{SQL: `INSERT INTO browser_sessions (token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES (?,?,?,?,?)`, Args: []any{"sid-other", "subject-2", int64(1), int64(999999), int64(1)}},
		{SQL: `INSERT INTO oidc_session_clients (sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES (?,?,?,?,?,?)`, Args: []any{"sid-target", "client-target", "https://rp.example.test/logout", int64(0), int64(0), int64(1)}},
		{SQL: `INSERT INTO oidc_session_clients (sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES (?,?,?,?,?,?)`, Args: []any{"sid-other", "client-other", "https://rp.example.test/logout", int64(0), int64(0), int64(1)}},
		{SQL: `INSERT INTO oauth_authorize_codes (signature,request_json,expires_at_unix_ms) VALUES (?,?,?)`, Args: []any{"code-target", `{"subject":"subject-1"}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_authorize_codes (signature,request_json,expires_at_unix_ms) VALUES (?,?,?)`, Args: []any{"code-deleted", `{"subject":"subject-1","extra":{"goauthy_oidc_session_id":"sid-deleted"}}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_authorize_codes (signature,request_json,expires_at_unix_ms) VALUES (?,?,?)`, Args: []any{"code-other", `{"subject":"subject-2"}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_pkce_requests (signature,request_json,expires_at_unix_ms) VALUES (?,?,?)`, Args: []any{"code-target", `{}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_pkce_requests (signature,request_json,expires_at_unix_ms) VALUES (?,?,?)`, Args: []any{"code-deleted", `{}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_pkce_requests (signature,request_json,expires_at_unix_ms) VALUES (?,?,?)`, Args: []any{"code-other", `{}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_access_tokens (signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES (?,?,?,?,?,?,?,?,?)`, Args: []any{"access-target", "r1", "client-target", int64(1), int64(999999), "[]", "[]", "[]", "[]"}},
		{SQL: `INSERT INTO oauth_token_requests (signature,request_json) VALUES (?,?)`, Args: []any{"access-target", `{"subject":"subject-1"}`}},
		{SQL: `INSERT INTO oauth_access_tokens (signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES (?,?,?,?,?,?,?,?,?)`, Args: []any{"access-other", "r2", "client-other", int64(1), int64(999999), "[]", "[]", "[]", "[]"}},
		{SQL: `INSERT INTO oauth_token_requests (signature,request_json) VALUES (?,?)`, Args: []any{"access-other", `{"subject":"subject-2"}`}},
		{SQL: `INSERT INTO oauth_access_tokens (signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES (?,?,?,?,?,?,?,?,?)`, Args: []any{"access-client", "r3", "client-credentials", int64(1), int64(999999), "[]", "[]", "[]", "[]"}},
		{SQL: `INSERT INTO oauth_token_requests (signature,request_json) VALUES (?,?)`, Args: []any{"access-client", `{}`}},
		{SQL: `INSERT INTO oauth_refresh_tokens (signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES (?,?,?,?,?)`, Args: []any{"refresh-target", "access-target", "r1", `{"subject":"subject-1"}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_refresh_tokens (signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES (?,?,?,?,?)`, Args: []any{"refresh-other", "access-other", "r2", `{"subject":"subject-2"}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_refresh_tokens (signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES (?,?,?,?,?)`, Args: []any{"refresh-client", "access-client", "r3", `{}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_device_grants (device_code_digest,user_code_digest,client_id,scopes_json,subject,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,'approved',?,?,?,?)`, Args: []any{"device-target", "user-target", "client-target", "[]", "subject-1", int64(999999), int64(5), int64(0), int64(1)}},
		{SQL: `INSERT INTO oauth_device_grants (device_code_digest,user_code_digest,client_id,scopes_json,subject,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,'approved',?,?,?,?)`, Args: []any{"device-other", "user-other", "client-other", "[]", "subject-2", int64(999999), int64(5), int64(0), int64(1)}},
		{SQL: `DELETE FROM browser_sessions WHERE token_digest = ?`, Args: []any{"sid-deleted"}},
	}}); err != nil {
		t.Fatal(err)
	}
	token, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	challenge := beginPasswordReset(t, store, "subject-1", token)
	if _, err := store.ResetPassword(ctx, "subject-1", token, challenge.CookieToken, challenge.CSRFToken, []byte("ResetPassword2"), ""); err != nil {
		t.Fatal(err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM browser_sessions WHERE subject = 'subject-1' AND revoked_at_unix_ms IS NULL`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM browser_sessions WHERE subject = 'subject-2' AND revoked_at_unix_ms IS NULL`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oidc_session_clients WHERE sid = 'sid-target'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM oidc_session_clients WHERE sid = 'sid-other'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid = 'sid-target'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature = 'code-target' AND invalidated = 1`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature = 'code-deleted' AND invalidated = 1`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature = 'code-other' AND invalidated = 0`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature = 'code-target'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature = 'code-deleted'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature = 'code-other'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature = 'access-target'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature = 'access-other'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature = 'access-client'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_token_requests WHERE signature = 'access-client'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature = 'refresh-target' AND active = 0`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature = 'refresh-other' AND active = 1`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature = 'refresh-client' AND active = 1`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_device_grants WHERE device_code_digest = 'device-target' AND state = 'denied'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_device_grants WHERE device_code_digest = 'device-other' AND state = 'approved'`, 1)
}

func TestPasswordResetRejectsDisabledSubjectWithoutMutation(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(1_000) }
	seedDeterministicRandom(store)
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	before := passwordPHC(t, store, "alice")
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "disable-reset-subject", SQL: `UPDATE identity_users SET disabled = 1 WHERE subject = ?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("disabled issue err=%v", err)
	}
	if got := passwordPHC(t, store, "alice"); got != before {
		t.Fatal("disabled reset changed password")
	}
}

func TestIssuePasswordResetRejectsShortRandomRead(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(1_000) }
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	store.random = func(value []byte) (int, error) {
		for i := range value[:len(value)-1] {
			value[i] = 1
		}
		return len(value) - 1, nil
	}
	if _, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute); !errors.Is(err, ErrPasswordResetUnavailable) {
		t.Fatalf("short issue random read err=%v", err)
	}
	if _, err := store.randomID(16); !errors.Is(err, ErrPasswordResetUnavailable) {
		t.Fatalf("short reset identifier random read err=%v", err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens`, 0)
}

func TestIssuePasswordResetRejectsGenerationChangedBeforeInsert(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(1_000) }
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	called := false
	store.random = func(value []byte) (int, error) {
		if !called {
			called = true
			if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
				RequestID: "identity-reset-issue-generation-race",
				SQL:       `UPDATE identity_users SET password_generation = password_generation + 1 WHERE subject = ?`,
				Args:      []any{"subject-1"},
			}); err != nil {
				t.Fatal(err)
			}
		}
		for i := range value {
			value[i] = 1
		}
		return len(value), nil
	}
	if _, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("generation race issue err=%v", err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens`, 0)
}

func TestIssuePasswordResetStaleIssuerDoesNotDeleteNewGenerationToken(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(1_000) }
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	issuer, err := NewStoreWithPasswordReset(store.db, store.hasher, store.rules, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = store.now
	issuer.random = func(value []byte) (int, error) {
		for i := range value {
			value[i] = 2
		}
		return len(value), nil
	}
	var currentToken string
	called := false
	store.random = func(value []byte) (int, error) {
		if !called {
			called = true
			if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
				RequestID: "identity-reset-stale-issuer-generation",
				SQL:       `UPDATE identity_users SET password_generation = password_generation + 1 WHERE subject = ?`,
				Args:      []any{"subject-1"},
			}); err != nil {
				t.Fatal(err)
			}
			var err error
			currentToken, _, err = issuer.IssuePasswordReset(ctx, "subject-1", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
		}
		for i := range value {
			value[i] = 1
		}
		return len(value), nil
	}
	if _, _, err := store.IssuePasswordReset(ctx, "subject-1", time.Minute); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("stale issue err=%v", err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE password_generation = 2 AND consumed_attempt IS NULL`, 1)
	challenge := beginPasswordReset(t, issuer, "subject-1", currentToken)
	if _, err := issuer.ResetPassword(ctx, "subject-1", currentToken, challenge.CookieToken, challenge.CSRFToken, []byte("ResetPassword2"), ""); err != nil {
		t.Fatalf("new generation token reset err=%v", err)
	}
}

func TestRegisterOpenUserFirstPasswordIsExactOnce(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(2))
	now := time.UnixMilli(42_000)
	store.now = func() time.Time { return now }
	seedDeterministicRandom(store)

	input := OpenRegistration{Email: "Alice@Example.test", PreferredUsername: "alice", GivenName: "Alice", FamilyName: "Example", UserValuesJSON: `{"department":"identity"}`, RedirectURI: "https://app.example.test/welcome", TTL: 72 * time.Hour}
	registered, err := store.RegisterOpenUser(ctx, input)
	if err != nil || !registered.Created || !validResetToken(registered.Token) || !registered.ExpiresAt.Equal(now.Add(72*time.Hour)) {
		t.Fatalf("registered=%#v err=%v", registered, err)
	}
	if got, err := CanonicalEmail(input.Email); err != nil || got != "alice@example.test" || ValidateUsername(got) != nil || ValidateUsername(input.Email) == nil {
		t.Fatalf("email canonicalization got=%q err=%v", got, err)
	}
	if revision, updatedAt := principalVersion(t, store, registered.Subject); revision != 1 || updatedAt != now.UnixMilli() {
		t.Fatalf("principal version=(%d,%d)", revision, updatedAt)
	}
	if _, _, err := store.IssuePasswordReset(ctx, registered.Subject, time.Minute); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("pending account reset issuance err=%v", err)
	}
	challenge := beginPasswordReset(t, store, registered.Subject, registered.Token)
	redirect, err := store.ResetPassword(ctx, registered.Subject, registered.Token, challenge.CookieToken, challenge.CSRFToken, []byte("InitialPassword2"), "")
	if err != nil || redirect != input.RedirectURI {
		t.Fatalf("first password redirect=%q err=%v", redirect, err)
	}
	if _, err := store.ResetPassword(ctx, registered.Subject, registered.Token, challenge.CookieToken, challenge.CSRFToken, []byte("OtherPassword3"), ""); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("replayed first password err=%v", err)
	}
	if got, err := store.Authenticate(ctx, "alice@example.test", []byte("InitialPassword2")); err != nil || got.Subject != registered.Subject {
		t.Fatalf("first password authentication=%#v err=%v", got, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_history WHERE subject = '`+registered.Subject+`'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject = '`+registered.Subject+`' AND email = 'alice@example.test' AND email_verified = 1`, 1)
}

func TestRegisterOpenUserDuplicateConcurrentHidesBearer(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(43_000) }
	seedDeterministicRandom(store)
	input := OpenRegistration{Email: "alice@example.test", TTL: 72 * time.Hour}
	start := make(chan struct{})
	results := make(chan OpenRegistrationResult, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			result, err := store.RegisterOpenUser(ctx, input)
			results <- result
			errs <- err
		}()
	}
	close(start)
	created, subject := 0, ""
	for range 2 {
		result, err := <-results, <-errs
		if err != nil {
			t.Fatal(err)
		}
		if subject == "" {
			subject = result.Subject
		}
		if result.Subject != subject {
			t.Fatalf("duplicate subjects %q and %q", subject, result.Subject)
		}
		if result.Created {
			created++
			if !validResetToken(result.Token) || result.ExpiresAt.IsZero() {
				t.Fatalf("created result=%#v", result)
			}
		} else if result.Token != "" || !result.ExpiresAt.IsZero() {
			t.Fatalf("duplicate leaked bearer=%#v", result)
		}
	}
	if created != 1 {
		t.Fatalf("created=%d", created)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username = 'alice@example.test'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject = '`+subject+`' AND usage = 'password_new' AND consumed_attempt IS NULL`, 1)
	if revision, _ := principalVersion(t, store, subject); revision != 1 {
		t.Fatalf("principal revision=%d", revision)
	}
}

func TestRegisterOpenUserExistingRecoveryOwnerDoesNotCreateOrphan(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(44_000) }
	seedDeterministicRandom(store)
	bootstrapPassword(t, store, "active-subject", "active", []byte("CurrentPassword1"))
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "open-registration-existing-recovery", SQL: `INSERT INTO identity_recovery_emails (subject,email) VALUES (?,?)`, Args: []any{"active-subject", "alice@example.test"}}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan OpenRegistrationResult, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			result, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "alice@example.test", TTL: 72 * time.Hour})
			results <- result
			errs <- err
		}()
	}
	close(start)
	for range 2 {
		result, err := <-results, <-errs
		if err != nil || result.Subject != "active-subject" || result.Created || result.Token != "" || !result.ExpiresAt.IsZero() {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE email = 'alice@example.test'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE usage = 'password_new'`, 0)
}

func TestRegisterOpenUserCleansExpiredPendingIdentityAtFixedClock(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	base := time.UnixMilli(45_000)
	store.now = func() time.Time { return base }
	seedDeterministicRandom(store)
	stale, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "stale@example.test", TTL: time.Minute})
	if err != nil || !stale.Created {
		t.Fatalf("stale=%#v err=%v", stale, err)
	}
	store.now = func() time.Time { return base.Add(time.Minute) }
	current, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "current@example.test", TTL: time.Minute})
	if err != nil || !current.Created {
		t.Fatalf("current=%#v err=%v", current, err)
	}
	for _, table := range []string{"identity_users", "identity_authentication_modes", "identity_recovery_emails", "identity_user_profiles", "identity_password_reset_tokens", "rbac_principal_versions"} {
		assertCount(t, store, `SELECT COUNT(*) FROM `+table+` WHERE subject = '`+stale.Subject+`'`, 0)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject = '`+current.Subject+`' AND password_phc = ''`, 1)
}

func TestCleanupExpiredOpenRegistrationsIsBoundedAcrossTicks(t *testing.T) {
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	now := time.UnixMilli(46_000)
	for start := 0; start < 65; start += 12 { // Rhiza accepts at most 64 statements per request.
		end := start + 12
		if end > 65 {
			end = 65
		}
		statements := make([]rhiza.SQLStatement, 0, (end-start)*5)
		for i := start; i < end; i++ {
			subject := fmt.Sprintf("expired-%03d", i)
			email := fmt.Sprintf("expired-%03d@example.test", i)
			digest := strings.Repeat("a", 40) + fmt.Sprintf("%03d", i)
			statements = append(statements,
				rhiza.SQLStatement{SQL: `INSERT INTO identity_users (subject,username,password_phc,password_changed_at_unix_ms,password_generation) VALUES (?,?, '',0,1)`, Args: []any{subject, email}},
				rhiza.SQLStatement{SQL: `INSERT INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES (?,'password',1,0)`, Args: []any{subject}},
				rhiza.SQLStatement{SQL: `INSERT INTO identity_recovery_emails (subject,email) VALUES (?,?)`, Args: []any{subject, email}},
				rhiza.SQLStatement{SQL: `INSERT INTO identity_user_profiles (subject,email,email_verified) VALUES (?,?,0)`, Args: []any{subject, email}},
				rhiza.SQLStatement{SQL: `INSERT INTO identity_password_reset_tokens (token_digest,subject,password_generation,issued_at_unix_ms,expires_at_unix_ms,usage) VALUES (?,?,?,?,?,'password_new')`, Args: []any{digest, subject, int64(1), now.Add(-time.Millisecond).UnixMilli(), now.UnixMilli()}},
			)
		}
		if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("identity-expired-pending-batch-%d", start), Statements: statements}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.CleanupExpiredOpenRegistrations(ctx, now); err != nil {
		t.Fatal(err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens`, 1)
	// A second batch at the exact same injected clock must not replay the first.
	if err := store.CleanupExpiredOpenRegistrations(ctx, now); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"identity_users", "identity_authentication_modes", "identity_recovery_emails", "identity_user_profiles", "identity_password_reset_tokens"} {
		assertCount(t, store, `SELECT COUNT(*) FROM `+table, 0)
	}
}

func TestAuthenticatePropagatesCredentialWorkCancellation(t *testing.T) {
	store := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Authenticate(ctx, "Invalid", []byte("password")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authentication err=%v", err)
	}
}

func TestValidateSubjectRejectsUnknownAndDisabled(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	password, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapUser(ctx, "subject-1", "alice", password); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateSubject(ctx, "subject-1"); err != nil {
		t.Fatalf("active subject err=%v", err)
	}
	if err := store.ValidateSubject(ctx, "unknown"); !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("unknown subject err=%v", err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "identity-test-disable-subject",
		SQL:       `UPDATE identity_users SET disabled = 1 WHERE subject = ?`,
		Args:      []any{"subject-1"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateSubject(ctx, "subject-1"); !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("disabled subject err=%v", err)
	}
	if err := store.ValidateSubject(ctx, " subject-1"); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("malformed subject err=%v", err)
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return testStoreWithHasher(t, hasher)
}

func testStoreWithHasher(t *testing.T, hasher *credential.Hasher) *Store {
	return testStoreWithPolicies(t, hasher, credential.DefaultRules())
}

func testStoreWithRules(t *testing.T, rules credential.Rules) *Store {
	t.Helper()
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return testStoreWithPolicies(t, hasher, rules)
}

func testStoreWithPolicies(t *testing.T, hasher *credential.Hasher, rules credential.Rules) *Store {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "identity-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "identity-test-schema", Statements: SchemaStatements()}); err != nil {
		t.Fatal(err)
	}
	store, err := NewStoreWithPolicies(db, hasher, rules)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testResetStore(t *testing.T, rules credential.Rules) *Store {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "identity-reset-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStoreWithPasswordReset(db, hasher, rules, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testConversionStore(t *testing.T) *Store {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "identity-conversion-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStoreWithPasswordReset(db, hasher, credential.DefaultRules(), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func makePasskeyOnly(t *testing.T, store *Store, subject, username string) {
	t.Helper()
	bootstrapPassword(t, store, subject, username, []byte("CurrentPassword1"))
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "reverse-credential-" + subject, SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,credential_version,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?)`, Args: []any{"credential-" + subject, subject, "primary", "ciphertext", int64(0), int64(0), int64(1), int64(0), int64(0)}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ConvertToPasskeyOnly(context.Background(), subject); err != nil {
		t.Fatal(err)
	}
}

func seedServiceProof(t *testing.T, store *Store, raw, subject, session, purpose string, expires time.Time) {
	t.Helper()
	digest := webAuthnServiceProofDigest(raw)
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "reverse-proof-" + digest, Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{digest, subject, session, expires.UnixMilli()}},
		{SQL: `INSERT INTO identity_webauthn_service_proof_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{digest, purpose}},
	}}); err != nil {
		t.Fatal(err)
	}
}

func assertProofUnconsumed(t *testing.T, store *Store, raw string) {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_webauthn_mfa_proofs WHERE code_digest=?`, Args: []any{webAuthnServiceProofDigest(raw)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != nil {
		t.Fatalf("proof consumption rows=%#v err=%v", result.Rows, err)
	}
}

func digestForTest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func seedDeterministicRandom(store *Store) {
	var value byte
	var mu sync.Mutex
	store.random = func(out []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		value++
		for i := range out {
			out[i] = value
		}
		return len(out), nil
	}
}

func testRules(history int) credential.Rules {
	return credential.Rules{LengthMin: 8, LengthMax: 128, LowerCase: 1, UpperCase: 1, Digits: 1, History: history}
}

func bootstrapPassword(t *testing.T, store *Store, subject, username string, password []byte) {
	t.Helper()
	phc, err := store.hasher.Hash(context.Background(), password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapUser(context.Background(), subject, username, phc); err != nil {
		t.Fatal(err)
	}
}

func ensureTestPasswordMode(t *testing.T, store *Store, subject string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "identity-test-mode-" + subject, SQL: `INSERT INTO identity_authentication_modes (subject, mode, generation, updated_at_unix_ms) VALUES (?, 'password', 1, 0)`, Args: []any{subject}}); err != nil {
		t.Fatal(err)
	}
}

func beginPasswordReset(t *testing.T, store *Store, subject, token string) PasswordResetChallenge {
	t.Helper()
	challenge, err := store.BeginPasswordReset(context.Background(), subject, token)
	if err != nil {
		t.Fatal(err)
	}
	if !validResetToken(challenge.CookieToken) || !validDigest(challenge.CSRFToken) || challenge.ExpiresAt.IsZero() {
		t.Fatal("invalid reset browser challenge")
	}
	return challenge
}

func passwordPHC(t *testing.T, store *Store, username string) string {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT password_phc FROM identity_users WHERE username = ?`,
		Args:        []any{username},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("read password credential: rows=%#v err=%v", result.Rows, err)
	}
	value, ok := result.Rows[0][0].(string)
	if !ok {
		t.Fatalf("password credential type=%T", result.Rows[0][0])
	}
	return value
}

func principalVersion(t *testing.T, store *Store, subject string) (int64, int64) {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT revision,updated_at_unix_ms FROM rbac_principal_versions WHERE subject = ?`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		t.Fatalf("read principal version: rows=%#v err=%v", result.Rows, err)
	}
	revision, revisionOK := result.Rows[0][0].(int64)
	updatedAt, updatedAtOK := result.Rows[0][1].(int64)
	if !revisionOK || !updatedAtOK {
		t.Fatalf("principal version types=%T,%T", result.Rows[0][0], result.Rows[0][1])
	}
	return revision, updatedAt
}

func passwordMetadata(t *testing.T, store *Store, subject string) (int64, int64) {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT password_generation, password_changed_at_unix_ms FROM identity_users WHERE subject = ?`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		t.Fatalf("read password metadata: rows=%#v err=%v", result.Rows, err)
	}
	generation, generationOK := result.Rows[0][0].(int64)
	changed, changedOK := result.Rows[0][1].(int64)
	if !generationOK || !changedOK {
		t.Fatalf("password metadata types=%T,%T", result.Rows[0][0], result.Rows[0][1])
	}
	return generation, changed
}

func passwordHistory(t *testing.T, store *Store, subject string) []string {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT password_phc FROM identity_password_history WHERE subject = ? ORDER BY generation`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	values := make([]string, len(result.Rows))
	for i, row := range result.Rows {
		if len(row) != 1 {
			t.Fatalf("history row=%#v", row)
		}
		value, ok := row[0].(string)
		if !ok {
			t.Fatalf("history type=%T", row[0])
		}
		values[i] = value
	}
	return values
}

func assertCount(t *testing.T, store *Store, sql string, want int64) {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: sql, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != want {
		t.Fatalf("count sql=%q rows=%#v err=%v want=%d", sql, result.Rows, err, want)
	}
}

func testPHC(password []byte, memory, iterations uint32, parallelism uint8) string {
	salt := []byte("1234567890abcdef")
	return "$argon2id$v=19$m=" + strconv.FormatUint(uint64(memory), 10) + ",t=" + strconv.FormatUint(uint64(iterations), 10) + ",p=" + strconv.FormatUint(uint64(parallelism), 10) + "$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(argon2.IDKey(password, salt, iterations, memory, parallelism, 32))
}
