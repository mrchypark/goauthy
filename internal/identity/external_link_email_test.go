package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

const testAutoLinkProviderID = "AutoLnkPrv1d"

var testAutoLinkNamespace = upstreamprovider.ComputeNamespace("https://accounts.example.com", "auto-client-id")

func testAutoLinkStore(t *testing.T) *Store {
	t.Helper()
	store := testResetStore(t, credential.DefaultRules())
	ctx := context.Background()
	seedArgs := []any{
		testAutoLinkProviderID, int64(1), "test-auto-link", "oidc",
		"https://accounts.example.com",
		"https://accounts.example.com/auth",
		"https://accounts.example.com/token",
		"https://accounts.example.com/userinfo",
		"auto-client-id", nil, "openid email",
		nil, nil, nil, nil,
		int64(1), int64(1), int64(0), nil, int64(1), int64(1),
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "auto-link-test-provider-seed",
		Statements: []rhiza.SQLStatement{
			{SQL: "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,use_pkce,client_secret_basic,client_secret_post,jwks_endpoint,auto_onboarding,auto_link) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", Args: seedArgs},
			{SQL: "INSERT INTO auth_provider_runtime_versions(provider_id, version) VALUES(?, ?)", Args: []any{testAutoLinkProviderID, "v1"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func testAutoLinkConfig() AutoLinkConfigSnapshot {
	return AutoLinkConfigSnapshot{
		Source:   "registry",
		Version:  "v1",
		Issuer:   "https://accounts.example.com",
		ClientID: "auto-client-id",
		Kind:     "oidc",
		AutoLink: true,
	}
}

func testAutoLinkSubject() upstreamprovider.SubjectResult {
	return upstreamprovider.SubjectResult{
		ProviderID:        testAutoLinkProviderID,
		Subject:           "upstream-auto-subject",
		IdentityNamespace: testAutoLinkNamespace,
	}
}

// bootstrapWithProfile creates a user via BootstrapUser and inserts a
// profile row with the given email and verification state.
func bootstrapWithProfile(t *testing.T, store *Store, subject, username, email string, emailVerified bool) {
	t.Helper()
	bootstrapPassword(t, store, subject, username, []byte("Password1!"))
	verified := int64(0)
	if emailVerified {
		verified = 1
	}
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
		RequestID: "profile-" + subject,
		SQL:       "INSERT OR IGNORE INTO identity_user_profiles(subject, email, email_verified) VALUES(?, ?, ?)",
		Args:      []any{subject, email, verified},
	}); err != nil {
		t.Fatal(err)
	}
}

// bootstrapPasskeyOnly creates a passkey-only account (no password) with a
// verified email and a registered WebAuthn credential.
func bootstrapPasskeyOnly(t *testing.T, store *Store, subject, username, email string, emailVerified bool) {
	t.Helper()
	now := store.now().UTC().Truncate(time.Millisecond)
	stmts := []rhiza.SQLStatement{
		{SQL: "INSERT INTO identity_users(subject, username, password_phc, created_at_unix_ms, password_changed_at_unix_ms, password_generation) VALUES(?, ?, '', ?, ?, 1)", Args: []any{subject, username, now.UnixMilli(), now.UnixMilli()}},
		{SQL: "INSERT OR IGNORE INTO rbac_principal_versions(subject, revision, updated_at_unix_ms) VALUES(?, 1, ?)", Args: []any{subject, now.UnixMilli()}},
		{SQL: "INSERT INTO identity_authentication_modes(subject, mode, generation, updated_at_unix_ms) VALUES(?, 'passkey', 1, ?)", Args: []any{subject, now.UnixMilli()}},
		{SQL: "INSERT INTO identity_webauthn_credentials(credential_id, subject, name, credential_json, sign_count, credential_version, user_verified, registered_at_unix_ms, last_used_at_unix_ms) VALUES(?, ?, 'primary', '{}', 0, 0, 1, 0, 0)", Args: []any{"cred-" + subject, subject}},
	}
	verified := int64(0)
	if emailVerified {
		verified = 1
	}
	stmts = append(stmts, rhiza.SQLStatement{
		SQL:  "INSERT OR IGNORE INTO identity_user_profiles(subject, email, email_verified) VALUES(?, ?, ?)",
		Args: []any{subject, email, verified},
	})
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
		RequestID:  "seed-passkey-" + subject,
		Statements: stmts,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAutoLinkExternalVerifiedSuccess creates an established account with a
// verified email, then auto-links it. The link must persist and the returned
// subject must match the local account.
func TestAutoLinkExternalVerifiedSuccess(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_000).UTC() }
	bootstrapWithProfile(t, store, "local-subject", "alice@example.test", "alice@example.test", true)

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "alice@example.test",
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("AutoLinkExternal err=%v", err)
	}
	if result.Subject != "local-subject" {
		t.Fatalf("subject=%q want=local-subject", result.Subject)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM identity_external_links WHERE provider_id='"+testAutoLinkProviderID+"' AND local_subject='local-subject'", 1)
}

// TestAutoLinkExternalPasskeyOnlySuccess creates a passkey-only account (no
// password, has WebAuthn credential) with a verified email, then auto-links
// it. This verifies the fix for passkey-only account support.
func TestAutoLinkExternalPasskeyOnlySuccess(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_020).UTC() }
	bootstrapPasskeyOnly(t, store, "passkey-subject", "passkeyuser@example.test", "passkeyuser@example.test", true)

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "passkeyuser@example.test",
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("AutoLinkExternal err=%v", err)
	}
	if result.Subject != "passkey-subject" {
		t.Fatalf("subject=%q want=passkey-subject", result.Subject)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM identity_external_links WHERE provider_id='"+testAutoLinkProviderID+"' AND local_subject='passkey-subject'", 1)
}

// TestAutoLinkExternalLocalUnverifiedRejects rejects auto-link when the
// local account's email is not verified.
func TestAutoLinkExternalLocalUnverifiedRejects(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_001).UTC() }
	bootstrapWithProfile(t, store, "local-subject", "bob@example.test", "bob@example.test", false)

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "bob@example.test",
		EmailVerified: true,
	})
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM identity_external_links WHERE provider_id='"+testAutoLinkProviderID+"'", 0)
	}

// TestAutoLinkExternalIneligibleLocalExistsNotNoAccount verifies that when
// a local account exists but is ineligible (e.g. not yet verified), the
// error is ErrAutoLinkUnavailable and NOT ErrAutoLinkNoAccount. The
// precheck finds the account; only the transactional batch rejects it.
func TestAutoLinkExternalIneligibleLocalExistsNotNoAccount(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_030).UTC() }
	bootstrapWithProfile(t, store, "ineligible-subject", "ineligible@example.test", "ineligible@example.test", true)
	// Disable the account so the batch WHERE disabled = 0 fails.
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "disable-ineligible",
		SQL:       "UPDATE identity_users SET disabled = 1 WHERE subject = ?",
		Args:      []any{"ineligible-subject"},
	}); err != nil {
		t.Fatal(err)
	}

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "ineligible@example.test",
		EmailVerified: true,
	})
	if errors.Is(err, ErrAutoLinkNoAccount) {
		t.Fatalf("must NOT be ErrAutoLinkNoAccount, got err=%v result=%#v", err, result)
	}
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM identity_external_links WHERE provider_id='"+testAutoLinkProviderID+"'", 0)
}

// TestAutoLinkExternalIncomingUnverifiedRejects rejects auto-link when the
// incoming email is not verified by the upstream provider.
func TestAutoLinkExternalIncomingUnverifiedRejects(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_002).UTC() }
	bootstrapWithProfile(t, store, "local-subject", "carol@example.test", "carol@example.test", true)

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "carol@example.test",
		EmailVerified: false,
	})
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
}

// TestAutoLinkExternalPendingAccountRejects rejects auto-link for a pending
// account (password_phc = '') that has not completed registration.
func TestAutoLinkExternalPendingAccountRejects(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_003).UTC() }
	registered, err := store.RegisterOpenUser(ctx, OpenRegistration{
		Email: "pending@example.test",
		TTL:   time.Minute,
	})
	if err != nil || !registered.Created {
		t.Fatalf("register err=%v created=%v", err, registered.Created)
	}

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "pending@example.test",
		EmailVerified: true,
	})
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
}

// TestAutoLinkExternalDisabledUserRejects rejects auto-link for a disabled
// account.
func TestAutoLinkExternalDisabledUserRejects(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_004).UTC() }
	bootstrapWithProfile(t, store, "disabled-subject", "disabled@example.test", "disabled@example.test", true)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "disable-subject",
		SQL:       "UPDATE identity_users SET disabled = 1 WHERE subject = ?",
		Args:      []any{"disabled-subject"},
	}); err != nil {
		t.Fatal(err)
	}

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "disabled@example.test",
		EmailVerified: true,
	})
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
}

// TestAutoLinkExternalExpiredUserRejects rejects auto-link when the local
// account has expired.
func TestAutoLinkExternalExpiredUserRejects(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	now := time.UnixMilli(5_000_005)
	store.now = func() time.Time { return now.UTC() }
	bootstrapWithProfile(t, store, "expired-subject", "expired@example.test", "expired@example.test", true)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "expire-subject",
		SQL:       "UPDATE identity_users SET user_expires_at_unix_ms = ? WHERE subject = ?",
		Args:      []any{now.Add(-time.Hour).UnixMilli(), "expired-subject"},
	}); err != nil {
		t.Fatal(err)
	}

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "expired@example.test",
		EmailVerified: true,
	})
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
}

// TestAutoLinkExternalExpiredPasskeyOnlyRejects rejects auto-link when an
// expired account has passkey credentials but no password.
func TestAutoLinkExternalExpiredPasskeyOnlyRejects(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	now := time.UnixMilli(5_000_021)
	store.now = func() time.Time { return now.UTC() }
	bootstrapPasskeyOnly(t, store, "exp-passkey", "exp-passkey@example.test", "exp-passkey@example.test", true)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "expire-passkey",
		SQL:       "UPDATE identity_users SET user_expires_at_unix_ms = ? WHERE subject = ?",
		Args:      []any{now.Add(-time.Hour).UnixMilli(), "exp-passkey"},
	}); err != nil {
		t.Fatal(err)
	}

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "exp-passkey@example.test",
		EmailVerified: true,
	})
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
}

// TestAutoLinkExternalNoPasswordNoPasskeyRejects rejects auto-link for an
// account with no password and no passkey credentials.
func TestAutoLinkExternalNoPasswordNoPasskeyRejects(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_022).UTC() }
	subject := "nopw-nopk"
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "seed-nopw-nopk",
		Statements: []rhiza.SQLStatement{
			{SQL: "INSERT INTO identity_users(subject, username, password_phc, created_at_unix_ms, password_changed_at_unix_ms, password_generation) VALUES(?, ?, '', 0, 0, 1)", Args: []any{subject, subject}},
			{SQL: "INSERT INTO identity_user_profiles(subject, email, email_verified) VALUES(?, 'nopw-nopk@example.test', 1)", Args: []any{subject}},
		},
	}); err != nil {
		t.Fatal(err)
	}

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "nopw-nopk@example.test",
		EmailVerified: true,
	})
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
}

// TestAutoLinkExternalExistingOtherProviderRejects rejects auto-link when the
// local account already has an external link to a different provider.
func TestAutoLinkExternalExistingOtherProviderRejects(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_006).UTC() }
	bootstrapWithProfile(t, store, "linked-subject", "linked@example.test", "linked@example.test", true)
	otherExternal := upstreamprovider.SubjectResult{ProviderID: "other-google", Subject: "other-subject"}
	if _, err := store.LinkExternal(ctx, "linked-subject", otherExternal, time.UnixMilli(5_000_006)); err != nil {
		t.Fatal(err)
	}

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "linked@example.test",
		EmailVerified: true,
	})
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
}

// TestAutoLinkExternalVersionChangedRejected rejects auto-link when the
// provider version has changed since the callback.
func TestAutoLinkExternalVersionChangedRejected(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_007).UTC() }
	bootstrapWithProfile(t, store, "ver-subject", "ver@example.test", "ver@example.test", true)

	config := testAutoLinkConfig()
	config.Version = "v99"

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        config,
		Email:         "ver@example.test",
		EmailVerified: true,
	})
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
}

// TestAutoLinkExternalPolicyChangeRejected rejects auto-link when auto_link
// has been disabled on the provider.
func TestAutoLinkExternalPolicyChangeRejected(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_008).UTC() }
	bootstrapWithProfile(t, store, "pol-subject", "pol@example.test", "pol@example.test", true)

	config := testAutoLinkConfig()
	config.AutoLink = false

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        config,
		Email:         "pol@example.test",
		EmailVerified: true,
	})
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
}

// TestAutoLinkExternalCollisionNoOrphan verifies that a collision (external
// key already linked to a different subject) does not leave orphan rows.
func TestAutoLinkExternalCollisionNoOrphan(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_009).UTC() }
	bootstrapWithProfile(t, store, "subject-a", "a@example.test", "a@example.test", true)
	bootstrapWithProfile(t, store, "subject-b", "b@example.test", "b@example.test", true)

	subject := testAutoLinkSubject()
	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       subject,
		Config:        testAutoLinkConfig(),
		Email:         "a@example.test",
		EmailVerified: true,
	})
	if err != nil || result.Subject != "subject-a" {
		t.Fatalf("first link subject=%q err=%v", result.Subject, err)
	}
	result, err = store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       subject,
		Config:        testAutoLinkConfig(),
		Email:         "b@example.test",
		EmailVerified: true,
	})
	if !errors.Is(err, ErrAutoLinkUnavailable) {
		t.Fatalf("collision expected ErrAutoLinkUnavailable, got err=%v result=%#v", err, result)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM identity_external_links WHERE provider_id='"+testAutoLinkProviderID+"' AND external_key='"+subject.ExternalKey()+"'", 1)
}

// TestAutoLinkExternalMissingLocalAccountReturnsUnavailable verifies that
// auto-link returns ErrAutoLinkUnavailable when no local account matches
// the email.
func TestAutoLinkExternalMissingLocalAccountReturnsNoAccount(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_010).UTC() }

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "nobody@example.test",
		EmailVerified: true,
	})
	if !errors.Is(err, ErrAutoLinkNoAccount) {
		t.Fatalf("expected ErrAutoLinkNoAccount, got err=%v result=%#v", err, result)
	}
}

// TestAutoLinkExternalCanonicalizesEmail verifies that the email is
// canonicalized before lookup.
func TestAutoLinkExternalCanonicalizesEmail(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(5_000_011).UTC() }
	bootstrapWithProfile(t, store, "canon-subject", "alice@example.test", "alice@example.test", true)

	result, err := store.AutoLinkExternal(ctx, AutoLinkInput{
		Subject:       testAutoLinkSubject(),
		Config:        testAutoLinkConfig(),
		Email:         "ALICE@example.test",
		EmailVerified: true,
	})
	if err != nil || result.Subject != "canon-subject" {
		t.Fatalf("canonicalize subject=%q err=%v", result.Subject, err)
	}
}

// TestFindExternalLinkActiveReturnsInactiveForLinkedButDisabled verifies that
// FindExternalLinkActive returns ErrInactiveSubject when the link exists
// but the user is disabled.
func TestFindExternalLinkActiveReturnsInactiveForLinkedButDisabled(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(6_000_000).UTC() }
	bootstrapPassword(t, store, "inactive-subject", "inactive@example.test", []byte("Password1!"))
	external := upstreamprovider.SubjectResult{ProviderID: "inactive-google", Subject: "inactive-upstream"}
	if _, err := store.LinkExternal(ctx, "inactive-subject", external, time.UnixMilli(6_000_000)); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "disable-inactive",
		SQL:       "UPDATE identity_users SET disabled = 1 WHERE subject = ?",
		Args:      []any{"inactive-subject"},
	}); err != nil {
		t.Fatal(err)
	}

	subject, err := store.FindExternalLinkActive(ctx, external)
	if !errors.Is(err, ErrInactiveSubject) || subject != "" {
		t.Fatalf("expected ErrInactiveSubject, got subject=%q err=%v", subject, err)
	}
}

// TestFindExternalLinkActiveReturnsInactiveForLinkedButExpired verifies that
// FindExternalLinkActive returns ErrInactiveSubject when the link exists
// but the user has expired.
func TestFindExternalLinkActiveReturnsInactiveForLinkedButExpired(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	now := time.UnixMilli(6_000_010)
	store.now = func() time.Time { return now.UTC() }
	bootstrapPassword(t, store, "expired-link-subject", "expiredlink@example.test", []byte("Password1!"))
	external := upstreamprovider.SubjectResult{ProviderID: "expired-link-google", Subject: "expired-link-upstream"}
	if _, err := store.LinkExternal(ctx, "expired-link-subject", external, now); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "expire-link-subject",
		SQL:       "UPDATE identity_users SET user_expires_at_unix_ms = ? WHERE subject = ?",
		Args:      []any{now.Add(-time.Hour).UnixMilli(), "expired-link-subject"},
	}); err != nil {
		t.Fatal(err)
	}

	subject, err := store.FindExternalLinkActive(ctx, external)
	if !errors.Is(err, ErrInactiveSubject) || subject != "" {
		t.Fatalf("expected ErrInactiveSubject, got subject=%q err=%v", subject, err)
	}
}

// TestFindExternalLinkActiveReturnsEmptyForNoLink verifies that
// FindExternalLinkActive returns ("", nil) when no link exists.
func TestFindExternalLinkActiveReturnsEmptyForNoLink(t *testing.T) {
	store := testAutoLinkStore(t)
	ctx := context.Background()
	external := upstreamprovider.SubjectResult{ProviderID: "nolink-google", Subject: "nolink-upstream"}

	subject, err := store.FindExternalLinkActive(ctx, external)
	if err != nil || subject != "" {
		t.Fatalf("expected empty, got subject=%q err=%v", subject, err)
	}
}
