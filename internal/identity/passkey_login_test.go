package identity

import (
	"context"
	"testing"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestLookupPasskeyOnlySubjectReturnsActivePasskeyOnlyAccount(t *testing.T) {
	t.Parallel()
	store := testStore(t)
	ctx := context.Background()
	if _, err := store.BootstrapUser(ctx, "subject-1", "alice", mustHashPassword(t)); err != nil {
		t.Fatal(err)
	}
	// Flip to passkey-only mode.
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "passkey-login-test-flip-mode",
		SQL:       `UPDATE identity_authentication_modes SET mode='passkey' WHERE subject=?`,
		Args:      []any{"subject-1"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "passkey-login-test-clear-password",
		SQL:       `UPDATE identity_users SET password_phc='' WHERE subject=?`,
		Args:      []any{"subject-1"},
	}); err != nil {
		t.Fatal(err)
	}

	subject, username, err := store.LookupPasskeyOnlySubject(ctx, "alice")
	if err != nil {
		t.Fatalf("expected success, got err=%v", err)
	}
	if subject != "subject-1" || username != "alice" {
		t.Fatalf("subject=%q username=%q", subject, username)
	}
}

func TestLookupPasskeyOnlySubjectRejectsPasswordModeUser(t *testing.T) {
	t.Parallel()
	store := testStore(t)
	ctx := context.Background()
	if _, err := store.BootstrapUser(ctx, "subject-1", "alice", mustHashPassword(t)); err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.LookupPasskeyOnlySubject(ctx, "alice"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got err=%v", err)
	}
}

func TestLookupPasskeyOnlySubjectRejectsUnknownUser(t *testing.T) {
	t.Parallel()
	store := testStore(t)
	ctx := context.Background()

	if _, _, err := store.LookupPasskeyOnlySubject(ctx, "nobody"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got err=%v", err)
	}
}

func TestLookupPasskeyOnlySubjectRejectsDisabledUser(t *testing.T) {
	t.Parallel()
	store := testStore(t)
	ctx := context.Background()
	if _, err := store.BootstrapUser(ctx, "subject-1", "alice", mustHashPassword(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "passkey-login-test-disable",
		SQL:       `UPDATE identity_users SET disabled=1 WHERE subject=?`,
		Args:      []any{"subject-1"},
	}); err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.LookupPasskeyOnlySubject(ctx, "alice"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got err=%v", err)
	}
}

func TestLookupPasskeyOnlySubjectRejectsInvalidUsername(t *testing.T) {
	t.Parallel()
	store := testStore(t)
	ctx := context.Background()

	// Empty username.
	if _, _, err := store.LookupPasskeyOnlySubject(ctx, ""); err != ErrInvalidUsername {
		t.Fatalf("expected ErrInvalidUsername, got err=%v", err)
	}
}

func TestLookupPasskeyOnlySubjectRejectsNilStore(t *testing.T) {
	t.Parallel()
	var store *Store
	if _, _, err := store.LookupPasskeyOnlySubject(context.Background(), "alice"); err == nil {
		t.Fatal("expected error for nil store")
	}
}

func mustHashPassword(t *testing.T) string {
	t.Helper()
	password, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	return password
}
