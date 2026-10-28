package account

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestPutSelfPasswordMapsUnexpectedMutationFailureToUnavailable(t *testing.T) {
	h, db, cookie, csrf := newPasswordIngressHandler(t)
	ctx := context.Background()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "account-reject-password-mutation",
		SQL:       `CREATE TRIGGER reject_account_password_change BEFORE UPDATE OF password_phc ON identity_users BEGIN SELECT RAISE(ABORT,'injected storage failure'); END`,
	}); err != nil {
		t.Fatal(err)
	}
	response := passwordRequest(t, h, cookie, csrf, "subject-1", passwordChangeRequest{
		Current: stringPtr("CurrentPassword1"), Next: stringPtr("UpdatedPassword2"),
	})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected storage failure status=%d body=%q want=%d", response.Code, response.Body.String(), http.StatusServiceUnavailable)
	}
	if got, err := h.identity.Authenticate(ctx, "alice", []byte("CurrentPassword1")); err != nil || got.Subject != "subject-1" {
		t.Fatalf("failed mutation changed password: auth=%+v err=%v", got, err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "account-drop-password-trigger", SQL: `DROP TRIGGER reject_account_password_change`}); err != nil {
		t.Fatal(err)
	}
}

func TestPutSelfPasswordReportsInvalidCurrentPasswordCode(t *testing.T) {
	h, _, cookie, csrf := newPasswordIngressHandler(t)
	response := passwordRequest(t, h, cookie, csrf, "subject-1", passwordChangeRequest{
		Current: stringPtr("WrongCurrentPassword1"), Next: stringPtr("UpdatedPassword2"),
	})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-current-password status=%d body=%q want=%d", response.Code, response.Body.String(), http.StatusUnauthorized)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("wrong-current-password content-type=%q want application/json", got)
	}
	var body struct {
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode wrong-current-password response: %v body=%q", err, response.Body.String())
	}
	if body.ErrorCode != "invalid_current_password" {
		t.Fatalf("wrong-current-password error_code=%q want invalid_current_password", body.ErrorCode)
	}
	if got, want := response.Body.String(), "{\"error_code\":\"invalid_current_password\"}\n"; got != want {
		t.Fatalf("wrong-current-password response exposed unexpected detail: %q", got)
	}
}

func TestPutSelfPasswordReportsUnknownMutationOutcome(t *testing.T) {
	objects := t.TempDir()
	backup := objects + "-backup"
	h, _, cookie, csrf := newPasswordIngressHandlerWithConfig(t, rhiza.Config{
		NodeID: "account-password-unknown-outcome", DataDir: t.TempDir(),
		ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: objects,
		ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck,
	})
	if err := os.Rename(objects, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objects, []byte("unavailable"), 0600); err != nil {
		t.Fatal(err)
	}
	restoreObjectStore := func() {
		_ = os.Remove(objects)
		_ = os.Rename(backup, objects)
	}
	t.Cleanup(restoreObjectStore)
	response := passwordRequest(t, h, cookie, csrf, "subject-1", passwordChangeRequest{
		Current: stringPtr("CurrentPassword1"), Next: stringPtr("UpdatedPassword2"),
	})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unknown password mutation outcome status=%d body=%q want=%d", response.Code, response.Body.String(), http.StatusServiceUnavailable)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("unknown password mutation outcome content-type=%q want application/json", got)
	}
	var body struct {
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode unknown password mutation outcome: %v body=%q", err, response.Body.String())
	}
	if body.ErrorCode != "mutation_outcome_unknown" {
		t.Fatalf("unknown password mutation error_code=%q want mutation_outcome_unknown", body.ErrorCode)
	}
}

func newPasswordIngressHandler(t *testing.T) (*Handler, *rhiza.DB, *http.Cookie, string) {
	return newPasswordIngressHandlerWithConfig(t, rhiza.Config{NodeID: "account-password-ingress-test", DataDir: t.TempDir()})
}

func newPasswordIngressHandlerWithConfig(t *testing.T, config rhiza.Config) (*Handler, *rhiza.DB, *http.Cookie, string) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	statements := append(browser.SchemaStatements(), identity.SchemaStatements()...)
	statements = append(statements, rhiza.SQLStatement{SQL: `CREATE TABLE IF NOT EXISTS identity_external_links (
		provider_id TEXT NOT NULL, external_key TEXT NOT NULL, local_subject TEXT NOT NULL,
		linked_at_unix_ms INTEGER NOT NULL, PRIMARY KEY(provider_id,external_key), UNIQUE(local_subject,provider_id)
	) STRICT`})
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "account-password-ingress-schema", Statements: statements}); err != nil {
		t.Fatal(err)
	}
	rules := testRules()
	hasher := testHasher(t)
	identities, err := identity.NewStoreWithPolicies(db, hasher, rules)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := hasher.Hash(ctx, []byte("CurrentPassword1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.BootstrapUser(ctx, "subject-1", "alice", phc); err != nil {
		t.Fatal(err)
	}
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateSession(ctx, "subject-1", "pwd", time.Date(2100, time.January, 1, 1, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie("https://issuer.example.test", issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := browser.DeriveCSRFToken(issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New("https://issuer.example.test", sessions, identities, rules)
	if err != nil {
		t.Fatal(err)
	}
	return h, db, cookie, csrf
}
