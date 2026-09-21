package identity

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDeleteUserCleansOnlyOwnedUpstreamSessionBindings(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	ctx := t.Context()
	for _, subject := range []string{"binding-target", "binding-other"} {
		bootstrapPassword(t, store, subject, subject, []byte("CurrentPassword1"))
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "upstream-binding-delete-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES('binding-target-a','binding-target',1,90000,1),('binding-target-b','binding-target',1,90000,1),('binding-other','binding-other',1,90000,1)`},
		{SQL: `INSERT INTO browser_upstream_session_bindings(session_digest,issuer,client_id,upstream_subject,upstream_sid,created_at_unix_ms) VALUES('binding-target-a','https://upstream.example.test','client','target','sid-a',1),('binding-target-b','https://upstream.example.test','client','target','sid-b',1),('binding-other','https://upstream.example.test','client','other','sid-other',1)`},
	}}); err != nil {
		t.Fatal(err)
	}
	assertBindings := func(target, other int64) {
		t.Helper()
		assertCount(t, store, `SELECT COUNT(*) FROM browser_upstream_session_bindings WHERE session_digest IN ('binding-target-a','binding-target-b')`, target)
		assertCount(t, store, `SELECT COUNT(*) FROM browser_upstream_session_bindings WHERE session_digest='binding-other'`, other)
	}
	if err := store.DeleteUserWithGuard(ctx, "binding-target", "0=1", nil); !errors.Is(err, ErrDeleteUnauthorized) {
		t.Fatalf("denied deletion: %v", err)
	}
	assertBindings(2, 1)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "upstream-binding-delete-trigger", SQL: `CREATE TRIGGER reject_binding_user_delete BEFORE DELETE ON identity_users WHEN OLD.subject='binding-target' BEGIN SELECT RAISE(ABORT,'delete failure'); END`}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUserWithGuard(ctx, "binding-target", "1=1", nil); err == nil {
		t.Fatal("late deletion failure committed")
	}
	assertBindings(2, 1)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "upstream-binding-delete-trigger-drop", SQL: `DROP TRIGGER reject_binding_user_delete`}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUserWithGuard(ctx, "binding-target", "1=1", nil); err != nil {
		t.Fatal(err)
	}
	assertBindings(0, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM browser_sessions WHERE subject='binding-target'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM browser_sessions WHERE subject='binding-other'`, 1)
}
