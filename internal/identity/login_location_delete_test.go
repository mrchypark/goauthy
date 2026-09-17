package identity

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDeleteUserCleansOnlyOwnedLoginLocationsAtomically(t *testing.T) {
	store := testConversionStore(t)
	ctx := t.Context()
	for _, subject := range []string{"location-target", "location-other"} {
		bootstrapPassword(t, store, subject, subject, []byte("CurrentPassword1"))
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "login-location-delete-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_login_locations(subject,ip_address,first_seen_at_unix_ms,last_seen_at_unix_ms,login_count,browser_id,user_agent,location) VALUES
			('location-target','192.0.2.10',1,1,1,'browser-a','ua-a','private-a'),
			('location-target','192.0.2.11',2,2,1,'browser-b','ua-b','private-b'),
			('location-other','192.0.2.12',3,3,1,'browser-c','ua-c','private-c')`},
	}}); err != nil {
		t.Fatal(err)
	}
	assertLocations := func(target, other int64) {
		t.Helper()
		assertCount(t, store, `SELECT COUNT(*) FROM identity_login_locations WHERE subject='location-target'`, target)
		assertCount(t, store, `SELECT COUNT(*) FROM identity_login_locations WHERE subject='location-other'`, other)
	}

	if err := store.DeleteUserWithGuard(ctx, "location-target", "0=1", nil); !errors.Is(err, ErrDeleteUnauthorized) {
		t.Fatalf("denied deletion: %v", err)
	}
	assertLocations(2, 1)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "login-location-delete-trigger", SQL: `CREATE TRIGGER reject_login_location_user_delete BEFORE DELETE ON identity_users WHEN OLD.subject='location-target' BEGIN SELECT RAISE(ABORT,'delete failure'); END`}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUserWithGuard(ctx, "location-target", "1=1", nil); err == nil {
		t.Fatal("late deletion failure committed")
	}
	assertLocations(2, 1)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "login-location-delete-trigger-drop", SQL: `DROP TRIGGER reject_login_location_user_delete`}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUserWithGuard(ctx, "location-target", "1=1", nil); err != nil {
		t.Fatal(err)
	}
	assertLocations(0, 1)
}
