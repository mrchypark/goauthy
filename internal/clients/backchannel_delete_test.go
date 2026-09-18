package clients

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDeleteWithGuardCleansBackchannelChildrenAtomically(t *testing.T) {
	s, ctx := testStore(t)
	c, err := s.CreateWithGuard(ctx, newClient(true), auth())
	if err != nil {
		t.Fatal(err)
	}
	seed := []rhiza.SQLStatement{
		{SQL: `INSERT INTO oidc_backchannel_deliveries(event_id,client_id,sid,subject,logout_uri,allow_private,allow_http,next_attempt_at_unix_ms,created_at_unix_ms) VALUES(?,?,?,?,?,0,0,0,0)`, Args: []any{"event", c.ID, nil, "user", "https://rp.example.test/logout"}},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,0,0,0)`, Args: []any{"sid", c.ID, "https://rp.example.test/logout"}},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,0,0,0)`, Args: []any{"user", c.ID, "https://rp.example.test/logout"}},
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "managed-delete-seed", Statements: seed}); err != nil {
		t.Fatal(err)
	}

	assertDeleteState := func(wantDeleted, wantEnabled int64, wantRevision int64, wantChildren int64) {
		t.Helper()
		row, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT deleted,enabled,revision,secret_envelope FROM managed_oauth_clients WHERE id=?`, Args: []any{c.ID}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || len(row.Rows[0]) != 4 {
			t.Fatalf("managed delete state rows=%v err=%v", row.Rows, err)
		}
		if row.Rows[0][0] != wantDeleted || row.Rows[0][1] != wantEnabled || row.Rows[0][2] != wantRevision {
			t.Fatalf("managed delete state=%v", row.Rows[0])
		}
		if wantDeleted == 0 && row.Rows[0][3] == nil {
			t.Fatal("secret envelope was cleared before delete committed")
		}
		if wantDeleted == 1 && row.Rows[0][3] != nil {
			t.Fatal("secret envelope survived delete")
		}
		for _, table := range []string{"oidc_backchannel_deliveries", "oidc_session_clients", "oidc_user_clients"} {
			children, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM " + table + " WHERE client_id=?", Args: []any{c.ID}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(children.Rows) != 1 || children.Rows[0][0] != wantChildren {
				t.Fatalf("%s rows=%v err=%v", table, children.Rows, err)
			}
		}
	}

	if err := s.DeleteWithGuard(ctx, c.ID, c.Revision, denied()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("denied delete=%v", err)
	}
	assertDeleteState(0, 1, c.Revision, 1)

	if err := s.DeleteWithGuard(ctx, c.ID, c.Revision+1, auth()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete=%v", err)
	}
	assertDeleteState(0, 1, c.Revision, 1)

	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "managed-delete-failure-trigger", SQL: `CREATE TRIGGER managed_delete_child_failure BEFORE DELETE ON oidc_user_clients WHEN OLD.client_id='managed-test-client' BEGIN SELECT RAISE(ABORT,'managed child delete failed'); END`}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteWithGuard(ctx, c.ID, c.Revision, auth()); err == nil {
		t.Fatal("child failure delete succeeded")
	}
	assertDeleteState(0, 1, c.Revision, 1)
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "managed-delete-drop-trigger", SQL: `DROP TRIGGER managed_delete_child_failure`}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteWithGuard(ctx, c.ID, c.Revision, auth()); err != nil {
		t.Fatal(err)
	}
	assertDeleteState(1, 0, c.Revision+1, 0)
}
