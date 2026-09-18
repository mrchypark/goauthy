package clients

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDeleteWithGuardCleansClientThemeAtomically(t *testing.T) {
	s, ctx := testStore(t)
	c, err := s.CreateWithGuard(ctx, newClient(false), auth())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: "managed-theme-delete-seed",
		SQL:       `INSERT INTO client_themes(client_id,version,updated_at_unix_ms,document_json) VALUES(?,1,1,?)`,
		Args:      []any{c.ID, `{"client_id":"managed-test-client"}`},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "logo-delete-seed", SQL: `INSERT INTO client_logos(client_id,res,content_type,data,updated) VALUES(?,'small','image/webp',?,1),(?,'favicon','image/webp',?,1)`, Args: []any{c.ID, []byte{1}, c.ID, []byte{2}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "legacy-favicon-delete-seed", SQL: `INSERT INTO client_favicons VALUES(?,'image/png',?,1)`, Args: []any{c.ID, []byte{3}}}); err != nil {
		t.Fatal(err)
	}
	assertTheme := func(want int64) {
		t.Helper()
		legacy, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM client_favicons WHERE client_id=?`, Args: []any{c.ID}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || legacy.Rows[0][0] != want {
			t.Fatalf("legacy favicon rows=%v err=%v", legacy.Rows, err)
		}
		logos, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM client_logos WHERE client_id=?`, Args: []any{c.ID}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || logos.Rows[0][0] != want*2 {
			t.Fatalf("client logo rows=%v err=%v", logos.Rows, err)
		}
		row, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM client_themes WHERE client_id=?`, Args: []any{c.ID}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != want {
			t.Fatalf("client theme rows=%v err=%v", row.Rows, err)
		}
	}

	if err := s.DeleteWithGuard(ctx, c.ID, c.Revision, denied()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("denied delete=%v", err)
	}
	assertTheme(1)

	if err := s.DeleteWithGuard(ctx, c.ID, c.Revision+1, auth()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete=%v", err)
	}
	assertTheme(1)

	if err := s.DeleteWithGuard(ctx, c.ID, c.Revision, auth()); err != nil {
		t.Fatal(err)
	}
	assertTheme(0)
}
