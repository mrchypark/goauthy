package dcr

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDeleteRegistrationCleansClientThemeAtomically(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	created, err := store.Create(ctx, validRequest("delete-theme", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "dcr-theme-delete-seed",
		SQL:       `INSERT INTO client_themes(client_id,version,updated_at_unix_ms,document_json) VALUES(?,1,1,?)`,
		Args:      []any{created.ClientID, `{"client_id":"delete-theme"}`},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "logo-delete-seed", SQL: `INSERT INTO client_logos(client_id,res,content_type,data,updated) VALUES(?,'small','image/webp',?,1),(?,'favicon','image/webp',?,1)`, Args: []any{created.ClientID, []byte{1}, created.ClientID, []byte{2}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "legacy-favicon-delete-seed", SQL: `INSERT INTO client_favicons VALUES(?,'image/png',?,1)`, Args: []any{created.ClientID, []byte{3}}}); err != nil {
		t.Fatal(err)
	}
	assertTheme := func(want int64) {
		t.Helper()
		legacy, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM client_favicons WHERE client_id=?`, Args: []any{created.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || legacy.Rows[0][0] != want {
			t.Fatalf("legacy favicon rows=%v err=%v", legacy.Rows, err)
		}
		logos, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM client_logos WHERE client_id=?`, Args: []any{created.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || logos.Rows[0][0] != want*2 {
			t.Fatalf("client logo rows=%v err=%v", logos.Rows, err)
		}
		row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM client_themes WHERE client_id=?`, Args: []any{created.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != want {
			t.Fatalf("client theme rows=%v err=%v", row.Rows, err)
		}
	}

	if err := store.DeleteRegistration(ctx, created.ClientID, "wrong-registration-token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong registration token delete=%v", err)
	}
	assertTheme(1)

	if err := store.DeleteRegistration(ctx, created.ClientID, created.RegistrationAccessToken); err != nil {
		t.Fatal(err)
	}
	assertTheme(0)
}
