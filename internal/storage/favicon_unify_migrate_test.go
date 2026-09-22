package storage

import (
	"bytes"
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV94UnifiesLegacyClientFavicons(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "favicon-unify", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "favicon-unify-fixture", SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV43(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV93(ctx, db); err != nil {
		t.Fatal(err)
	}

	legacyPNG := []byte("legacy-png-bytes")
	legacyICO := []byte("legacy-ico-bytes")
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "favicon-unify-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO client_logos(client_id,res,content_type,data,updated) VALUES
 ('client-a','small','image/webp',?,50),
 ('client-a','svg','image/svg+xml',?,60),
 ('client-a','favicon','image/webp',?,200),
 ('client-c','favicon','image/webp',?,100),
 ('client-tie','favicon','image/webp',?,400)`, Args: []any{[]byte("existing-raster"), []byte("existing-svg"), []byte("newer-favicon"), []byte("older-favicon"), []byte("tie-existing")}},
		{SQL: `INSERT INTO client_favicons(client_id,content_type,data,updated_at_unix_ms) VALUES
 ('client-a','image/png',?,150),
 ('client-b','image/png',?,300),
 ('client-c','image/x-icon',?,101),
 ('client-tie','image/png',?,400)`, Args: []any{legacyPNG, legacyPNG, legacyICO, []byte("tie-legacy")}},
	}}); err != nil {
		t.Fatal(err)
	}

	if err := migrateSchemaV94(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV95(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV96(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV97(ctx, db); err != nil {
		t.Fatal(err)
	}
	assertFaviconUnifiedRow(t, db, "client-a", "small", "image/webp", []byte("existing-raster"), 50)
	assertFaviconUnifiedRow(t, db, "client-a", "svg", "image/svg+xml", []byte("existing-svg"), 60)
	// The existing unified favicon is newer, so the legacy PNG cannot replace it.
	assertFaviconUnifiedRow(t, db, "client-a", "favicon", "image/webp", []byte("newer-favicon"), 200)
	assertFaviconUnifiedRow(t, db, "client-b", "favicon", "image/png", legacyPNG, 300)
	// A newer legacy ICO replaces the older unified favicon, preserving its MIME and bytes.
	assertFaviconUnifiedRow(t, db, "client-c", "favicon", "image/x-icon", legacyICO, 101)
	// Equal timestamps deterministically keep the existing unified row.
	assertFaviconUnifiedRow(t, db, "client-tie", "favicon", "image/webp", []byte("tie-existing"), 400)

	legacyCount := queryInt64(t, db, `SELECT COUNT(*) FROM client_favicons`)
	if legacyCount != 4 {
		t.Fatalf("legacy favicon rows=%d want=4", legacyCount)
	}

	if err := migrateSchemaV94(ctx, db); err != nil {
		t.Fatal(err)
	}
	assertFaviconUnifiedRow(t, db, "client-b", "favicon", "image/png", legacyPNG, 300)
	assertFaviconUnifiedRow(t, db, "client-c", "favicon", "image/x-icon", legacyICO, 101)
	assertFaviconUnifiedRow(t, db, "client-tie", "favicon", "image/webp", []byte("tie-existing"), 400)
	if got := queryInt64(t, db, `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=94`); got != 1 {
		t.Fatalf("schema 94 markers=%d want=1", got)
	}

	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "favicon-unify-allowed-legacy-mime", SQL: `INSERT INTO client_logos(client_id,res,content_type,data,updated) VALUES('client-d','favicon','image/png',?,1),('client-e','favicon','image/x-icon',?,1)`, Args: []any{[]byte("png"), []byte("ico")}}); err != nil {
		t.Fatalf("legacy favicon MIME rejected: %v", err)
	}
	for _, tc := range []struct {
		name, resolution, contentType string
	}{
		{"png on raster", "small", "image/png"},
		{"ico on svg", "svg", "image/x-icon"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "favicon-unify-reject-" + tc.name, SQL: `INSERT INTO client_logos(client_id,res,content_type,data,updated) VALUES(?,?,?,?,1)`, Args: []any{"invalid-" + tc.name, tc.resolution, tc.contentType, []byte("invalid")}}); err == nil {
				t.Fatalf("accepted %s for %s", tc.contentType, tc.resolution)
			}
		})
	}
}

func TestMigrationV94FullPathIsIdempotentAndReady(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "favicon-unify-full", DataDir: testDatabaseDir(t, "favicon-unify-full")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for range 2 {
		if err := Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
		if err := Ready(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if got := queryInt64(t, db, `SELECT MAX(version) FROM goauthy_schema_migrations`); got != int64(schemaVersion) {
		t.Fatalf("schema version=%d want=%d", got, schemaVersion)
	}
}

func assertFaviconUnifiedRow(t *testing.T, db *rhiza.DB, clientID, resolution, contentType string, wantData []byte, wantUpdated int64) {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT content_type,data,updated FROM client_logos WHERE client_id=? AND res=?`, Args: []any{clientID, resolution}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 3 {
		t.Fatalf("row %s/%s=%#v err=%v", clientID, resolution, result.Rows, err)
	}
	data, ok := result.Rows[0][1].([]byte)
	if !ok || result.Rows[0][0] != contentType || !bytes.Equal(data, wantData) || result.Rows[0][2] != wantUpdated {
		t.Fatalf("row %s/%s=%#v want=(%q,%q,%d)", clientID, resolution, result.Rows[0], contentType, wantData, wantUpdated)
	}
}

func queryInt64(t *testing.T, db *rhiza.DB, sql string) int64 {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: sql, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("query %q rows=%#v err=%v", sql, result.Rows, err)
	}
	value, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("query %q value=%#v is not int64", sql, result.Rows[0][0])
	}
	return value
}
