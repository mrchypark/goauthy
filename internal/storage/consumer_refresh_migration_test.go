package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV82ConsumerRefresh(t *testing.T) {
	t.Run("fresh and replay default false", func(t *testing.T) {
		db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "consumer-refresh-v82", DataDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if err := Migrate(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"saas_use_grants", "saas_use_handoffs"} {
			rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT dflt_value FROM pragma_table_info(?) WHERE name='allow_refresh'`, Args: []any{table}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "0" {
				t.Fatalf("%s default=%v err=%v", table, rows.Rows, err)
			}
		}
		if err := Migrate(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=82`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(1) {
			t.Fatalf("marker=%v err=%v", marker.Rows, err)
		}
	})

	t.Run("legacy true preserved and invalid rejected", func(t *testing.T) {
		db := openRefreshLegacy(t, "consumer-refresh-v82-legacy")
		if err := migrateSchemaV82(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"saas_use_grants", "saas_use_handoffs"} {
			rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT allow_refresh FROM ` + table + ` WHERE id='existing'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
				t.Fatalf("%s legacy=%v err=%v", table, rows.Rows, err)
			}
		}
		for _, table := range []string{"saas_use_grants", "saas_use_handoffs"} {
			if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "consumer-refresh-v82-invalid-" + table, SQL: `UPDATE ` + table + ` SET allow_refresh=-1 WHERE id='existing'`}); err == nil {
				t.Fatalf("%s accepted negative allow_refresh", table)
			}
		}
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "consumer-refresh-v82-enable", Statements: []rhiza.SQLStatement{
			{SQL: `UPDATE saas_use_grants SET allow_refresh=1 WHERE id='existing'`},
			{SQL: `UPDATE saas_use_handoffs SET allow_refresh=1 WHERE id='existing'`},
		}}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV82(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"saas_use_grants", "saas_use_handoffs"} {
			rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT allow_refresh FROM ` + table + ` WHERE id='existing'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) {
				t.Fatalf("%s replay changed true value: %v err=%v", table, rows.Rows, err)
			}
		}
	})

	t.Run("missing second table rolls back first alteration", func(t *testing.T) {
		db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "consumer-refresh-v82-missing", DataDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "consumer-refresh-v82-missing-schema", Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(81)`},
			{SQL: `CREATE TABLE saas_use_grants(id TEXT PRIMARY KEY NOT NULL) STRICT`},
		}}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV82(t.Context(), db); err == nil {
			t.Fatal("migration succeeded without saas_use_handoffs")
		}
		column, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM pragma_table_info('saas_use_grants') WHERE name='allow_refresh'`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(column.Rows) != 1 || column.Rows[0][0] != int64(0) {
			t.Fatalf("first alteration was not rolled back: %v err=%v", column.Rows, err)
		}
		marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=82`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(0) {
			t.Fatalf("marker=%v err=%v", marker.Rows, err)
		}
	})
}

func openRefreshLegacy(t *testing.T, nodeID string) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: nodeID, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: nodeID + "-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(81)`},
		{SQL: `CREATE TABLE saas_use_grants(id TEXT PRIMARY KEY NOT NULL) STRICT`},
		{SQL: `CREATE TABLE saas_use_handoffs(id TEXT PRIMARY KEY NOT NULL) STRICT`},
		{SQL: `INSERT INTO saas_use_grants(id) VALUES('existing')`},
		{SQL: `INSERT INTO saas_use_handoffs(id) VALUES('existing')`},
	}}); err != nil {
		t.Fatal(err)
	}
	return db
}
