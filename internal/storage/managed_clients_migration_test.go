package storage

import (
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV63ManagedClientsContract(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "managed-clients-v63", DataDir: testDatabaseDir(t, "managed-clients-v63")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT name,type,"notnull" FROM pragma_table_info('managed_oauth_clients') ORDER BY cid`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) != 9 {
		t.Fatalf("managed client columns=%d", len(rows.Rows))
	}
	for _, name := range []string{"id", "generation", "revision", "enabled", "deleted", "metadata_json", "secret_hash", "secret_envelope", "force_mfa"} {
		found := false
		for _, row := range rows.Rows {
			if row[0] == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing managed client column %q", name)
		}
	}
	if err := Ready(context.Background(), db); err != nil {
		t.Fatal(err)
	}
}
