package storage

import (
	"reflect"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV115FollowsV114AndPreservesOTPState(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "otp-verification-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for range 2 {
		if err := Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	versions, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version IN (114,115) ORDER BY version`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(versions.Rows) != 2 || !reflect.DeepEqual(versions.Rows, [][]any{{int64(114)}, {int64(115)}}) {
		t.Fatalf("migration versions=%v err=%v", versions.Rows, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "otp-v115-preserve", SQL: `INSERT INTO identity_email_otp(code_digest,subject,expires_at_unix_ms) VALUES('existing','subject',2000)`}); err != nil {
		t.Fatal(err)
	}
	if err := migrateOTPVerificationLimits(ctx, db); err != nil {
		t.Fatal(err)
	}
	if got := queryInt64(t, db, `SELECT COUNT(*) FROM identity_email_otp WHERE code_digest='existing'`); got != 1 {
		t.Fatalf("existing OTP rows=%d", got)
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatal(err)
	}
}
