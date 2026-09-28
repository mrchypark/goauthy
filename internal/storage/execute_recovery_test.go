package storage

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/mrchypark/rhiza"
)

// Both outcomes can apply locally before the before-ACK object-store write fails.
// RequestStatus alone is neither a fingerprint nor a durability confirmation.
func TestExecuteRecoveryRequiresDurableExactReceipt(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "rejected"}[rejected], func(t *testing.T) {
			ctx := context.Background()
			objects := t.TempDir()
			config := rhiza.Config{NodeID: "receipt-recovery", DataDir: t.TempDir(), ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: objects, ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck}
			db, err := rhiza.Open(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if db != nil {
					_ = db.Close()
				}
			})
			if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "schema", SQL: "CREATE TABLE proof (id INTEGER PRIMARY KEY) STRICT"}); err != nil {
				t.Fatal(err)
			}
			one := int64(1)
			predicate := 1
			if rejected {
				predicate = 0
			}
			request := rhiza.ExecuteRequest{RequestID: "proof", Statements: []rhiza.SQLStatement{{SQL: "INSERT INTO proof SELECT 1 WHERE ?=1", Args: []any{predicate}, ExpectedRowsAffected: &one}}}
			backup := objects + "-backup"
			if err := os.Rename(objects, backup); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(objects, []byte("unavailable"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(objects); _ = os.Rename(backup, objects) })
			expected := rhiza.MutationCommitted
			if rejected {
				expected = rhiza.MutationRejected
			}
			var original rhiza.MutationReceipt
			for range 2 {
				response, err := Execute(ctx, db, request)
				if !errors.Is(err, rhiza.ErrCommitUnknown) || response.Status != expected {
					t.Fatalf("unconfirmed receipt=%+v err=%v", response.MutationReceipt, err)
				}
				original = response.MutationReceipt
			}
			if err := os.Remove(objects); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(backup, objects); err != nil {
				t.Fatal(err)
			}
			check := func() {
				t.Helper()
				response, err := Execute(ctx, db, request)
				if response.Slot != original.Slot || response.Status != expected || response.RetryThroughSlot != original.RetryThroughSlot {
					t.Fatalf("replay changed receipt: %+v", response)
				}
				if rejected {
					if err == nil || errors.Is(err, rhiza.ErrCommitUnknown) || response.ErrorCode != rhiza.MutationErrorCodePreconditionFailed {
						t.Fatalf("confirmed rejection=%+v err=%v", response, err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				changed := request
				changed.Statements = append([]rhiza.SQLStatement(nil), request.Statements...)
				changed.Statements[0].Args = []any{1 - predicate}
				if _, err := Execute(ctx, db, changed); !errors.Is(err, rhiza.ErrRequestConflict) {
					t.Fatalf("changed request=%v", err)
				}
				rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM proof"})
				want := int64(1)
				if rejected {
					want = 0
				}
				if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != want {
					t.Fatalf("effects=%+v err=%v", rows, err)
				}
			}
			check()
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = rhiza.Open(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			check()
		})
	}
}
