//go:build confirmationproof

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mrchypark/rhiza"
)

type confirmationRecoveryKey struct{}
type confirmationRecoveryCall struct {
	calls int
	first string
}

func confirmationRecoveryExecute(ctx context.Context, db *rhiza.DB, request rhiza.ExecuteRequest) (rhiza.ExecuteResponse, error) {
	if call, ok := ctx.Value(confirmationRecoveryKey{}).(*confirmationRecoveryCall); ok {
		encoded, err := json.Marshal(request)
		if err != nil {
			panic(err)
		}
		call.calls++
		if call.calls == 1 {
			call.first = string(encoded)
			return rhiza.ExecuteResponse{}, rhiza.ErrCommitUnknown
		}
		if string(encoded) != call.first {
			panic("recovery changed exact request")
		}
	}
	return db.Execute(ctx, request)
}

func TestConfirmationRecoveryRechecksFingerprint(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "rejected"}[rejected], func(t *testing.T) {
			db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "fingerprint", DataDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "schema", SQL: "CREATE TABLE proof(id INTEGER PRIMARY KEY)"}); err != nil {
				t.Fatal(err)
			}
			one := int64(1)
			predicate := 1
			if rejected {
				predicate = 0
			}
			original := rhiza.ExecuteRequest{RequestID: "collision", Statements: []rhiza.SQLStatement{{SQL: "INSERT INTO proof SELECT 1 WHERE ?=1", Args: []any{predicate}, ExpectedRowsAffected: &one}}}
			receipt, err := Execute(t.Context(), db, original)
			if (err != nil) != rejected {
				t.Fatalf("seed: %v", err)
			}
			for _, changed := range []bool{false, true} {
				request := original
				request.Statements = append([]rhiza.SQLStatement(nil), original.Statements...)
				if changed {
					request.Statements[0].Args = []any{1 - predicate}
				}
				call := &confirmationRecoveryCall{}
				ctx := context.WithValue(t.Context(), confirmationRecoveryKey{}, call)
				got, err := Execute(ctx, db, request)
				if call.calls != 2 {
					t.Fatalf("recovery Execute calls=%d; ID-only status accepted", call.calls)
				}
				if changed {
					if !errors.Is(err, rhiza.ErrCommitUnknown) || !errors.Is(err, rhiza.ErrRequestConflict) || got.Status != receipt.Status {
						t.Fatalf("conflicting recovery=%+v %v", got, err)
					}
				} else if got.Slot != receipt.Slot || got.Status != receipt.Status || (err != nil) != rejected || errors.Is(err, rhiza.ErrCommitUnknown) {
					t.Fatalf("exact recovery=%+v %v", got, err)
				}
			}
		})
	}
}
