package storage

import (
	"context"
	"errors"

	"github.com/mrchypark/rhiza"
)

// ExecuteEnvelope executes a mutation with the master-key retirement fence in
// the same replicated transaction. The old writer is rejected only after the
// barrier reaches fenced or ready, and a writer whose key retired a completed
// generation is rejected for good, so it cannot acquire new ciphertext
// references after a later rotation rewrites the barrier row (GA66-RETIRE-001).
// All preceding statements roll back with the rejection.
func ExecuteEnvelope(ctx context.Context, db *rhiza.DB, writerKeyID string, request rhiza.ExecuteRequest) (rhiza.ExecuteResponse, error) {
	if db == nil {
		return rhiza.ExecuteResponse{}, errors.New("envelope database is required")
	}
	if !validRetirementKeyID(writerKeyID) {
		return rhiza.ExecuteResponse{}, errors.New("invalid envelope writer key ID")
	}
	if request.RequireOne {
		return rhiza.ExecuteResponse{}, errors.New("envelope requests do not support require_one")
	}

	topLevel := len(request.Statements) == 0
	statements := make([]rhiza.SQLStatement, 0, len(request.Statements)+1)
	if topLevel {
		statements = append(statements, rhiza.SQLStatement{
			SQL:      request.SQL,
			Args:     append([]any(nil), request.Args...),
			WantRows: request.WantRows,
		})
	} else {
		statements = append(statements, request.Statements...)
	}
	statements = append(statements, rhiza.SQLStatement{
		SQL:  `UPDATE master_key_retirement_barrier SET epoch=-1 WHERE barrier_id=1 AND ((state IN ('fenced','ready') AND replacement_key_id<>?) OR EXISTS (SELECT 1 FROM master_key_retirement_generations WHERE old_key_id=? AND ready_at_unix_ms IS NOT NULL))`,
		Args: []any{writerKeyID, writerKeyID},
	})

	if topLevel {
		request.SQL = ""
		request.Args = nil
		request.WantRows = false
	}
	request.Statements = statements
	return Execute(ctx, db, request)
}
