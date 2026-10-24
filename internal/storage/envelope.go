package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/mrchypark/rhiza"
)

const envelopeWriterRejectedPredicate = `((master_key_retirement_barrier.state IN ('fenced','ready') AND master_key_retirement_barrier.replacement_key_id<>?) OR EXISTS (SELECT 1 FROM master_key_retirement_generations WHERE old_key_id=? AND ready_at_unix_ms IS NOT NULL))`

// CheckEnvelopeWriterAllowed performs a fresh linearizable admission check for
// a writer that is about to return newly sealed ciphertext. Unlike the cached
// retention registration, this result is permission for this issuance only.
func CheckEnvelopeWriterAllowed(ctx context.Context, db *rhiza.DB, writerKeyID string) error {
	if db == nil || ctx == nil || ctx.Err() != nil || !validRetirementKeyID(writerKeyID) {
		return errors.New("invalid envelope writer admission check")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:  `SELECT EXISTS(SELECT 1 FROM master_key_retirement_barrier WHERE barrier_id=1 AND ` + envelopeWriterRejectedPredicate + `)`,
		Args: []any{writerKeyID, writerKeyID}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return errors.New("invalid envelope writer admission result")
	}
	rejected, ok := result.Rows[0][0].(int64)
	if !ok || (rejected != 0 && rejected != 1) {
		return errors.New("invalid envelope writer admission state")
	}
	if rejected == 1 {
		return fmt.Errorf("%w: envelope writer key is fenced or retired", ErrMasterKeyRetirementConflict)
	}
	return nil
}

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
		SQL:  `UPDATE master_key_retirement_barrier SET epoch=-1 WHERE barrier_id=1 AND ` + envelopeWriterRejectedPredicate,
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
