package storage

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

func TestExecuteEnvelopeFenceStates(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"none", MasterKeyRetirementPrepared, MasterKeyRetirementAborted, MasterKeyRetirementFenced, MasterKeyRetirementReady} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			db := envelopeTestDB(t, state)
			if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "envelope-create-" + state, SQL: `CREATE TABLE envelope_mutations (value TEXT NOT NULL) STRICT`}); err != nil {
				t.Fatal(err)
			}

			_, err := ExecuteEnvelope(ctx, db, "key-a", rhiza.ExecuteRequest{
				RequestID: "envelope-mutate-" + state,
				SQL:       `INSERT INTO envelope_mutations(value) VALUES (?)`,
				Args:      []any{"before-fence"},
			})
			if state == MasterKeyRetirementFenced || state == MasterKeyRetirementReady {
				if err == nil {
					t.Fatal("old writer was accepted after fence")
				}
			} else if err != nil {
				t.Fatalf("writer rejected in %s state: %v", state, err)
			}
			expectedCount := int64(1)
			if state == MasterKeyRetirementFenced || state == MasterKeyRetirementReady {
				expectedCount = 0
			}
			result, queryErr := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM envelope_mutations`, Consistency: rhiza.ConsistencyLinearizable})
			if queryErr != nil || len(result.Rows) != 1 || result.Rows[0][0] != expectedCount {
				t.Fatalf("mutation count=%#v err=%v", result.Rows, queryErr)
			}
		})
	}
}

func TestExecuteEnvelopeAllowsReplacementAndPreservesRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := envelopeTestDB(t, MasterKeyRetirementFenced)
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "envelope-create-replacement", SQL: `CREATE TABLE envelope_replacement (value TEXT NOT NULL) STRICT`}); err != nil {
		t.Fatal(err)
	}
	response, err := ExecuteEnvelope(ctx, db, "key-b", rhiza.ExecuteRequest{
		RequestID: "envelope-replacement",
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO envelope_replacement(value) VALUES (?) RETURNING value`, Args: []any{"replacement"}, WantRows: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Statements) != 2 || len(response.Statements[0].Rows) != 1 || response.Statements[0].Rows[0][0] != "replacement" {
		t.Fatalf("response statements=%#v", response.Statements)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM envelope_replacement`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("replacement count=%#v err=%v", result.Rows, err)
	}
}

func TestExecuteEnvelopeRejectsThirdKeyAndRollsBack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := envelopeTestDB(t, MasterKeyRetirementFenced)
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "envelope-create-third-key", SQL: `CREATE TABLE envelope_third_key (value TEXT NOT NULL) STRICT`}); err != nil {
		t.Fatal(err)
	}

	if _, err := ExecuteEnvelope(ctx, db, "key-c", rhiza.ExecuteRequest{
		RequestID: "envelope-third-key",
		SQL:       `INSERT INTO envelope_third_key(value) VALUES (?)`,
		Args:      []any{"rejected"},
	}); err == nil {
		t.Fatal("third writer was accepted after fence")
	}

	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM envelope_third_key`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("third-key mutation count=%#v err=%v", result.Rows, err)
	}
}

func TestExecuteEnvelopeValidatesInputs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, err := ExecuteEnvelope(ctx, nil, "key-a", rhiza.ExecuteRequest{RequestID: "nil-db", SQL: "SELECT 1"}); err == nil {
		t.Fatal("nil database accepted")
	}
	db := envelopeTestDB(t, "none")
	for _, writerKeyID := range []string{"", "bad key", "key/a"} {
		if _, err := ExecuteEnvelope(ctx, db, writerKeyID, rhiza.ExecuteRequest{RequestID: "invalid-writer-" + writerKeyID, SQL: "SELECT 1"}); err == nil {
			t.Fatalf("invalid writer key %q accepted", writerKeyID)
		}
	}
}

func envelopeTestDB(t *testing.T, state string) *rhiza.DB {
	t.Helper()
	db := retirementTestDB(t)
	if state == "none" {
		return db
	}
	ctx := context.Background()
	now := time.UnixMilli(1_800_000_000_000).UTC()
	if _, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now}); err != nil {
		t.Fatal(err)
	}
	switch state {
	case MasterKeyRetirementPrepared:
	case MasterKeyRetirementAborted:
		if _, err := AbortMasterKeyRetirement(ctx, db, 1, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	case MasterKeyRetirementFenced, MasterKeyRetirementReady:
		if _, err := FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if state == MasterKeyRetirementReady {
			for _, node := range []string{"node-0", "node-1", "node-2"} {
				if _, err := AttestMasterKeyRetirement(ctx, db, MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: node, BootID: node + "-boot", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: now.Add(2 * time.Second), Status: MasterKeyRetirementStatus{}}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ReadyMasterKeyRetirement(ctx, db, 1, now.Add(3*time.Second)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return db
}
