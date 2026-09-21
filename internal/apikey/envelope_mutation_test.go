package apikey

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// envelopeFixture sets up a store, principal, and context, then optionally
// advances the master-key retirement barrier to the given state.  When state
// is empty the barrier is left untouched (no retirement in progress).
func envelopeFixture(t *testing.T, state string, rights ...Right) (*Store, *Principal, context.Context) {
	t.Helper()
	ctx := context.Background()
	db := openTestDB(t, "apikey-envelope-"+state)
	if state != "" {
		now := time.UnixMilli(1_800_000_000_000).UTC()
		if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{
			Epoch:            1,
			OldKeyID:         "key-a",
			ReplacementKeyID: "key-b",
			MemberIDs:        []string{"node-0", "node-1", "node-2"},
			PreparedAt:       now,
		}); err != nil {
			t.Fatal(err)
		}
		switch state {
		case storage.MasterKeyRetirementFenced:
			if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		case storage.MasterKeyRetirementReady:
			if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			for _, node := range []string{"node-0", "node-1", "node-2"} {
				if _, err := storage.AttestMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementAttestationRequest{
					Epoch:               1,
					NodeID:              node,
					BootID:              node + "-boot",
					ActiveKeyID:         "key-b",
					AttestationSequence: 1,
					AttestedAt:          now.Add(2 * time.Second),
					Status:              storage.MasterKeyRetirementStatus{},
				}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := storage.ReadyMasterKeyRetirement(ctx, db, 1, now.Add(3*time.Second)); err != nil {
				t.Fatal(err)
			}
		}
	}
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	if len(rights) == 0 {
		rights = []Right{Create, Update, Delete}
	}
	_, token, err := s.Create(ctx, nil, Request{Name: "manager", Access: []Access{{Group: GroupAPIKeys, AccessRights: rights}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	return s, &p, ctx
}

func TestRunEnvelopeMutationAuthorizedMutationSucceeds(t *testing.T) {
	t.Parallel()
	s, p, ctx := envelopeFixture(t, "")
	requestID := strings.Repeat("e", 43)
	targetDigest := strings.Repeat("T", 43)
	response, ok, err := s.RunEnvelopeMutation(ctx, "key-a", p, GroupAPIKeys, Create, requestID, []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms,expires_at_unix_ms) SELECT ?,?,?,NULL WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{"target", targetDigest, int64(1), requestID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("mutation reported forbidden")
	}
	if response.RowsAffected < 2 {
		t.Fatalf("rows_affected=%d", response.RowsAffected)
	}
	if _, err := s.byName(ctx, "target"); err != nil {
		t.Fatalf("target missing: %v", err)
	}
	// Guard must be cleaned up.
	guards, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_key_mutation_guards`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || guards.Rows[0][0] != int64(0) {
		t.Fatalf("guards=%v err=%v", guards.Rows, err)
	}
}

func TestRunEnvelopeMutationRevokedBeforeSubmissionChangesNothing(t *testing.T) {
	t.Parallel()
	s, p, ctx := envelopeFixture(t, "")
	// Revoke the key before the mutation is submitted.
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: "revoke-before-envelope",
		SQL:       `UPDATE api_keys SET secret_digest=? WHERE name=?`,
		Args:      []any{strings.Repeat("Z", 43), p.Name},
	}); err != nil {
		t.Fatal(err)
	}
	requestID := strings.Repeat("r", 43)
	_, ok, err := s.RunEnvelopeMutation(ctx, "key-a", p, GroupAPIKeys, Create, requestID, []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms,expires_at_unix_ms) SELECT ?,?,?,NULL WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{"target", strings.Repeat("T", 43), int64(1), requestID}},
	})
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if _, err := s.byName(ctx, "target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("target=%v", err)
	}
	// Guard must be cleaned up.
	guards, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_key_mutation_guards`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || guards.Rows[0][0] != int64(0) {
		t.Fatalf("guards=%v err=%v", guards.Rows, err)
	}
}

func TestRunEnvelopeMutationFencedOldWriterRollsBackIncludingGuard(t *testing.T) {
	t.Parallel()
	s, p, ctx := envelopeFixture(t, storage.MasterKeyRetirementFenced)
	requestID := strings.Repeat("f", 43)
	targetDigest := strings.Repeat("T", 43)
	// key-a is the old writer; the barrier is fenced so the envelope fence
	// statement should reject the mutation, rolling back the guard row too.
	_, ok, err := s.RunEnvelopeMutation(ctx, "key-a", p, GroupAPIKeys, Create, requestID, []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms,expires_at_unix_ms) SELECT ?,?,?,NULL WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{"target", targetDigest, int64(1), requestID}},
	})
	if ok {
		t.Fatal("old writer accepted after fence")
	}
	if err == nil {
		// err may be nil when RowsAffected < 2 returns ok=false;
		// the important thing is that nothing persisted.
	}
	if _, err := s.byName(ctx, "target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("target=%v", err)
	}
	guards, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_key_mutation_guards`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || guards.Rows[0][0] != int64(0) {
		t.Fatalf("guards=%v err=%v", guards.Rows, err)
	}
}

func TestRunEnvelopeMutationReplacementWriterSucceeds(t *testing.T) {
	t.Parallel()
	s, p, ctx := envelopeFixture(t, storage.MasterKeyRetirementFenced)
	requestID := strings.Repeat("w", 43)
	targetDigest := strings.Repeat("T", 43)
	// key-b is the replacement writer; the fence statement should pass.
	response, ok, err := s.RunEnvelopeMutation(ctx, "key-b", p, GroupAPIKeys, Create, requestID, []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms,expires_at_unix_ms) SELECT ?,?,?,NULL WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{"target", targetDigest, int64(1), requestID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("replacement writer rejected")
	}
	if response.RowsAffected < 2 {
		t.Fatalf("rows_affected=%d", response.RowsAffected)
	}
	if _, err := s.byName(ctx, "target"); err != nil {
		t.Fatalf("target missing: %v", err)
	}
}

func TestRunEnvelopeMutationConstraintFailureRollsBackTargetsAndGuard(t *testing.T) {
	t.Parallel()
	s, p, ctx := envelopeFixture(t, "")
	requestID := strings.Repeat("c", 43)
	// The audit insert has a unique constraint on event_id; duplicate
	// requestID forces a constraint failure.  The first statement
	// (create target) must be rolled back.
	statements := []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms,expires_at_unix_ms) SELECT ?,?,?,NULL WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{"target", strings.Repeat("T", 43), int64(1), requestID}},
		{SQL: `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash) SELECT ?,sequence,?,?,?,?,?,?,? FROM (SELECT COALESCE(MAX(sequence),0)+1 AS sequence FROM audit_events) WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{requestID, int64(1), "not-a-real-event", "create", "success", "browser_admin", nil, strings.Repeat("H", 43), requestID}},
	}
	if _, _, err := s.RunEnvelopeMutation(ctx, "key-a", p, GroupAPIKeys, Create, requestID, statements); err == nil {
		t.Fatal("constraint failure accepted")
	}
	if _, err := s.byName(ctx, "target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rolled-back target=%v", err)
	}
	if _, err := s.byName(ctx, "manager"); err != nil {
		t.Fatalf("actor rolled back=%v", err)
	}
	audit, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM audit_events WHERE event_id=?`, Args: []any{requestID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || audit.Rows[0][0] != int64(0) {
		t.Fatalf("audit=%v err=%v", audit.Rows, err)
	}
	guards, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_key_mutation_guards`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || guards.Rows[0][0] != int64(0) {
		t.Fatalf("guards=%v err=%v", guards.Rows, err)
	}
}
