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

func mutationAtomicityFixture(t *testing.T, rights ...Right) (*Store, *Principal, context.Context) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "apikey-mutation-atomicity", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
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

func TestRunMutationAuthorizationRevokedBeforeSubmissionChangesNothing(t *testing.T) {
	s, p, ctx := mutationAtomicityFixture(t, Create)
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "revoke-before-submit", SQL: `UPDATE api_keys SET secret_digest=? WHERE name=?`, Args: []any{strings.Repeat("Z", 43), p.Name}}); err != nil {
		t.Fatal(err)
	}
	requestID := strings.Repeat("r", 43)
	_, ok, err := s.RunMutation(ctx, p, GroupAPIKeys, Create, requestID, []rhiza.SQLStatement{{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms,expires_at_unix_ms) SELECT ?,?,?,NULL WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{"target", strings.Repeat("T", 43), int64(1), requestID}}})
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if _, err := s.byName(ctx, "target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("target=%v", err)
	}
	rows, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_key_mutation_guards`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(0) {
		t.Fatalf("guards=%v err=%v", rows.Rows, err)
	}
}

func TestRunMutationSnapshotSurvivesSelfRevocationForRemainingStatements(t *testing.T) {
	s, p, ctx := mutationAtomicityFixture(t, Delete)
	requestID := strings.Repeat("s", 43)
	targetDigest := strings.Repeat("T", 43)
	actorHash := strings.Repeat("A", 43)
	statements := []rhiza.SQLStatement{
		{SQL: `DELETE FROM api_keys WHERE name=? AND secret_digest=? AND EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{p.Name, p.digest, requestID}},
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms,expires_at_unix_ms) SELECT ?,?,?,NULL WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{"target", targetDigest, int64(1), requestID}},
		{SQL: `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash) SELECT ?,sequence,?,?,?,?,?,?,? FROM (SELECT COALESCE(MAX(sequence),0)+1 AS sequence FROM audit_events) WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{requestID, int64(1), "api_key.deleted", "delete", "success", "api_key", actorHash, targetDigest, requestID}},
	}
	if _, ok, err := s.RunMutation(ctx, p, GroupAPIKeys, Delete, requestID, statements); err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if _, err := s.byName(ctx, "target"); err != nil {
		t.Fatalf("target=%v", err)
	}
	_, ok, err := s.RunMutation(ctx, p, GroupAPIKeys, Delete, strings.Repeat("n", 43), []rhiza.SQLStatement{{SQL: `DELETE FROM api_keys WHERE name=? AND EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{"target", strings.Repeat("n", 43)}}})
	if err != nil || ok {
		t.Fatalf("next request ok=%v err=%v", ok, err)
	}
	if _, err := s.byName(ctx, "target"); err != nil {
		t.Fatalf("next request changed target=%v", err)
	}
	rows, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM audit_events WHERE event_id=?`, Args: []any{requestID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(1) {
		t.Fatalf("audit=%v err=%v", rows.Rows, err)
	}
}

func TestRunMutationConstraintFailureRollsBackTargetsAndGuard(t *testing.T) {
	s, p, ctx := mutationAtomicityFixture(t, Create)
	requestID := strings.Repeat("c", 43)
	statements := []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms,expires_at_unix_ms) SELECT ?,?,?,NULL WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{"target", strings.Repeat("T", 43), int64(1), requestID}},
		{SQL: `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash) SELECT ?,sequence,?,?,?,?,?,?,? FROM (SELECT COALESCE(MAX(sequence),0)+1 AS sequence FROM audit_events) WHERE EXISTS (SELECT 1 FROM api_key_mutation_guards WHERE request_id=?)`, Args: []any{requestID, int64(1), "not-a-real-event", "create", "success", "browser_admin", nil, strings.Repeat("H", 43), requestID}},
	}
	if _, _, err := s.RunMutation(ctx, p, GroupAPIKeys, Create, requestID, statements); err == nil {
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
	rows, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_key_mutation_guards`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(0) {
		t.Fatalf("guards=%v err=%v", rows.Rows, err)
	}
}
