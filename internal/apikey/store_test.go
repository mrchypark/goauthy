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

func TestCreateAuthenticateRotateAndExpiryBoundary(t *testing.T) {
	t.Parallel()
	db := openTestDB(t, "apikey-test")
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.random = func(b []byte) (int, error) {
		for i := range b {
			b[i] = byte(i)
		}
		return len(b), nil
	}
	exp := now.Unix()
	req := Request{Name: "manager", Exp: &exp, Access: []Access{{Group: GroupAPIKeys, AccessRights: []Right{Read, Create, Update, Delete}}}}
	key, token, err := s.Create(context.Background(), nil, req)
	if err != nil || !strings.HasPrefix(token, "manager$") || key.Name != "manager" {
		t.Fatalf("key=%+v token=%q err=%v", key, token, err)
	}
	p, err := s.Authenticate(context.Background(), "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Authorize(context.Background(), p, GroupAPIKeys, Read); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Millisecond)
	if _, err = s.Authenticate(context.Background(), "API-Key "+token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expiry err=%v", err)
	}
	now = now.Add(-time.Millisecond)
	s.random = func(b []byte) (int, error) {
		for i := range b {
			b[i] = 1
		}
		return len(b), nil
	}
	rotated, err := s.Rotate(context.Background(), &p, "manager")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authenticate(context.Background(), "API-Key "+token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old token err=%v", err)
	}
	if _, err = s.Authenticate(context.Background(), "API-Key "+rotated); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticateAcrossStoresRejectsKeyDeletedByPeer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := bootstrapTestDB(t, "apikey-cross-store-revocation")
	first, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := first.Create(ctx, nil, Request{Name: "cross-store", Access: []Access{{Group: "Clients", AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Authenticate(ctx, "API-Key "+token); err != nil {
		t.Fatalf("warm authentication: %v", err)
	}
	if err := second.Delete(ctx, nil, "cross-store"); err != nil {
		t.Fatalf("peer delete: %v", err)
	}
	if _, err := first.Authenticate(ctx, "API-Key "+token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked key authentication err=%v", err)
	}
}

func TestRequestRejectsDuplicateGroupAndRight(t *testing.T) {
	t.Parallel()
	if err := validate(Request{Name: "key", Access: []Access{{Group: "Groups", AccessRights: []Right{Read, Read}}}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v", err)
	}
}

func TestAPIKeyMutationsAppendAuditsAndEventsRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t, "apikey-audit")
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	_, managerToken, err := s.Create(ctx, nil, Request{Name: "manager", Access: []Access{{Group: GroupAPIKeys, AccessRights: []Right{Create, Update, Delete}}, {Group: "Events", AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := s.Authenticate(ctx, "API-Key "+managerToken)
	if err != nil {
		t.Fatal(err)
	}
	target := Request{Name: "target", Access: []Access{{Group: "Events", AccessRights: []Right{Read}}}}
	now = now.Add(time.Millisecond)
	if _, _, err := s.Create(ctx, &manager, target); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Millisecond)
	if _, err := s.Update(ctx, &manager, "target", target); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Millisecond)
	if _, err := s.Rotate(ctx, &manager, "target"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Millisecond)
	if err := s.Delete(ctx, &manager, "target"); err != nil {
		t.Fatal(err)
	}
	events, _, err := s.ListAuditEvents(ctx, manager, nil, 10)
	if err != nil || len(events) != 5 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	for _, event := range events {
		if event.ActorKind != "browser_admin" && event.ActorHash == "" || event.TargetHash == "" || event.Outcome != "success" {
			t.Fatalf("unsafe audit event=%#v", event)
		}
	}
	_, noEventsToken, err := s.Create(ctx, nil, Request{Name: "noevents", Access: []Access{{Group: "Groups", AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	noEvents, err := s.Authenticate(ctx, "API-Key "+noEventsToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ListAuditEvents(ctx, noEvents, nil, 1); !errors.Is(err, ErrForbidden) {
		t.Fatalf("events authorization err=%v", err)
	}
}

func TestUpdateInterpositionDoesNotReportSuccessOrAppendAudit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t, "apikey-audit-interpose")
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := s.Create(ctx, nil, Request{Name: "manager", Access: []Access{{Group: GroupAPIKeys, AccessRights: []Right{Create, Update}}, {Group: "Events", AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := s.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	target := Request{Name: "target", Access: []Access{{Group: "Events", AccessRights: []Right{Read}}}}
	if _, _, err := s.Create(ctx, &manager, target); err != nil {
		t.Fatal(err)
	}
	s.beforeMutation = func() {
		s.beforeMutation = nil
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "apikey-audit-interpose-change", SQL: `UPDATE api_keys SET secret_digest=? WHERE name='target'`, Args: []any{strings.Repeat("Z", 43)}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Update(ctx, &manager, "target", target); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale update err=%v", err)
	}
	events, _, err := s.ListAuditEvents(ctx, manager, nil, 32)
	if err != nil || len(events) != 2 {
		t.Fatalf("stale update events=%#v err=%v", events, err)
	}
}

func TestCreateDeleteRotateDoNotReportStaleSuccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t, "apikey-audit-stale")
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := s.Create(ctx, nil, Request{Name: "manager", Access: []Access{{Group: GroupAPIKeys, AccessRights: []Right{Create, Update, Delete}}, {Group: "Events", AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := s.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Name: "target", Access: []Access{{Group: "Events", AccessRights: []Right{Read}}}}
	if _, _, err := s.Create(ctx, &manager, request); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create(ctx, &manager, request); !errors.Is(err, ErrNotFound) {
		t.Fatalf("duplicate create err=%v", err)
	}
	for _, operation := range []string{"rotate", "delete"} {
		name := operation + "-target"
		request.Name = name
		if _, _, err := s.Create(ctx, &manager, request); err != nil {
			t.Fatal(err)
		}
		s.beforeMutation = func() {
			s.beforeMutation = nil
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "apikey-stale-" + operation, SQL: `UPDATE api_keys SET secret_digest=? WHERE name=?`, Args: []any{strings.Repeat("Y", 43), name}}); err != nil {
				t.Fatal(err)
			}
		}
		if operation == "rotate" {
			if _, err := s.Rotate(ctx, &manager, name); !errors.Is(err, ErrNotFound) {
				t.Fatalf("stale rotate err=%v", err)
			}
		} else if err := s.Delete(ctx, &manager, name); !errors.Is(err, ErrNotFound) {
			t.Fatalf("stale delete err=%v", err)
		}
	}
	events, _, err := s.ListAuditEvents(ctx, manager, nil, 32)
	if err != nil || len(events) != 4 {
		t.Fatalf("stale events=%#v err=%v", events, err)
	}
}

func TestListAuditEventsRechecksGrantInPageSnapshot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t, "apikey-audit-read-guard")
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := s.Create(ctx, nil, Request{Name: "reader", Access: []Access{{Group: "Events", AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	s.beforeAuditRead = func() {
		s.beforeAuditRead = nil
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "apikey-audit-revoke-before-page", SQL: `DELETE FROM api_key_access WHERE key_name=? AND group_name='Events' AND right_name='read'`, Args: []any{p.Name}}); err != nil {
			t.Fatal(err)
		}
	}
	if events, _, err := s.ListAuditEvents(ctx, p, nil, 32); !errors.Is(err, ErrForbidden) || len(events) != 0 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestRejectedMutationLeavesNoGuardOrTarget(t *testing.T) {
	t.Parallel()
	db := openTestDB(t, "apikey-guard")
	s, _ := NewStore(db)
	s.now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	s.random = func(b []byte) (int, error) {
		for i := range b {
			b[i] = 2
		}
		return len(b), nil
	}
	_, token, err := s.Create(context.Background(), nil, Request{Name: "reader", Access: []Access{{Group: "Groups", AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(context.Background(), "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Create(context.Background(), &p, Request{Name: "blocked", Access: []Access{{Group: "Groups", AccessRights: []Right{Read}}}}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("create err=%v", err)
	}
	r, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_key_mutation_guards`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || r.Rows[0][0] != int64(0) {
		t.Fatalf("guards=%#v err=%v", r.Rows, err)
	}
	if _, err = s.byName(context.Background(), "blocked"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("blocked key err=%v", err)
	}
}

func TestRunMutationRejectsUnguardedTargets(t *testing.T) {
	t.Parallel()
	db := openTestDB(t, "apikey-misuse")
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.RunMutation(context.Background(), nil, GroupAPIKeys, Create, "test", []rhiza.SQLStatement{{SQL: `SELECT 1`}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unguarded err=%v", err)
	}
	if _, _, err = s.RunMutation(context.Background(), nil, GroupAPIKeys, Create, "test", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty err=%v", err)
	}
}

func TestAPIKeyCannotDelegateRightsItDoesNotHold(t *testing.T) {
	t.Parallel()
	db := openTestDB(t, "apikey-delegate")
	s, _ := NewStore(db)
	s.random = func(b []byte) (int, error) {
		for i := range b {
			b[i] = 3
		}
		return len(b), nil
	}
	_, managerToken, err := s.Create(context.Background(), nil, Request{Name: "manager", Access: []Access{{Group: GroupAPIKeys, AccessRights: []Right{Create, Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(context.Background(), "API-Key "+managerToken)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Create(context.Background(), &p, Request{Name: "escalate", Access: []Access{{Group: "Users", AccessRights: []Right{Delete}}}})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("escalation err=%v", err)
	}
	if _, err = s.byName(context.Background(), "escalate"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("target err=%v", err)
	}
}

func TestAPIKeyCannotSelfEscalateOnUpdate(t *testing.T) {
	t.Parallel()
	db := openTestDB(t, "apikey-self-update")
	s, _ := NewStore(db)
	s.random = func(b []byte) (int, error) {
		for i := range b {
			b[i] = 4
		}
		return len(b), nil
	}
	_, token, err := s.Create(context.Background(), nil, Request{Name: "manager", Access: []Access{{Group: GroupAPIKeys, AccessRights: []Right{Read, Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(context.Background(), "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Update(context.Background(), &p, "manager", Request{Name: "manager", Access: []Access{{Group: GroupAPIKeys, AccessRights: []Right{Read, Create, Update, Delete}}}})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("self-escalation err=%v", err)
	}
	k, err := s.Get(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Access) != 1 || len(k.Access[0].AccessRights) != 2 {
		t.Fatalf("self-escalation changed access: %+v", k.Access)
	}
}

func TestDeleteMissingKeyReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := openTestDB(t, "apikey-delete-missing")
	s, _ := NewStore(db)
	if err := s.Delete(context.Background(), nil, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing delete err=%v", err)
	}
}

// TestUpdateRevertsToEarlierConfigurationAndReplaysExactRetry pins
// GA-APIKEY-001: the update request ID identifies the prepared mutation rather
// than the configuration it applies, so reverting to a configuration that an
// earlier update already applied is an independent update. Replaying one exact
// prepared mutation still deduplicates on its retained receipt.
func TestUpdateRevertsToEarlierConfigurationAndReplaysExactRetry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t, "apikey-operation-identity")
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	_, token, err := s.Create(ctx, nil, Request{Name: "manager", Access: []Access{{Group: GroupAPIKeys, AccessRights: []Right{Create, Update}}, {Group: "Events", AccessRights: []Right{Read}}, {Group: "Groups", AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := s.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	configA := Request{Name: "target", Access: []Access{{Group: "Events", AccessRights: []Right{Read}}}}
	configB := Request{Name: "target", Access: []Access{{Group: "Groups", AccessRights: []Right{Read}}}}
	if _, _, err := s.Create(ctx, &manager, configB); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := s.Update(ctx, &manager, "target", configA); err != nil {
		t.Fatalf("apply A: %v", err)
	}
	now = now.Add(time.Second)
	if _, err := s.Update(ctx, &manager, "target", configB); err != nil {
		t.Fatalf("apply B: %v", err)
	}
	var submitted rhiza.ExecuteRequest
	s.beforeSubmit = func(request rhiza.ExecuteRequest) {
		s.beforeSubmit = nil
		submitted = request
	}
	now = now.Add(time.Second)
	reverted, err := s.Update(ctx, &manager, "target", configA)
	if err != nil {
		t.Fatalf("revert to A: %v", err)
	}
	if len(reverted.Access) != 1 || reverted.Access[0].Group != "Events" || len(reverted.Access[0].AccessRights) != 1 || reverted.Access[0].AccessRights[0] != Read {
		t.Fatalf("reverted access=%+v", reverted.Access)
	}
	if submitted.RequestID == "" {
		t.Fatal("revert submitted no request")
	}
	response, err := storage.Execute(ctx, db, submitted)
	if err != nil || response.Status != "committed" {
		t.Fatalf("exact retry response=%+v err=%v", response, err)
	}
	events, _, err := s.ListAuditEvents(ctx, manager, nil, 32)
	if err != nil || len(events) != 5 {
		t.Fatalf("audit events after exact retry=%d err=%v", len(events), err)
	}
	guards, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_key_mutation_guards`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || guards.Rows[0][0] != int64(0) {
		t.Fatalf("guards=%#v err=%v", guards.Rows, err)
	}
}
