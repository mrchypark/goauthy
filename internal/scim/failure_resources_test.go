package scim

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestScimResourceFailuresEmitExactTerminalEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, request := range map[string]func(*Outbox, time.Time) error{
		"group": func(o *Outbox, now time.Time) error {
			_, err := o.EnqueueGroup(ctx, "client-1", Group{ExternalID: "group-1", DisplayName: "Engineering"}, now)
			return err
		},
		"delete": func(o *Outbox, now time.Time) error {
			generation := "AAAAAAAAAAAAAAAAAAAAAA"
			if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "resource-delete-seed", Statements: []rhiza.SQLStatement{
				{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?,?,1,1,?,?)`, Args: []any{"ext-1", "alice", generation, now.UnixMilli()}},
				{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: []any{"ext-1", "client-1", int64(DeleteRemote)}},
			}}); err != nil {
				return err
			}
			_, admitted, err := o.EnqueueTombstoneDelete(ctx, "client-1", testUser(), DeleteRemote, generation, now)
			if err == nil && !admitted {
				err = errors.New("delete was not admitted")
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
				return fakeReconciler(func(context.Context, Request) (Result, error) { return Result{}, ErrRetryable }), nil
			}, OutboxConfig{MaxAttempts: 1, Random: bytes.NewReader(bytes.Repeat([]byte{12}, 128))})
			now := time.UnixMilli(1_704_067_210_000).UTC()
			if err := request(o, now); err != nil {
				t.Fatal(err)
			}
			if err := o.Step(ctx, now); err != nil {
				t.Fatal(err)
			}
			rows, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT timestamp,level,ip,data,text FROM event_log WHERE typ=?`, Args: []any{string(eventlog.ScimTaskFailed)}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != now.UnixMilli() || rows.Rows[0][1] != int64(eventlog.Critical.Rank()) || rows.Rows[0][2] != nil || rows.Rows[0][3] != int64(1) {
				t.Fatalf("resource event=%#v err=%v", rows.Rows, err)
			}
			want := `client-1 / GroupCreateUpdate("group-1")`
			if name == "delete" {
				want = `client-1 / UserDelete("ext-1")`
			}
			if rows.Rows[0][4] != want {
				t.Fatalf("resource event text=%v want=%v", rows.Rows[0][4], want)
			}
		})
	}
}

func TestScimDeleteFailureStaleTombstoneGenerationSuppressesEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var o *Outbox
	generation := "BBBBBBBBBBBBBBBBBBBBBB"
	o = newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) {
			if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "resource-delete-stale-generation", SQL: `UPDATE scim_user_tombstones SET generation=? WHERE local_external_id=?`, Args: []any{"CCCCCCCCCCCCCCCCCCCCCC", "ext-1"}}); err != nil {
				t.Fatalf("generation update: %v", err)
			}
			return Result{}, ErrRetryable
		}), nil
	}, OutboxConfig{MaxAttempts: 1, Random: bytes.NewReader(bytes.Repeat([]byte{13}, 128))})
	now := time.UnixMilli(1_704_067_211_000).UTC()
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "resource-delete-stale-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?,?,1,1,?,?)`, Args: []any{"ext-1", "alice", generation, now.UnixMilli()}},
		{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: []any{"ext-1", "client-1", int64(DeleteRemote)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, admitted, err := o.EnqueueTombstoneDelete(ctx, "client-1", testUser(), DeleteRemote, generation, now); err != nil || !admitted {
		t.Fatalf("enqueue admitted=%v err=%v", admitted, err)
	}
	if err := o.Step(ctx, now); err != nil && !errors.Is(err, ErrOutboxLease) {
		t.Fatal(err)
	}
	if got := scimFailureEventCount(t, o); got != 0 {
		t.Fatalf("stale tombstone event count=%d", got)
	}
}

func TestScimDeleteFailureStaleProviderPolicySuppressesEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var o *Outbox
	generation := "DDDDDDDDDDDDDDDDDDDDDD"
	o = newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) {
			if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "resource-delete-stale-policy", SQL: `UPDATE scim_user_tombstone_providers SET delete_policy=? WHERE local_external_id=? AND client_id=?`, Args: []any{int64(UnlinkRemote), "ext-1", "client-1"}}); err != nil {
				t.Fatalf("policy update: %v", err)
			}
			return Result{}, ErrRetryable
		}), nil
	}, OutboxConfig{MaxAttempts: 1, Random: bytes.NewReader(bytes.Repeat([]byte{14}, 128))})
	now := time.UnixMilli(1_704_067_212_000).UTC()
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "resource-delete-policy-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?,?,1,1,?,?)`, Args: []any{"ext-1", "alice", generation, now.UnixMilli()}},
		{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: []any{"ext-1", "client-1", int64(DeleteRemote)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, admitted, err := o.EnqueueTombstoneDelete(ctx, "client-1", testUser(), DeleteRemote, generation, now); err != nil || !admitted {
		t.Fatalf("enqueue admitted=%v err=%v", admitted, err)
	}
	if err := o.Step(ctx, now); err != nil && !errors.Is(err, ErrOutboxLease) {
		t.Fatal(err)
	}
	if got := scimFailureEventCount(t, o); got != 0 {
		t.Fatalf("stale provider policy event count=%d", got)
	}
	rows, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT delete_policy FROM scim_user_tombstone_providers WHERE local_external_id=? AND client_id=?`, Args: []any{"ext-1", "client-1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(UnlinkRemote) {
		t.Fatalf("provider policy rows=%#v err=%v", rows.Rows, err)
	}
}

func TestScimExpiredFinalDeleteAfterTombstoneRemovalPreservesRow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) { return Result{}, ErrRetryable }), nil
	}, OutboxConfig{MaxAttempts: 1, Random: bytes.NewReader(bytes.Repeat([]byte{15}, 128))})
	now := time.UnixMilli(1_704_067_213_000).UTC()
	generation := "EEEEEEEEEEEEEEEEEEEEEE"
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "resource-delete-expired-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?,?,1,1,?,?)`, Args: []any{"ext-1", "alice", generation, now.UnixMilli()}},
		{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: []any{"ext-1", "client-1", int64(DeleteRemote)}},
	}}); err != nil {
		t.Fatal(err)
	}
	_, admitted, err := o.EnqueueTombstoneDelete(ctx, "client-1", testUser(), DeleteRemote, generation, now)
	if err != nil || !admitted {
		t.Fatalf("enqueue admitted=%v err=%v", admitted, err)
	}
	job, found, err := o.claim(ctx, now)
	if err != nil || !found || job.Attempts != 1 {
		t.Fatalf("final claim found=%v attempts=%d err=%v", found, job.Attempts, err)
	}
	expired := now.Add(o.LeaseDuration)
	candidate, found, err := o.nextCandidate(ctx, expired)
	if err != nil || !found {
		t.Fatalf("expired candidate found=%v err=%v", found, err)
	}
	before := scimFailureRollbackState(t, o.DB, job.ID)
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "resource-delete-expired-remove", Statements: []rhiza.SQLStatement{
		{SQL: `DELETE FROM scim_user_tombstone_providers WHERE local_external_id=?`, Args: []any{"ext-1"}},
		{SQL: `DELETE FROM scim_user_tombstones WHERE local_external_id=?`, Args: []any{"ext-1"}},
	}}); err != nil {
		t.Fatal(err)
	}
	response, err := o.deadLetterExpired(ctx, candidate, expired)
	if err != nil || response.RowsAffected != 0 {
		t.Fatalf("stale delete dead-letter affected=%d err=%v", response.RowsAffected, err)
	}
	if err := o.Step(ctx, expired); err != nil {
		t.Fatal(err)
	}
	got, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || got.Status != "processing" || got.Attempts != 1 {
		t.Fatalf("expired removed-tombstone row=%+v found=%v err=%v", got, found, err)
	}
	scimFailureRollbackCompareState(t, scimFailureRollbackState(t, o.DB, job.ID), before)
	if got := scimFailureEventCount(t, o); got != 0 {
		t.Fatalf("expired removed-tombstone event count=%d", got)
	}
}
