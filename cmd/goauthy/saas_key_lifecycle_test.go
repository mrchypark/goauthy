package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestMasterKeyLifecycleRejectsTamperedOrphanSaaSCredential(t *testing.T) {
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	keys := retirementCmdKeyring(t, "key-b")
	now := time.UnixMilli(1_800_000_000_000).UTC()
	status, err := inspectMasterKeyStatus(ctx, db, keys, "http://localhost:8080", nil, now)
	if err != nil || !status.Safe {
		t.Fatalf("empty status=%#v err=%v", status, err)
	}
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "saas-orphan-tamper",
		SQL: `INSERT INTO saas_connection_credentials
		(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential)
		VALUES ('orphan','owner','collection','provider','generation',1,'revoked',?)`,
		Args: []any{[]byte("tampered")},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err = inspectMasterKeyStatus(ctx, db, keys, "http://localhost:8080", nil, now)
	if err == nil || status.Safe || !status.ScanError {
		t.Fatalf("tampered status=%#v err=%v", status, err)
	}
	retirement, err := inspectMasterKeyRetirement(ctx, db, keys, "http://localhost:8080", nil, "key-a", now)
	if err == nil || retirement.TamperReferences == 0 {
		t.Fatalf("tampered retirement=%#v err=%v", retirement, err)
	}
	worker, err := newMasterKeyRewrapWorker(db, keys, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Step(ctx); err == nil || !strings.Contains(err.Error(), "rewrap SaaS credentials") {
		t.Fatal("production worker ignored malformed SaaS credential")
	}
}

func TestMasterKeyRewrapSaaSCursorOnlyAdvancesOnSuccess(t *testing.T) {
	ctx := context.Background()
	w, err := newMasterKeyRewrapWorker(retirementCmdDB(t, true), retirementCmdKeyring(t, "key-b"), "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	w.rewrapSigning = func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
		return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
	}
	failure := errors.New("injected batch failure")
	step := 0
	w.rewrapSaaS = func(_ context.Context, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
		step++
		switch step {
		case 1:
			if cursor != "" {
				t.Fatalf("initial cursor=%q", cursor)
			}
			return oidc.SigningKeyRewrapBatchResult{Cursor: "next"}, nil
		case 2:
			if cursor != "next" {
				t.Fatalf("advanced cursor=%q", cursor)
			}
			return oidc.SigningKeyRewrapBatchResult{Cursor: "must-not-save"}, failure
		default:
			if cursor != "next" {
				t.Fatalf("retry cursor=%q", cursor)
			}
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		}
	}
	if err := w.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Step(ctx); !errors.Is(err, failure) || w.saasCursor != "next" {
		t.Fatalf("failed batch cursor=%q err=%v", w.saasCursor, err)
	}
	if err := w.Step(ctx); err != nil || w.saasCursor != "" || step != 3 {
		t.Fatalf("completed cursor=%q steps=%d err=%v", w.saasCursor, step, err)
	}
}
