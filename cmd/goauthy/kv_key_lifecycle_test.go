package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/kv"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestMasterKeyRewrapWorkerRunsKVAfterOtherFamilies(t *testing.T) {
	t.Parallel()
	var order []string
	w := &masterKeyRewrapWorker{
		rewrapSigning: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			order = append(order, "signing")
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapIdempotency: func(context.Context, string) (string, int, error) {
			order = append(order, "dcr")
			return "", 0, nil
		},
		rewrapTransactions: func(context.Context, time.Time, string) (string, bool, int64, error) {
			order = append(order, "upstream")
			return "", true, 0, nil
		},
		rewrapPasskey: func(context.Context, string) (passkey.RewrapBatchResult, error) {
			order = append(order, "passkey")
			return passkey.RewrapBatchResult{Done: true}, nil
		},
		rewrapKV: func(context.Context, string) (kv.RewrapResult, error) {
			order = append(order, "kv")
			return kv.RewrapResult{Done: true}, nil
		},
		now: time.Now,
	}
	if err := w.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"signing", "dcr", "upstream", "passkey", "kv"}
	if len(order) != len(want) {
		t.Fatalf("order=%v want=%v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order=%v want=%v", order, want)
		}
	}
}

func TestMasterKeyLifecycleCountsOldKVReferencesAndDetectsTamper(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	oldKeyring := retirementCmdKeyring(t, "key-a")
	newKeyring := retirementCmdKeyring(t, "key-b")
	oldStore, err := kv.NewStore(db, oldKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldStore.PutNamespace(ctx, "", "retirement-ns", false, true); err != nil {
		t.Fatal(err)
	}
	access, err := oldStore.CreateAccess(ctx, "retirement-ns", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldStore.Set(ctx, kv.Access{Namespace: access.Namespace}, kv.Value{Key: "payload", Encrypted: true, Value: json.RawMessage(`{"ok":true}`)}); err != nil {
		t.Fatal(err)
	}

	newStore, err := kv.NewStore(db, newKeyring)
	if err != nil {
		t.Fatal(err)
	}
	status, err := inspectMasterKeyStatus(ctx, db, newKeyring, "http://localhost:8080", nil, time.UnixMilli(1_800_000_000_000).UTC())
	if err != nil || status.Safe || status.KVAccess.Total != 1 || status.KVAccess.NonActive != 1 || status.KVValues.Total != 1 || status.KVValues.NonActive != 1 {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	retirement, err := inspectMasterKeyRetirement(ctx, db, newKeyring, "http://localhost:8080", nil, "key-a", time.UnixMilli(1_800_000_000_000).UTC())
	if err != nil || retirement.OldReferences != 2 || retirement.NonActiveReferences != 0 || retirement.TamperReferences != 0 {
		t.Fatalf("retirement=%#v err=%v", retirement, err)
	}
	for cursor := ""; ; {
		batch, err := newStore.RewrapBatch(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		if batch.Done {
			break
		}
		cursor = batch.Cursor
	}
	retirement, err = inspectMasterKeyRetirement(ctx, db, newKeyring, "http://localhost:8080", nil, "key-a", time.UnixMilli(1_800_000_000_000).UTC())
	if err != nil || retirement.OldReferences != 0 || retirement.NonActiveReferences != 0 || retirement.TamperReferences != 0 {
		t.Fatalf("rewrapped retirement=%#v err=%v", retirement, err)
	}
	status, err = inspectMasterKeyStatus(ctx, db, newKeyring, "http://localhost:8080", nil, time.UnixMilli(1_800_000_000_000).UTC())
	if err != nil || !status.Safe {
		t.Fatalf("rewrapped status=%#v err=%v", status, err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "kv-retirement-tamper", SQL: "UPDATE kv_values SET value=? WHERE namespace=? AND key=?", Args: []any{[]byte("tampered"), "retirement-ns", "payload"}}); err != nil {
		t.Fatal(err)
	}
	retirement, err = inspectMasterKeyRetirement(ctx, db, newKeyring, "http://localhost:8080", nil, "key-a", time.UnixMilli(1_800_000_000_000).UTC())
	if err == nil || retirement.TamperReferences != 1 {
		t.Fatalf("tampered retirement=%#v err=%v", retirement, err)
	}
}
