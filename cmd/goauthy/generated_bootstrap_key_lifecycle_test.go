package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestGeneratedBootstrapEnvelopeBlocksRetirementUntilRewrapped(t *testing.T) {
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	oldKeys := retirementCmdKeyring(t, "key-a")
	envelope, err := oldKeys.SealEnvelope(oidc.GeneratedAPIKeyBootstrapEnvelopePurpose, []byte(`{"version":1,"entries":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "seed-generated-bootstrap-old-key", SQL: `INSERT INTO generated_api_key_bootstrap(singleton,config_digest,payload_envelope,deadline_unix_s,created_at_unix_ms) VALUES(1,?,?,?,?)`, Args: []any{"config-digest", envelope, int64(1_900_000_000), int64(1_800_000_000_000)}}); err != nil {
		t.Fatal(err)
	}

	newKeys := retirementCmdKeyring(t, "key-b")
	now := time.UnixMilli(1_800_000_000_000).UTC()
	status, err := inspectMasterKeyStatus(ctx, db, newKeys, "http://localhost:8080", nil, now)
	if err != nil || status.Safe || status.GeneratedAPIKeyBootstrap.Total != 1 || status.GeneratedAPIKeyBootstrap.NonActive != 1 {
		t.Fatalf("old generated bootstrap status=%#v err=%v", status, err)
	}
	retirement, err := inspectMasterKeyRetirement(ctx, db, newKeys, "http://localhost:8080", nil, "key-a", now)
	if err != nil || retirement.OldReferences != 1 || retirement.NonActiveReferences != 0 {
		t.Fatalf("old generated bootstrap retirement=%#v err=%v", retirement, err)
	}

	result, err := oidc.RewrapGeneratedAPIKeyBootstrapEnvelope(ctx, db, newKeys)
	if err != nil || !result.Done || result.Rewrapped != 1 {
		t.Fatalf("generated bootstrap rewrap=%#v err=%v", result, err)
	}
	status, err = inspectMasterKeyStatus(ctx, db, newKeys, "http://localhost:8080", nil, now)
	if err != nil || !status.Safe || status.GeneratedAPIKeyBootstrap.NonActive != 0 {
		t.Fatalf("rewrapped generated bootstrap status=%#v err=%v", status, err)
	}
	retirement, err = inspectMasterKeyRetirement(ctx, db, newKeys, "http://localhost:8080", nil, "key-a", now)
	if err != nil || retirement.OldReferences != 0 || retirement.NonActiveReferences != 0 || retirement.TamperReferences != 0 {
		t.Fatalf("rewrapped generated bootstrap retirement=%#v err=%v", retirement, err)
	}
}

func TestMasterKeyRewrapStepIncludesGeneratedBootstrap(t *testing.T) {
	generatedErr := errors.New("generated bootstrap envelope unavailable")
	calls := 0
	w := &masterKeyRewrapWorker{
		now: func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		rewrapSigning: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapIdempotency: func(context.Context, string) (string, int, error) { return "", 0, nil },
		rewrapTransactions: func(context.Context, time.Time, string) (string, bool, int64, error) {
			return "", true, 0, nil
		},
		rewrapGeneratedAPIKeyBootstrap: func(context.Context) (oidc.SigningKeyRewrapBatchResult, error) {
			calls++
			return oidc.SigningKeyRewrapBatchResult{}, generatedErr
		},
	}
	if err := w.Step(context.Background()); !errors.Is(err, generatedErr) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
