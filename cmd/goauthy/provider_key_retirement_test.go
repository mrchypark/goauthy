package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

func TestMasterKeyRewrapStepIncludesSaaSProviderFamily(t *testing.T) {
	t.Parallel()
	var cursors []string
	providerErr := errors.New("provider envelope unavailable")
	w := &masterKeyRewrapWorker{
		now: func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		rewrapSigning: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapIdempotency: func(context.Context, string) (string, int, error) { return "", 0, nil },
		rewrapTransactions: func(context.Context, time.Time, string) (string, bool, int64, error) {
			return "", true, 0, nil
		},
		rewrapSaaSProvider: func(_ context.Context, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
			cursors = append(cursors, cursor)
			if len(cursors) == 1 {
				return oidc.SigningKeyRewrapBatchResult{Cursor: "provider-next"}, nil
			}
			return oidc.SigningKeyRewrapBatchResult{}, providerErr
		},
	}
	if err := w.Step(context.Background()); err != nil || w.saasProviderCursor != "provider-next" {
		t.Fatalf("first step err=%v cursor=%q", err, w.saasProviderCursor)
	}
	if err := w.Step(context.Background()); !errors.Is(err, providerErr) || w.saasProviderCursor != "provider-next" {
		t.Fatalf("failed step err=%v cursor=%q", err, w.saasProviderCursor)
	}
	if want := []string{"", "provider-next"}; len(cursors) != len(want) || cursors[0] != want[0] || cursors[1] != want[1] {
		t.Fatalf("provider cursors=%v want %v", cursors, want)
	}
}

func TestSummarizeSaaSProviderFamilyCountsNonActiveKeys(t *testing.T) {
	t.Parallel()
	got := summarizeOIDCFamily(oidc.MasterKeyReferenceFamily{
		ByKeyID: map[string]int64{"master-a": 2, "master-b": 3},
		Total:   5,
	}, "master-b")
	if got.Total != 5 || got.NonActive != 2 {
		t.Fatalf("provider summary=%+v", got)
	}
}

func TestSaaSProviderEnvelopeBlocksRetirementUntilRewrapped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	oldKeys := retirementCmdKeyring(t, "key-a")
	providerStore, err := saas.NewProviderStore(db, oldKeys)
	if err != nil {
		t.Fatal(err)
	}
	_, err = providerStore.Create(ctx, saas.ProviderInput{
		ID: "provider", Name: "Provider", Kind: "oauth2", Enabled: true,
		ClientID: "client", ClientSecret: "client-secret-123",
		CallbackURI:      "https://example.test/callback",
		AuthorizationURL: "https://example.test/authorize", TokenURL: "https://example.test/token",
		Scopes: []string{"openid"}, AuthStyle: "header",
	}, func() (string, []any) { return "1=1", nil })
	if err != nil {
		t.Fatal(err)
	}

	newKeys := retirementCmdKeyring(t, "key-b")
	now := time.UnixMilli(1_800_000_000_000).UTC()
	status, err := inspectMasterKeyStatus(ctx, db, newKeys, "http://localhost:8080", nil, now)
	if err != nil || status.Safe || status.SaaSProviders.Total != 1 || status.SaaSProviders.NonActive != 1 {
		t.Fatalf("old provider status=%#v err=%v", status, err)
	}
	retirement, err := inspectMasterKeyRetirement(ctx, db, newKeys, "http://localhost:8080", nil, "key-a", now)
	if err != nil || retirement.OldReferences != 1 || retirement.NonActiveReferences != 0 {
		t.Fatalf("old provider retirement=%#v err=%v", retirement, err)
	}

	result, err := saas.RewrapProviderEnvelopeBatch(ctx, db, newKeys, "")
	if err != nil || !result.Done || result.Rewrapped != 1 {
		t.Fatalf("provider rewrap=%#v err=%v", result, err)
	}
	status, err = inspectMasterKeyStatus(ctx, db, newKeys, "http://localhost:8080", nil, now)
	if err != nil || !status.Safe || status.SaaSProviders.NonActive != 0 {
		t.Fatalf("rewrapped provider status=%#v err=%v", status, err)
	}
	retirement, err = inspectMasterKeyRetirement(ctx, db, newKeys, "http://localhost:8080", nil, "key-a", now)
	if err != nil || retirement.OldReferences != 0 || retirement.NonActiveReferences != 0 || retirement.TamperReferences != 0 {
		t.Fatalf("rewrapped provider retirement=%#v err=%v", retirement, err)
	}
}


func TestMasterKeyRewrapStepIncludesAuthProviderSecretFamily(t *testing.T) {
	t.Parallel()
	var cursors []string
	secretErr := errors.New("auth-provider secret unavailable")
	w := &masterKeyRewrapWorker{
		now: func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		rewrapSigning: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapIdempotency: func(context.Context, string) (string, int, error) { return "", 0, nil },
		rewrapTransactions: func(context.Context, time.Time, string) (string, bool, int64, error) {
			return "", true, 0, nil
		},
		rewrapAuthProviderSecret: func(_ context.Context, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
			cursors = append(cursors, cursor)
			if len(cursors) == 1 {
				return oidc.SigningKeyRewrapBatchResult{Cursor: "secret-next"}, nil
			}
			return oidc.SigningKeyRewrapBatchResult{}, secretErr
		},
	}
	if err := w.Step(context.Background()); err != nil || w.authProviderSecretCursor != "secret-next" {
		t.Fatalf("first step err=%v cursor=%q", err, w.authProviderSecretCursor)
	}
	if err := w.Step(context.Background()); !errors.Is(err, secretErr) || w.authProviderSecretCursor != "secret-next" {
		t.Fatalf("failed step err=%v cursor=%q", err, w.authProviderSecretCursor)
	}
	if want := []string{"", "secret-next"}; len(cursors) != len(want) || cursors[0] != want[0] || cursors[1] != want[1] {
		t.Fatalf("secret cursors=%v want %v", cursors, want)
	}
}

func TestAuthProviderSecretEnvelopeBlocksRetirementUntilRewrapped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	oldKeys := retirementCmdKeyring(t, "key-a")

	// Insert an auth-provider with a secret encrypted under the old key.
	secretEnvelope, err := oldKeys.SealEnvelope(upstreamprovider.ProviderSecretPurpose("test-provider"), []byte("client-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "auth-provider-secret-retirement",
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{"test-provider", 1, "Test Provider", "oidc", "http://localhost", "http://localhost/auth", "http://localhost/token", "http://localhost/userinfo", "client-id", secretEnvelope, "openid", 1},
	}); err != nil {
		t.Fatal(err)
	}

	newKeys := retirementCmdKeyring(t, "key-b")
	now := time.UnixMilli(1_800_000_000_000).UTC()

	// Status: old key should show as non-active.
	status, err := inspectMasterKeyStatus(ctx, db, newKeys, "http://localhost:8080", nil, now)
	if err != nil || status.Safe || status.AuthProviderSecrets.Total != 1 || status.AuthProviderSecrets.NonActive != 1 {
		t.Fatalf("old provider secret status=%#v err=%v", status, err)
	}

	// Retirement: old reference should block.
	retirement, err := inspectMasterKeyRetirement(ctx, db, newKeys, "http://localhost:8080", nil, "key-a", now)
	if err != nil || retirement.OldReferences != 1 || retirement.NonActiveReferences != 0 {
		t.Fatalf("old provider secret retirement=%#v err=%v", retirement, err)
	}

	// Rewrap should migrate the envelope.
	result, err := upstreamprovider.RewrapAuthProviderSecretBatch(ctx, db, newKeys, "")
	if err != nil || !result.Done || result.Rewrapped != 1 {
		t.Fatalf("auth-provider secret rewrap=%#v err=%v", result, err)
	}

	// Status after rewrap: safe, zero non-active.
	status, err = inspectMasterKeyStatus(ctx, db, newKeys, "http://localhost:8080", nil, now)
	if err != nil || !status.Safe || status.AuthProviderSecrets.NonActive != 0 {
		t.Fatalf("rewrapped provider secret status=%#v err=%v", status, err)
	}
	retirement, err = inspectMasterKeyRetirement(ctx, db, newKeys, "http://localhost:8080", nil, "key-a", now)
	if err != nil || retirement.OldReferences != 0 || retirement.NonActiveReferences != 0 || retirement.TamperReferences != 0 {
		t.Fatalf("rewrapped provider secret retirement=%#v err=%v", retirement, err)
	}
}

func TestAuthProviderSecretTamperBlocksStatusSafety(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	keys := retirementCmdKeyring(t, "key-b")

	// Insert a tampered (non-envelope) secret.
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "auth-provider-tamper",
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{"tampered-provider", 1, "Tampered", "oidc", "http://localhost", "http://localhost/auth", "http://localhost/token", "http://localhost/userinfo", "client-id", []byte("tampered-data"), "openid", 1},
	}); err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(1_800_000_000_000).UTC()
	status, err := inspectMasterKeyStatus(ctx, db, keys, "http://localhost:8080", nil, now)
	if err == nil || status.Safe || !status.ScanError {
		t.Fatalf("tampered status=%#v err=%v", status, err)
	}
	retirement, err := inspectMasterKeyRetirement(ctx, db, keys, "http://localhost:8080", nil, "key-a", now)
	if err == nil || retirement.TamperReferences == 0 {
		t.Fatalf("tampered retirement=%#v err=%v", retirement, err)
	}
}

func TestMasterKeyRewrapWorkerInvokesAuthProviderSecretFamily(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	keys := retirementCmdKeyring(t, "key-b")

	worker, err := newMasterKeyRewrapWorker(db, keys, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	worker.rewrapSigning = func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
		return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
	}
	if err := worker.Step(ctx); err != nil {
		t.Fatal(err)
	}
	// Cursor should be empty since no auth-providers exist (Done=true from empty scan).
	if worker.authProviderSecretCursor != "" {
		t.Fatalf("auth-provider secret cursor=%q want empty", worker.authProviderSecretCursor)
	}
}
