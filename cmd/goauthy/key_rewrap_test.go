package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/kv"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
)

func TestMasterKeyRewrapStepSyntheticBudgetModel(t *testing.T) {
	var order []string
	var deadlineCount int
	worker := syntheticMasterKeyRewrapWorker(func(name string, ctx context.Context) {
		order = append(order, name)
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Errorf("%s callback has no family deadline", name)
			return
		}
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > masterKeyRewrapFamilyTimeout {
			t.Errorf("%s callback deadline remaining=%s, want >0 and <=%s", name, remaining, masterKeyRewrapFamilyTimeout)
		}
		deadlineCount++
	})
	if err := worker.Step(context.Background()); err != nil {
		t.Fatal("synthetic worker step failed")
	}
	wantOrder := []string{
		"signing", "idempotency", "transactions", "passkey", "kv", "managed",
		"login-revoke", "email-outbox", "generated-api-key-bootstrap", "saas",
		"saas-provider", "saas-authorization", "auth-provider-secret",
	}
	if !equalStrings(order, wantOrder) || deadlineCount != len(wantOrder) {
		t.Fatalf("family callbacks=%v deadlines=%d want %v", order, deadlineCount, wantOrder)
	}
	if got, want := time.Duration(len(wantOrder))*masterKeyRewrapFamilyTimeout, 130*time.Second; got != want {
		t.Fatalf("synthetic per-family timeout budget=%s want %s", got, want)
	}
	for _, cursor := range []struct{ name, got, want string }{
		{"signing", worker.signingCursor, "signing-next"},
		{"idempotency", worker.idempotencyCursor, "idempotency-next"},
		{"transactions", worker.transactionCursor, "transactions-next"},
		{"passkey", worker.passkeyCursor, "passkey-next"},
		{"kv", worker.kvCursor, "kv-next"},
		{"managed", worker.managedCursor, "managed-next"},
		{"login-revoke", worker.loginRevokeCursor, "login-revoke-next"},
		{"email-outbox", worker.emailOutboxCursor, "email-outbox-next"},
		{"saas", worker.saasCursor, "saas-next"},
		{"saas-provider", worker.saasProviderCursor, "saas-provider-next"},
		{"saas-authorization", worker.saasAuthorizationCursor, "saas-authorization-next"},
		{"auth-provider-secret", worker.authProviderSecretCursor, "auth-provider-secret-next"},
	} {
		if cursor.got != cursor.want {
			t.Errorf("%s cursor=%q want %q", cursor.name, cursor.got, cursor.want)
		}
	}
}

func BenchmarkMasterKeyRewrapStepSyntheticCallbacks(b *testing.B) {
	worker := syntheticMasterKeyRewrapWorker(func(string, context.Context) {})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := worker.Step(context.Background()); err != nil {
			b.Fatal("synthetic worker step failed")
		}
	}
	b.ReportMetric(13, "families/op")
	b.ReportMetric(float64(13*int(masterKeyRewrapFamilyTimeout/time.Second)), "modeled-timeout-budget-sec/op")
}

func syntheticMasterKeyRewrapWorker(observe func(string, context.Context)) *masterKeyRewrapWorker {
	call := func(name string, ctx context.Context) { observe(name, ctx) }
	return &masterKeyRewrapWorker{
		now: func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		rewrapSigning: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			call("signing", ctx)
			return oidc.SigningKeyRewrapBatchResult{Cursor: "signing-next"}, nil
		},
		rewrapIdempotency: func(ctx context.Context, _ string) (string, int, error) {
			call("idempotency", ctx)
			return "idempotency-next", 0, nil
		},
		rewrapTransactions: func(ctx context.Context, _ time.Time, _ string) (string, bool, int64, error) {
			call("transactions", ctx)
			return "transactions-next", false, 0, nil
		},
		rewrapPasskey: func(ctx context.Context, _ string) (passkey.RewrapBatchResult, error) {
			call("passkey", ctx)
			return passkey.RewrapBatchResult{Cursor: "passkey-next"}, nil
		},
		rewrapKV: func(ctx context.Context, _ string) (kv.RewrapResult, error) {
			call("kv", ctx)
			return kv.RewrapResult{Cursor: "kv-next"}, nil
		},
		rewrapManaged: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			call("managed", ctx)
			return oidc.SigningKeyRewrapBatchResult{Cursor: "managed-next"}, nil
		},
		rewrapLoginRevoke: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			call("login-revoke", ctx)
			return oidc.SigningKeyRewrapBatchResult{Cursor: "login-revoke-next"}, nil
		},
		rewrapEmailOutbox: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			call("email-outbox", ctx)
			return oidc.SigningKeyRewrapBatchResult{Cursor: "email-outbox-next"}, nil
		},
		rewrapGeneratedAPIKeyBootstrap: func(ctx context.Context) (oidc.SigningKeyRewrapBatchResult, error) {
			call("generated-api-key-bootstrap", ctx)
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapSaaS: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			call("saas", ctx)
			return oidc.SigningKeyRewrapBatchResult{Cursor: "saas-next"}, nil
		},
		rewrapSaaSProvider: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			call("saas-provider", ctx)
			return oidc.SigningKeyRewrapBatchResult{Cursor: "saas-provider-next"}, nil
		},
		rewrapSaaSAuthorization: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			call("saas-authorization", ctx)
			return oidc.SigningKeyRewrapBatchResult{Cursor: "saas-authorization-next"}, nil
		},
		rewrapAuthProviderSecret: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			call("auth-provider-secret", ctx)
			return oidc.SigningKeyRewrapBatchResult{Cursor: "auth-provider-secret-next"}, nil
		},
	}
}

func TestMasterKeyRewrapStepAdvancesAndResetsCursors(t *testing.T) {
	t.Parallel()
	var signingCursors, idempotencyCursors, transactionCursors, passkeyCursors []string
	pass := 0
	worker := &masterKeyRewrapWorker{
		now: func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		rewrapSigning: func(_ context.Context, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
			signingCursors = append(signingCursors, cursor)
			if pass == 0 {
				return oidc.SigningKeyRewrapBatchResult{Cursor: "signing-32"}, nil
			}
			return oidc.SigningKeyRewrapBatchResult{Cursor: "signing-last", Done: true}, nil
		},
		rewrapIdempotency: func(_ context.Context, cursor string) (string, int, error) {
			idempotencyCursors = append(idempotencyCursors, cursor)
			if pass == 0 {
				return "idempotency-32", 32, nil
			}
			return "", 1, nil
		},
		rewrapTransactions: func(_ context.Context, _ time.Time, cursor string) (string, bool, int64, error) {
			transactionCursors = append(transactionCursors, cursor)
			if pass == 0 {
				return "transaction-32", false, 32, nil
			}
			return "transaction-last", true, 1, nil
		},
		rewrapPasskey: func(_ context.Context, cursor string) (passkey.RewrapBatchResult, error) {
			passkeyCursors = append(passkeyCursors, cursor)
			if pass == 0 {
				return passkey.RewrapBatchResult{Cursor: "passkey-32"}, nil
			}
			return passkey.RewrapBatchResult{Done: true}, nil
		},
	}
	if err := worker.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	pass++
	if err := worker.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := worker.signingCursor, ""; got != want {
		t.Fatalf("signing cursor=%q want %q", got, want)
	}
	if got, want := worker.idempotencyCursor, ""; got != want {
		t.Fatalf("idempotency cursor=%q want %q", got, want)
	}
	if got, want := worker.transactionCursor, ""; got != want {
		t.Fatalf("transaction cursor=%q want %q", got, want)
	}
	if got, want := worker.passkeyCursor, ""; got != want {
		t.Fatalf("passkey cursor=%q want %q", got, want)
	}
	if got, want := signingCursors, []string{"", "signing-32"}; !equalStrings(got, want) || !equalStrings(idempotencyCursors, []string{"", "idempotency-32"}) || !equalStrings(transactionCursors, []string{"", "transaction-32"}) || !equalStrings(passkeyCursors, []string{"", "passkey-32"}) {
		t.Fatalf("cursors signing=%v idempotency=%v transaction=%v passkey=%v", signingCursors, idempotencyCursors, transactionCursors, passkeyCursors)
	}
}

func TestMasterKeyRewrapStepIncludesLoginRevoke(t *testing.T) {
	t.Parallel()
	loginRevokeErr := errors.New("login-revoke envelope unavailable")
	calls := 0
	worker := &masterKeyRewrapWorker{
		now: func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		rewrapSigning: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapIdempotency: func(context.Context, string) (string, int, error) { return "", 0, nil },
		rewrapTransactions: func(context.Context, time.Time, string) (string, bool, int64, error) {
			return "", true, 0, nil
		},
		rewrapLoginRevoke: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			calls++
			return oidc.SigningKeyRewrapBatchResult{}, loginRevokeErr
		},
	}
	if err := worker.Step(context.Background()); !errors.Is(err, loginRevokeErr) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestMasterKeyRewrapStepIncludesEmailOutbox(t *testing.T) {
	t.Parallel()
	emailOutboxErr := errors.New("email outbox envelope unavailable")
	calls := 0
	worker := &masterKeyRewrapWorker{
		now: func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		rewrapSigning: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapIdempotency: func(context.Context, string) (string, int, error) { return "", 0, nil },
		rewrapTransactions: func(context.Context, time.Time, string) (string, bool, int64, error) {
			return "", true, 0, nil
		},
		rewrapEmailOutbox: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			calls++
			return oidc.SigningKeyRewrapBatchResult{}, emailOutboxErr
		},
	}
	if err := worker.Step(context.Background()); !errors.Is(err, emailOutboxErr) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestMasterKeyRewrapStepPasskeyDisabledIsNoOp(t *testing.T) {
	t.Parallel()
	worker := &masterKeyRewrapWorker{
		now: func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		rewrapSigning: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapIdempotency: func(context.Context, string) (string, int, error) {
			return "", 0, nil
		},
		rewrapTransactions: func(context.Context, time.Time, string) (string, bool, int64, error) {
			return "", true, 0, nil
		},
		passkeyCursor: "stale-cursor",
	}
	if err := worker.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if worker.passkeyCursor != "" {
		t.Fatalf("disabled passkey cursor=%q want empty", worker.passkeyCursor)
	}
}

func TestMasterKeyRewrapStepPasskeyCursorChangesOnlyAfterSuccess(t *testing.T) {
	t.Parallel()
	passkeyErr := errors.New("passkey envelope unavailable")
	pass := 0
	worker := &masterKeyRewrapWorker{
		now: func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		rewrapSigning: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapIdempotency: func(context.Context, string) (string, int, error) {
			return "", 0, nil
		},
		rewrapTransactions: func(context.Context, time.Time, string) (string, bool, int64, error) {
			return "", true, 0, nil
		},
		rewrapPasskey: func(context.Context, string) (passkey.RewrapBatchResult, error) {
			if pass == 0 {
				return passkey.RewrapBatchResult{Cursor: "passkey-next"}, nil
			}
			return passkey.RewrapBatchResult{}, passkeyErr
		},
	}
	if err := worker.Step(context.Background()); err != nil || worker.passkeyCursor != "passkey-next" {
		t.Fatalf("first pass err=%v cursor=%q", err, worker.passkeyCursor)
	}
	pass++
	if err := worker.Step(context.Background()); !errors.Is(err, passkeyErr) || worker.passkeyCursor != "passkey-next" {
		t.Fatalf("failed pass err=%v cursor=%q", err, worker.passkeyCursor)
	}
}

func TestMasterKeyRewrapRunImmediatelyReportsAndContinues(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	errorsReported := make(chan error, 1)
	completed := make(chan struct{}, 1)
	signingCalls := 0
	idempotencyCalls := 0
	transactionCalls := 0
	worker := &masterKeyRewrapWorker{
		now:     func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		onError: func(err error) { errorsReported <- err },
		rewrapSigning: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			signingCalls++
			if signingCalls == 1 {
				return oidc.SigningKeyRewrapBatchResult{}, errors.New("tampered envelope")
			}
			completed <- struct{}{}
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapIdempotency: func(context.Context, string) (string, int, error) {
			idempotencyCalls++
			return "", 0, nil
		},
		rewrapTransactions: func(context.Context, time.Time, string) (string, bool, int64, error) {
			transactionCalls++
			return "", true, 0, nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- worker.run(ctx, ticks) }()
	if err := <-errorsReported; err == nil {
		t.Fatal("missing immediate error")
	}
	if idempotencyCalls != 1 || transactionCalls != 1 {
		t.Fatalf("calls after signing failure: idempotency=%d transactions=%d", idempotencyCalls, transactionCalls)
	}
	ticks <- time.Time{}
	<-completed
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run error=%v", err)
	}
}

func TestMasterKeyRewrapStepContinuesAfterDCRFailure(t *testing.T) {
	t.Parallel()
	dcrErr := errors.New("tampered idempotency envelope")
	upstreamCalled := false
	passkeyCalled := false
	worker := &masterKeyRewrapWorker{
		now: func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		rewrapSigning: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.SigningKeyRewrapBatchResult{Cursor: "signing-next"}, nil
		},
		rewrapIdempotency: func(context.Context, string) (string, int, error) {
			return "idempotency-next", 0, dcrErr
		},
		rewrapTransactions: func(context.Context, time.Time, string) (string, bool, int64, error) {
			upstreamCalled = true
			return "transaction-next", false, 32, nil
		},
		rewrapPasskey: func(context.Context, string) (passkey.RewrapBatchResult, error) {
			passkeyCalled = true
			return passkey.RewrapBatchResult{Done: true}, nil
		},
	}
	err := worker.Step(context.Background())
	if !errors.Is(err, dcrErr) || !upstreamCalled || !passkeyCalled || worker.signingCursor != "signing-next" || worker.idempotencyCursor != "" || worker.transactionCursor != "transaction-next" {
		t.Fatalf("err=%v upstream=%t passkey=%t cursors=%q/%q/%q", err, upstreamCalled, passkeyCalled, worker.signingCursor, worker.idempotencyCursor, worker.transactionCursor)
	}
}

func TestMasterKeyRewrapRunFamilyTimeoutAllowsLaterTickRecovery(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	firstStarted := make(chan struct{})
	firstFinished := make(chan struct{})
	recovered := make(chan struct{})
	secondFinished := make(chan struct{})
	firstCancel := make(chan context.CancelFunc, 1)
	reported := make(chan error, 1)
	starved := make(chan error, 2)
	callOrder := make(chan string, 14)
	var signingCalls int
	var contextCalls int
	var passkeyCalls int
	var managedCalls int
	var loginRevokeCalls int
	var emailOutboxCalls int
	worker := &masterKeyRewrapWorker{
		now:     func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		onError: func(err error) { reported <- err },
		newFamilyContext: func(parent context.Context) (context.Context, context.CancelFunc) {
			contextCalls++
			child, childCancel := context.WithCancel(parent)
			if contextCalls == 1 {
				firstCancel <- childCancel
			}
			return child, childCancel
		},
		rewrapSigning: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			signingCalls++
			callOrder <- "signing"
			if signingCalls == 1 {
				close(firstStarted)
				<-ctx.Done()
				close(firstFinished)
				return oidc.SigningKeyRewrapBatchResult{}, ctx.Err()
			}
			close(recovered)
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapIdempotency: func(ctx context.Context, _ string) (string, int, error) {
			callOrder <- "idempotency"
			if err := ctx.Err(); err != nil {
				select {
				case starved <- err:
				default:
				}
				return "", 0, err
			}
			return "", 0, nil
		},
		rewrapTransactions: func(ctx context.Context, _ time.Time, _ string) (string, bool, int64, error) {
			callOrder <- "transactions"
			if err := ctx.Err(); err != nil {
				select {
				case starved <- err:
				default:
				}
				return "", false, 0, err
			}
			return "", true, 0, nil
		},
		rewrapPasskey: func(ctx context.Context, _ string) (passkey.RewrapBatchResult, error) {
			passkeyCalls++
			callOrder <- "passkey"
			if err := ctx.Err(); err != nil {
				select {
				case starved <- err:
				default:
				}
				return passkey.RewrapBatchResult{}, err
			}
			return passkey.RewrapBatchResult{Done: true}, nil
		},
		rewrapManaged: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			managedCalls++
			callOrder <- "managed"
			if err := ctx.Err(); err != nil {
				select {
				case starved <- err:
				default:
				}
				return oidc.SigningKeyRewrapBatchResult{}, err
			}

			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapLoginRevoke: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			loginRevokeCalls++
			callOrder <- "login-revoke"
			if err := ctx.Err(); err != nil {
				starved <- err
				return oidc.SigningKeyRewrapBatchResult{}, err
			}
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
		rewrapEmailOutbox: func(ctx context.Context, _ string) (oidc.SigningKeyRewrapBatchResult, error) {
			emailOutboxCalls++
			callOrder <- "email-outbox"
			if err := ctx.Err(); err != nil {
				starved <- err
				return oidc.SigningKeyRewrapBatchResult{}, err
			}
			// Let the last configured family check its context before stopping the worker.
			if emailOutboxCalls == 2 {
				close(secondFinished)
			}
			return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- worker.run(ctx, ticks) }()
	<-firstStarted
	(<-firstCancel)()
	if err := <-reported; !errors.Is(err, context.Canceled) {
		t.Fatalf("reported timeout error=%v", err)
	}
	<-firstFinished
	ticks <- time.Time{}
	<-recovered
	<-secondFinished
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run error=%v", err)
	}
	select {
	case err := <-starved:
		t.Fatalf("family was starved by signing timeout: %v", err)
	default:
	}
	var gotOrder []string
	for i := 0; i < cap(callOrder); i++ {
		gotOrder = append(gotOrder, <-callOrder)
	}
	wantOrder := []string{"signing", "idempotency", "transactions", "passkey", "managed", "login-revoke", "email-outbox", "signing", "idempotency", "transactions", "passkey", "managed", "login-revoke", "email-outbox"}
	if !equalStrings(gotOrder, wantOrder) {
		t.Fatalf("family call order=%v want %v", gotOrder, wantOrder)
	}
	if signingCalls != 2 || passkeyCalls != 2 || managedCalls != 2 || loginRevokeCalls != 2 || emailOutboxCalls != 2 || contextCalls != 14 {
		t.Fatalf("calls signing=%d passkey=%d managed=%d email-outbox=%d family-context=%d, want 2/2/2/2/14", signingCalls, passkeyCalls, managedCalls, emailOutboxCalls, contextCalls)
	}
}

func TestMasterKeyRewrapRunStopsBeforeImmediateStepWhenCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	worker := &masterKeyRewrapWorker{
		now: time.Now,
		rewrapSigning: func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
			called = true
			return oidc.SigningKeyRewrapBatchResult{}, nil
		},
		rewrapIdempotency:  func(context.Context, string) (string, int, error) { return "", 0, nil },
		rewrapTransactions: func(context.Context, time.Time, string) (string, bool, int64, error) { return "", true, 0, nil },
	}
	if err := worker.run(ctx, make(chan time.Time)); err != nil || called {
		t.Fatalf("run err=%v called=%t", err, called)
	}
}
