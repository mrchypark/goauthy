package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
)

func TestMasterKeyRewrapStepAdvancesAndResetsCursors(t *testing.T) {
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

func TestMasterKeyRewrapStepPasskeyDisabledIsNoOp(t *testing.T) {
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
	callOrder := make(chan string, 12)
	var signingCalls int
	var contextCalls int
	var passkeyCalls int
	var managedCalls int
	var loginRevokeCalls int
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
			if loginRevokeCalls == 2 {
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
	wantOrder := []string{"signing", "idempotency", "transactions", "passkey", "managed", "login-revoke", "signing", "idempotency", "transactions", "passkey", "managed", "login-revoke"}
	if !equalStrings(gotOrder, wantOrder) {
		t.Fatalf("family call order=%v want %v", gotOrder, wantOrder)
	}
	if signingCalls != 2 || passkeyCalls != 2 || managedCalls != 2 || loginRevokeCalls != 2 || contextCalls != 12 {
		t.Fatalf("calls signing=%d passkey=%d managed=%d family-context=%d, want 2/2/2/12", signingCalls, passkeyCalls, managedCalls, contextCalls)
	}
}

func TestMasterKeyRewrapRunStopsBeforeImmediateStepWhenCanceled(t *testing.T) {
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
