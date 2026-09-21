package oidc

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestSigningKeyRotationWorkerPrepublishesActivatesAndCleansUp(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	worker := SigningKeyRotationWorker{
		DB: db, Keyring: keyring, Issuer: issuer, TickInterval: time.Hour,
		RotationPeriod: 2 * MinimumSigningKeyRetirement,
	}
	old, err := EnsureSigningKey(context.Background(), db, keyring, issuer, now.Add(-worker.RotationPeriod+JWKSCacheMaxAge))
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	pendingKID, activatesAfter, found, err := pendingSigningKey(context.Background(), db)
	if err != nil || !found {
		t.Fatalf("pending key found=%v err=%v", found, err)
	}
	assertSigningKeyStates(t, db, 1, 1, 0)
	if got := rotationOrderHighwater(t, db); got != 0 {
		t.Fatalf("prepublication emitted event: %d", got)
	}
	if _, err := ActivatePreparedSigningKey(context.Background(), db, keyring, issuer, old.PublicJWK.KeyID, pendingKID, activatesAfter.Add(MinimumSigningKeyRetirement), activatesAfter.Add(-time.Millisecond)); err == nil {
		t.Fatal("activated before prepublication elapsed")
	}
	if err := worker.Step(context.Background(), activatesAfter); err != nil {
		t.Fatal(err)
	}
	assertSigningKeyStates(t, db, 1, 0, 1)
	if got := rotationOrderHighwater(t, db); got != 1 {
		t.Fatalf("activation event count: %d", got)
	}
	retireAfter := activatesAfter.Add(MinimumSigningKeyRetirement)
	if err := worker.Step(context.Background(), retireAfter.Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	assertSigningKeyStates(t, db, 1, 0, 1)
	if err := worker.Step(context.Background(), retireAfter); err != nil {
		t.Fatal(err)
	}
	assertSigningKeyStates(t, db, 1, 0, 1)
	if err := worker.Step(context.Background(), retireAfter.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	assertSigningKeyStates(t, db, 1, 0, 0)
	if got := rotationOrderHighwater(t, db); got != 1 {
		t.Fatalf("cleanup/noop emitted extra event: %d", got)
	}
}

func TestSigningKeyRotationWorkersConvergeAndStopOnCancellation(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	worker := SigningKeyRotationWorker{DB: db, Keyring: keyring, Issuer: issuer, TickInterval: time.Hour, RotationPeriod: 2 * MinimumSigningKeyRetirement}
	if _, err := EnsureSigningKey(context.Background(), db, keyring, issuer, now.Add(-worker.RotationPeriod+JWKSCacheMaxAge)); err != nil {
		t.Fatal(err)
	}
	const pods = 3
	errs := make([]error, pods)
	var wait sync.WaitGroup
	for i := range pods {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errs[i] = worker.Step(context.Background(), now)
		}()
	}
	wait.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertSigningKeyStates(t, db, 1, 1, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := worker.Run(ctx); err != nil {
		t.Fatalf("cancelled worker: %v", err)
	}
}

func TestSigningKeyRotationWorkerRetriesRuntimeError(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	errs := make(chan error, 1)
	worker := SigningKeyRotationWorker{
		DB: db, Keyring: keyring, Issuer: issuer, TickInterval: time.Hour,
		RotationPeriod: 2 * MinimumSigningKeyRetirement,
		OnError: func(err error) {
			select {
			case errs <- err:
			default:
			}
		},
	}
	ctx := context.Background()
	err := worker.Step(ctx, now)
	if err == nil {
		t.Fatal("missing runtime error")
	}
	worker.OnError(err)
	select {
	case reported := <-errs:
		if reported != err {
			t.Fatalf("reported error = %v, want %v", reported, err)
		}
	default:
		t.Fatal("worker did not report the missing active key")
	}
	if _, err := EnsureSigningKey(ctx, db, keyring, issuer, now.Add(-worker.RotationPeriod+JWKSCacheMaxAge)); err != nil {
		t.Fatal(err)
	}
	if err := worker.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := pendingSigningKey(ctx, db); err != nil || !found {
		t.Fatalf("pending key found=%v err=%v", found, err)
	}
}
