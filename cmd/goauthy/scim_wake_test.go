package main

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/scim"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func scimWakeRuntime(t *testing.T) (*scimRuntime, *identity.Store, *rhiza.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "scim-wake-test", DataDir: migratedDataDir(t, "scim-wake-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStoreWithPasswordReset(db, hasher, credential.DefaultRules(), bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	outbox := scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, _ scim.Request) (scim.Result, error) {
			return scim.Result{Action: scim.ActionCreated, RemoteID: "remote"}, nil
		}), nil
	}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{3}, 4096))})
	return &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{"provider": {}}, providerIDs: []string{"provider"}, drainLimit: 128, wake: make(chan struct{}, 1)}, store, db
}

func TestSCIMRuntimeWakeReconcilesNewPendingUserAcrossProviders(t *testing.T) {
	t.Parallel()
	runtime, store, db := scimWakeRuntime(t)
	runtime.providerIDs = []string{"provider-a", "provider-b"}
	runtime.providers = map[string]configuredSCIMProvider{"provider-a": {}, "provider-b": {}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var seen []struct {
		provider, email, subject string
		active                   bool
	}
	runtime.outbox = scim.NewOutbox(db, func(_ context.Context, provider string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, request scim.Request) (scim.Result, error) {
			mu.Lock()
			seen = append(seen, struct {
				provider, email, subject string
				active                   bool
			}{provider, request.User.UserName, request.User.ExternalID, request.User.Active})
			n := len(seen)
			mu.Unlock()
			if n == 2 {
				cancel()
			}
			return scim.Result{Action: scim.ActionCreated, RemoteID: provider + "-remote"}, nil
		}), nil
	}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{9}, 8192))})
	startup := make(chan struct{})
	allowInitial := make(chan struct{})
	var initialOnce sync.Once
	runtime.beforeTombstoneEnqueue = func() {
		initialOnce.Do(func() {
			close(startup)
			select {
			case <-allowInitial:
			case <-ctx.Done():
			}
		})
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runtime.Run(ctx, 24*time.Hour, func() time.Time { return time.UnixMilli(5000) }, nil)
	}()
	defer func() { cancel(); <-done }()
	<-startup
	released := false
	defer func() {
		if !released {
			close(allowInitial)
		}
	}()
	created, err := store.CreateUserWithGuard(ctx, identity.UserCreation{OpenRegistration: identity.OpenRegistration{Email: "pending@example.test", Language: "en", TTL: time.Hour}}, "1=1", nil)
	if err != nil || !created.Created {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	runtime.Wake()
	close(allowInitial)
	released = true
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("wake reconciliation did not finish")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("provider requests=%#v", seen)
	}
	for _, request := range seen {
		if request.email != "pending@example.test" || request.subject != created.Subject || request.active {
			t.Fatalf("pending projection=%#v", request)
		}
	}
}

func seedSCIMWakeUser(t *testing.T, db *rhiza.DB, subject string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "scim-wake-seed-" + subject, Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users(subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation) VALUES(?,?,?,0,0,1)`, Args: []any{subject, subject, "phc"}},
		{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES(?,?,1,0)`, Args: []any{subject, "password"}},
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestSCIMRuntimeWakeStartupImmediateAndCancellation(t *testing.T) {
	t.Parallel()
	runtime, _, db := scimWakeRuntime(t)
	seedSCIMWakeUser(t, db, "startup-user")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var seen []scim.User
	runtime.outbox = scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, request scim.Request) (scim.Result, error) {
			seen = append(seen, request.User)
			cancel()
			return scim.Result{Action: scim.ActionCreated, RemoteID: "startup-remote"}, nil
		}), nil
	}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{4}, 4096))})
	if err := runtime.Run(ctx, 24*time.Hour, func() time.Time { return time.UnixMilli(1000) }, nil); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].ExternalID != "startup-user" || !seen[0].Active {
		t.Fatalf("startup reconciliation=%#v", seen)
	}
}

func TestSCIMRuntimeWakeRetainsWakeDuringActiveReconciliation(t *testing.T) {
	t.Parallel()
	runtime, _, db := scimWakeRuntime(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var seen []string
	runtime.outbox = scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, request scim.Request) (scim.Result, error) {
			mu.Lock()
			seen = append(seen, request.User.ExternalID)
			n := len(seen)
			mu.Unlock()
			if n == 1 {
				close(started)
				<-release
			}
			if n >= 2 {
				cancel()
			}
			return scim.Result{Action: scim.ActionCreated, RemoteID: request.User.ExternalID}, nil
		}), nil
	}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{5}, 8192))})
	seedSCIMWakeUser(t, db, "wake-first")
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runtime.Run(ctx, 24*time.Hour, func() time.Time { return time.UnixMilli(2000) }, nil)
	}()
	<-started
	seedSCIMWakeUser(t, db, "wake-second")
	runtime.Wake()
	runtime.Wake()
	close(release)
	<-ctx.Done()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != "wake-first" || seen[1] != "wake-second" {
		t.Fatalf("wake reconciliation=%v", seen)
	}
}

func TestSCIMRuntimeWakeBurstCoalescesAndNilIsHarmless(t *testing.T) {
	t.Parallel()
	var nilRuntime *scimRuntime
	nilRuntime.Wake()
	runtime, _, _ := scimWakeRuntime(t)
	for i := 0; i < 100; i++ {
		runtime.Wake()
	}
	select {
	case <-runtime.wake:
	default:
		t.Fatal("burst did not retain a wake")
	}
	select {
	case <-runtime.wake:
		t.Fatal("burst was not coalesced")
	default:
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); runtime.Wake() }()
	}
	wg.Wait()
	select {
	case <-runtime.wake:
	default:
		t.Fatal("concurrent wake lost")
	}
}
