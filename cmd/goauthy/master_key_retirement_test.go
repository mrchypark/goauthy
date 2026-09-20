package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestNewMasterKeyBootIDFromIsRandomAndFailsClosed(t *testing.T) {
	one, err := newMasterKeyBootIDFrom(bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	two, err := newMasterKeyBootIDFrom(bytes.NewReader(bytes.Repeat([]byte{2}, 32)))
	if err != nil || one == two {
		t.Fatalf("boot IDs=%q/%q err=%v", one, two, err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(one)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("boot ID=%q decoded=%d err=%v", one, len(decoded), err)
	}
	if _, err := newMasterKeyBootIDFrom(bytes.NewReader([]byte{1})); err == nil {
		t.Fatal("short random source accepted")
	}
}

func TestAdmitMasterKeyRuntimeFencesOldAndAllowsReplacement(t *testing.T) {
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	old := retirementCmdKeyring(t, "key-a")
	replacement := retirementCmdKeyring(t, "key-b")
	if err := admitMasterKeyRuntime(ctx, db, old); err != nil {
		t.Fatalf("unprepared admission: %v", err)
	}
	now := time.UnixMilli(1_800_000_000_000).UTC()
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := admitMasterKeyRuntime(ctx, db, old); err != nil {
		t.Fatalf("prepared admission: %v", err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := admitMasterKeyRuntime(ctx, db, old); err == nil {
		t.Fatal("old key admitted after fence")
	}
	if err := admitMasterKeyRuntime(ctx, db, replacement); err != nil {
		t.Fatalf("replacement rejected after fence: %v", err)
	}
	for _, node := range []string{"node-0", "node-1", "node-2"} {
		if _, err := storage.AttestMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: node, BootID: node + "-boot", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: now.Add(2 * time.Second), Status: storage.MasterKeyRetirementStatus{}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := storage.ReadyMasterKeyRetirement(ctx, db, 1, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := admitMasterKeyRuntime(ctx, db, old); err == nil {
		t.Fatal("old key admitted after ready")
	}
	if err := admitMasterKeyRuntime(ctx, db, replacement); err != nil {
		t.Fatalf("replacement rejected after ready: %v", err)
	}
}

func TestMasterKeyRetirementWorkerSkipsUnsafeAndAttestsWithMonotonicSequence(t *testing.T) {
	db := retirementCmdDB(t, false)
	keyring := retirementCmdKeyring(t, "key-b")
	barrier := storage.MasterKeyRetirement{Epoch: 7, OldKeyID: "key-a", ReplacementKeyID: "key-b", State: storage.MasterKeyRetirementFenced}
	unsafe := storage.MasterKeyRetirementStatus{OldReferences: 1, PasskeyEnabled: false}
	var inspections int
	var requests []storage.MasterKeyRetirementAttestationRequest
	worker := &masterKeyRetirementWorker{
		db: db, keyring: keyring, issuer: "http://localhost:8080", nodeID: "node-0", bootID: "boot-0",
		now:  func() time.Time { return time.UnixMilli(1_800_000_000_010).UTC() },
		load: func(context.Context, *rhiza.DB) (storage.MasterKeyRetirement, error) { return barrier, nil },
		inspect: func(context.Context, *rhiza.DB, *oidc.Keyring, string, *passkey.Service, string, time.Time) (storage.MasterKeyRetirementStatus, error) {
			inspections++
			if inspections == 1 {
				return unsafe, nil
			}
			return storage.MasterKeyRetirementStatus{}, nil
		},
		attest: func(_ context.Context, _ *rhiza.DB, request storage.MasterKeyRetirementAttestationRequest) (storage.MasterKeyRetirement, error) {
			requests = append(requests, request)
			return barrier, nil
		},
	}
	if err := worker.Step(context.Background()); err != nil || len(requests) != 0 || worker.sequence != 0 {
		t.Fatalf("unsafe step err=%v requests=%d sequence=%d", err, len(requests), worker.sequence)
	}
	if err := worker.Step(context.Background()); err != nil || len(requests) != 1 || requests[0].AttestationSequence != 1 || worker.sequence != 1 {
		t.Fatalf("first safe step err=%v requests=%#v sequence=%d", err, requests, worker.sequence)
	}
	if err := worker.Step(context.Background()); err != nil || len(requests) != 2 || requests[1].AttestationSequence != 2 || worker.sequence != 2 {
		t.Fatalf("second safe step err=%v requests=%#v sequence=%d", err, requests, worker.sequence)
	}
	persisted := barrier
	persisted.Attestations = []storage.MasterKeyRetirementAttestation{{NodeID: "node-0", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 2, AttestedAt: time.UnixMilli(1_800_000_000_010).UTC(), Status: storage.MasterKeyRetirementStatus{}}}
	var restartRequest storage.MasterKeyRetirementAttestationRequest
	restarted := &masterKeyRetirementWorker{
		db: db, keyring: keyring, issuer: "http://localhost:8080", nodeID: "node-0", bootID: "boot-1",
		now:  func() time.Time { return time.UnixMilli(1_800_000_000_011).UTC() },
		load: func(context.Context, *rhiza.DB) (storage.MasterKeyRetirement, error) { return persisted, nil },
		inspect: func(context.Context, *rhiza.DB, *oidc.Keyring, string, *passkey.Service, string, time.Time) (storage.MasterKeyRetirementStatus, error) {
			return storage.MasterKeyRetirementStatus{}, nil
		},
		attest: func(_ context.Context, _ *rhiza.DB, request storage.MasterKeyRetirementAttestationRequest) (storage.MasterKeyRetirement, error) {
			restartRequest = request
			return persisted, nil
		},
	}
	if err := restarted.Step(context.Background()); err != nil || restartRequest.BootID != "boot-1" || restartRequest.AttestationSequence != 3 || restarted.sequence != 3 {
		t.Fatalf("restart err=%v request=%#v sequence=%d", err, restartRequest, restarted.sequence)
	}
}

func TestInspectMasterKeyRetirementPasskeyDisabledIsExplicitZero(t *testing.T) {
	db := retirementCmdDB(t, true)
	keyring := retirementCmdKeyring(t, "key-b")
	status, err := inspectMasterKeyRetirement(context.Background(), db, keyring, "http://localhost:8080", nil, "key-a", time.UnixMilli(1_800_000_000_000).UTC())
	if err != nil || status.PasskeyEnabled || status.PasskeyReferences != 0 {
		t.Fatalf("status=%#v err=%v", status, err)
	}
}

// GA-STOR-001: with passkeys disabled the passkey families cannot be inspected
// or rewrapped, so retained rows must block retirement instead of reporting
// zero passkey references.
func TestMasterKeyRetirementRejectsRetainedPasskeyRowsWhenDisabled(t *testing.T) {
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	keyring := retirementCmdKeyring(t, "key-b")
	now := time.UnixMilli(1_800_000_000_000).UTC()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-disabled-passkey-credential", SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{"credential-id", "subject", "privacy", "sealed-under-key-a", int64(0), int64(1), now.UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	status, err := inspectMasterKeyRetirement(ctx, db, keyring, "http://localhost:8080", nil, "key-a", now)
	if err == nil || status.PasskeyEnabled || status.PasskeyReferences != 0 {
		t.Fatalf("retained passkey rows were not rejected: status=%#v err=%v", status, err)
	}
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	worker, err := newMasterKeyRetirementWorker(db, keyring, "http://localhost:8080", "node-0", "boot-0", nil)
	if err != nil {
		t.Fatal(err)
	}
	worker.now = func() time.Time { return now.Add(2 * time.Second) }
	if err := worker.Step(ctx); err == nil {
		t.Fatal("worker attested while uninspected passkey rows were retained")
	}
	barrier, err := storage.LoadMasterKeyRetirement(ctx, db)
	if err != nil || barrier.State != storage.MasterKeyRetirementFenced || len(barrier.Attestations) != 0 {
		t.Fatalf("retirement advanced past uninspected passkey rows: %#v err=%v", barrier, err)
	}
	if !keyring.HasKey("key-a") {
		t.Fatal("old key was retired while uninspected passkey rows remained")
	}
}

func TestInspectMasterKeyRetirementIncludesLoginRevoke(t *testing.T) {
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	old, active := retirementCmdKeyring(t, "key-a"), retirementCmdKeyring(t, "key-b")
	subject, generation := "login-revoke-retirement", strings.Repeat("g", 22)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "login-revoke-retirement-user", SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES(?,?,?)`, Args: []any{subject, subject, ""}}); err != nil {
		t.Fatal(err)
	}
	envelope, err := old.SealEnvelope(oidc.LoginRevokeCodePurpose(subject, generation), []byte(strings.Repeat("A", 48)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "login-revoke-retirement-row", SQL: `INSERT INTO identity_login_revoke(subject,generation,code_envelope) VALUES(?,?,?)`, Args: []any{subject, generation, envelope}}); err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_800_000_000_000).UTC()
	status, err := inspectMasterKeyRetirement(ctx, db, active, "http://localhost:8080", nil, "key-a", now)
	if err != nil || status.OldReferences != 1 || status.NonActiveReferences != 0 {
		t.Fatalf("old login-revoke retirement=%#v err=%v", status, err)
	}
	if result, err := oidc.RewrapLoginRevokeCodeBatch(ctx, db, active, ""); err != nil || result.Rewrapped != 1 {
		t.Fatalf("login-revoke rewrap=%#v err=%v", result, err)
	}
	status, err = inspectMasterKeyRetirement(ctx, db, active, "http://localhost:8080", nil, "key-a", now)
	if err != nil || status.OldReferences != 0 || status.NonActiveReferences != 0 || status.TamperReferences != 0 {
		t.Fatalf("rewrapped login-revoke retirement=%#v err=%v", status, err)
	}
}

func TestMasterKeyRetirementWorkerRunUsesInjectedTriggerAndCancellation(t *testing.T) {
	db := retirementCmdDB(t, false)
	keyring := retirementCmdKeyring(t, "key-b")
	ticks := make(chan time.Time)
	called := make(chan struct{}, 1)
	worker := &masterKeyRetirementWorker{
		db: db, keyring: keyring, nodeID: "node-0", bootID: "boot-0", now: time.Now,
		load: func(context.Context, *rhiza.DB) (storage.MasterKeyRetirement, error) {
			called <- struct{}{}
			return storage.MasterKeyRetirement{}, storage.ErrMasterKeyRetirementNotPrepared
		},
		inspect: func(context.Context, *rhiza.DB, *oidc.Keyring, string, *passkey.Service, string, time.Time) (storage.MasterKeyRetirementStatus, error) {
			return storage.MasterKeyRetirementStatus{}, nil
		},
		attest: func(context.Context, *rhiza.DB, storage.MasterKeyRetirementAttestationRequest) (storage.MasterKeyRetirement, error) {
			return storage.MasterKeyRetirement{}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.run(ctx, ticks) }()
	ticks <- time.Time{}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("injected trigger did not run worker")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("worker run=%v", err)
	}
}

func TestMasterKeyRetirementWorkerRunReportsInjectedError(t *testing.T) {
	db := retirementCmdDB(t, false)
	keyring := retirementCmdKeyring(t, "key-b")
	want := errors.New("barrier unavailable")
	reported := make(chan error, 1)
	worker := &masterKeyRetirementWorker{
		db: db, keyring: keyring, nodeID: "node-0", bootID: "boot-0", now: time.Now,
		load: func(context.Context, *rhiza.DB) (storage.MasterKeyRetirement, error) {
			return storage.MasterKeyRetirement{}, want
		},
		inspect: func(context.Context, *rhiza.DB, *oidc.Keyring, string, *passkey.Service, string, time.Time) (storage.MasterKeyRetirementStatus, error) {
			return storage.MasterKeyRetirementStatus{}, nil
		},
		attest: func(context.Context, *rhiza.DB, storage.MasterKeyRetirementAttestationRequest) (storage.MasterKeyRetirement, error) {
			return storage.MasterKeyRetirement{}, nil
		},
		onError: func(err error) { reported <- err },
	}
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan error, 1)
	go func() { done <- worker.run(ctx, ticks) }()
	ticks <- time.Time{}
	if err := <-reported; !errors.Is(err, want) {
		t.Fatalf("reported=%v want=%v", err, want)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("worker run=%v", err)
	}
}

// The worker must never delete a retired key: the housekeeping cleanup owner
// is the only path, and it waits out the overlap period and requires an
// acknowledged archival receipt (GA-STOR-002).
func TestMasterKeyRetirementWorkerLeavesRetiredKeyToCleanupOwner(t *testing.T) {
	db := retirementCmdDB(t, false)
	keyring := retirementCmdKeyring(t, "key-b")
	barrier := storage.MasterKeyRetirement{Epoch: 3, OldKeyID: "key-a", ReplacementKeyID: "key-b", State: storage.MasterKeyRetirementReady}
	worker := &masterKeyRetirementWorker{
		db: db, keyring: keyring, issuer: "http://localhost:8080", nodeID: "node-0", bootID: "boot-0",
		now:  func() time.Time { return time.UnixMilli(1_800_000_000_010).UTC() },
		load: func(context.Context, *rhiza.DB) (storage.MasterKeyRetirement, error) { return barrier, nil },
		inspect: func(context.Context, *rhiza.DB, *oidc.Keyring, string, *passkey.Service, string, time.Time) (storage.MasterKeyRetirementStatus, error) {
			return storage.MasterKeyRetirementStatus{}, nil
		},
		attest: func(_ context.Context, _ *rhiza.DB, request storage.MasterKeyRetirementAttestationRequest) (storage.MasterKeyRetirement, error) {
			return barrier, nil
		},
	}
	if !keyring.HasKey("key-a") {
		t.Fatal("key-a not in keyring before step")
	}
	if err := worker.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !keyring.HasKey("key-a") {
		t.Fatal("worker deleted the retired key outside the acknowledged-archival cleanup owner")
	}
}

func retirementCmdDB(t *testing.T, migrate bool) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "cmd-retirement-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if migrate {
		if err := storage.Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func retirementCmdKeyring(t *testing.T, active string) *oidc.Keyring {
	t.Helper()
	dir := t.TempDir()
	for _, id := range []string{"key-a", "key-b"} {
		path := filepath.Join(dir, id)
		value := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(id[len(id)-1])}, 32))
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keyring, err := oidc.LoadKeyring(dir, active)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}
