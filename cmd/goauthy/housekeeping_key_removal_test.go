package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// GA-RUNTIME-001: event cleanup, account expiry, open-registration cleanup and
// anonymous-DCR cleanup are owned by their dedicated workers in main. The shared
// scheduler owning one of them as well made every replica run that task twice.
func TestHousekeepingLeavesDedicatedTasksToTheirOwners(t *testing.T) {
	t.Parallel()
	db := retirementCmdDB(t, true)
	jobs := buildHousekeepingJobs(db, nil, loginpolicy.NewStore(db), retirementCmdKeyring(t, "key-c"), nil, nil)
	owners := map[string]int{}
	for _, job := range jobs {
		owners[job.Name]++
	}
	if len(owners) == 0 {
		t.Fatal("expected the scheduler to own maintenance tasks")
	}
	for name, count := range owners {
		if count > 1 {
			t.Fatalf("task %q has %d lifecycle owners", name, count)
		}
	}
	for _, dedicated := range []string{"event-cleanup", "user-expiry", "open-registration-cleanup", "dcr-anonymous-cleanup"} {
		if owners[dedicated] != 0 {
			t.Fatalf("task %q is owned by the scheduler and by its dedicated worker", dedicated)
		}
	}
}

// GA-STOR-002: the retired key is deleted by one cleanup owner, only after the
// overlap period and only once the exact ready barrier is acknowledged durable.
// GA66-RETIRE-002: advancing to the next epoch must not forget a pending
// key-deletion obligation. Each retained generation keeps its own overlap
// window and its own archival acknowledgment, and every member that still
// holds the key still sees the obligation after another node recorded removal.
func TestHousekeepingKeyRemovalRetainsObligationsAcrossEpochs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	first, second := retirementCmdKeyring(t, "key-c"), retirementCmdKeyring(t, "key-c")
	base := time.UnixMilli(1_800_000_000_000).UTC()
	complete := func(epoch int64, oldKey, newKey string, at time.Time) time.Time {
		t.Helper()
		if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: epoch, OldKeyID: oldKey, ReplacementKeyID: newKey, MemberIDs: []string{"node-0"}, PreparedAt: at}); err != nil {
			t.Fatal(err)
		}
		if _, err := storage.FenceMasterKeyRetirement(ctx, db, epoch, at.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := storage.AttestMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementAttestationRequest{Epoch: epoch, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: newKey, AttestationSequence: 1, AttestedAt: at.Add(2 * time.Second), Status: storage.MasterKeyRetirementStatus{}}); err != nil {
			t.Fatal(err)
		}
		ready := at.Add(3 * time.Second)
		if _, err := storage.ReadyMasterKeyRetirement(ctx, db, epoch, ready); err != nil {
			t.Fatal(err)
		}
		return ready
	}
	var acknowledged []int64
	ack := func(_ context.Context, _ *rhiza.DB, epoch int64) error {
		acknowledged = append(acknowledged, epoch)
		return nil
	}

	// A->B completes, then B->C starts before A's overlap expires.
	firstReady := complete(1, "key-a", "key-b", base)
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 2, OldKeyID: "key-b", ReplacementKeyID: "key-c", MemberIDs: []string{"node-0"}, PreparedAt: base.Add(4 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := removeRetiredMasterKey(ctx, db, first, 0, func() time.Time { return firstReady.Add(time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 0 || !first.HasKey("key-a") {
		t.Fatalf("overlap period ignored across epochs: acknowledged=%v", acknowledged)
	}
	if err := removeRetiredMasterKey(ctx, db, first, 0, func() time.Time { return firstReady.Add(25 * time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 1 || acknowledged[0] != 1 || first.HasKey("key-a") || !first.HasKey("key-b") {
		t.Fatalf("retained generation cleanup epochs=%v retained-a=%v retained-b=%v", acknowledged, first.HasKey("key-a"), first.HasKey("key-b"))
	}

	// A member that missed the first cleanup still sees the obligation even
	// though another node already recorded the removal.
	if err := removeRetiredMasterKey(ctx, db, second, 0, func() time.Time { return firstReady.Add(26 * time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 2 || acknowledged[1] != 1 || second.HasKey("key-a") {
		t.Fatalf("missed member cleanup epochs=%v retained-a=%v", acknowledged, second.HasKey("key-a"))
	}

	// B keeps its own independent overlap window.
	secondReady := complete(2, "key-b", "key-c", base.Add(5*time.Second))
	if err := removeRetiredMasterKey(ctx, db, first, 0, func() time.Time { return secondReady.Add(time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 2 || !first.HasKey("key-b") {
		t.Fatalf("second generation overlap ignored: epochs=%v retained-b=%v", acknowledged, first.HasKey("key-b"))
	}
	if err := removeRetiredMasterKey(ctx, db, first, 0, func() time.Time { return secondReady.Add(25 * time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 3 || acknowledged[2] != 2 || first.HasKey("key-b") {
		t.Fatalf("second generation cleanup epochs=%v retained-b=%v", acknowledged, first.HasKey("key-b"))
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT epoch, removed_at_unix_ms FROM master_key_retirement_generations ORDER BY epoch`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 2 {
		t.Fatalf("generation receipts=%#v err=%v", rows.Rows, err)
	}
	for i, row := range rows.Rows {
		if row[0] != int64(i+1) || row[1] == nil {
			t.Fatalf("generation row %d=%#v", i, row)
		}
	}
}

func TestKeyRemovalRequiresAcknowledgedArchivalAndOverlap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	keyring := retirementCmdKeyring(t, "key-b")
	base := time.UnixMilli(1_800_000_000_000).UTC()
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: base}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.AttestMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: base.Add(2 * time.Second), Status: storage.MasterKeyRetirementStatus{}}); err != nil {
		t.Fatal(err)
	}
	ready := base.Add(3 * time.Second)
	if _, err := storage.ReadyMasterKeyRetirement(ctx, db, 1, ready); err != nil {
		t.Fatal(err)
	}

	var acknowledged []int64
	ack := func(_ context.Context, _ *rhiza.DB, epoch int64) error {
		acknowledged = append(acknowledged, epoch)
		return nil
	}
	unavailable := errors.New("object-store durability unavailable")
	if err := removeRetiredMasterKey(ctx, db, keyring, 0, func() time.Time { return ready.Add(25 * time.Hour) }, func(context.Context, *rhiza.DB, int64) error { return unavailable }); !errors.Is(err, unavailable) {
		t.Fatalf("removal without acknowledged archival err=%v", err)
	}
	if !keyring.HasKey("key-a") {
		t.Fatal("old key deleted from visible but unacknowledged readiness")
	}
	if err := removeRetiredMasterKey(ctx, db, keyring, 0, func() time.Time { return ready.Add(time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 0 || !keyring.HasKey("key-a") {
		t.Fatalf("overlap period ignored: acknowledged=%v", acknowledged)
	}
	if err := removeRetiredMasterKey(ctx, db, keyring, 0, func() time.Time { return ready.Add(25 * time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 1 || acknowledged[0] != 1 || keyring.HasKey("key-a") {
		t.Fatalf("acknowledged removal epochs=%v retained=%v", acknowledged, keyring.HasKey("key-a"))
	}
	if err := storage.AcknowledgeMasterKeyRetirementArchival(ctx, db, 1); err != nil {
		t.Fatalf("archival acknowledgment of the ready epoch: %v", err)
	}
	if err := storage.AcknowledgeMasterKeyRetirementArchival(ctx, db, 2); !errors.Is(err, storage.ErrMasterKeyRetirementConflict) {
		t.Fatalf("archival acknowledgment accepted a foreign epoch: %v", err)
	}
}

func TestKeyRemovalWaitsForPasswordlessCookieRetentionAfterPreexistingReady(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config *passkey.Config
	}{
		{name: "default", config: &passkey.Config{}},
		{name: "shorter configured ttl", config: &passkey.Config{RenewTTL: 30 * 24 * time.Hour}},
		{name: "configured", config: &passkey.Config{RenewTTL: 120 * 24 * time.Hour}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			db := retirementCmdDB(t, true)
			keyring := retirementCmdKeyring(t, "key-b")
			fencedAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
			if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: fencedAt.Add(-time.Hour)}); err != nil {
				t.Fatal(err)
			}
			if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, fencedAt); err != nil {
				t.Fatal(err)
			}
			if _, err := storage.AttestMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: fencedAt.Add(time.Second), Status: storage.MasterKeyRetirementStatus{}}); err != nil {
				t.Fatal(err)
			}
			readyAt := fencedAt.Add(2 * time.Second)
			if _, err := storage.ReadyMasterKeyRetirement(ctx, db, 1, readyAt); err != nil {
				t.Fatal(err)
			}
			var acknowledged []int64
			ack := func(_ context.Context, _ *rhiza.DB, epoch int64) error {
				acknowledged = append(acknowledged, epoch)
				return nil
			}
			cookieTTL := passkey.PasswordlessCookieTTLForConfig(test.config)
			beforeCookieExpiry := func() time.Time { return fencedAt.Add(cookieTTL - time.Second) }
			if err := removeRetiredMasterKey(ctx, db, keyring, cookieTTL, beforeCookieExpiry, ack); err != nil {
				t.Fatal(err)
			}
			if len(acknowledged) != 0 || !keyring.HasKey("key-a") {
				t.Fatalf("preexisting ready barrier removed a key before passwordless-cookie expiry: acknowledged=%v retained=%v", acknowledged, keyring.HasKey("key-a"))
			}
			if err := removeRetiredMasterKey(ctx, db, keyring, cookieTTL, func() time.Time { return fencedAt.Add(cookieTTL) }, ack); err != nil {
				t.Fatal(err)
			}
			if len(acknowledged) != 1 || acknowledged[0] != 1 || keyring.HasKey("key-a") {
				t.Fatalf("key removal at passwordless-cookie expiry acknowledgments=%v retained=%v", acknowledged, keyring.HasKey("key-a"))
			}
		})
	}
}

func TestKeyRemovalRetainsDefaultCookieGraceWhenPasskeysAreDisabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	keyring := retirementCmdKeyring(t, "key-b")
	fencedAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: fencedAt.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, fencedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.AttestMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: fencedAt.Add(time.Second), Status: storage.MasterKeyRetirementStatus{}}); err != nil {
		t.Fatal(err)
	}
	readyAt := fencedAt.Add(2 * time.Second)
	if _, err := storage.ReadyMasterKeyRetirement(ctx, db, 1, readyAt); err != nil {
		t.Fatal(err)
	}
	var acknowledged []int64
	ack := func(_ context.Context, _ *rhiza.DB, epoch int64) error {
		acknowledged = append(acknowledged, epoch)
		return nil
	}
	// Passkeys may be disabled now, but an older default-TTL cookie can still
	// have been issued using this generation's fenced master key.
	if err := removeRetiredMasterKey(ctx, db, keyring, passkey.PasswordlessCookieTTLForConfig(nil), func() time.Time {
		return readyAt.Add(25 * time.Hour)
	}, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 0 || !keyring.HasKey("key-a") {
		t.Fatalf("disabling passkeys shortened default cookie retention: acknowledged=%v retained=%v", acknowledged, keyring.HasKey("key-a"))
	}
	if err := removeRetiredMasterKey(ctx, db, keyring, passkey.PasswordlessCookieTTLForConfig(nil), func() time.Time {
		return fencedAt.Add(90 * 24 * time.Hour)
	}, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 1 || acknowledged[0] != 1 || keyring.HasKey("key-a") {
		t.Fatalf("key removal at default cookie expiry acknowledgments=%v retained=%v", acknowledged, keyring.HasKey("key-a"))
	}
}

func TestKeyRemovalRetainsHistoricalPasswordlessCookieTTLAfterReduction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	oldKeyring := retirementCmdKeyring(t, "key-a")
	oldConfig := passkey.Config{
		RPID: "example.com", RPDisplayName: "GoAuthy", Origins: []string{"https://example.com"},
		CookieKey: bytes.Repeat([]byte{0x42}, 32), RenewTTL: 120 * 24 * time.Hour, Keyring: oldKeyring,
	}
	oldService, err := passkey.New(db, oldConfig)
	if err != nil {
		t.Fatal(err)
	}
	oldCookie, err := oldService.PasswordlessCookie(ctx, "subject")
	if err != nil {
		t.Fatal(err)
	}
	// The service has since been reconfigured with a shorter lifetime and a
	// replacement active key, but the cookie above can still live for 120 days.
	currentKeyring := retirementCmdKeyring(t, "key-b")
	currentConfig := oldConfig
	currentConfig.Keyring = currentKeyring
	currentConfig.RenewTTL = 30 * 24 * time.Hour
	currentService, err := passkey.New(db, currentConfig)
	if err != nil {
		t.Fatal(err)
	}
	if subject, err := currentService.SubjectFromCookie(oldCookie); err != nil || subject != "subject" {
		t.Fatalf("old cookie stopped decrypting after TTL reduction: subject=%q err=%v", subject, err)
	}

	issuedAt := time.Now().UTC()
	fencedAt := issuedAt.Add(time.Second)
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: fencedAt.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, fencedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.AttestMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: fencedAt.Add(time.Second), Status: storage.MasterKeyRetirementStatus{}}); err != nil {
		t.Fatal(err)
	}
	readyAt := fencedAt.Add(2 * time.Second)
	if _, err := storage.ReadyMasterKeyRetirement(ctx, db, 1, readyAt); err != nil {
		t.Fatal(err)
	}
	var acknowledged []int64
	ack := func(_ context.Context, _ *rhiza.DB, epoch int64) error {
		acknowledged = append(acknowledged, epoch)
		return nil
	}
	currentTTL := passkey.PasswordlessCookieTTLForConfig(&currentConfig)
	if err := removeRetiredMasterKey(ctx, db, currentKeyring, currentTTL, func() time.Time {
		return fencedAt.Add(90*24*time.Hour + time.Second)
	}, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 0 || !currentKeyring.HasKey("key-a") {
		t.Fatalf("TTL reduction pruned a key while its historical cookie remained valid: acknowledged=%v retained=%v", acknowledged, currentKeyring.HasKey("key-a"))
	}
	// Disabling passkeys after the reduction must still consult the persisted
	// high-water mark, even though there is no current service configuration.
	disabledTTL := passkey.PasswordlessCookieTTLForConfig(nil)
	if err := removeRetiredMasterKey(ctx, db, currentKeyring, disabledTTL, func() time.Time {
		return fencedAt.Add(100*24*time.Hour + time.Second)
	}, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 0 || !currentKeyring.HasKey("key-a") {
		t.Fatalf("disabling passkeys discarded historical cookie retention: acknowledged=%v retained=%v", acknowledged, currentKeyring.HasKey("key-a"))
	}
	if err := removeRetiredMasterKey(ctx, db, currentKeyring, disabledTTL, func() time.Time {
		return fencedAt.Add(120*24*time.Hour + time.Second)
	}, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 1 || acknowledged[0] != 1 || currentKeyring.HasKey("key-a") {
		t.Fatalf("key removal after historical cookie expiry acknowledgments=%v retained=%v", acknowledged, currentKeyring.HasKey("key-a"))
	}
}

func TestKeyRemovalFailsClosedWhenCookieRetentionCannotBeRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	keyring := retirementCmdKeyring(t, "key-b")
	fencedAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: fencedAt.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, fencedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.AttestMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: fencedAt.Add(time.Second), Status: storage.MasterKeyRetirementStatus{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.ReadyMasterKeyRetirement(ctx, db, 1, fencedAt.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-drop-cookie-retention-for-test", SQL: `DROP TABLE passkey_cookie_key_retention`}); err != nil {
		t.Fatal(err)
	}
	var acknowledged []int64
	err := removeRetiredMasterKey(ctx, db, keyring, 90*24*time.Hour, func() time.Time {
		return fencedAt.Add(120 * 24 * time.Hour)
	}, func(_ context.Context, _ *rhiza.DB, epoch int64) error {
		acknowledged = append(acknowledged, epoch)
		return nil
	})
	if err == nil || len(acknowledged) != 0 || !keyring.HasKey("key-a") {
		t.Fatalf("pruning without readable retention err=%v acknowledgments=%v retained=%v", err, acknowledged, keyring.HasKey("key-a"))
	}
}
