package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// GA-STOR-002: the retired key is deleted by one cleanup owner, only after the
// overlap period and only once the exact ready barrier is acknowledged durable.
// GA66-RETIRE-002: advancing to the next epoch must not forget a pending
// key-deletion obligation. Each retained generation keeps its own overlap
// window and its own archival acknowledgment, and every member that still
// holds the key still sees the obligation after another node recorded removal.
func TestHousekeepingKeyRemovalRetainsObligationsAcrossEpochs(t *testing.T) {
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
	if err := removeRetiredMasterKey(ctx, db, first, func() time.Time { return firstReady.Add(time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 0 || !first.HasKey("key-a") {
		t.Fatalf("overlap period ignored across epochs: acknowledged=%v", acknowledged)
	}
	if err := removeRetiredMasterKey(ctx, db, first, func() time.Time { return firstReady.Add(25 * time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 1 || acknowledged[0] != 1 || first.HasKey("key-a") || !first.HasKey("key-b") {
		t.Fatalf("retained generation cleanup epochs=%v retained-a=%v retained-b=%v", acknowledged, first.HasKey("key-a"), first.HasKey("key-b"))
	}

	// A member that missed the first cleanup still sees the obligation even
	// though another node already recorded the removal.
	if err := removeRetiredMasterKey(ctx, db, second, func() time.Time { return firstReady.Add(26 * time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 2 || acknowledged[1] != 1 || second.HasKey("key-a") {
		t.Fatalf("missed member cleanup epochs=%v retained-a=%v", acknowledged, second.HasKey("key-a"))
	}

	// B keeps its own independent overlap window.
	secondReady := complete(2, "key-b", "key-c", base.Add(5*time.Second))
	if err := removeRetiredMasterKey(ctx, db, first, func() time.Time { return secondReady.Add(time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 2 || !first.HasKey("key-b") {
		t.Fatalf("second generation overlap ignored: epochs=%v retained-b=%v", acknowledged, first.HasKey("key-b"))
	}
	if err := removeRetiredMasterKey(ctx, db, first, func() time.Time { return secondReady.Add(25 * time.Hour) }, ack); err != nil {
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
	if err := removeRetiredMasterKey(ctx, db, keyring, func() time.Time { return ready.Add(25 * time.Hour) }, func(context.Context, *rhiza.DB, int64) error { return unavailable }); !errors.Is(err, unavailable) {
		t.Fatalf("removal without acknowledged archival err=%v", err)
	}
	if !keyring.HasKey("key-a") {
		t.Fatal("old key deleted from visible but unacknowledged readiness")
	}
	if err := removeRetiredMasterKey(ctx, db, keyring, func() time.Time { return ready.Add(time.Hour) }, ack); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 0 || !keyring.HasKey("key-a") {
		t.Fatalf("overlap period ignored: acknowledged=%v", acknowledged)
	}
	if err := removeRetiredMasterKey(ctx, db, keyring, func() time.Time { return ready.Add(25 * time.Hour) }, ack); err != nil {
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
