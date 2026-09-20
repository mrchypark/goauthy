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
