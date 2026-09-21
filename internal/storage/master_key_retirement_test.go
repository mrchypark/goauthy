package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/audit"
	"github.com/mrchypark/rhiza"
)

func TestMasterKeyRetirementStateMachineRequiresFreshExactThreeAttestations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementTestDB(t)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	prepared, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-2", "node-0", "node-1"}, PreparedAt: now})
	if err != nil || prepared.State != MasterKeyRetirementPrepared || len(prepared.Membership) != 3 {
		t.Fatalf("prepare=%#v err=%v", prepared, err)
	}
	if got, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now.Add(time.Hour)}); err != nil || got.PreparedAt != now {
		t.Fatalf("prepare replay=%#v err=%v", got, err)
	}
	fenced, err := FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Second))
	if err != nil || fenced.State != MasterKeyRetirementFenced {
		t.Fatalf("fence=%#v err=%v", fenced, err)
	}
	if _, err := ReadyMasterKeyRetirement(ctx, db, 1, now.Add(2*time.Second)); err == nil {
		t.Fatal("ready succeeded without attestations")
	}
	for _, node := range []string{"node-0", "node-1", "node-2"} {
		if _, err := AttestMasterKeyRetirement(ctx, db, MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: node, BootID: node + "-boot", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: now.Add(2 * time.Second), Status: MasterKeyRetirementStatus{}}); err != nil {
			t.Fatalf("attest %s: %v", node, err)
		}
	}
	ready, err := ReadyMasterKeyRetirement(ctx, db, 1, now.Add(3*time.Second))
	if err != nil || ready.State != MasterKeyRetirementReady || ready.ReadyAt != now.Add(3*time.Second) {
		t.Fatalf("ready=%#v err=%v", ready, err)
	}
	if got, err := ReadyMasterKeyRetirement(ctx, db, 1, now.Add(4*time.Second)); err != nil || got.State != MasterKeyRetirementReady {
		t.Fatalf("ready replay=%#v err=%v", got, err)
	}
}

func TestMasterKeyRetirementRejectsUnsafeAttestationsAndAbortsWithoutDeletion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementTestDB(t)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	if _, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	unsafe := MasterKeyRetirementStatus{OldReferences: 1}
	if _, err := AttestMasterKeyRetirement(ctx, db, MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: now.Add(time.Second), Status: unsafe}); err == nil {
		t.Fatal("old-key reference attestation accepted")
	}
	if _, err := AttestMasterKeyRetirement(ctx, db, MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: now, Status: MasterKeyRetirementStatus{}}); err == nil {
		t.Fatal("pre-fence attestation accepted")
	}
	if _, err := AttestMasterKeyRetirement(ctx, db, MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: now.Add(time.Second), Status: MasterKeyRetirementStatus{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := AttestMasterKeyRetirement(ctx, db, MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-1", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: now.Add(time.Second), Status: MasterKeyRetirementStatus{}}); err == nil {
		t.Fatal("duplicate boot ID accepted")
	}
	aborted, err := AbortMasterKeyRetirement(ctx, db, 1, now.Add(2*time.Second))
	if err != nil || aborted.State != MasterKeyRetirementAborted || len(aborted.Attestations) != 1 {
		t.Fatalf("abort=%#v err=%v", aborted, err)
	}
	if _, err := AbortMasterKeyRetirement(ctx, db, 1, now.Add(3*time.Second)); err != nil {
		t.Fatal("abort replay failed: ", err)
	}
	if _, err := ReadyMasterKeyRetirement(ctx, db, 1, now.Add(3*time.Second)); err == nil {
		t.Fatal("aborted barrier became ready")
	}
	if _, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-c", MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now.Add(4 * time.Second)}); !errors.Is(err, ErrMasterKeyRetirementConflict) {
		t.Fatalf("non-monotonic epoch err=%v", err)
	}
	if _, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 2, OldKeyID: "key-a", ReplacementKeyID: "key-c", MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now.Add(4 * time.Second)}); err != nil {
		t.Fatal("new epoch after abort: ", err)
	}
}

// GA-STOR-005: a completed epoch admits a new epoch only when the prior
// replacement becomes the new old key, so rotations chain A->B->C without
// deleting the barrier or weakening monotonic fencing.
func TestMasterKeyRetirementChainsSecondEpochAfterReady(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementTestDB(t)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	digestBytes := sha256.Sum256([]byte("retirement-chain-key"))
	digest := base64.RawURLEncoding.EncodeToString(digestBytes[:])
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-chain-key", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms) VALUES(?,?,?)`, Args: []any{"ops", digest, now.UnixMilli()}},
		{SQL: `INSERT INTO api_key_access(key_name,group_name,right_name) VALUES(?,?,?),(?,?,?),(?,?,?)`, Args: []any{"ops", "Secrets", "create", "ops", "Secrets", "update", "ops", "Secrets", "delete"}},
	}}); err != nil {
		t.Fatal(err)
	}
	auth := func(right string) MasterKeyRetirementAuthorization {
		return MasterKeyRetirementAuthorization{KeyName: "ops", KeyDigest: digest, Group: "Secrets", Right: right, AuthorizedAt: now}
	}
	complete := func(epoch int64, oldKey, newKey string, at time.Time) {
		t.Helper()
		if _, err := PrepareMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: epoch, OldKeyID: oldKey, ReplacementKeyID: newKey, MemberIDs: []string{"node-0"}, PreparedAt: at}, auth("create")); err != nil {
			t.Fatalf("prepare epoch %d: %v", epoch, err)
		}
		if _, err := FenceMasterKeyRetirementGuarded(ctx, db, epoch, at.Add(time.Second), auth("update")); err != nil {
			t.Fatalf("fence epoch %d: %v", epoch, err)
		}
		if _, err := AttestMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementAttestationRequest{Epoch: epoch, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: newKey, AttestationSequence: 1, AttestedAt: at.Add(2 * time.Second), Status: MasterKeyRetirementStatus{}}, auth("update")); err != nil {
			t.Fatalf("attest epoch %d: %v", epoch, err)
		}
		ready, err := ReadyMasterKeyRetirementGuarded(ctx, db, epoch, at.Add(3*time.Second), auth("update"))
		if err != nil || ready.State != MasterKeyRetirementReady || ready.ReplacementKeyID != newKey {
			t.Fatalf("ready epoch %d: %#v err=%v", epoch, ready, err)
		}
	}
	complete(1, "key-a", "key-b", now)
	if _, err := PrepareMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 2, OldKeyID: "key-a", ReplacementKeyID: "key-c", MemberIDs: []string{"node-0"}, PreparedAt: now.Add(4 * time.Second)}, auth("create")); !errors.Is(err, ErrMasterKeyRetirementConflict) {
		t.Fatalf("second epoch restarted from a retired generation: %v", err)
	}
	// A completed generation permanently prohibits its old key, so a fence that
	// named it would reject every writer.
	if _, err := PrepareMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 2, OldKeyID: "key-b", ReplacementKeyID: "key-a", MemberIDs: []string{"node-0"}, PreparedAt: now.Add(4 * time.Second)}, auth("create")); !errors.Is(err, ErrMasterKeyRetirementConflict) {
		t.Fatalf("second epoch nominated a permanently prohibited replacement: %v", err)
	}
	if _, err := PrepareMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 2, OldKeyID: "key-b", ReplacementKeyID: "key-c", MemberIDs: []string{"node-0"}, PreparedAt: now.Add(4 * time.Second)}, auth("create")); err != nil {
		t.Fatal("second epoch from the prior replacement: ", err)
	}
	if _, err := PrepareMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 2, OldKeyID: "key-b", ReplacementKeyID: "key-d", MemberIDs: []string{"node-0"}, PreparedAt: now.Add(5 * time.Second)}, auth("create")); !errors.Is(err, ErrMasterKeyRetirementConflict) {
		t.Fatalf("prepared epoch was rewritten: %v", err)
	}
	complete(2, "key-b", "key-c", now.Add(6*time.Second))
	loaded, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil || loaded.Epoch != 2 || loaded.OldKeyID != "key-b" || loaded.ReplacementKeyID != "key-c" || loaded.State != MasterKeyRetirementReady {
		t.Fatalf("second epoch barrier=%#v err=%v", loaded, err)
	}
	// Every epoch is audited exactly once, including the second prepare that
	// started from the completed barrier; rejected attempts emit nothing.
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT event_type,action,target_hash FROM audit_events ORDER BY sequence`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 6 {
		t.Fatalf("audit rows=%#v err=%v", rows.Rows, err)
	}
	wantTypes := []string{"master_key_retirement.prepared", "master_key_retirement.fenced", "master_key_retirement.ready", "master_key_retirement.prepared", "master_key_retirement.fenced", "master_key_retirement.ready"}
	wantActions := []string{"prepare", "fence", "ready", "prepare", "fence", "ready"}
	wantEpochs := []string{"epoch:1", "epoch:1", "epoch:1", "epoch:2", "epoch:2", "epoch:2"}
	for i, row := range rows.Rows {
		if row[0] != wantTypes[i] || row[1] != wantActions[i] || row[2] != audit.Pseudonym(digest, "target", wantEpochs[i]) {
			t.Fatalf("audit row %d=%#v", i, row)
		}
	}
}

// GA66-RETIRE-001: a completed generation's old key must not become an
// accepted writer again when a later epoch replaces the singleton barrier row,
// in the prepared state, the aborted state, and after the archival
// acknowledgment that precedes deletion.
func TestMasterKeyRetirementKeepsRetiredWriterFencedAcrossLaterEpochs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementTestDB(t)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-writer-probe-table", SQL: `CREATE TABLE retirement_writer_probe (value TEXT NOT NULL) STRICT`}); err != nil {
		t.Fatal(err)
	}
	complete := func(epoch int64, oldKey, newKey string, at time.Time) {
		t.Helper()
		if _, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: epoch, OldKeyID: oldKey, ReplacementKeyID: newKey, MemberIDs: []string{"node-0"}, PreparedAt: at}); err != nil {
			t.Fatalf("prepare epoch %d: %v", epoch, err)
		}
		if _, err := FenceMasterKeyRetirement(ctx, db, epoch, at.Add(time.Second)); err != nil {
			t.Fatalf("fence epoch %d: %v", epoch, err)
		}
		if _, err := AttestMasterKeyRetirement(ctx, db, MasterKeyRetirementAttestationRequest{Epoch: epoch, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: newKey, AttestationSequence: 1, AttestedAt: at.Add(2 * time.Second), Status: MasterKeyRetirementStatus{}}); err != nil {
			t.Fatalf("attest epoch %d: %v", epoch, err)
		}
		if _, err := ReadyMasterKeyRetirement(ctx, db, epoch, at.Add(3*time.Second)); err != nil {
			t.Fatalf("ready epoch %d: %v", epoch, err)
		}
	}
	write := func(keyID, id string) error {
		t.Helper()
		_, err := ExecuteEnvelope(ctx, db, keyID, rhiza.ExecuteRequest{RequestID: "retirement-writer-probe-" + id, SQL: `INSERT INTO retirement_writer_probe(value) VALUES (?)`, Args: []any{id}})
		return err
	}
	requireRejected := func(id, keyID string) {
		t.Helper()
		if err := write(keyID, id); err == nil {
			t.Fatalf("writer %q was admitted as %s", keyID, id)
		}
	}
	requireAdmitted := func(id, keyID string) {
		t.Helper()
		if err := write(keyID, id); err != nil {
			t.Fatalf("writer %q was rejected as %s: %v", keyID, id, err)
		}
	}

	complete(1, "key-a", "key-b", now)
	requireRejected("epoch1-ready-a", "key-a")
	requireAdmitted("epoch1-ready-b", "key-b")

	if _, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 2, OldKeyID: "key-b", ReplacementKeyID: "key-c", MemberIDs: []string{"node-0"}, PreparedAt: now.Add(4 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	requireRejected("epoch2-prepared-a", "key-a")
	requireAdmitted("epoch2-prepared-b", "key-b")
	if prohibited, err := MasterKeyRetirementProhibitsWriter(ctx, db, "key-b"); err != nil || prohibited {
		t.Fatalf("a prepared epoch was treated as completed: prohibited=%v err=%v", prohibited, err)
	}

	if _, err := AbortMasterKeyRetirement(ctx, db, 2, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	requireRejected("epoch2-aborted-a", "key-a")
	requireAdmitted("epoch2-aborted-b", "key-b")

	if _, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 3, OldKeyID: "key-b", ReplacementKeyID: "key-d", MemberIDs: []string{"node-0"}, PreparedAt: now.Add(6 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	requireRejected("epoch3-prepared-a", "key-a")
	requireAdmitted("epoch3-prepared-b", "key-b")
	complete(3, "key-b", "key-d", now.Add(7*time.Second))
	requireRejected("epoch3-ready-a", "key-a")
	requireRejected("epoch3-ready-b", "key-b")
	requireAdmitted("epoch3-ready-d", "key-d")

	// The acknowledgment of an older generation must still work after the
	// barrier moved on, and must not unretire its key.
	if err := AcknowledgeMasterKeyRetirementArchival(ctx, db, 1); err != nil {
		t.Fatalf("acknowledge retained generation: %v", err)
	}
	requireRejected("epoch3-acknowledged-a", "key-a")

	generations, err := LoadMasterKeyRetirementGenerations(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(generations) != 2 {
		t.Fatalf("retained generations=%#v", generations)
	}
	if first := generations[0]; first.Epoch != 1 || first.OldKeyID != "key-a" || first.ReplacementKeyID != "key-b" || !first.ReadyAt.Equal(now.Add(3*time.Second)) {
		t.Fatalf("first generation=%#v", first)
	}
	if third := generations[1]; third.Epoch != 3 || third.OldKeyID != "key-b" || third.ReplacementKeyID != "key-d" || !third.ReadyAt.Equal(now.Add(10*time.Second)) {
		t.Fatalf("third generation=%#v", third)
	}
	if result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM retirement_writer_probe`, Consistency: rhiza.ConsistencyLinearizable}); err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(5) {
		t.Fatalf("admitted mutations=%#v err=%v", result.Rows, err)
	}
}

func TestMasterKeyRetirementRejectsInvalidPreparation(t *testing.T) {
	t.Parallel()
	db := retirementTestDB(t)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	for _, members := range [][]string{
		{},
		{"a", "b"},
		{"a", "b", "c", "d"},
		{"a", "a", "b"},
	} {
		req := MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "a", ReplacementKeyID: "b", MemberIDs: members, PreparedAt: now}
		if _, err := PrepareMasterKeyRetirement(context.Background(), db, req); err == nil {
			t.Fatalf("invalid membership accepted: %#v", members)
		}
	}
	for _, req := range []MasterKeyRetirementPrepareRequest{
		{Epoch: 1, OldKeyID: "a", ReplacementKeyID: "a", MemberIDs: []string{"a", "b", "c"}, PreparedAt: now},
		{Epoch: 1, OldKeyID: "a bad", ReplacementKeyID: "b", MemberIDs: []string{"a", "b", "c"}, PreparedAt: now},
	} {
		if _, err := PrepareMasterKeyRetirement(context.Background(), db, req); err == nil {
			t.Fatalf("invalid request accepted: %#v", req)
		}
	}
}

func TestGuardedRetirementReceiptRejectsInterposedNoOp(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		want int64
		got  int64
		ok   bool
	}{
		{name: "prepare", want: 3, got: 0},
		{name: "fence", want: 2, got: 1},
		{name: "ready", want: 2, got: 0},
		{name: "abort", want: 2, got: 1},
		{name: "attest", want: 1, got: 1, ok: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := rhiza.ExecuteResponse{MutationReceipt: rhiza.MutationReceipt{RowsAffected: test.got}}
			if applied := retirementMutationApplied(response, test.want); applied != test.ok {
				t.Fatalf("retirementMutationApplied(rows=%d, minimum=%d)=%v, want %v", test.got, test.want, applied, test.ok)
			}
		})
	}
}

func TestMasterKeyRetirementExactOneLifecycleSurvivesRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementTestDB(t)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	prepared, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: now})
	if err != nil || len(prepared.Membership) != 1 {
		t.Fatalf("prepare=%#v err=%v", prepared, err)
	}
	if _, err := FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	attest := func(sequence int64, boot string, at time.Time) {
		t.Helper()
		if _, err := AttestMasterKeyRetirement(ctx, db, MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: boot, ActiveKeyID: "key-b", AttestationSequence: sequence, AttestedAt: at, Status: MasterKeyRetirementStatus{}}); err != nil {
			t.Fatal(err)
		}
	}
	attest(1, "boot-1", now.Add(2*time.Second))
	attest(2, "boot-2", now.Add(3*time.Second))
	ready, err := ReadyMasterKeyRetirement(ctx, db, 1, now.Add(4*time.Second))
	if err != nil || ready.State != MasterKeyRetirementReady || len(ready.Attestations) != 1 || ready.Attestations[0].BootID != "boot-2" || ready.Attestations[0].AttestationSequence != 2 {
		t.Fatalf("ready=%#v err=%v", ready, err)
	}
}

func TestMasterKeyRetirementGuardedTransitionsUseFixedAPIKeyPredicate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementTestDB(t)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	digestBytes := sha256.Sum256([]byte("retirement-api-key"))
	digest := base64.RawURLEncoding.EncodeToString(digestBytes[:])
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-api-key-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms) VALUES(?,?,?)`, Args: []any{"ops", digest, now.UnixMilli()}},
		{SQL: `INSERT INTO api_key_access(key_name,group_name,right_name) VALUES(?,?,?),(?,?,?)`, Args: []any{"ops", "Secrets", "create", "ops", "Secrets", "update"}},
	}}); err != nil {
		t.Fatal(err)
	}
	authorization := MasterKeyRetirementAuthorization{KeyName: "ops", KeyDigest: digest, Group: "Secrets", Right: "create", AuthorizedAt: now}
	if _, err := PrepareMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: now}, authorization); err != nil {
		t.Fatal("prepare: ", err)
	}
	authorization.Right = "update"
	if _, err := FenceMasterKeyRetirementGuarded(ctx, db, 1, now.Add(time.Second), authorization); err != nil {
		t.Fatal("fence: ", err)
	}
	if _, err := AttestMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 1, AttestedAt: now.Add(time.Second), Status: MasterKeyRetirementStatus{}}, authorization); err != nil {
		t.Fatal("attest: ", err)
	}
	if ready, err := ReadyMasterKeyRetirementGuarded(ctx, db, 1, now.Add(2*time.Second), authorization); err != nil || ready.State != MasterKeyRetirementReady {
		t.Fatalf("ready=%#v err=%v", ready, err)
	}
}

func TestMasterKeyRetirementRejectsStaleSequenceAndTerminalAttestation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementTestDB(t)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	if _, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	current := MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: "boot-0", ActiveKeyID: "key-b", AttestationSequence: 2, AttestedAt: now.Add(time.Second), Status: MasterKeyRetirementStatus{}}
	if _, err := AttestMasterKeyRetirement(ctx, db, current); err != nil {
		t.Fatal(err)
	}
	stale := current
	stale.AttestationSequence = 1
	stale.BootID = "old-boot"
	if _, err := AttestMasterKeyRetirement(ctx, db, stale); err == nil {
		t.Fatal("stale attestation sequence accepted")
	}
	loaded, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil || len(loaded.Attestations) != 1 || loaded.Attestations[0].AttestationSequence != 2 {
		t.Fatalf("stale update changed evidence: %#v err=%v", loaded, err)
	}
	if _, err := AbortMasterKeyRetirement(ctx, db, 1, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	terminal := current
	terminal.AttestationSequence = 3
	terminal.BootID = "new-boot"
	if _, err := AttestMasterKeyRetirement(ctx, db, terminal); err == nil {
		t.Fatal("terminal-state attestation accepted")
	}
	loaded, err = LoadMasterKeyRetirement(ctx, db)
	if err != nil || loaded.State != MasterKeyRetirementAborted || len(loaded.Attestations) != 1 || loaded.Attestations[0].AttestationSequence != 2 {
		t.Fatalf("terminal update changed evidence: %#v err=%v", loaded, err)
	}
}

func TestGuardedRetirementTransitionsAuditExactlyOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementTestDB(t)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	digestBytes := sha256.Sum256([]byte("retirement-audit-key"))
	digest := base64.RawURLEncoding.EncodeToString(digestBytes[:])
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-audit-key", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms) VALUES(?,?,?)`, Args: []any{"ops", digest, now.UnixMilli()}},
		{SQL: `INSERT INTO api_key_access(key_name,group_name,right_name) VALUES(?,?,?),(?,?,?),(?,?,?)`, Args: []any{"ops", "Secrets", "create", "ops", "Secrets", "update", "ops", "Secrets", "delete"}},
	}}); err != nil {
		t.Fatal(err)
	}
	auth := func(right string) MasterKeyRetirementAuthorization {
		return MasterKeyRetirementAuthorization{KeyName: "ops", KeyDigest: digest, Group: "Secrets", Right: right, AuthorizedAt: now}
	}
	if _, err := PrepareMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: now}, auth("create")); err != nil {
		t.Fatal("prepare: ", err)
	}
	if _, err := PrepareMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: now}, auth("create")); err != nil {
		t.Fatal("prepare replay: ", err)
	}
	if _, err := FenceMasterKeyRetirementGuarded(ctx, db, 1, now.Add(time.Second), auth("update")); err != nil {
		t.Fatal("fence: ", err)
	}
	if _, err := FenceMasterKeyRetirementGuarded(ctx, db, 1, now.Add(time.Second), auth("update")); err != nil {
		t.Fatal("fence replay: ", err)
	}
	if _, err := AbortMasterKeyRetirementGuarded(ctx, db, 1, now.Add(2*time.Second), auth("delete")); err != nil {
		t.Fatal("abort: ", err)
	}
	if _, err := AbortMasterKeyRetirementGuarded(ctx, db, 1, now.Add(2*time.Second), auth("delete")); err != nil {
		t.Fatal("abort replay: ", err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT event_type,action,actor_kind,actor_hash,target_hash FROM audit_events ORDER BY sequence`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 3 {
		t.Fatalf("audit rows=%#v err=%v", rows.Rows, err)
	}
	want := []string{"master_key_retirement.prepared", "master_key_retirement.fenced", "master_key_retirement.aborted"}
	for i, row := range rows.Rows {
		if row[0] != want[i] || row[1] != map[string]string{"master_key_retirement.prepared": "prepare", "master_key_retirement.fenced": "fence", "master_key_retirement.aborted": "abort"}[want[i]] || row[2] != "api_key" || row[3] != audit.Pseudonym(digest, "actor", "ops") || row[4] != audit.Pseudonym(digest, "target", "epoch:1") {
			t.Fatalf("audit row %d=%#v", i, row)
		}
	}
}

func TestGuardedRetirementUnauthorizedAndRevokedEmitNoAudit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementTestDB(t)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	digestBytes := sha256.Sum256([]byte("retirement-audit-revocation"))
	digest := base64.RawURLEncoding.EncodeToString(digestBytes[:])
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-audit-revocation-key", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms) VALUES(?,?,?)`, Args: []any{"ops", digest, now.UnixMilli()}},
		{SQL: `INSERT INTO api_key_access(key_name,group_name,right_name) VALUES(?,?,?)`, Args: []any{"ops", "Secrets", "create"}},
	}}); err != nil {
		t.Fatal(err)
	}
	auth := MasterKeyRetirementAuthorization{KeyName: "ops", KeyDigest: digest, Group: "Secrets", Right: "create", AuthorizedAt: now}
	unauthorized := auth
	unauthorized.KeyDigest = strings.Repeat("A", 43)
	if _, err := PrepareMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: now}, unauthorized); err == nil {
		t.Fatal("unauthorized prepare succeeded")
	}
	if _, err := PrepareMasterKeyRetirementGuarded(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: now}, auth); err != nil {
		t.Fatal("prepare: ", err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-audit-revoke", SQL: `DELETE FROM api_key_access WHERE key_name=?`, Args: []any{"ops"}}); err != nil {
		t.Fatal(err)
	}
	fenceAuth := auth
	fenceAuth.Right = "update"
	if _, err := FenceMasterKeyRetirementGuarded(ctx, db, 1, now.Add(time.Second), fenceAuth); err == nil {
		t.Fatal("revoked fence succeeded")
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM audit_events`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) {
		t.Fatalf("audit rows=%#v err=%v", rows.Rows, err)
	}
}

func TestLoadMasterKeyRetirementGuardedRechecksReadAuthorityAndRejectsMalformedState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementTestDB(t)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	digestBytes := sha256.Sum256([]byte("retirement-read-key"))
	digest := base64.RawURLEncoding.EncodeToString(digestBytes[:])
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-read-key", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms) VALUES(?,?,?)`, Args: []any{"reader", digest, now.UnixMilli()}},
		{SQL: `INSERT INTO api_key_access(key_name,group_name,right_name) VALUES(?,?,?)`, Args: []any{"reader", "Secrets", "read"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareMasterKeyRetirement(ctx, db, MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: now}); err != nil {
		t.Fatal(err)
	}
	auth := MasterKeyRetirementAuthorization{KeyName: "reader", KeyDigest: digest, Group: "Secrets", Right: "read", AuthorizedAt: now}
	loaded, err := LoadMasterKeyRetirementGuarded(ctx, db, auth)
	if err != nil || loaded.State != MasterKeyRetirementPrepared || len(loaded.Membership) != 1 {
		t.Fatalf("guarded load=%#v err=%v", loaded, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-read-revoke", SQL: `DELETE FROM api_key_access WHERE key_name=?`, Args: []any{"reader"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKeyRetirementGuarded(ctx, db, auth); err == nil {
		t.Fatal("revoked read succeeded")
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-read-restore", SQL: `INSERT INTO api_key_access(key_name,group_name,right_name) VALUES(?,?,?)`, Args: []any{"reader", "Secrets", "read"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "retirement-read-malformed", SQL: `DELETE FROM master_key_retirement_members WHERE epoch=?`, Args: []any{int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKeyRetirementGuarded(ctx, db, auth); err == nil {
		t.Fatal("malformed membership accepted")
	}
}

func retirementTestDB(t *testing.T) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "retirement-test", DataDir: testDatabaseDir(t, "retirement-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}
