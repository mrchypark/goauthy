package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/audit"
	"github.com/mrchypark/rhiza"
)

const masterKeyRetirementHAMemberCount = 3

const (
	MasterKeyRetirementPrepared = "prepared"
	MasterKeyRetirementFenced   = "fenced"
	MasterKeyRetirementReady    = "ready"
	MasterKeyRetirementAborted  = "aborted"
)

var (
	ErrMasterKeyRetirementNotPrepared = errors.New("master-key retirement is not prepared")
	ErrMasterKeyRetirementConflict    = errors.New("master-key retirement state conflict")
)

// MasterKeyRetirementAuthorization is an immutable API-key authority snapshot
// for a guarded retirement mutation. The predicate is fixed to api_keys and
// api_key_access; callers cannot provide SQL.
type MasterKeyRetirementAuthorization struct {
	KeyName      string
	KeyDigest    string
	Group        string
	Right        string
	AuthorizedAt time.Time
}

// MasterKeyRetirementPrepareRequest is the operator-supplied Stage A input.
// It is deliberately inert: preparing a row does not inspect or delete keys.
type MasterKeyRetirementPrepareRequest struct {
	Epoch            int64
	OldKeyID         string
	ReplacementKeyID string
	MemberIDs        []string
	ExpectedNodeIDs  []string // compatibility alias for MemberIDs
	PreparedAt       time.Time
}

// MasterKeyRetirementStatus is the sanitized all-family evidence recorded by
// one member. Counts are references, never envelope or ciphertext material.
type MasterKeyRetirementStatus struct {
	OldReferences       int64
	NonActiveReferences int64
	LegacyReferences    int64
	TamperReferences    int64
	OIDCReferences      int64
	DCRReferences       int64
	UpstreamReferences  int64
	PasskeyEnabled      bool
	PasskeyReferences   int64
}

type MasterKeyRetirementAttestationRequest struct {
	Epoch               int64
	NodeID              string
	BootID              string
	ActiveKeyID         string
	AttestationSequence int64
	AttestedAt          time.Time
	Status              MasterKeyRetirementStatus
}

type MasterKeyRetirementAttestation struct {
	NodeID              string
	BootID              string
	ActiveKeyID         string
	AttestationSequence int64
	AttestedAt          time.Time
	Status              MasterKeyRetirementStatus
}

type MasterKeyRetirement struct {
	Epoch            int64
	OldKeyID         string
	ReplacementKeyID string
	Membership       []string
	MembershipDigest string
	State            string
	PreparedAt       time.Time
	FencedAt         time.Time
	ReadyAt          time.Time
	AbortedAt        time.Time
	Attestations     []MasterKeyRetirementAttestation
}

// PrepareMasterKeyRetirement creates or replays one exact-one or exact-three
// membership set. A new epoch is permitted only after an earlier attempt was
// aborted.
func PrepareMasterKeyRetirement(ctx context.Context, db *rhiza.DB, req MasterKeyRetirementPrepareRequest) (MasterKeyRetirement, error) {
	return prepareMasterKeyRetirement(ctx, db, req, nil)
}

// PrepareMasterKeyRetirementGuarded revalidates API-key authority inside the
// same Rhiza mutation as the preparation writes.
func PrepareMasterKeyRetirementGuarded(ctx context.Context, db *rhiza.DB, req MasterKeyRetirementPrepareRequest, authorization MasterKeyRetirementAuthorization) (MasterKeyRetirement, error) {
	return prepareMasterKeyRetirement(ctx, db, req, &authorization)
}

func prepareMasterKeyRetirement(ctx context.Context, db *rhiza.DB, req MasterKeyRetirementPrepareRequest, authorization *MasterKeyRetirementAuthorization) (MasterKeyRetirement, error) {
	if db == nil {
		return MasterKeyRetirement{}, errors.New("master-key retirement database is required")
	}
	if err := validateRetirementAuthorization(authorization, "create"); err != nil {
		return MasterKeyRetirement{}, err
	}
	members, err := normalizeMemberIDs(req.MemberIDs, req.ExpectedNodeIDs)
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if req.Epoch <= 0 || !validRetirementKeyID(req.OldKeyID) || !validRetirementKeyID(req.ReplacementKeyID) || req.OldKeyID == req.ReplacementKeyID {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement keys or epoch")
	}
	if err := validRetirementTime(req.PreparedAt); err != nil {
		return MasterKeyRetirement{}, fmt.Errorf("prepared time: %w", err)
	}
	if err := retirementReplayAuthorization(ctx, db, authorization, "create", req.PreparedAt); err != nil {
		return MasterKeyRetirement{}, err
	}
	digest := retirementMembershipDigest(members)
	current, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil && !errors.Is(err, ErrMasterKeyRetirementNotPrepared) {
		return MasterKeyRetirement{}, err
	}
	if err == nil {
		if current.State == MasterKeyRetirementPrepared && samePreparation(current, req, members, digest) {
			if err := retirementReplayAuthorization(ctx, db, authorization, "create", req.PreparedAt); err != nil {
				return MasterKeyRetirement{}, err
			}
			return current, nil
		}
		if current.State != MasterKeyRetirementAborted || req.Epoch <= current.Epoch {
			return MasterKeyRetirement{}, fmt.Errorf("%w: cannot prepare epoch %d while epoch %d is %s", ErrMasterKeyRetirementConflict, req.Epoch, current.Epoch, current.State)
		}
	}

	requestID := retirementRequestID("prepare", req.Epoch, req.OldKeyID, req.ReplacementKeyID, digest, req.PreparedAt.UnixMilli())
	statements := []rhiza.SQLStatement{}
	if authorization != nil {
		condition := `NOT EXISTS (SELECT 1 FROM master_key_retirement_barrier WHERE barrier_id=1)`
		conditionArgs := []any(nil)
		if err == nil {
			condition = `EXISTS (SELECT 1 FROM master_key_retirement_barrier WHERE barrier_id=1 AND state='aborted' AND epoch<?)`
			conditionArgs = []any{req.Epoch}
		}
		event, eventErr := retirementAuditStatement(*authorization, requestID, "master_key_retirement.prepared", "prepare", req.Epoch, req.PreparedAt, condition, conditionArgs...)
		if eventErr != nil {
			return MasterKeyRetirement{}, eventErr
		}
		statements = append(statements, event)
	}
	if err == nil {
		statements = append(statements, retirementGuardedStatementAt(authorization, rhiza.SQLStatement{SQL: `DELETE FROM master_key_retirement_members WHERE epoch = (SELECT epoch FROM master_key_retirement_barrier WHERE barrier_id = 1 AND state = 'aborted')`}, req.PreparedAt))
	}
	barrierSQL := `INSERT INTO master_key_retirement_barrier (barrier_id, epoch, old_key_id, replacement_key_id, membership_digest, state, prepared_at_unix_ms) VALUES (1, ?, ?, ?, ?, 'prepared', ?)
			ON CONFLICT(barrier_id) DO UPDATE SET epoch=excluded.epoch, old_key_id=excluded.old_key_id, replacement_key_id=excluded.replacement_key_id, membership_digest=excluded.membership_digest, state='prepared', prepared_at_unix_ms=excluded.prepared_at_unix_ms, fenced_at_unix_ms=NULL, ready_at_unix_ms=NULL, aborted_at_unix_ms=NULL
			WHERE master_key_retirement_barrier.state = 'aborted' AND excluded.epoch > master_key_retirement_barrier.epoch`
	barrierArgs := []any{req.Epoch, req.OldKeyID, req.ReplacementKeyID, digest, req.PreparedAt.UnixMilli()}
	if authorization != nil {
		barrierSQL = `INSERT INTO master_key_retirement_barrier (barrier_id, epoch, old_key_id, replacement_key_id, membership_digest, state, prepared_at_unix_ms) SELECT 1, ?, ?, ?, ?, 'prepared', ? WHERE ` + retirementAuthorizationPredicate()
		barrierSQL += ` ON CONFLICT(barrier_id) DO UPDATE SET epoch=excluded.epoch, old_key_id=excluded.old_key_id, replacement_key_id=excluded.replacement_key_id, membership_digest=excluded.membership_digest, state='prepared', prepared_at_unix_ms=excluded.prepared_at_unix_ms, fenced_at_unix_ms=NULL, ready_at_unix_ms=NULL, aborted_at_unix_ms=NULL WHERE master_key_retirement_barrier.state = 'aborted' AND excluded.epoch > master_key_retirement_barrier.epoch`
		barrierArgs = append(barrierArgs, retirementAuthorizationArgs(*authorization, req.PreparedAt)...)
	}
	statements = append(statements, rhiza.SQLStatement{SQL: barrierSQL, Args: barrierArgs})
	for _, member := range members {
		memberSQL := `INSERT INTO master_key_retirement_members (epoch, node_id) VALUES (?, ?)`
		memberArgs := []any{req.Epoch, member}
		if authorization != nil {
			memberSQL = `INSERT INTO master_key_retirement_members (epoch, node_id) SELECT ?, ? WHERE ` + retirementAuthorizationPredicate()
			memberArgs = append(memberArgs, retirementAuthorizationArgs(*authorization, req.PreparedAt)...)
		}
		statements = append(statements, rhiza.SQLStatement{SQL: memberSQL, Args: memberArgs})
	}
	response, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if authorization != nil && !retirementMutationApplied(response, int64(len(members)+2)) {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	result, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if !samePreparation(result, req, members, digest) || result.State != MasterKeyRetirementPrepared {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	return result, nil
}

func FenceMasterKeyRetirement(ctx context.Context, db *rhiza.DB, epoch int64, now time.Time) (MasterKeyRetirement, error) {
	return fenceMasterKeyRetirement(ctx, db, epoch, now, nil)
}

// FenceMasterKeyRetirementGuarded revalidates API-key authority inside the
// same Rhiza mutation as the fence transition.
func FenceMasterKeyRetirementGuarded(ctx context.Context, db *rhiza.DB, epoch int64, now time.Time, authorization MasterKeyRetirementAuthorization) (MasterKeyRetirement, error) {
	return fenceMasterKeyRetirement(ctx, db, epoch, now, &authorization)
}

func fenceMasterKeyRetirement(ctx context.Context, db *rhiza.DB, epoch int64, now time.Time, authorization *MasterKeyRetirementAuthorization) (MasterKeyRetirement, error) {
	if epoch <= 0 {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement epoch")
	}
	if err := validRetirementTime(now); err != nil {
		return MasterKeyRetirement{}, fmt.Errorf("fence time: %w", err)
	}
	if err := retirementReplayAuthorization(ctx, db, authorization, "update", now); err != nil {
		return MasterKeyRetirement{}, err
	}
	if err := validateRetirementAuthorization(authorization, "update"); err != nil {
		return MasterKeyRetirement{}, err
	}
	current, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if current.Epoch != epoch {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	if current.State == MasterKeyRetirementFenced || current.State == MasterKeyRetirementReady {
		if err := retirementReplayAuthorization(ctx, db, authorization, "update", now); err != nil {
			return MasterKeyRetirement{}, err
		}
		return current, nil
	}
	if current.State != MasterKeyRetirementPrepared || now.Before(current.PreparedAt) {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	requestID := retirementRequestID("fence", epoch, current.OldKeyID, current.ReplacementKeyID, current.MembershipDigest, now.UnixMilli())
	sql := `UPDATE master_key_retirement_barrier SET state='fenced', fenced_at_unix_ms=? WHERE barrier_id=1 AND epoch=? AND state='prepared'`
	args := []any{now.UnixMilli(), epoch}
	statements := make([]rhiza.SQLStatement, 0, 2)
	if authorization != nil {
		event, eventErr := retirementAuditStatement(*authorization, requestID, "master_key_retirement.fenced", "fence", epoch, now, `EXISTS (SELECT 1 FROM master_key_retirement_barrier WHERE barrier_id=1 AND epoch=? AND state='prepared')`, epoch)
		if eventErr != nil {
			return MasterKeyRetirement{}, eventErr
		}
		statements = append(statements, event)
	}
	sql, args = retirementGuardedSQLAt(sql, args, authorization, now)
	statements = append(statements, rhiza.SQLStatement{SQL: sql, Args: args})
	response, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if authorization != nil && !retirementMutationApplied(response, 2) {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	result, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if result.Epoch != epoch || (result.State != MasterKeyRetirementFenced && result.State != MasterKeyRetirementReady) {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	return result, nil
}

// AttestMasterKeyRetirement stores one member's fresh, sanitized evidence.
// It is allowed only after the replicated fence and never transitions state.
func AttestMasterKeyRetirement(ctx context.Context, db *rhiza.DB, req MasterKeyRetirementAttestationRequest) (MasterKeyRetirement, error) {
	return attestMasterKeyRetirement(ctx, db, req, nil)
}

// AttestMasterKeyRetirementGuarded revalidates API-key authority inside the
// same Rhiza mutation as the attestation write. Runtime workers should use
// AttestMasterKeyRetirement directly.
func AttestMasterKeyRetirementGuarded(ctx context.Context, db *rhiza.DB, req MasterKeyRetirementAttestationRequest, authorization MasterKeyRetirementAuthorization) (MasterKeyRetirement, error) {
	return attestMasterKeyRetirement(ctx, db, req, &authorization)
}

func attestMasterKeyRetirement(ctx context.Context, db *rhiza.DB, req MasterKeyRetirementAttestationRequest, authorization *MasterKeyRetirementAuthorization) (MasterKeyRetirement, error) {
	if req.Epoch <= 0 || req.AttestationSequence <= 0 || !validRetirementID(req.NodeID) || !validRetirementID(req.BootID) || !validRetirementKeyID(req.ActiveKeyID) {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement attestation identity")
	}
	if err := validRetirementTime(req.AttestedAt); err != nil {
		return MasterKeyRetirement{}, fmt.Errorf("attestation time: %w", err)
	}
	if err := validateRetirementAuthorization(authorization, "update"); err != nil {
		return MasterKeyRetirement{}, err
	}
	if err := validateRetirementStatus(req.Status); err != nil {
		return MasterKeyRetirement{}, err
	}
	current, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if current.Epoch != req.Epoch || current.State != MasterKeyRetirementFenced || req.ActiveKeyID != current.ReplacementKeyID || req.AttestedAt.Before(current.FencedAt) {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	for _, member := range current.Membership {
		if member == req.NodeID {
			goto memberFound
		}
	}
	return MasterKeyRetirement{}, errors.New("attestation node is not in barrier membership")
memberFound:
	for _, attestation := range current.Attestations {
		if attestation.NodeID != req.NodeID && attestation.BootID == req.BootID {
			return MasterKeyRetirement{}, errors.New("attestation boot ID is already used by another member")
		}
		if attestation.NodeID == req.NodeID {
			if req.AttestationSequence < attestation.AttestationSequence || req.AttestationSequence == attestation.AttestationSequence && !sameAttestation(attestation, req) {
				return MasterKeyRetirement{}, errors.New("stale or conflicting master-key retirement attestation")
			}
			if req.AttestationSequence == attestation.AttestationSequence {
				if err := retirementReplayAuthorization(ctx, db, authorization, "update", req.AttestedAt); err != nil {
					return MasterKeyRetirement{}, err
				}
				return current, nil
			}
		}
	}
	requestID := retirementRequestID("attest", req.Epoch, req.NodeID, req.BootID, req.ActiveKeyID, req.AttestationSequence, req.AttestedAt.UnixMilli(), req.Status.OldReferences, req.Status.NonActiveReferences, req.Status.LegacyReferences, req.Status.TamperReferences, req.Status.OIDCReferences, req.Status.DCRReferences, req.Status.UpstreamReferences, req.Status.PasskeyEnabled, req.Status.PasskeyReferences)
	sql := `UPDATE master_key_retirement_members SET attestation_state='attested', attestation_sequence=?, boot_id=?, active_key_id=?, attested_at_unix_ms=?, old_references=?, non_active_references=?, legacy_references=?, tamper_references=?, oidc_references=?, dcr_references=?, upstream_references=?, passkey_enabled=?, passkey_references=? WHERE epoch=? AND node_id=? AND attestation_sequence < ? AND (SELECT state FROM master_key_retirement_barrier WHERE barrier_id=1 AND epoch=?)='fenced'`
	args := []any{req.AttestationSequence, req.BootID, req.ActiveKeyID, req.AttestedAt.UnixMilli(), req.Status.OldReferences, req.Status.NonActiveReferences, req.Status.LegacyReferences, req.Status.TamperReferences, req.Status.OIDCReferences, req.Status.DCRReferences, req.Status.UpstreamReferences, boolInt(req.Status.PasskeyEnabled), req.Status.PasskeyReferences, req.Epoch, req.NodeID, req.AttestationSequence, req.Epoch}
	sql, args = retirementGuardedSQLAt(sql, args, authorization, req.AttestedAt)
	response, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql, Args: args})
	if err != nil {
		loaded, loadErr := LoadMasterKeyRetirement(ctx, db)
		if loadErr == nil && loaded.State == MasterKeyRetirementFenced && attestationMatches(loaded, req) && retirementReplayAuthorization(ctx, db, authorization, "update", req.AttestedAt) == nil {
			return loaded, nil
		}
		return MasterKeyRetirement{}, err
	}
	if authorization != nil && !retirementMutationApplied(response, 1) {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	loaded, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if loaded.State != MasterKeyRetirementFenced || !attestationMatches(loaded, req) {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	return loaded, nil
}

func ReadyMasterKeyRetirement(ctx context.Context, db *rhiza.DB, epoch int64, now time.Time) (MasterKeyRetirement, error) {
	return readyMasterKeyRetirement(ctx, db, epoch, now, nil)
}

// ReadyMasterKeyRetirementGuarded revalidates API-key authority inside the
// same Rhiza mutation as the ready transition.
func ReadyMasterKeyRetirementGuarded(ctx context.Context, db *rhiza.DB, epoch int64, now time.Time, authorization MasterKeyRetirementAuthorization) (MasterKeyRetirement, error) {
	return readyMasterKeyRetirement(ctx, db, epoch, now, &authorization)
}

func readyMasterKeyRetirement(ctx context.Context, db *rhiza.DB, epoch int64, now time.Time, authorization *MasterKeyRetirementAuthorization) (MasterKeyRetirement, error) {
	if epoch <= 0 {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement epoch")
	}
	if err := validRetirementTime(now); err != nil {
		return MasterKeyRetirement{}, fmt.Errorf("ready time: %w", err)
	}
	if err := retirementReplayAuthorization(ctx, db, authorization, "update", now); err != nil {
		return MasterKeyRetirement{}, err
	}
	if err := validateRetirementAuthorization(authorization, "update"); err != nil {
		return MasterKeyRetirement{}, err
	}
	current, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if current.Epoch != epoch {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	if current.State == MasterKeyRetirementReady {
		if err := retirementReplayAuthorization(ctx, db, authorization, "update", now); err != nil {
			return MasterKeyRetirement{}, err
		}
		return current, nil
	}
	if current.State != MasterKeyRetirementFenced || now.Before(current.FencedAt) || !readyAttestations(current, now) {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	requestID := retirementRequestID("ready", epoch, current.OldKeyID, current.ReplacementKeyID, current.MembershipDigest, now.UnixMilli())
	predicate := `EXISTS (SELECT 1 FROM master_key_retirement_barrier WHERE barrier_id=1 AND epoch=? AND state='fenced') AND (SELECT COUNT(*) FROM master_key_retirement_members WHERE epoch=? AND attestation_state='attested')=(SELECT COUNT(*) FROM master_key_retirement_members WHERE epoch=?) AND (SELECT COUNT(DISTINCT boot_id) FROM master_key_retirement_members WHERE epoch=? AND attestation_state='attested')=(SELECT COUNT(*) FROM master_key_retirement_members WHERE epoch=?) AND NOT EXISTS (SELECT 1 FROM master_key_retirement_members WHERE epoch=? AND (active_key_id <> (SELECT replacement_key_id FROM master_key_retirement_barrier WHERE barrier_id=1) OR old_references <> 0 OR non_active_references <> 0 OR legacy_references <> 0 OR tamper_references <> 0 OR oidc_references <> 0 OR dcr_references <> 0 OR upstream_references <> 0 OR passkey_references <> 0 OR attested_at_unix_ms < (SELECT fenced_at_unix_ms FROM master_key_retirement_barrier WHERE barrier_id=1) OR attested_at_unix_ms > ?))`
	predicateArgs := []any{epoch, epoch, epoch, epoch, epoch, epoch, now.UnixMilli()}
	sql := `UPDATE master_key_retirement_barrier SET state='ready', ready_at_unix_ms=? WHERE barrier_id=1 AND ` + predicate
	args := append([]any{now.UnixMilli()}, predicateArgs...)
	statements := make([]rhiza.SQLStatement, 0, 2)
	if authorization != nil {
		event, eventErr := retirementAuditStatement(*authorization, requestID, "master_key_retirement.ready", "ready", epoch, now, predicate, predicateArgs...)
		if eventErr != nil {
			return MasterKeyRetirement{}, eventErr
		}
		statements = append(statements, event)
	}
	sql, args = retirementGuardedSQLAt(sql, args, authorization, now)
	statements = append(statements, rhiza.SQLStatement{SQL: sql, Args: args})
	response, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if authorization != nil && !retirementMutationApplied(response, 2) {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	result, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if result.State != MasterKeyRetirementReady {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	return result, nil
}

func AbortMasterKeyRetirement(ctx context.Context, db *rhiza.DB, epoch int64, now time.Time) (MasterKeyRetirement, error) {
	return abortMasterKeyRetirement(ctx, db, epoch, now, nil)
}

// AbortMasterKeyRetirementGuarded revalidates API-key authority inside the
// same Rhiza mutation as the abort transition.
func AbortMasterKeyRetirementGuarded(ctx context.Context, db *rhiza.DB, epoch int64, now time.Time, authorization MasterKeyRetirementAuthorization) (MasterKeyRetirement, error) {
	return abortMasterKeyRetirement(ctx, db, epoch, now, &authorization)
}

func abortMasterKeyRetirement(ctx context.Context, db *rhiza.DB, epoch int64, now time.Time, authorization *MasterKeyRetirementAuthorization) (MasterKeyRetirement, error) {
	if epoch <= 0 {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement epoch")
	}
	if err := validRetirementTime(now); err != nil {
		return MasterKeyRetirement{}, fmt.Errorf("abort time: %w", err)
	}
	if err := retirementReplayAuthorization(ctx, db, authorization, "delete", now); err != nil {
		return MasterKeyRetirement{}, err
	}
	if err := validateRetirementAuthorization(authorization, "delete"); err != nil {
		return MasterKeyRetirement{}, err
	}
	current, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if current.Epoch != epoch {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	if current.State == MasterKeyRetirementAborted {
		if err := retirementReplayAuthorization(ctx, db, authorization, "delete", now); err != nil {
			return MasterKeyRetirement{}, err
		}
		return current, nil
	}
	if current.State == MasterKeyRetirementReady {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	if now.Before(current.PreparedAt) {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	requestID := retirementRequestID("abort", epoch, current.OldKeyID, current.ReplacementKeyID, current.MembershipDigest, now.UnixMilli())
	sql := `UPDATE master_key_retirement_barrier SET state='aborted', aborted_at_unix_ms=? WHERE barrier_id=1 AND epoch=? AND state IN ('prepared','fenced')`
	args := []any{now.UnixMilli(), epoch}
	statements := make([]rhiza.SQLStatement, 0, 2)
	if authorization != nil {
		event, eventErr := retirementAuditStatement(*authorization, requestID, "master_key_retirement.aborted", "abort", epoch, now, `EXISTS (SELECT 1 FROM master_key_retirement_barrier WHERE barrier_id=1 AND epoch=? AND state IN ('prepared','fenced'))`, epoch)
		if eventErr != nil {
			return MasterKeyRetirement{}, eventErr
		}
		statements = append(statements, event)
	}
	sql, args = retirementGuardedSQLAt(sql, args, authorization, now)
	statements = append(statements, rhiza.SQLStatement{SQL: sql, Args: args})
	response, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if authorization != nil && !retirementMutationApplied(response, 2) {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	result, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if result.State != MasterKeyRetirementAborted {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementConflict
	}
	return result, nil
}

func LoadMasterKeyRetirement(ctx context.Context, db *rhiza.DB) (MasterKeyRetirement, error) {
	if db == nil {
		return MasterKeyRetirement{}, errors.New("master-key retirement database is required")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT epoch, old_key_id, replacement_key_id, membership_digest, state, prepared_at_unix_ms, fenced_at_unix_ms, ready_at_unix_ms, aborted_at_unix_ms FROM master_key_retirement_barrier WHERE barrier_id=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if len(result.Rows) == 0 {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementNotPrepared
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 9 {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement barrier row")
	}
	barrier, err := decodeRetirementBarrier(result.Rows[0])
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	epoch := barrier.Epoch
	members, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT node_id, attestation_state, attestation_sequence, boot_id, active_key_id, attested_at_unix_ms, old_references, non_active_references, legacy_references, tamper_references, oidc_references, dcr_references, upstream_references, passkey_enabled, passkey_references FROM master_key_retirement_members WHERE epoch=? ORDER BY node_id`, Args: []any{epoch}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	return assembleRetirementMembers(barrier, members.Rows)
}

// LoadMasterKeyRetirementGuarded reads the barrier and its captured members
// in one linearizable query gated by a fixed Secrets:read API-key predicate.
// AuthorizedAt is the operation timestamp used for key expiry.
func LoadMasterKeyRetirementGuarded(ctx context.Context, db *rhiza.DB, authorization MasterKeyRetirementAuthorization) (MasterKeyRetirement, error) {
	if db == nil {
		return MasterKeyRetirement{}, errors.New("master-key retirement database is required")
	}
	if err := validateRetirementAuthorization(&authorization, "read"); err != nil || validRetirementTime(authorization.AuthorizedAt) != nil {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement authorization")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT b.epoch, b.old_key_id, b.replacement_key_id, b.membership_digest, b.state, b.prepared_at_unix_ms, b.fenced_at_unix_ms, b.ready_at_unix_ms, b.aborted_at_unix_ms, m.node_id, m.attestation_state, m.attestation_sequence, m.boot_id, m.active_key_id, m.attested_at_unix_ms, m.old_references, m.non_active_references, m.legacy_references, m.tamper_references, m.oidc_references, m.dcr_references, m.upstream_references, m.passkey_enabled, m.passkey_references FROM master_key_retirement_barrier b LEFT JOIN master_key_retirement_members m ON m.epoch=b.epoch WHERE b.barrier_id=1 AND ` + retirementAuthorizationPredicate() + ` ORDER BY m.node_id`, Args: retirementAuthorizationArgs(authorization, authorization.AuthorizedAt), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	if len(result.Rows) == 0 {
		return MasterKeyRetirement{}, ErrMasterKeyRetirementNotPrepared
	}
	barrier, err := decodeRetirementBarrier(result.Rows[0][:9])
	if err != nil {
		return MasterKeyRetirement{}, err
	}
	members := make([][]any, 0, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) != 24 {
			return MasterKeyRetirement{}, errors.New("invalid master-key retirement guarded row")
		}
		if row[9] != nil {
			members = append(members, row[9:])
		}
	}
	return assembleRetirementMembers(barrier, members)
}

func decodeRetirementBarrier(row []any) (MasterKeyRetirement, error) {
	if len(row) != 9 {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement barrier row")
	}
	epoch, ok := row[0].(int64)
	if !ok {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement epoch")
	}
	barrier := MasterKeyRetirement{Epoch: epoch}
	if barrier.OldKeyID, ok = row[1].(string); !ok || !validRetirementKeyID(barrier.OldKeyID) {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement old key")
	}
	if barrier.ReplacementKeyID, ok = row[2].(string); !ok || !validRetirementKeyID(barrier.ReplacementKeyID) || barrier.ReplacementKeyID == barrier.OldKeyID {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement replacement key")
	}
	if barrier.MembershipDigest, ok = row[3].(string); !ok || !validRetirementDigest(barrier.MembershipDigest) {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement membership digest")
	}
	if barrier.State, ok = row[4].(string); !ok || !validRetirementState(barrier.State) {
		return MasterKeyRetirement{}, errors.New("invalid master-key retirement state")
	}
	var err error
	if barrier.PreparedAt, err = retirementTime(row[5], true); err != nil {
		return MasterKeyRetirement{}, err
	}
	if barrier.FencedAt, err = retirementTime(row[6], false); err != nil {
		return MasterKeyRetirement{}, err
	}
	if barrier.ReadyAt, err = retirementTime(row[7], false); err != nil {
		return MasterKeyRetirement{}, err
	}
	if barrier.AbortedAt, err = retirementTime(row[8], false); err != nil {
		return MasterKeyRetirement{}, err
	}
	return barrier, nil
}

func assembleRetirementMembers(barrier MasterKeyRetirement, members [][]any) (MasterKeyRetirement, error) {
	if !validRetirementMemberCount(len(members)) {
		return MasterKeyRetirement{}, fmt.Errorf("master-key retirement membership has %d rows, want exactly one or three", len(members))
	}
	barrier.Membership = make([]string, 0, len(members))
	barrier.Attestations = make([]MasterKeyRetirementAttestation, 0, len(members))
	seenMembers := make(map[string]struct{}, len(members))
	for _, member := range members {
		attestation, err := decodeRetirementMember(member)
		if err != nil {
			return MasterKeyRetirement{}, err
		}
		if _, exists := seenMembers[attestation.NodeID]; exists {
			return MasterKeyRetirement{}, errors.New("master-key retirement membership contains duplicate node IDs")
		}
		seenMembers[attestation.NodeID] = struct{}{}
		barrier.Membership = append(barrier.Membership, attestation.NodeID)
		if attestation.StatusOldState {
			barrier.Attestations = append(barrier.Attestations, attestation.MasterKeyRetirementAttestation)
		}
	}
	if retirementMembershipDigest(barrier.Membership) != barrier.MembershipDigest {
		return MasterKeyRetirement{}, errors.New("master-key retirement membership digest mismatch")
	}
	return barrier, nil
}

// retirementMemberDecode is kept private so malformed replicated rows fail
// closed at the storage boundary instead of being treated as safe evidence.
type retirementMemberDecode struct {
	MasterKeyRetirementAttestation
	StatusOldState bool
}

func decodeRetirementMember(row []any) (retirementMemberDecode, error) {
	if len(row) != 15 {
		return retirementMemberDecode{}, errors.New("invalid master-key retirement member row")
	}
	node, nodeOK := row[0].(string)
	state, stateOK := row[1].(string)
	sequence, sequenceOK := row[2].(int64)
	boot, bootOK := row[3].(string)
	active, activeOK := row[4].(string)
	if !nodeOK || !validRetirementID(node) || !stateOK || (state != "pending" && state != "attested") || !sequenceOK || sequence < 0 || !bootOK || !activeOK {
		return retirementMemberDecode{}, errors.New("invalid master-key retirement member identity")
	}
	attestation := retirementMemberDecode{MasterKeyRetirementAttestation: MasterKeyRetirementAttestation{NodeID: node}}
	if state == "pending" {
		if sequence != 0 || boot != "" || active != "" || row[5] != nil {
			return retirementMemberDecode{}, errors.New("invalid pending master-key retirement attestation")
		}
		for _, value := range row[6:] {
			count, ok := value.(int64)
			if !ok || count != 0 {
				return retirementMemberDecode{}, errors.New("invalid pending master-key retirement status")
			}
		}
		return attestation, nil
	}
	if sequence <= 0 || !validRetirementID(boot) || !validRetirementKeyID(active) {
		return retirementMemberDecode{}, errors.New("invalid attested master-key retirement identity")
	}
	attestation.BootID, attestation.ActiveKeyID = boot, active
	when, err := retirementTime(row[5], true)
	if err != nil {
		return retirementMemberDecode{}, err
	}
	attestation.AttestedAt = when
	values := make([]int64, 0, 9)
	for _, value := range row[6:] {
		count, ok := value.(int64)
		if !ok || count < 0 {
			return retirementMemberDecode{}, errors.New("invalid master-key retirement status count")
		}
		values = append(values, count)
	}
	passkeyEnabled := values[7]
	if passkeyEnabled != 0 && passkeyEnabled != 1 {
		return retirementMemberDecode{}, errors.New("invalid master-key retirement passkey state")
	}
	attestation.AttestationSequence = sequence
	attestation.Status = MasterKeyRetirementStatus{OldReferences: values[0], NonActiveReferences: values[1], LegacyReferences: values[2], TamperReferences: values[3], OIDCReferences: values[4], DCRReferences: values[5], UpstreamReferences: values[6], PasskeyEnabled: passkeyEnabled == 1, PasskeyReferences: values[8]}
	attestation.StatusOldState = true
	return attestation, nil
}

func readyAttestations(barrier MasterKeyRetirement, now time.Time) bool {
	if !validRetirementMemberCount(len(barrier.Membership)) || len(barrier.Attestations) != len(barrier.Membership) {
		return false
	}
	seen := make(map[string]struct{}, len(barrier.Attestations))
	for _, attestation := range barrier.Attestations {
		if _, exists := seen[attestation.BootID]; exists || attestation.BootID == "" || attestation.ActiveKeyID != barrier.ReplacementKeyID || attestation.AttestedAt.Before(barrier.FencedAt) || attestation.AttestedAt.After(now) || attestation.Status.OldReferences != 0 || attestation.Status.NonActiveReferences != 0 || attestation.Status.LegacyReferences != 0 || attestation.Status.TamperReferences != 0 || attestation.Status.OIDCReferences != 0 || attestation.Status.DCRReferences != 0 || attestation.Status.UpstreamReferences != 0 || attestation.Status.PasskeyReferences != 0 {
			return false
		}
		seen[attestation.BootID] = struct{}{}
	}
	return true
}

func validRetirementDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func normalizeMemberIDs(memberIDs, expected []string) ([]string, error) {
	if len(memberIDs) > 0 && len(expected) > 0 && !sameStrings(memberIDs, expected) {
		return nil, errors.New("MemberIDs and ExpectedNodeIDs differ")
	}
	if len(memberIDs) == 0 {
		memberIDs = expected
	}
	if !validRetirementMemberCount(len(memberIDs)) {
		return nil, errors.New("master-key retirement requires exactly one or three members")
	}
	copyIDs := append([]string(nil), memberIDs...)
	sort.Strings(copyIDs)
	for i, id := range copyIDs {
		if !validRetirementID(id) || (i > 0 && copyIDs[i-1] == id) {
			return nil, errors.New("master-key retirement membership must contain distinct valid node IDs")
		}
	}
	return copyIDs, nil
}

func validRetirementMemberCount(count int) bool {
	return count == 1 || count == masterKeyRetirementHAMemberCount
}

func samePreparation(current MasterKeyRetirement, req MasterKeyRetirementPrepareRequest, members []string, digest string) bool {
	return current.Epoch == req.Epoch && current.OldKeyID == req.OldKeyID && current.ReplacementKeyID == req.ReplacementKeyID && current.MembershipDigest == digest && sameStrings(current.Membership, members)
}

func attestationMatches(barrier MasterKeyRetirement, req MasterKeyRetirementAttestationRequest) bool {
	for _, attestation := range barrier.Attestations {
		if attestation.NodeID == req.NodeID {
			return sameAttestation(attestation, req)
		}
	}
	return false
}

func sameAttestation(attestation MasterKeyRetirementAttestation, req MasterKeyRetirementAttestationRequest) bool {
	return attestation.NodeID == req.NodeID && attestation.BootID == req.BootID && attestation.ActiveKeyID == req.ActiveKeyID && attestation.AttestationSequence == req.AttestationSequence && attestation.AttestedAt.Equal(req.AttestedAt.UTC().Truncate(time.Millisecond)) && attestation.Status == req.Status
}

func validateRetirementStatus(status MasterKeyRetirementStatus) error {
	if status.OldReferences < 0 || status.NonActiveReferences < 0 || status.LegacyReferences < 0 || status.TamperReferences < 0 || status.OIDCReferences < 0 || status.DCRReferences < 0 || status.UpstreamReferences < 0 || status.PasskeyReferences < 0 {
		return errors.New("master-key retirement status counts must be non-negative")
	}
	if !status.PasskeyEnabled && status.PasskeyReferences != 0 {
		return errors.New("passkey-disabled attestation must report zero passkey references")
	}
	if status.OldReferences != 0 || status.NonActiveReferences != 0 || status.LegacyReferences != 0 || status.TamperReferences != 0 || status.OIDCReferences != 0 || status.DCRReferences != 0 || status.UpstreamReferences != 0 || status.PasskeyReferences != 0 {
		return errors.New("master-key retirement attestation has non-zero references")
	}
	return nil
}

func validRetirementID(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '_' || ch == ':' || ch == '-') {
			return false
		}
	}
	return true
}

func validRetirementKeyID(value string) bool {
	if len(value) == 0 || len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

func validRetirementState(state string) bool {
	return state == MasterKeyRetirementPrepared || state == MasterKeyRetirementFenced || state == MasterKeyRetirementReady || state == MasterKeyRetirementAborted
}

func validRetirementTime(value time.Time) error {
	if value.IsZero() || value.UnixMilli() < 0 {
		return errors.New("must be a non-zero non-negative time")
	}
	return nil
}

func retirementTime(value any, required bool) (time.Time, error) {
	if value == nil {
		if required {
			return time.Time{}, errors.New("required timestamp is NULL")
		}
		return time.Time{}, nil
	}
	millis, ok := value.(int64)
	if !ok || millis < 0 {
		return time.Time{}, errors.New("invalid master-key retirement timestamp")
	}
	return time.UnixMilli(millis).UTC(), nil
}

func retirementMembershipDigest(members []string) string {
	input := strings.Join(members, "\x00")
	digest := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func retirementRequestID(operation string, values ...any) string {
	var input strings.Builder
	input.WriteString(operation)
	for _, value := range values {
		fmt.Fprintf(&input, "\x00%v", value)
	}
	digest := sha256.Sum256([]byte(input.String()))
	return "master-key-retirement/" + operation + "/" + base64.RawURLEncoding.EncodeToString(digest[:16])
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func boolInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func validateRetirementAuthorization(authorization *MasterKeyRetirementAuthorization, expectedRight string) error {
	if authorization == nil {
		return nil
	}
	if !validRetirementID(authorization.KeyName) || !validRetirementDigest(authorization.KeyDigest) || authorization.Group != "Secrets" || authorization.Right != expectedRight {
		return errors.New("invalid master-key retirement authorization")
	}
	return nil
}

func validRetirementAuthorizationGroup(group string) bool {
	switch group {
	case "Blacklist", "Clients", "Events", "Generic", "Groups", "Roles", "Secrets", "Sessions", "Scopes", "UserAttributes", "Users", "Pam", "AuthProviders", "ApiKeys":
		return true
	default:
		return false
	}
}

func validRetirementAuthorizationRight(right string) bool {
	return right == "read" || right == "create" || right == "update" || right == "delete"
}

func retirementAuthorizationPredicate() string {
	return `EXISTS (SELECT 1 FROM api_keys k JOIN api_key_access a ON a.key_name=k.name WHERE k.name=? AND k.secret_digest=? AND (k.expires_at_unix_ms IS NULL OR k.expires_at_unix_ms >= ?) AND a.group_name=? AND a.right_name=?)`
}

func retirementAuthorizationArgs(authorization MasterKeyRetirementAuthorization, operationAt time.Time) []any {
	return []any{authorization.KeyName, authorization.KeyDigest, operationAt.UnixMilli(), authorization.Group, authorization.Right}
}

func retirementGuardedSQLAt(sql string, args []any, authorization *MasterKeyRetirementAuthorization, operationAt time.Time) (string, []any) {
	if authorization == nil {
		return sql, args
	}
	return sql + " AND " + retirementAuthorizationPredicate(), append(args, retirementAuthorizationArgs(*authorization, operationAt)...)
}

func retirementGuardedStatementAt(authorization *MasterKeyRetirementAuthorization, statement rhiza.SQLStatement, operationAt time.Time) rhiza.SQLStatement {
	statement.SQL, statement.Args = retirementGuardedSQLAt(statement.SQL, statement.Args, authorization, operationAt)
	return statement
}

func retirementMutationApplied(response rhiza.ExecuteResponse, minimumRows int64) bool {
	// Rhiza's bounded receipt is the durable marker for a multi-statement
	// command. Requiring the audit plus transition effects prevents a guarded
	// no-op from being mistaken for success after an interposed transition.
	return minimumRows > 0 && response.RowsAffected >= minimumRows
}

func retirementAuditStatement(authorization MasterKeyRetirementAuthorization, requestID, eventType, action string, epoch int64, occurredAt time.Time, condition string, conditionArgs ...any) (rhiza.SQLStatement, error) {
	actorHash := audit.Pseudonym(authorization.KeyDigest, "actor", authorization.KeyName)
	targetHash := audit.Pseudonym(authorization.KeyDigest, "target", fmt.Sprintf("epoch:%d", epoch))
	event := audit.NewEvent(requestID, eventType, action, "api_key", actorHash, targetHash, occurredAt)
	condition += " AND " + retirementAuthorizationPredicate()
	conditionArgs = append(conditionArgs, retirementAuthorizationArgs(authorization, occurredAt)...)
	return event.Statement(condition, conditionArgs...)
}

func retirementReplayAuthorization(ctx context.Context, db *rhiza.DB, authorization *MasterKeyRetirementAuthorization, expectedRight string, operationAt time.Time) error {
	if authorization == nil {
		return nil
	}
	if db == nil {
		return errors.New("master-key retirement database is required")
	}
	if err := validateRetirementAuthorization(authorization, expectedRight); err != nil {
		return err
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 WHERE ` + retirementAuthorizationPredicate(), Args: retirementAuthorizationArgs(*authorization, operationAt), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) > 1 || len(result.Rows) == 1 && (len(result.Rows[0]) != 1 || result.Rows[0][0] != int64(1)) {
		return errors.New("invalid master-key retirement authorization result")
	}
	if len(result.Rows) == 0 {
		return ErrMasterKeyRetirementConflict
	}
	return nil
}
