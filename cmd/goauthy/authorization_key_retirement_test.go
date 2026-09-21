package main

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

func TestSaaSAuthorizationProofEnvelopeBlocksRetirementUntilRewrapped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := retirementCmdDB(t, true)
	oldKeys := retirementCmdKeyring(t, "key-a")
	stateDigest := upstreamprovider.DigestSHA256("state-digest")
	purpose := "saas/proof/v1/" + stateDigest
	envelope, err := oldKeys.SealEnvelope(purpose, []byte("verifier"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "seed-saas-authorization-proof",
		SQL: `INSERT INTO saas_authorization_requests
		(state_digest,verifier_digest,session_digest,provider_digest,owner_subject,collection_id,connection_id,provider_id,generation,created_at_unix_ms,expires_at_unix_ms,verifier_envelope)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		Args: []any{stateDigest, upstreamprovider.DigestSHA256("verifier"), upstreamprovider.DigestSHA256("session"), upstreamprovider.DigestSHA256("provider"), "owner", "collection", "connection", "provider", "generation", int64(100), int64(200), envelope},
	})
	if err != nil {
		t.Fatal(err)
	}

	newKeys := retirementCmdKeyring(t, "key-b")
	now := time.UnixMilli(1_800_000_000_000).UTC()
	status, err := inspectMasterKeyStatus(ctx, db, newKeys, "http://localhost:8080", nil, now)
	if err != nil || status.Safe || status.SaaSAuthorizations.Total != 1 || status.SaaSAuthorizations.NonActive != 1 {
		t.Fatalf("old authorization status=%#v err=%v", status, err)
	}
	retirement, err := inspectMasterKeyRetirement(ctx, db, newKeys, "http://localhost:8080", nil, "key-a", now)
	if err != nil || retirement.OldReferences != 1 || retirement.NonActiveReferences != 0 {
		t.Fatalf("old authorization retirement=%#v err=%v", retirement, err)
	}

	result, err := saas.RewrapAuthorizationEnvelopeBatch(ctx, db, newKeys, "")
	if err != nil || !result.Done || result.Rewrapped != 1 {
		t.Fatalf("authorization rewrap=%#v err=%v", result, err)
	}
	status, err = inspectMasterKeyStatus(ctx, db, newKeys, "http://localhost:8080", nil, now)
	if err != nil || !status.Safe || status.SaaSAuthorizations.NonActive != 0 {
		t.Fatalf("rewrapped authorization status=%#v err=%v", status, err)
	}
	retirement, err = inspectMasterKeyRetirement(ctx, db, newKeys, "http://localhost:8080", nil, "key-a", now)
	if err != nil || retirement.OldReferences != 0 || retirement.NonActiveReferences != 0 || retirement.TamperReferences != 0 {
		t.Fatalf("rewrapped authorization retirement=%#v err=%v", retirement, err)
	}
}
