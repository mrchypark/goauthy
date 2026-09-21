package main

import (
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
)

func TestAggregateMasterKeyStatusDisabledPasskeysAreExplicitZeroFamily(t *testing.T) {
	t.Parallel()
	oidcStatus := oidc.MasterKeyReferenceStatus{
		ActiveMasterKeyID: "master-b",
		Safe:              true,
		SigningKeys:       oidc.MasterKeyReferenceFamily{ByKeyID: map[string]int64{"master-b": 2}, Total: 2},
	}
	passkeyStatus := passkey.EnvelopeReferenceStatus{
		ActiveMasterKeyID: "master-b",
		Credentials: passkey.EnvelopeReferenceFamily{
			ByKeyID: map[string]int64{"master-a": 1}, Legacy: 1, Total: 2,
		},
		Safe: true,
	}
	status, err := aggregateMasterKeyStatus("master-b", time.Unix(1_900_000_000, 0).UTC(), false, oidcStatus, nil, passkeyStatus, nil)
	if err != nil || !status.Safe || status.PasskeyEnabled {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if status.PasskeyCredentials != (masterKeyStatusFamily{}) || status.PasskeyCeremonies != (masterKeyStatusFamily{}) || status.PasskeyMFACeremonies != (masterKeyStatusFamily{}) {
		t.Fatalf("disabled passkey families=%+v/%+v/%+v want zero", status.PasskeyCredentials, status.PasskeyCeremonies, status.PasskeyMFACeremonies)
	}
}

func TestAggregateMasterKeyStatusEnabledOldAndLegacyAreUnsafe(t *testing.T) {
	t.Parallel()
	oidcStatus := oidc.MasterKeyReferenceStatus{ActiveMasterKeyID: "master-b", Safe: true}
	passkeyStatus := passkey.EnvelopeReferenceStatus{
		ActiveMasterKeyID: "master-b",
		Credentials: passkey.EnvelopeReferenceFamily{
			ByKeyID: map[string]int64{"master-b": 3, "master-a": 2}, Legacy: 1, Total: 6,
		},
		Safe: false,
	}
	status, err := aggregateMasterKeyStatus("master-b", time.Unix(1_900_000_000, 0).UTC(), true, oidcStatus, nil, passkeyStatus, nil)
	if err != nil || status.Safe || status.ScanError {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if got := status.PasskeyCredentials; got.Total != 6 || got.NonActive != 2 || got.Legacy != 1 {
		t.Fatalf("passkey summary=%+v", got)
	}
}

func TestAggregateMasterKeyStatusTamperErrorsFailClosedAndJoin(t *testing.T) {
	t.Parallel()
	oidcErr := oidc.ErrUnsafeMasterKeyStatus
	passkeyErr := passkey.ErrUnsafeEnvelopeReferences
	status, err := aggregateMasterKeyStatus(
		"master-b", time.Unix(1_900_000_000, 0).UTC(), true,
		oidc.MasterKeyReferenceStatus{ActiveMasterKeyID: "master-b", Safe: false}, oidcErr,
		passkey.EnvelopeReferenceStatus{ActiveMasterKeyID: "master-b", Safe: false}, passkeyErr,
	)
	if !errors.Is(err, oidcErr) || !errors.Is(err, passkeyErr) || !status.ScanError || status.Safe {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestAggregateMasterKeyStatusRejectsInspectorActiveIDMismatch(t *testing.T) {
	t.Parallel()
	status, err := aggregateMasterKeyStatus(
		"master-b", time.Unix(1_900_000_000, 0).UTC(), true,
		oidc.MasterKeyReferenceStatus{ActiveMasterKeyID: "master-a", Safe: true}, nil,
		passkey.EnvelopeReferenceStatus{ActiveMasterKeyID: "master-b", Safe: true}, nil,
	)
	if err != nil || !status.ScanError || status.Safe {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestAggregateMasterKeyStatusIncludesLoginRevoke(t *testing.T) {
	t.Parallel()
	status, err := aggregateMasterKeyStatus(
		"master-b", time.Unix(1_900_000_000, 0).UTC(), false,
		oidc.MasterKeyReferenceStatus{
			ActiveMasterKeyID: "master-b",
			Safe:              false,
			LoginRevoke: oidc.MasterKeyReferenceFamily{
				ByKeyID: map[string]int64{"master-a": 2, "master-b": 1}, Total: 3,
			},
		}, nil, passkey.EnvelopeReferenceStatus{}, nil,
	)
	if err != nil || status.Safe || status.LoginRevoke.Total != 3 || status.LoginRevoke.NonActive != 2 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}
