package oidc

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCleanupRetiredSigningKeysSkipsNoopMutation(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	cutoff := time.Unix(1_800_000_000, 0).UTC()
	if err := CleanupRetiredSigningKeys(context.Background(), db, cutoff); err != nil {
		t.Fatal(err)
	}
	status, err := db.RequestStatus(context.Background(), rhiza.RequestStatusRequest{
		Kind: "sql", RequestID: "oidc-key-cleanup/" + fmt.Sprint(cutoff.UnixMilli()),
	})
	if err != nil || status.State != "unknown_or_expired" {
		t.Fatalf("cleanup mutation status=%#v err=%v", status, err)
	}
}

func TestActivationRequestIDBindsMutationInputs(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 123_000_000).UTC()
	retireAfter := now.Add(MinimumSigningKeyRetirement)
	base := activationRequestID("active-1", "pending-1", retireAfter, now)
	if got := activationRequestID("active-1", "pending-1", retireAfter, now); got != base {
		t.Fatalf("same activation inputs generated different request IDs: %q != %q", got, base)
	}
	for _, changed := range []string{
		activationRequestID("active-2", "pending-1", retireAfter, now),
		activationRequestID("active-1", "pending-2", retireAfter, now),
		activationRequestID("active-1", "pending-1", retireAfter.Add(time.Millisecond), now),
		activationRequestID("active-1", "pending-1", retireAfter, now.Add(time.Millisecond)),
	} {
		if changed == base {
			t.Fatal("different activation mutation inputs reused a request ID")
		}
	}
	if len(base) > 128 {
		t.Fatalf("request ID length=%d exceeds Rhiza limit", len(base))
	}
}

func TestSigningKeyPrepublicationPreventsCachedJWKSBreakage(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	old, err := EnsureSigningKey(context.Background(), db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := LoadJWKSKeys(context.Background(), db, now)
	if err != nil || len(cached) != 1 {
		t.Fatalf("cached JWKS=%#v err=%v", cached, err)
	}
	prepared, err := PrepareSigningKey(context.Background(), db, keyring, issuer, now)
	if err != nil || !prepared.Prepared {
		t.Fatalf("prepare=%#v err=%v", prepared, err)
	}
	if keys, err := LoadJWKSKeys(context.Background(), db, now); err != nil || len(keys) != 2 || keys[0].KeyID != old.PublicJWK.KeyID || keys[1].KeyID != prepared.PendingKID {
		t.Fatalf("prepublished JWKS=%#v err=%v", keys, err)
	}
	retireAfter := prepared.ActivatesAfter.Add(MinimumSigningKeyRetirement)
	if _, err := ActivatePreparedSigningKey(context.Background(), db, keyring, issuer, old.PublicJWK.KeyID, prepared.PendingKID, retireAfter, prepared.ActivatesAfter.Add(-time.Millisecond)); err == nil {
		t.Fatal("activated before cached JWKS lifetime elapsed")
	}
	rotation, err := ActivatePreparedSigningKey(context.Background(), db, keyring, issuer, old.PublicJWK.KeyID, prepared.PendingKID, retireAfter, prepared.ActivatesAfter)
	if err != nil || !rotation.Activated {
		t.Fatalf("activate=%#v err=%v", rotation, err)
	}
	if prepared.ActivatesAfter.Sub(now) != JWKSCacheMaxAge {
		t.Fatal("activation did not wait for JWKS cache lifetime")
	}
	claims := IDTokenClaims{Issuer: issuer, Subject: "user", Audience: []string{"client"}, IssuedAt: prepared.ActivatesAfter, ExpiresAt: prepared.ActivatesAfter.Add(MaxIDTokenLifetime)}
	compact, err := SignIDToken(rotation.Active, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIDToken(compact, jose.JSONWebKeySet{Keys: cached}, issuer, "client", prepared.ActivatesAfter); err == nil {
		t.Fatal("expired cached old JWKS accepted new kid")
	}
	keys, err := LoadJWKSKeys(context.Background(), db, prepared.ActivatesAfter)
	if err != nil || len(keys) != 2 {
		t.Fatalf("post-activation JWKS=%#v err=%v", keys, err)
	}
	if _, err := VerifyIDToken(compact, jose.JSONWebKeySet{Keys: keys}, issuer, "client", prepared.ActivatesAfter); err != nil {
		t.Fatal(err)
	}
	if err := CleanupRetiredSigningKeys(context.Background(), db, retireAfter.Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	assertSigningKeyStates(t, db, 1, 0, 1)
	if err := CleanupRetiredSigningKeys(context.Background(), db, retireAfter); err != nil {
		t.Fatal(err)
	}
	assertSigningKeyStates(t, db, 1, 0, 1)
	keys, err = LoadJWKSKeys(context.Background(), db, retireAfter)
	if err != nil || len(keys) != 2 {
		t.Fatalf("retirement-boundary JWKS=%#v err=%v", keys, err)
	}
	oldHint, err := SignIDToken(old, IDTokenClaims{Issuer: issuer, Subject: "user", Audience: []string{"client"}, IssuedAt: prepared.ActivatesAfter, ExpiresAt: prepared.ActivatesAfter.Add(MaxIDTokenLifetime)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLogoutIDToken(oldHint, jose.JSONWebKeySet{Keys: keys}, issuer, "client", prepared.ActivatesAfter.Add(MaxIDTokenLifetime+logoutIDTokenClockLeeway)); err != nil {
		t.Fatalf("retired key did not verify logout hint at leeway boundary: %v", err)
	}
	if err := CleanupRetiredSigningKeys(context.Background(), db, retireAfter.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	assertSigningKeyStates(t, db, 1, 0, 0)
}

func TestRetiringKeyCoversMaximumSignedAccessTokenLifetime(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	old, err := EnsureSigningKey(context.Background(), db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareSigningKey(context.Background(), db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	activateAt := prepared.ActivatesAfter
	retireAfter := activateAt.Add(MinimumSigningKeyRetirement)
	if _, err := ActivatePreparedSigningKey(context.Background(), db, keyring, issuer, old.PublicJWK.KeyID, prepared.PendingKID, retireAfter, activateAt); err != nil {
		t.Fatal(err)
	}
	claims := AccessTokenClaims{Issuer: issuer, Subject: "user", Audience: []string{"client"}, IssuedAt: activateAt, NotBefore: activateAt, ExpiresAt: activateAt.Add(MaxAccessTokenLifetime), ID: "jti", AuthorizedParty: "client", Scope: []string{"openid"}, Type: "Bearer"}
	compact, err := SignAccessToken(old, claims)
	if err != nil {
		t.Fatal(err)
	}
	beforeExpiry := claims.ExpiresAt.Add(-time.Second)
	keys, err := LoadJWKSKeys(context.Background(), db, beforeExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccessToken(compact, jose.JSONWebKeySet{Keys: keys}, issuer, beforeExpiry); err != nil {
		t.Fatalf("old key missing before max access token expiry: %v", err)
	}
	if err := CleanupRetiredSigningKeys(context.Background(), db, retireAfter.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	keys, err = LoadJWKSKeys(context.Background(), db, retireAfter.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccessToken(compact, jose.JSONWebKeySet{Keys: keys}, issuer, claims.ExpiresAt); err == nil {
		t.Fatal("expired token or cleaned key was accepted")
	}
}

func TestSigningKeyRotationRejectsUnsafeRetentionAndConcurrentPrepareConverges(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0)
	old, err := EnsureSigningKey(context.Background(), db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 4
	results := make([]KeyPreparationResult, callers)
	errs := make([]error, callers)
	var wait sync.WaitGroup
	for i := range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[i], errs[i] = PrepareSigningKey(context.Background(), db, keyring, issuer, now)
		}()
	}
	wait.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("prepare %d: %v", i, err)
		}
		if results[i].PendingKID != results[0].PendingKID {
			t.Fatal("concurrent preparation did not converge")
		}
	}
	if _, err := ActivatePreparedSigningKey(context.Background(), db, keyring, issuer, old.PublicJWK.KeyID, results[0].PendingKID, results[0].ActivatesAfter.Add(MinimumSigningKeyRetirement-time.Millisecond), results[0].ActivatesAfter); err == nil {
		t.Fatal("unsafe retiring period accepted")
	}
	assertSigningKeyStates(t, db, 1, 1, 0)
}

func TestConcurrentSigningKeyActivationWithSameInputsConverges(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	old, err := EnsureSigningKey(context.Background(), db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareSigningKey(context.Background(), db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	activateAt := prepared.ActivatesAfter
	retireAfter := activateAt.Add(MinimumSigningKeyRetirement)
	const callers = 4
	results := make([]RotationResult, callers)
	errs := make([]error, callers)
	var wait sync.WaitGroup
	for i := range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[i], errs[i] = ActivatePreparedSigningKey(context.Background(), db, keyring, issuer, old.PublicJWK.KeyID, prepared.PendingKID, retireAfter, activateAt)
		}()
	}
	wait.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("activation %d: %v", i, err)
		}
		if results[i].Active.PublicJWK.KeyID != prepared.PendingKID {
			t.Fatalf("activation %d key=%q, want %q", i, results[i].Active.PublicJWK.KeyID, prepared.PendingKID)
		}
	}
	assertSigningKeyStates(t, db, 1, 0, 1)
}

func TestSigningKeyActivationRejectsTamperedPendingEnvelope(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0)
	old, err := EnsureSigningKey(context.Background(), db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareSigningKey(context.Background(), db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "tamper-pending-envelope", SQL: `UPDATE oidc_signing_keys SET private_envelope = 'bad' WHERE kid = ?`, Args: []any{prepared.PendingKID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivatePreparedSigningKey(context.Background(), db, keyring, issuer, old.PublicJWK.KeyID, prepared.PendingKID, prepared.ActivatesAfter.Add(MinimumSigningKeyRetirement), prepared.ActivatesAfter); err == nil {
		t.Fatal("tampered pending key was activated")
	}
	assertSigningKeyStates(t, db, 1, 1, 0)
}

func assertSigningKeyStates(t *testing.T, db *rhiza.DB, active, pending, retiring int64) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oidc_signing_keys WHERE state='active'), (SELECT COUNT(*) FROM oidc_signing_keys WHERE state='pending'), (SELECT COUNT(*) FROM oidc_signing_keys WHERE state='retiring')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 3 {
		t.Fatalf("states=%#v err=%v", result.Rows, err)
	}
	a, aOK := result.Rows[0][0].(int64)
	p, pOK := result.Rows[0][1].(int64)
	r, rOK := result.Rows[0][2].(int64)
	if !aOK || !pOK || !rOK || a != active || p != pending || r != retiring {
		t.Fatalf("states=(%d,%d,%d), want=(%d,%d,%d)", a, p, r, active, pending, retiring)
	}
}
