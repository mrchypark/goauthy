package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestInspectMasterKeyReferencesCountsLiveAuthenticatedEnvelopes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	issuer := "https://id.example.com"
	now := time.Unix(1_900_000_000, 123_000_000).UTC()
	old, active := fixedKeyring("master-a"), fixedKeyring("master-b")
	if _, err := EnsureSigningKey(ctx, db, old, issuer, now); err != nil {
		t.Fatal(err)
	}

	insertStatusDCR(t, ctx, db, old, "old", now.Add(time.Hour))
	insertStatusDCR(t, ctx, db, active, "active", now.Add(time.Hour))
	insertStatusDCR(t, ctx, db, old, "expired", now)
	insertStatusTransaction(t, ctx, db, old, "old", now.Add(time.Hour))
	insertStatusTransaction(t, ctx, db, active, "active", now.Add(time.Hour))
	insertStatusTransaction(t, ctx, db, old, "expired", now)

	status, err := InspectMasterKeyReferences(ctx, db, active, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	if status.Safe || status.ActiveMasterKeyID != "master-b" || !status.CheckedAt.Equal(now) {
		t.Fatalf("status=%+v", status)
	}
	if got := status.SigningKeys.ByKeyID["master-a"]; got != 1 || status.SigningKeys.Total != 1 {
		t.Fatalf("signing=%+v", status.SigningKeys)
	}
	if got := status.DCRIdempotency.ByKeyID["master-a"]; got != 1 || status.DCRIdempotency.ByKeyID["master-b"] != 1 || status.DCRIdempotency.Total != 2 {
		t.Fatalf("DCR=%+v", status.DCRIdempotency)
	}
	if got := status.Upstream.ByKeyID["master-a"]; got != 1 || status.Upstream.ByKeyID["master-b"] != 1 || status.Upstream.Total != 2 {
		t.Fatalf("upstream=%+v", status.Upstream)
	}
}

func TestInspectMasterKeyReferencesSafeOnlyForActiveKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	issuer := "https://id.example.com"
	now := time.Unix(1_900_000_000, 0).UTC()
	active := fixedKeyring("master-b")
	if _, err := EnsureSigningKey(ctx, db, active, issuer, now); err != nil {
		t.Fatal(err)
	}
	insertStatusDCR(t, ctx, db, active, "active", now.Add(time.Hour))
	insertStatusTransaction(t, ctx, db, active, "active", now.Add(time.Hour))

	status, err := InspectMasterKeyReferences(ctx, db, active, issuer, now)
	if err != nil || !status.Safe {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestInspectMasterKeyReferencesScansBoundedPages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	issuer := "https://id.example.com"
	now := time.Unix(1_900_000_000, 0).UTC()
	active := fixedKeyring("master-b")
	for i := 0; i < masterKeyStatusScanLimit+1; i++ {
		insertStatusDCR(t, ctx, db, active, fmt.Sprintf("page-%03d", i), now.Add(time.Hour))
	}

	status, err := InspectMasterKeyReferences(ctx, db, active, issuer, now)
	if err != nil || !status.Safe || status.DCRIdempotency.Total != int64(masterKeyStatusScanLimit+1) || status.DCRIdempotency.ByKeyID["master-b"] != int64(masterKeyStatusScanLimit+1) {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestInspectMasterKeyReferencesFailsClosedForTampering(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	issuer := "https://id.example.com"
	now := time.Unix(1_900_000_000, 0).UTC()
	active := fixedKeyring("master-b")
	insertStatusDCR(t, ctx, db, active, "tampered", now.Add(time.Hour))
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "key-status-tamper", SQL: `UPDATE dcr_registration_idempotency SET response_envelope='not-base64' WHERE client_id='status-tampered'`}); err != nil {
		t.Fatal(err)
	}

	status, err := InspectMasterKeyReferences(ctx, db, active, issuer, now)
	if !errors.Is(err, ErrUnsafeMasterKeyStatus) || status.Safe {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestInspectMasterKeyReferencesFailsClosedForAuthenticatedTamperingAndUnknownKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	issuer := "https://id.example.com"
	now := time.Unix(1_900_000_000, 0).UTC()

	t.Run("authenticated tampering", func(t *testing.T) {
		t.Parallel()
		db := testDB(t)
		active := fixedKeyring("master-b")
		insertStatusDCR(t, ctx, db, active, "authenticated-tamper", now.Add(time.Hour))
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT response_envelope FROM dcr_registration_idempotency WHERE client_id='status-authenticated-tamper'`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(result.Rows) != 1 {
			t.Fatalf("row=%v err=%v", result.Rows, err)
		}
		text := result.Rows[0][0].(string)
		envelope, err := base64.RawURLEncoding.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		envelope[len(envelope)-1] ^= 1
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "key-status-authenticated-tamper", SQL: `UPDATE dcr_registration_idempotency SET response_envelope=? WHERE client_id='status-authenticated-tamper'`, Args: []any{base64.RawURLEncoding.EncodeToString(envelope)}}); err != nil {
			t.Fatal(err)
		}
		status, err := InspectMasterKeyReferences(ctx, db, active, issuer, now)
		if !errors.Is(err, ErrUnsafeMasterKeyStatus) || status.Safe {
			t.Fatalf("status=%+v err=%v", status, err)
		}
	})

	t.Run("unknown key", func(t *testing.T) {
		t.Parallel()
		db := testDB(t)
		old := fixedKeyring("master-a")
		knownOnly := fixedKeyring("master-b")
		delete(knownOnly.keys, "master-a")
		insertStatusDCR(t, ctx, db, old, "unknown-key", now.Add(time.Hour))
		status, err := InspectMasterKeyReferences(ctx, db, knownOnly, issuer, now)
		if !errors.Is(err, ErrUnsafeMasterKeyStatus) || status.Safe {
			t.Fatalf("status=%+v err=%v", status, err)
		}
	})
}

func insertStatusDCR(t *testing.T, ctx context.Context, db *rhiza.DB, keyring *Keyring, label string, expiresAt time.Time) {
	t.Helper()
	envelope, err := keyring.SealEnvelope("dcr-registration-response", []byte(`{"status":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "key-status-dcr-" + label, SQL: `INSERT INTO dcr_registration_idempotency(principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{keyStatusDigest("principal/" + label), keyStatusDigest("key/" + label), keyStatusDigest("request/" + label), "status-" + label, base64.RawURLEncoding.EncodeToString(envelope), expiresAt.UnixMilli(), expiresAt.Add(-time.Hour).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
}

func insertStatusTransaction(t *testing.T, ctx context.Context, db *rhiza.DB, keyring *Keyring, label string, expiresAt time.Time) {
	t.Helper()
	envelope, err := keyring.SealEnvelope("upstream/transaction", []byte(`{"status":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "key-status-upstream-" + label, SQL: `INSERT INTO upstream_provider_transactions(state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'login',?,?)`, Args: []any{keyStatusDigest("state/" + label), keyStatusDigest("browser/" + label), "provider", base64.RawURLEncoding.EncodeToString(envelope), "https://issuer.example.test", "", "client", `["openid"]`, "https://goauthy.example.test/callback", expiresAt.UnixMilli(), expiresAt.Add(-time.Hour).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
}

func keyStatusDigest(label string) string {
	sum := sha256.Sum256([]byte(label))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
