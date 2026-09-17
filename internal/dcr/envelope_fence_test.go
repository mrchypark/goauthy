package dcr

import (
	"context"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestResponseEnvelopeWritersRespectRetirementFence(t *testing.T) {
	ctx, _, db := testStore(t)
	old, replacement := rewrapKeyrings(t)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{
		Epoch: 1, OldKeyID: "master-old", ReplacementKeyID: "master-new",
		MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	request := validRequest("fenced-create", TokenEndpointAuthNone)
	digest, err := effectiveCreateDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	build := func(registration Registration) ([]byte, error) {
		return registrationResponseBody("https://id.example.test", registration, true)
	}
	oldStore := NewStore(db, Config{Keyring: old, Now: func() time.Time { return now.Add(2 * time.Second) }})
	if _, err := oldStore.CreateIdempotent(ctx, request, "fenced-create-key", testGlobalToken, digest, build); err == nil {
		t.Fatal("fenced old idempotent writer succeeded")
	}

	anonymousRequest := validRequest("fenced-anonymous", TokenEndpointAuthNone)
	anonymousDigest, err := effectiveCreateDigest(anonymousRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldStore.CreateAnonymousIdempotent(ctx, anonymousRequest, "fenced-anonymous-key", netip.MustParseAddr("192.0.2.50"), anonymousDigest, time.Minute, build); err == nil {
		t.Fatal("fenced old anonymous writer succeeded")
	}

	newEnvelope, err := replacement.SealEnvelope(idempotencyPurpose, []byte(`{"before":"old-writer"}`))
	if err != nil {
		t.Fatal(err)
	}
	newEnvelopeText := base64.RawURLEncoding.EncodeToString(newEnvelope)
	oldEnvelope, err := old.SealEnvelope(idempotencyPurpose, []byte(`{"before":"replacement"}`))
	if err != nil {
		t.Fatal(err)
	}
	oldEnvelopeText := base64.RawURLEncoding.EncodeToString(oldEnvelope)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "dcr-fenced-rewrap-seed",
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO dcr_registration_idempotency (principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{digestString("fenced-rewrap-old-writer-principal"), digestString("fenced-rewrap-old-writer-key"), digestString("fenced-rewrap-old-writer-request"), "fenced-rewrap-old-writer", newEnvelopeText, now.Add(time.Hour).UnixMilli(), now.UnixMilli()}},
			{SQL: `INSERT INTO dcr_registration_idempotency (principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{digestString("fenced-rewrap-replacement-principal"), digestString("fenced-rewrap-replacement-key"), digestString("fenced-rewrap-replacement-request"), "fenced-rewrap-replacement", oldEnvelopeText, now.Add(time.Hour).UnixMilli(), now.UnixMilli()}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := oldStore.RewrapIdempotencyBatch(ctx, ""); err == nil {
		t.Fatal("fenced old rewrap writer succeeded")
	}
	if got := queryFencedEnvelope(t, ctx, db, "fenced-rewrap-old-writer"); got != newEnvelopeText {
		t.Fatalf("fenced rewrap changed envelope: got %q want %q", got, newEnvelopeText)
	}
	if got := queryFencedCount(t, ctx, db, `SELECT COUNT(*) FROM dynamic_oauth_clients`); got != 0 {
		t.Fatalf("fenced create writers committed %d clients", got)
	}

	replacementStore := NewStore(db, Config{Keyring: replacement, Now: func() time.Time { return now.Add(2 * time.Second) }})
	if _, err := replacementStore.CreateIdempotent(ctx, request, "fenced-create-key", testGlobalToken, digest, build); err != nil {
		t.Fatalf("replacement idempotent writer rejected: %v", err)
	}
	if _, err := replacementStore.CreateAnonymousIdempotent(ctx, anonymousRequest, "fenced-anonymous-key", netip.MustParseAddr("192.0.2.50"), anonymousDigest, time.Minute, build); err != nil {
		t.Fatalf("replacement anonymous writer rejected: %v", err)
	}
	if _, updated, err := replacementStore.RewrapIdempotencyBatch(ctx, ""); err != nil || updated != 1 {
		t.Fatalf("replacement rewrap updated=%d err=%v", updated, err)
	}
	if got := queryFencedCount(t, ctx, db, `SELECT COUNT(*) FROM dynamic_oauth_clients`); got != 2 {
		t.Fatalf("replacement create writers committed %d clients", got)
	}
	if got := queryFencedEnvelope(t, ctx, db, "fenced-rewrap-replacement"); got == oldEnvelopeText {
		t.Fatal("replacement rewrap did not replace envelope")
	}
}

func queryFencedEnvelope(t *testing.T, ctx context.Context, db *rhiza.DB, clientID string) string {
	t.Helper()
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT response_envelope FROM dcr_registration_idempotency WHERE client_id=?`, Args: []any{clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("fenced envelope rows=%#v err=%v", result.Rows, err)
	}
	return result.Rows[0][0].(string)
}

func queryFencedCount(t *testing.T, ctx context.Context, db *rhiza.DB, sql string) int64 {
	t.Helper()
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: sql, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("count rows=%#v err=%v", result.Rows, err)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("count value=%#v", result.Rows[0][0])
	}
	return count
}
