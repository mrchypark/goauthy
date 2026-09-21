package saas

import (
	"bytes"
	"context"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDecodeCredentialRowRejectsWrongTypesAndAcceptsBlob(t *testing.T) {
	t.Parallel()
	binding := credentialBinding{"owner", "collection", "connection", "provider", "generation", 1}
	row := []any{"connection", "owner", "collection", "provider", "generation", int64(1), []byte("envelope")}
	got, envelope, id, err := decodeCredentialRow(row)
	if err != nil || got != binding || id != "connection" || !bytes.Equal(envelope, []byte("envelope")) {
		t.Fatalf("decode = %#v, %q, %q, %v", got, envelope, id, err)
	}
	row[6] = "text-envelope"
	if _, _, _, err := decodeCredentialRow(row); err == nil {
		t.Fatal("string envelope accepted for BLOB")
	}
}

func TestCredentialRewrapSQLCarriesFullCASBinding(t *testing.T) {
	t.Parallel()
	rows := []credentialRewrapCandidate{{binding: credentialBinding{Owner: "owner", CollectionID: "collection", ConnectionID: "connection", ProviderID: "provider", Generation: "generation", TokenVersion: 2}, connectionID: "connection", state: "refreshing", claim: "claim", oldEnvelope: []byte("old"), newEnvelope: []byte("new")}}
	sql, args := credentialRewrapSQL(rows)
	for _, want := range []string{"owner_subject", "collection_id", "provider_id", "generation", "token_version", "refresh_claim", "credential=?"} {
		if !contains(sql, want) {
			t.Errorf("SQL missing %q: %s", want, sql)
		}
	}
	if len(args) == 0 {
		t.Fatal("empty CAS args")
	}
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

func TestCredentialEnvelopeReferencesAndRewrap(t *testing.T) {
	t.Parallel()
	ctx, _, db, _ := credentialStoreFixture(t)
	oldKeys := credentialKeys(t, "old", "old", "master")
	rotated := credentialKeys(t, "master", "old", "master")
	rows := []struct {
		binding credentialBinding
		state   string
		claim   any
	}{
		{credentialBinding{"owner", "collection", "conn-old", "github", "generation", 1}, "ready", nil},
		{credentialBinding{"orphan", "missing-collection", "conn-revoked", "github", "generation", 1}, "revoked", nil},
		{credentialBinding{"owner", "collection", "conn-refreshing", "github", "generation", 2}, "refreshing", "claim"},
	}
	for _, row := range rows {
		envelope, err := sealCredential(oldKeys, row.binding, credential{AccessToken: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		insertCredentialEnvelope(t, ctx, db, row.binding, row.state, envelope, row.claim)
	}
	family, err := InspectCredentialEnvelopeReferences(ctx, db, oldKeys)
	if err != nil || family.Total != 3 || family.ByKeyID["old"] != 3 {
		t.Fatalf("references=%+v err=%v", family, err)
	}
	result, err := RewrapCredentialEnvelopeBatch(ctx, db, rotated, "")
	if err != nil || !result.Done || result.Rewrapped != 3 {
		t.Fatalf("rewrap=%+v err=%v", result, err)
	}
	newOnly := credentialKeys(t, "master", "master")
	for _, row := range rows {
		envelope := readCredentialEnvelope(t, ctx, db, row.binding.ConnectionID)
		if value, err := openCredential(newOnly, row.binding, envelope); err != nil || value.AccessToken != "secret" {
			t.Fatalf("new-key decrypt %s: %v", row.binding.ConnectionID, err)
		}
		stored, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state,refresh_claim FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{row.binding.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(stored.Rows) != 1 || stored.Rows[0][0] != row.state || stored.Rows[0][1] != row.claim {
			t.Fatalf("rewrap changed lifecycle: rows=%#v err=%v", stored.Rows, err)
		}
	}
}

func TestCredentialEnvelopeTamperedBatchHasNoPartialWrite(t *testing.T) {
	t.Parallel()
	ctx, _, db, _ := credentialStoreFixture(t)
	oldKeys := credentialKeys(t, "old", "old", "master")
	rotated := credentialKeys(t, "master", "old", "master")
	bindings := []credentialBinding{
		{"owner", "collection", "conn-a", "github", "generation", 1},
		{"owner", "collection", "conn-b", "github", "generation", 1},
	}
	for _, binding := range bindings {
		envelope, err := sealCredential(oldKeys, binding, credential{AccessToken: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		insertCredentialEnvelope(t, ctx, db, binding, "ready", envelope, nil)
	}
	// Corrupt one stored ciphertext after insertion; preflight must fail before any update.
	corrupt := readCredentialEnvelope(t, ctx, db, "conn-b")
	corrupt[len(corrupt)-1] ^= 1
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "tamper-credential", SQL: `UPDATE saas_connection_credentials SET credential=? WHERE connection_id=?`, Args: []any{corrupt, "conn-b"}}); err != nil {
		t.Fatal(err)
	}
	before := readCredentialEnvelope(t, ctx, db, "conn-a")
	if _, err := RewrapCredentialEnvelopeBatch(ctx, db, rotated, ""); err == nil {
		t.Fatal("tampered batch accepted")
	}
	if after := readCredentialEnvelope(t, ctx, db, "conn-a"); !bytes.Equal(after, before) {
		t.Fatal("partial rewrap committed before tamper failure")
	}
}

func insertCredentialEnvelope(t *testing.T, ctx context.Context, db *rhiza.DB, b credentialBinding, state string, envelope []byte, claim any) {
	t.Helper()
	_, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "insert-" + b.ConnectionID, SQL: `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential,refresh_claim) VALUES(?,?,?,?,?,?,?,?,?)`, Args: []any{b.ConnectionID, b.Owner, b.CollectionID, b.ProviderID, b.Generation, b.TokenVersion, state, envelope, claim}})
	if err != nil {
		t.Fatal(err)
	}
}

func readCredentialEnvelope(t *testing.T, ctx context.Context, db *rhiza.DB, connectionID string) []byte {
	t.Helper()
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{connectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("read %s: rows=%#v err=%v", connectionID, result.Rows, err)
	}
	value, ok := result.Rows[0][0].([]byte)
	if !ok {
		t.Fatalf("credential %s type=%T", connectionID, result.Rows[0][0])
	}
	return value
}
