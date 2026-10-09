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

func TestCredentialEnvelopeActiveKeySecondPassIsNoOp(t *testing.T) {
	t.Parallel()
	ctx, credentials, db, _ := credentialStoreFixture(t)
	keys := credentials.keys
	bindings := []credentialBinding{
		{"owner", "collection", "conn-a", "github", "generation", 1},
		{"owner", "collection", "conn-b", "github", "generation", 1},
	}
	before := make(map[string][]byte, len(bindings))
	for _, binding := range bindings {
		envelope, err := sealCredential(keys, binding, testCredential())
		if err != nil {
			t.Fatal(err)
		}
		before[binding.ConnectionID] = append([]byte(nil), envelope...)
		insertCredentialEnvelope(t, ctx, db, binding, "ready", envelope, nil)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "credential-rewrap-noop-probe", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE credential_rewrap_write_probe(writes INTEGER NOT NULL)`},
		{SQL: `INSERT INTO credential_rewrap_write_probe(writes) VALUES(0)`},
		{SQL: `CREATE TRIGGER credential_rewrap_write_probe_trigger AFTER UPDATE OF credential ON saas_connection_credentials BEGIN UPDATE credential_rewrap_write_probe SET writes=writes+1; END`},
	}}); err != nil {
		t.Fatal(err)
	}

	result, err := RewrapCredentialEnvelopeBatch(ctx, db, keys, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Rewrapped != 0 || !result.Done || result.Cursor != "conn-b" {
		t.Errorf("active-key second pass result=%+v want cursor=conn-b rewrapped=0 done=true", result)
	}
	for _, binding := range bindings {
		if envelope := readCredentialEnvelope(t, ctx, db, binding.ConnectionID); !bytes.Equal(envelope, before[binding.ConnectionID]) {
			t.Errorf("active-key ciphertext changed for %s", binding.ConnectionID)
		}
	}
	probe, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT writes FROM credential_rewrap_write_probe`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(probe.Rows) != 1 || probe.Rows[0][0] != int64(0) {
		t.Errorf("active-key durable update count=%v err=%v want=0", probe.Rows, err)
	}
}

func TestCredentialEnvelopeActiveKeyTamperingStillFails(t *testing.T) {
	t.Parallel()
	ctx, credentials, db, _ := credentialStoreFixture(t)
	keys := credentials.keys
	validBinding := credentialBinding{"owner", "collection", "conn-valid", "github", "generation", 1}
	tamperedBinding := credentialBinding{"owner", "collection", "conn-tampered", "github", "generation", 1}
	validEnvelope, err := sealCredential(keys, validBinding, testCredential())
	if err != nil {
		t.Fatal(err)
	}
	tamperedEnvelope, err := sealCredential(keys, tamperedBinding, testCredential())
	if err != nil {
		t.Fatal(err)
	}
	insertCredentialEnvelope(t, ctx, db, validBinding, "ready", validEnvelope, nil)
	insertCredentialEnvelope(t, ctx, db, tamperedBinding, "ready", tamperedEnvelope, nil)
	tamperedEnvelope[len(tamperedEnvelope)-1] ^= 1
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "credential-active-key-tamper", SQL: `UPDATE saas_connection_credentials SET credential=? WHERE connection_id=?`, Args: []any{tamperedEnvelope, tamperedBinding.ConnectionID}}); err != nil {
		t.Fatal(err)
	}

	if _, err := RewrapCredentialEnvelopeBatch(ctx, db, keys, ""); err == nil {
		t.Fatal("tampered active-key envelope accepted")
	}
	if after := readCredentialEnvelope(t, ctx, db, validBinding.ConnectionID); !bytes.Equal(after, validEnvelope) {
		t.Fatal("valid row was written before tampered active-key envelope failed")
	}
}

func TestCredentialEnvelopeMixedRotationSkipsActiveAndAdvancesCursor(t *testing.T) {
	t.Parallel()
	ctx, _, db, _ := credentialStoreFixture(t)
	oldKeys := credentialKeys(t, "old", "old", "master")
	rotated := credentialKeys(t, "master", "old", "master")
	bindings := []credentialBinding{
		{"owner", "collection", "conn-a-active", "github", "generation", 1},
		{"owner", "collection", "conn-b-old", "github", "generation", 1},
		{"owner", "collection", "conn-z-active", "github", "generation", 1},
	}
	activeBindings := []credentialBinding{bindings[0], bindings[2]}
	oldBinding := bindings[1]
	activeEnvelopes := make(map[string][]byte, len(activeBindings))
	for _, binding := range activeBindings {
		envelope, err := sealCredential(rotated, binding, testCredential())
		if err != nil {
			t.Fatal(err)
		}
		activeEnvelopes[binding.ConnectionID] = append([]byte(nil), envelope...)
		insertCredentialEnvelope(t, ctx, db, binding, "ready", envelope, nil)
	}
	oldEnvelope, err := sealCredential(oldKeys, oldBinding, testCredential())
	if err != nil {
		t.Fatal(err)
	}
	insertCredentialEnvelope(t, ctx, db, oldBinding, "refreshing", oldEnvelope, "claim")

	result, err := RewrapCredentialEnvelopeBatch(ctx, db, rotated, "")
	if err != nil || result.Rewrapped != 1 || !result.Done || result.Cursor != "conn-z-active" {
		t.Fatalf("mixed rotation result=%+v err=%v", result, err)
	}
	for _, binding := range activeBindings {
		if after := readCredentialEnvelope(t, ctx, db, binding.ConnectionID); !bytes.Equal(after, activeEnvelopes[binding.ConnectionID]) {
			t.Errorf("active-key envelope changed for %s", binding.ConnectionID)
		}
	}
	newOnly := credentialKeys(t, "master", "master")
	updated := readCredentialEnvelope(t, ctx, db, oldBinding.ConnectionID)
	if value, err := openCredential(newOnly, oldBinding, updated); err != nil || value.AccessToken != "access" {
		t.Errorf("old-key row not rewrapped with preserved binding: err=%v", err)
	}
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state,refresh_claim FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{oldBinding.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(state.Rows) != 1 || state.Rows[0][0] != "refreshing" || state.Rows[0][1] != "claim" {
		t.Errorf("rewrap changed refresh state: rows=%v err=%v", state.Rows, err)
	}
}

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
