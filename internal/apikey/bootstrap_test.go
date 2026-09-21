package apikey

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const bootstrapTestSecret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01"

func TestParseBootstrapStrictAndPolicy(t *testing.T) {
	valid := fmt.Sprintf(`[{"name":"runner","exp":2000000000,"secret":{"Plain":%q},"access":[{"group":"Clients","access_rights":["read"]}]}]`, bootstrapTestSecret)
	tests := []struct {
		name string
		json string
		want error
	}{
		{"valid", valid, nil},
		{"object root", valid[1 : len(valid)-1], errors.New("invalid")},
		{"null root", "null", errors.New("invalid")},
		{"unknown field", strings.Replace(valid, `"name"`, `"extra":true,"name"`, 1), errors.New("invalid")},
		{"trailing json", valid + "{}", errors.New("invalid")},
		{"trailing garbage", valid + "garbage", errors.New("invalid")},
		{"duplicate field", strings.Replace(valid, `"name":"runner"`, `"name":"runner","name":"runner"`, 1), errors.New("invalid")},
		{"duplicate name", "[" + strings.TrimSuffix(strings.TrimPrefix(valid, "["), "]") + "," + strings.TrimSuffix(strings.TrimPrefix(valid, "["), "]") + "]", errors.New("invalid")},
		{"short plain", strings.Replace(valid, bootstrapTestSecret, "short", 1), errors.New("invalid")},
		{"api keys policy", strings.Replace(valid, `"Clients"`, `"ApiKeys"`, 1), errors.New("invalid")},
		{"sso policy", strings.Replace(valid, `"Clients"`, `"AuthProviders"`, 1), errors.New("invalid")},
		{"generate", strings.Replace(valid, fmt.Sprintf(`{"Plain":%q}`, bootstrapTestSecret), `"generate"`, 1), ErrUnsupportedSecret},
		{"encrypted", strings.Replace(valid, fmt.Sprintf(`{"Plain":%q}`, bootstrapTestSecret), `{"Encrypted":"Y2lwaGVydGV4dA=="}`, 1), ErrUnsupportedSecret},
		{"encrypted malformed", strings.Replace(valid, fmt.Sprintf(`{"Plain":%q}`, bootstrapTestSecret), `{"Encrypted":"not-base64!!"}`, 1), errors.New("invalid")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := parseBootstrapKeys([]byte(tc.json))
			if tc.want == nil {
				if err != nil || len(keys) != 1 || string(keys[0].Secret) != bootstrapTestSecret {
					t.Fatalf("keys=%#v err=%v", keys, err)
				}
				wipeBootstrapKeys(keys)
				return
			}
			if err == nil {
				t.Fatal("accepted invalid bootstrap JSON")
			}
			if errors.Is(tc.want, ErrUnsupportedSecret) && !errors.Is(err, ErrUnsupportedSecret) {
				t.Fatalf("err=%v does not identify unsupported secret mode", err)
			}
			if strings.Contains(err.Error(), bootstrapTestSecret) {
				t.Fatal("error leaked bootstrap secret")
			}
		})
	}
	for _, tc := range []struct{ field, original string }{
		{field: "Name", original: "name"},
		{field: "EXP", original: "exp"},
		{field: "Secret", original: "secret"},
		{field: "Access", original: "access"},
	} {
		t.Run("case variant "+tc.field, func(t *testing.T) {
			variant := strings.Replace(valid, `"`+tc.original+`"`, `"`+tc.field+`"`, 1)
			if _, err := parseBootstrapKeys([]byte(variant)); err == nil {
				t.Fatalf("accepted case-variant field %q", tc.field)
			}
		})
	}
	for _, variant := range []string{
		strings.Replace(valid, `"group"`, `"Group"`, 1),
		strings.Replace(valid, `"access_rights"`, `"Access_Rights"`, 1),
		strings.Replace(valid, `"Plain"`, `"plain"`, 1),
	} {
		if _, err := parseBootstrapKeys([]byte(variant)); err == nil {
			t.Fatalf("accepted case-variant nested field: %s", variant)
		}
	}
	max := fmt.Sprintf(`[{"name":"runner","exp":%d,"secret":{"Plain":%q},"access":[{"group":"Clients","access_rights":["read"]}]}]`, maxExpiryUnixSeconds, bootstrapTestSecret)
	if _, err := parseBootstrapKeys([]byte(max)); err != nil {
		t.Fatalf("max representable expiry rejected: %v", err)
	}
	overflow := fmt.Sprintf(`[{"name":"runner","exp":%d,"secret":{"Plain":%q},"access":[{"group":"Clients","access_rights":["read"]}]}]`, maxExpiryUnixSeconds+1, bootstrapTestSecret)
	if _, err := parseBootstrapKeys([]byte(overflow)); err == nil {
		t.Fatal("accepted expiry that overflows milliseconds")
	}
}

func TestBootstrapFileNoOpAndAtomicPlainImport(t *testing.T) {
	db := bootstrapTestDB(t, "bootstrap-atomic")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.Unix(2_000_000_000, 0).UTC() }

	if err := store.Bootstrap(context.Background(), filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing explicitly configured file succeeded")
	}
	empty := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(empty, []byte("\n  \t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(context.Background(), empty); err != nil {
		t.Fatalf("empty file err=%v", err)
	}
	array := filepath.Join(t.TempDir(), "array.json")
	if err := os.WriteFile(array, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(context.Background(), array); err != nil {
		t.Fatalf("empty array err=%v", err)
	}

	bad := filepath.Join(t.TempDir(), "bad.json")
	content := fmt.Sprintf(`[{"name":"first","secret":{"Plain":%q},"access":[{"group":"Clients","access_rights":["read"]}]},{"name":"second","secret":{"Plain":"short"},"access":[{"group":"Clients","access_rights":["read"]}]}]`, bootstrapTestSecret)
	if err := os.WriteFile(bad, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(context.Background(), bad); err == nil {
		t.Fatal("accepted invalid bootstrap")
	}
	assertBootstrapCount(t, db, 0)

	good := filepath.Join(t.TempDir(), "good.json")
	content = fmt.Sprintf(`[{"name":"first","exp":2000000000,"secret":{"Plain":%q},"access":[{"group":"Clients","access_rights":["read","update"]}]}]`, bootstrapTestSecret)
	if err := os.WriteFile(good, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(context.Background(), good); err != nil {
		t.Fatal(err)
	}
	assertBootstrapCount(t, db, 1)
	p, err := store.Authenticate(context.Background(), "API-Key first$"+bootstrapTestSecret)
	if err != nil {
		t.Fatalf("authenticate imported key: %v", err)
	}
	if err := store.Authorize(context.Background(), p, "Clients", Read); err != nil {
		t.Fatalf("authorize imported key: %v", err)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT secret_digest FROM api_keys WHERE name=?`, Args: []any{"first"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || strings.Contains(fmt.Sprint(rows.Rows[0]), bootstrapTestSecret) {
		t.Fatalf("stored secret rows=%#v err=%v", rows.Rows, err)
	}
	if err := store.Bootstrap(context.Background(), good); err != nil {
		t.Fatalf("repeat identical bootstrap err=%v", err)
	}

	createdRows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT created_at_unix_ms FROM api_keys WHERE name=?`, Args: []any{"first"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(createdRows.Rows) != 1 {
		t.Fatalf("created timestamp rows=%#v err=%v", createdRows.Rows, err)
	}
	updatedSecret := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"
	updated := filepath.Join(t.TempDir(), "updated.json")
	updatedContent := fmt.Sprintf(`[{"name":"first","exp":2000000001,"secret":{"Plain":%q},"access":[{"group":"Roles","access_rights":["read"]}]}]`, updatedSecret)
	if err := os.WriteFile(updated, []byte(updatedContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(context.Background(), updated); err != nil {
		t.Fatalf("update existing bootstrap err=%v", err)
	}
	if _, err := store.Authenticate(context.Background(), "API-Key first$"+bootstrapTestSecret); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old secret authentication err=%v", err)
	}
	p, err = store.Authenticate(context.Background(), "API-Key first$"+updatedSecret)
	if err != nil {
		t.Fatalf("new secret authentication err=%v", err)
	}
	updatedKey, err := store.byName(context.Background(), "first")
	if err != nil {
		t.Fatalf("get updated key err=%v", err)
	}
	if updatedKey.Expires == nil || *updatedKey.Expires != 2000000001 || len(updatedKey.Access) != 1 || updatedKey.Access[0].Group != "Roles" || len(updatedKey.Access[0].AccessRights) != 1 || updatedKey.Access[0].AccessRights[0] != Read {
		t.Fatalf("updated key=%+v created rows=%#v", updatedKey, createdRows.Rows)
	}
	newCreatedRows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT created_at_unix_ms FROM api_keys WHERE name=?`, Args: []any{"first"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(newCreatedRows.Rows) != 1 || newCreatedRows.Rows[0][0] != createdRows.Rows[0][0] {
		t.Fatalf("created timestamp changed old=%#v new=%#v err=%v", createdRows.Rows, newCreatedRows.Rows, err)
	}
}

func TestBootstrapConcurrentSameFileIsAtomic(t *testing.T) {
	db := bootstrapTestDB(t, "bootstrap-concurrent")
	path := filepath.Join(t.TempDir(), "keys.json")
	content := fmt.Sprintf(`[{"name":"concurrent","secret":{"Plain":%q},"access":[{"group":"Clients","access_rights":["read"]},{"group":"Roles","access_rights":["read"]}]}]`, bootstrapTestSecret)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	const callers = 4
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store, err := NewStore(db)
			if err == nil {
				err = store.Bootstrap(context.Background(), path)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent bootstrap err=%v", err)
		}
	}
	assertBootstrapCount(t, db, 1)
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_key_access WHERE key_name=?`, Args: []any{"concurrent"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(2) {
		t.Fatalf("access rows=%#v err=%v", rows.Rows, err)
	}
}

func TestBootstrapRequiresBeforeAckDurability(t *testing.T) {
	ctx := context.Background()
	storeDir := t.TempDir()
	db, err := rhiza.Open(ctx, rhiza.Config{
		NodeID: "bootstrap-durability", DataDir: t.TempDir(),
		ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: storeDir,
		ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0)
	store.now = func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "keys.json")
	content := fmt.Sprintf(`[{"name":"durable","secret":{"Plain":%q},"access":[{"group":"Clients","access_rights":["read"]}]}]`, bootstrapTestSecret)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	backup := storeDir + "-unavailable"
	if err := os.Rename(storeDir, backup); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(storeDir); _ = os.Rename(backup, storeDir) })
	if err := os.WriteFile(storeDir, []byte("unavailable"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, advance := range []time.Duration{0, 0, time.Millisecond} {
		now = now.Add(advance)
		if err := store.Bootstrap(ctx, path); !errors.Is(err, rhiza.ErrCommitUnknown) {
			t.Fatalf("bootstrap acknowledged unavailable durability (clock advance %s): %v", advance, err)
		}
	}
	if err := os.Remove(storeDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, storeDir); err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(ctx, path); err != nil {
		t.Fatalf("bootstrap after storage recovery: %v", err)
	}
	assertBootstrapCount(t, db, 1)
	if _, err := store.Authenticate(ctx, "API-Key durable$"+bootstrapTestSecret); err != nil {
		t.Fatalf("recovered bootstrap authentication: %v", err)
	}
}

func bootstrapTestDB(t *testing.T, nodeID string) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: nodeID, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func assertBootstrapCount(t *testing.T, db *rhiza.DB, want int64) {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_keys`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != want {
		t.Fatalf("api key count=%#v err=%v want=%d", rows.Rows, err, want)
	}
}

// GA-CONFIG-001: preflight validation tests for the bootstrap API-key file.

func TestValidateBootstrapFileAcceptsValidPlainFile(t *testing.T) {
	dir := t.TempDir()
	valid := "[{\"name\":\"runner\",\"exp\":2000000000,\"secret\":{\"Plain\":\"" + bootstrapTestSecret + "\"},\"access\":[{\"group\":\"Clients\",\"access_rights\":[\"read\"]}]}]"
	path := writeBootstrapTestFile(t, dir, "bootstrap.json", valid)
	if err := ValidateBootstrapFile(path, nil, false); err != nil {
		t.Fatalf("valid plain file rejected: %v", err)
	}
}

func TestValidateBootstrapFileRejectsMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")
	err := ValidateBootstrapFile(path, nil, false)
	if err == nil {
		t.Fatal("missing file accepted")
	}
	if !strings.Contains(err.Error(), "API-key bootstrap file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateBootstrapFileRejectsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeBootstrapTestFile(t, dir, "bad.json", "not valid json")
	err := ValidateBootstrapFile(path, nil, false)
	if err == nil {
		t.Fatal("malformed JSON accepted")
	}
	if !strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "JSON") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateBootstrapFileRejectsDuplicateNames(t *testing.T) {
	dir := t.TempDir()
	dup := "[{\"name\":\"dup\",\"secret\":{\"Plain\":\"" + bootstrapTestSecret + "\"},\"access\":[{\"group\":\"Clients\",\"access_rights\":[\"read\"]}]},{\"name\":\"dup\",\"secret\":{\"Plain\":\"" + bootstrapTestSecret + "\"},\"access\":[{\"group\":\"Clients\",\"access_rights\":[\"read\"]}]}]"
	path := writeBootstrapTestFile(t, dir, "dup.json", dup)
	err := ValidateBootstrapFile(path, nil, false)
	if err == nil {
		t.Fatal("duplicate names accepted")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateBootstrapFileAcceptsEncryptedMode(t *testing.T) {
	dir := t.TempDir()
	enc := "[{\"name\":\"secret-key\",\"secret\":{\"Encrypted\":\"Y2lwaGVydGV4dA==\"},\"access\":[{\"group\":\"Clients\",\"access_rights\":[\"read\"]}]}]"
	path := writeBootstrapTestFile(t, dir, "encrypted.json", enc)
	if err := ValidateBootstrapFile(path, nil, false); err != nil {
		t.Fatalf("encrypted-mode file rejected: %v", err)
	}
}

// GA-CONFIG-001: the preflight has no master key, so an Encrypted entry stays
// deferred and the parser must keep validating the rest of the document. A
// duplicate name behind a deferred entry used to be skipped entirely.
func TestValidateBootstrapFileValidatesEntriesAfterDeferredEncrypted(t *testing.T) {
	dir := t.TempDir()
	entry := "{\"name\":\"dup\",\"secret\":{\"Encrypted\":\"Y2lwaGVydGV4dA==\"},\"access\":[{\"group\":\"Clients\",\"access_rights\":[\"read\"]}]}"
	path := writeBootstrapTestFile(t, dir, "deferred-dup.json", "["+entry+","+entry+"]")
	err := ValidateBootstrapFile(path, nil, false)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate name behind a deferred entry err=%v", err)
	}
	bad := writeBootstrapTestFile(t, dir, "deferred-bad.json", "["+entry+",{\"name\":\"second\",\"secret\":{\"Plain\":\"short\"},\"access\":[{\"group\":\"Clients\",\"access_rights\":[\"read\"]}]}]")
	if err := ValidateBootstrapFile(bad, nil, false); err == nil {
		t.Fatal("invalid entry behind a deferred entry accepted")
	}
}

// GA-CONFIG-001: a malformed Encrypted payload is not the deferred encrypted
// mode, so the preflight must reject it instead of letting `config check` pass
// a file that deterministically fails startup after Rhiza is opened.
func TestValidateBootstrapFileRejectsMalformedEncryptedSecret(t *testing.T) {
	dir := t.TempDir()
	bad := "[{\"name\":\"secret-key\",\"secret\":{\"Encrypted\":\"not-base64!!\"}}]"
	path := writeBootstrapTestFile(t, dir, "bad-encrypted.json", bad)
	err := ValidateBootstrapFile(path, nil, false)
	if err == nil {
		t.Fatal("malformed Encrypted secret accepted")
	}
	if errors.Is(err, ErrUnsupportedSecret) {
		t.Fatalf("malformed payload reported as the deferred encrypted mode: %v", err)
	}
}

func TestValidateBootstrapFileAcceptsGenerateMode(t *testing.T) {
	dir := t.TempDir()
	gen := "[{\"name\":\"gen-key\",\"secret\":\"generate\",\"access\":[{\"group\":\"Clients\",\"access_rights\":[\"read\"]}]}]"
	path := writeBootstrapTestFile(t, dir, "generate.json", gen)
	// GA-CONFIG-001: generate mode needs the generated-secret export that
	// startup configures, so the preflight accepts it only when that is present.
	if err := ValidateBootstrapFile(path, nil, false); err == nil {
		t.Fatal("generate-mode file accepted without generated-secret configuration")
	}
	if err := ValidateBootstrapFile(path, nil, true); err != nil {
		t.Fatalf("generate-mode file rejected with generated-secret configuration: %v", err)
	}
}

// GA-CONFIG-001: the runtime statement budget is a preflight condition too.
// The store rejects an oversized batch only after Rhiza is open, by which point
// a generated-secret artifact may already be on disk.
func TestValidateBootstrapFileEnforcesStatementBudget(t *testing.T) {
	dir := t.TempDir()
	entry := func(name string) string {
		return "{\"name\":\"" + name + "\",\"secret\":{\"Plain\":\"" + bootstrapTestSecret + "\"},\"access\":[{\"group\":\"Clients\",\"access_rights\":[\"read\"]}]}"
	}
	// Two statements per key plus one per access right: 21 keys stay inside the
	// 64-statement cap, 22 keys exceed it.
	within := make([]string, 0, 21)
	over := make([]string, 0, 22)
	for i := 0; i < 22; i++ {
		name := fmt.Sprintf("key-%02d", i)
		over = append(over, entry(name))
		if i < 21 {
			within = append(within, entry(name))
		}
	}
	if err := ValidateBootstrapFile(writeBootstrapTestFile(t, dir, "within.json", "["+strings.Join(within, ",")+"]"), nil, false); err != nil {
		t.Fatalf("file inside the statement budget rejected: %v", err)
	}
	err := ValidateBootstrapFile(writeBootstrapTestFile(t, dir, "over.json", "["+strings.Join(over, ",")+"]"), nil, false)
	if err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("file over the statement budget err=%v", err)
	}
}

func TestValidateBootstrapFileAcceptsEmptyArray(t *testing.T) {
	dir := t.TempDir()
	path := writeBootstrapTestFile(t, dir, "empty.json", "[]")
	if err := ValidateBootstrapFile(path, nil, false); err != nil {
		t.Fatalf("empty array rejected: %v", err)
	}
}

// GA-CONFIG-001-A: the generated-secret configuration selects the shared
// generated-secret path, which requires a Generate entry. A plain-only document
// used to pass the preflight and then fail startup after Rhiza was opened.
func TestValidateBootstrapFileRejectsPlainOnlyDocumentWithGeneratedExport(t *testing.T) {
	dir := t.TempDir()
	plain := "[{\"name\":\"runner\",\"secret\":{\"Plain\":\"" + bootstrapTestSecret + "\"},\"access\":[{\"group\":\"Clients\",\"access_rights\":[\"read\"]}]}]"
	path := writeBootstrapTestFile(t, dir, "plain-only.json", plain)
	err := ValidateBootstrapFile(path, nil, true)
	if err == nil || !strings.Contains(err.Error(), "Generate API key") {
		t.Fatalf("plain-only document with generated export err=%v", err)
	}
	// An empty array follows the same missing-Generate branch on the shared path.
	empty := writeBootstrapTestFile(t, dir, "empty-shared.json", "[]")
	if err := ValidateBootstrapFile(empty, nil, true); err == nil || !strings.Contains(err.Error(), "Generate API key") {
		t.Fatalf("empty document with generated export err=%v", err)
	}
	if err := ValidateBootstrapFile(empty, nil, false); err != nil {
		t.Fatalf("empty document without generated export rejected: %v", err)
	}
}

// GA-CONFIG-001-B: the shared generated-secret path prepends the
// generated_api_key_bootstrap row and ExecuteEnvelope appends the master-key
// retirement fence to the same command, so a document that fits the budget on
// the plain path exceeds it on the shared path. The preflight has to apply the
// budget of the path startup actually selects.
func TestValidateBootstrapFileBudgetMatchesSelectedPath(t *testing.T) {
	dir := t.TempDir()
	// Two statements per key plus one per access right. 20 generated keys with
	// two extra rights are 62 key statements, and the shared command adds its own
	// two for exactly 64. 21 keys with one right each are 63 key statements:
	// inside the ordinary budget, over the shared one.
	document := func(keys, extraRights int, secret string) string {
		entries := make([]string, 0, keys)
		for i := 0; i < keys; i++ {
			rights := "[\"read\"]"
			if i < extraRights {
				rights = "[\"read\",\"create\"]"
			}
			entries = append(entries, fmt.Sprintf("{\"name\":\"gen-%02d\",\"secret\":%s,\"access\":[{\"group\":\"Clients\",\"access_rights\":%s}]}", i, secret, rights))
		}
		return "[" + strings.Join(entries, ",") + "]"
	}
	generate := "\"generate\""
	plain := "{\"Plain\":\"" + bootstrapTestSecret + "\"}"
	within := writeBootstrapTestFile(t, dir, "shared-within.json", document(20, 2, generate))
	if err := ValidateBootstrapFile(within, nil, true); err != nil {
		t.Fatalf("shared document at the statement budget rejected: %v", err)
	}
	boundary := writeBootstrapTestFile(t, dir, "boundary.json", document(21, 0, plain))
	if err := ValidateBootstrapFile(boundary, nil, false); err != nil {
		t.Fatalf("plain document at the statement budget rejected: %v", err)
	}
	err := ValidateBootstrapFile(boundary, nil, true)
	if err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("shared document over the statement budget with its own row err=%v", err)
	}
	// The shared path itself refuses the same oversized batch, so the preflight
	// limit is not stricter than the path it predicts.
	_, keyDir, artifact := generatedBootstrapFiles(t, "runner", time.Time{})
	store, err := NewStore(bootstrapTestDB(t, "shared-budget"))
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(keyDir, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	over := writeBootstrapTestFile(t, dir, "shared-over.json", document(21, 0, generate))
	if err := store.BootstrapWithSharedGeneratedSecrets(context.Background(), over, keyDir, artifact, keyring, time.Time{}); err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("shared runtime over the statement budget err=%v", err)
	}
}

func writeBootstrapTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
