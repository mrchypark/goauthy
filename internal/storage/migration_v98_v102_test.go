package storage

import (
	"fmt"
	"testing"

	"github.com/mrchypark/rhiza"
)

// --- helpers ---

func assertTableExists(t *testing.T, db *rhiza.DB, name string) {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL:         fmt.Sprintf("SELECT name FROM sqlite_master WHERE type='table' AND name='%s'", name),
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("table %s not found: rows=%#v err=%v", name, result.Rows, err)
	}
}

func assertColumnExists(t *testing.T, db *rhiza.DB, table, col string) {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL:         "SELECT name FROM pragma_table_info(?) WHERE name=?",
		Args:        []any{table, col},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("column %s.%s not found: rows=%#v err=%v", table, col, result.Rows, err)
	}
}

func assertAbsent(t *testing.T, db *rhiza.DB, name, kind string) {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL:         "SELECT name FROM sqlite_master WHERE type='" + kind + "' AND name='" + name + "'",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 0 {
		t.Fatalf("%s %s should not exist after v97 reconstruction", kind, name)
	}
}

func assertColumnAbsent(t *testing.T, db *rhiza.DB, table, col string) {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL:         "SELECT name FROM pragma_table_info(?) WHERE name=?",
		Args:        []any{table, col},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 0 {
		t.Fatalf("column %s.%s should not exist after v97 reconstruction", table, col)
	}
}

func TestMigrationV98V102SchemaVerification(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v98-102-schema", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	// v98: scim_client_config table exists.
	assertTableExists(t, db, "scim_client_config")
	for _, col := range []string{"client_id", "endpoint", "bearer_envelope", "ca_cert", "enabled", "created_at_unix_ms", "updated_at_unix_ms"} {
		assertColumnExists(t, db, "scim_client_config", col)
	}

	// v99: force_mfa column on managed_oauth_clients.
	assertColumnExists(t, db, "managed_oauth_clients", "force_mfa")

	// v100: system_lockdown table.
	assertTableExists(t, db, "system_lockdown")
	for _, col := range []string{"id", "enabled", "reason", "until_unix_ms", "created_at_unix_ms", "updated_at_unix_ms"} {
		assertColumnExists(t, db, "system_lockdown", col)
	}

	// v101: identity_email_otp tables.
	assertTableExists(t, db, "identity_email_otp")
	for _, col := range []string{"code_digest", "subject", "expires_at_unix_ms", "consumed_attempt", "consumed_at_unix_ms"} {
		assertColumnExists(t, db, "identity_email_otp", col)
	}
	assertTableExists(t, db, "identity_email_otp_rate_limits")
	for _, col := range []string{"subject_digest", "window_start_unix_seconds", "count"} {
		assertColumnExists(t, db, "identity_email_otp_rate_limits", col)
	}

	// v102: prev_hash / integrity_hash on event_log.
	assertColumnExists(t, db, "event_log", "prev_hash")
	assertColumnExists(t, db, "event_log", "integrity_hash")

	// Version marker = 102.
	if got := queryInt64(t, db, "SELECT MAX(version) FROM goauthy_schema_migrations"); got != 102 {
		t.Fatalf("schema version=%d want=102", got)
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatal(err)
	}
}

// TestMigrationV98V102UpgradeFromV97PreservesData builds a fresh v97 schema
// via migrateThroughV97, seeds v97 data, then invokes the public Migrate
// to perform the real v98-v102 upgrade.
func TestMigrationV98V102UpgradeFromV97PreservesData(t *testing.T) {
	ctx := t.Context()
	dataDir := t.TempDir()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v98-102-upgrade", DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Apply v1-v97 only. Never reaches v98, so no cached RequestID receipts.
	if err := migrateThroughV97(ctx, db); err != nil {
		t.Fatal(err)
	}

	// Verify v97 state: MAX marker = 97.
	if got := queryInt64(t, db, "SELECT MAX(version) FROM goauthy_schema_migrations"); got != 97 {
		t.Fatalf("version=%d want=97", got)
	}

	// Verify all v98-v102 schema additions are absent.
	assertAbsent(t, db, "scim_client_config", "table")
	assertAbsent(t, db, "system_lockdown", "table")
	assertAbsent(t, db, "identity_email_otp", "table")
	assertAbsent(t, db, "identity_email_otp_rate_limits", "table")
	assertColumnAbsent(t, db, "managed_oauth_clients", "force_mfa")
	assertColumnAbsent(t, db, "event_log", "prev_hash")
	assertColumnAbsent(t, db, "event_log", "integrity_hash")

	// Persist and reopen to prove the v97 fixture survives recovery.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = rhiza.Open(ctx, rhiza.Config{NodeID: "v98-102-upgrade", DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if got := queryInt64(t, db, "SELECT MAX(version) FROM goauthy_schema_migrations"); got != 97 {
		t.Fatalf("reopened version=%d want=97", got)
	}

	// Seed v97-only data: auth_providers, managed_oauth_clients, event_log.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "seed-prov",
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{"prov-upgrade", int64(1), "Upgrade Provider", "oidc", "https://issuer.example", "https://issuer.example/auth", "https://issuer.example/token", "https://issuer.example/userinfo", "cid-upgrade", "openid", int64(1)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "seed-mc",
		SQL:       "INSERT INTO managed_oauth_clients(id,generation,revision,enabled,metadata_json) VALUES(?,?,?,?,?)",
		Args:      []any{"upgrade-mc", "g1", int64(1), int64(1), "{}"},
	}); err != nil {
		t.Fatal(err)
	}
	eventID := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "seed-ev",
		SQL:       "INSERT INTO event_log(id,timestamp,level,typ,text) VALUES(?,?,?,?,?)",
		Args:      []any{eventID, int64(2000), int64(0), "Test", "upgrade-data"},
	}); err != nil {
		t.Fatal(err)
	}

	// Invoke PUBLIC Migrate to perform the real v98-v102 upgrade.
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	// Verify schema version advanced to 102.
	if got := queryInt64(t, db, "SELECT MAX(version) FROM goauthy_schema_migrations"); got != 102 {
		t.Fatalf("post-upgrade version=%d want=102", got)
	}

	// Verify v98-v102 schema additions now exist.
	assertTableExists(t, db, "scim_client_config")
	assertTableExists(t, db, "system_lockdown")
	assertTableExists(t, db, "identity_email_otp")
	assertTableExists(t, db, "identity_email_otp_rate_limits")
	assertColumnExists(t, db, "managed_oauth_clients", "force_mfa")
	assertColumnExists(t, db, "event_log", "prev_hash")
	assertColumnExists(t, db, "event_log", "integrity_hash")

	// Verify v97 auth_providers data survived.
	row, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT id,name,typ FROM auth_providers WHERE id='prov-upgrade'",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("auth provider after upgrade=%#v err=%v", row.Rows, err)
	}
	if row.Rows[0][0] != "prov-upgrade" || row.Rows[0][1] != "Upgrade Provider" || row.Rows[0][2] != "oidc" {
		t.Fatalf("auth provider data changed: row=%v", row.Rows[0])
	}

	// Verify managed client survived; force_mfa defaults to 0.
	row, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT id,generation,revision,enabled,force_mfa FROM managed_oauth_clients WHERE id='upgrade-mc'",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("managed client after upgrade=%#v err=%v", row.Rows, err)
	}
	if row.Rows[0][0] != "upgrade-mc" || row.Rows[0][1] != "g1" || row.Rows[0][2] != int64(1) || row.Rows[0][3] != int64(1) {
		t.Fatalf("managed client data changed: row=%v", row.Rows[0])
	}
	if row.Rows[0][4] != int64(0) {
		t.Fatalf("force_mfa default wrong: got %v want 0", row.Rows[0][4])
	}

	// Verify event survived; prev_hash and integrity_hash default to empty string.
	row, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT id,text,prev_hash,integrity_hash FROM event_log WHERE id=?",
		Args:        []any{eventID},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("event after upgrade=%#v err=%v", row.Rows, err)
	}
	if row.Rows[0][1] != "upgrade-data" {
		t.Fatalf("event text changed: %v", row.Rows[0][1])
	}
	if row.Rows[0][2] != "" || row.Rows[0][3] != "" {
		t.Fatalf("hashes not defaulted: prev=%v integrity=%v", row.Rows[0][2], row.Rows[0][3])
	}

	// Verify v97 trigger still works: cross-mode oidc->oauth_userinfo blocked.
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "v97-trigger-check",
		SQL:       "UPDATE auth_providers SET typ='oauth_userinfo' WHERE id='prov-upgrade'",
	})
	if err == nil {
		t.Fatal("v97 trigger broken: cross-mode oidc->oauth_userinfo accepted after upgrade")
	}

	// Populate representative v98-v102 data with non-default values.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "v98-seed-scim",
		SQL:       "INSERT INTO scim_client_config(client_id,endpoint,enabled,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)",
		Args:      []any{"scim-prod", "https://scim.prod.example", int64(1), int64(1000), int64(1000)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "v98-seed-fm",
		SQL:       "UPDATE managed_oauth_clients SET force_mfa=1 WHERE id='upgrade-mc'",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "v98-seed-lockdown",
		SQL:       "INSERT INTO system_lockdown(id,enabled,reason,until_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(1,1,'maintenance',9999,1000,1000)",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "v98-seed-otp",
		SQL:       "INSERT INTO identity_email_otp(code_digest,subject,expires_at_unix_ms) VALUES(?,?,?)",
		Args:      []any{"otp-digest-123", "user@example.com", int64(5000)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "v98-seed-rl",
		SQL:       "INSERT INTO identity_email_otp_rate_limits(subject_digest,window_start_unix_seconds,count) VALUES(?,?,?)",
		Args:      []any{"rate-subj", int64(100), int64(5)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "v98-seed-evhash",
		SQL:       "UPDATE event_log SET prev_hash='prev-abc',integrity_hash='int-xyz' WHERE id=?",
		Args:      []any{eventID},
	}); err != nil {
		t.Fatal(err)
	}

	// Close and reopen to verify all non-default v98-v102 data persists.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = rhiza.Open(ctx, rhiza.Config{NodeID: "v98-102-upgrade", DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if got := queryInt64(t, db, "SELECT MAX(version) FROM goauthy_schema_migrations"); got != 102 {
		t.Fatalf("recovery version=%d want=102", got)
	}

	// Verify non-default v98-v102 data survived recovery.
	row, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT client_id,endpoint FROM scim_client_config WHERE client_id='scim-prod'",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != "scim-prod" || row.Rows[0][1] != "https://scim.prod.example" {
		t.Fatalf("scim config after recovery: rows=%#v err=%v", row.Rows, err)
	}
	row, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT force_mfa FROM managed_oauth_clients WHERE id='upgrade-mc'",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(1) {
		t.Fatalf("force_mfa after recovery: got %v want 1", row.Rows)
	}
	row, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT enabled,reason FROM system_lockdown WHERE id=1",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(1) || row.Rows[0][1] != "maintenance" {
		t.Fatalf("lockdown after recovery: rows=%#v err=%v", row.Rows, err)
	}
	row, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT subject,expires_at_unix_ms FROM identity_email_otp WHERE code_digest='otp-digest-123'",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != "user@example.com" {
		t.Fatalf("otp after recovery: rows=%#v err=%v", row.Rows, err)
	}
	row, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT count FROM identity_email_otp_rate_limits WHERE subject_digest='rate-subj'",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(5) {
		t.Fatalf("rate limit after recovery: rows=%#v err=%v", row.Rows, err)
	}
	row, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT prev_hash,integrity_hash FROM event_log WHERE id=?",
		Args:        []any{eventID},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != "prev-abc" || row.Rows[0][1] != "int-xyz" {
		t.Fatalf("event hashes after recovery: rows=%#v err=%v", row.Rows, err)
	}

	// Final Migrate replay is idempotent; Ready confirms the store.
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatal(err)
	}
}
func TestMigrationV98V102ReplayIdempotent(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v98-102-replay", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for range 2 {
		if err := Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatal(err)
	}
	if got := queryInt64(t, db, "SELECT MAX(version) FROM goauthy_schema_migrations"); got != 102 {
		t.Fatalf("schema version=%d want=102", got)
	}
}

func TestMigrationV98V102Constraints(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v98-102-constraints", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	// --- v98 scim_client_config constraints ---
	// empty client_id rejected.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v98-empty-client",
		SQL:       "INSERT INTO scim_client_config(client_id,endpoint,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?)",
		Args:      []any{"", "https://scim.example", int64(0), int64(0)},
	}); err == nil {
		t.Fatal("empty client_id accepted")
	}
	// empty endpoint rejected.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v98-empty-endpoint",
		SQL:       "INSERT INTO scim_client_config(client_id,endpoint,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?)",
		Args:      []any{"cid-ok", "", int64(0), int64(0)},
	}); err == nil {
		t.Fatal("empty endpoint accepted")
	}
	// negative timestamp rejected.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v98-neg-ts",
		SQL:       "INSERT INTO scim_client_config(client_id,endpoint,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?)",
		Args:      []any{"cid-ok2", "https://scim.example", int64(-1), int64(0)},
	}); err == nil {
		t.Fatal("negative created_at accepted")
	}
	// updated_at < created_at rejected.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v98-bad-updated",
		SQL:       "INSERT INTO scim_client_config(client_id,endpoint,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?)",
		Args:      []any{"cid-ok3", "https://scim.example", int64(100), int64(50)},
	}); err == nil {
		t.Fatal("updated_at < created_at accepted")
	}
	// valid row accepted.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v98-valid",
		SQL:       "INSERT INTO scim_client_config(client_id,endpoint,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?)",
		Args:      []any{"cid-valid", "https://scim.example", int64(100), int64(100)},
	}); err != nil {
		t.Fatal(err)
	}

	// --- v99 force_mfa constraint ---
	// Insert a row then verify force_mfa=2 is rejected.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v99-seed",
		SQL:       "INSERT INTO managed_oauth_clients(id,generation,revision,enabled,metadata_json) VALUES(?,?,?,?,?)",
		Args:      []any{"v99-test", "g1", int64(1), int64(1), "{}"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v99-bad-fm",
		SQL:       "UPDATE managed_oauth_clients SET force_mfa=2 WHERE id='v99-test'",
	}); err == nil {
		t.Fatal("force_mfa=2 accepted")
	}

	// --- v100 system_lockdown constraints ---
	// Seed the singleton row, then test constraints.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v100-seed",
		SQL:       "INSERT INTO system_lockdown(id,enabled,reason,until_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(1,0,'',0,0,0)",
	}); err != nil {
		t.Fatal(err)
	}
	// second row rejected (singleton id=1).
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v100-second-row",
		SQL:       "INSERT INTO system_lockdown(id,enabled,reason,until_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(2,0,'',0,0,0)",
	}); err == nil {
		t.Fatal("second lockdown row accepted")
	}
	// enabled must be 0 or 1.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v100-bad-enabled",
		SQL:       "UPDATE system_lockdown SET enabled=2 WHERE id=1",
	}); err == nil {
		t.Fatal("enabled=2 accepted")
	}

	// --- v101 email OTP constraints ---
	// empty subject rejected.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v101-empty-subject",
		SQL:       "INSERT INTO identity_email_otp(code_digest,subject,expires_at_unix_ms) VALUES(?,?,?)",
		Args:      []any{"digest1", "", int64(1000)},
	}); err == nil {
		t.Fatal("empty subject accepted")
	}
	// valid OTP row accepted.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v101-valid",
		SQL:       "INSERT INTO identity_email_otp(code_digest,subject,expires_at_unix_ms) VALUES(?,?,?)",
		Args:      []any{"digest-ok", "user@example.com", int64(1000)},
	}); err != nil {
		t.Fatal(err)
	}
	// duplicate code_digest rejected.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v101-dup",
		SQL:       "INSERT INTO identity_email_otp(code_digest,subject,expires_at_unix_ms) VALUES(?,?,?)",
		Args:      []any{"digest-ok", "other@example.com", int64(2000)},
	}); err == nil {
		t.Fatal("duplicate code_digest accepted")
	}
	// rate limit row accepted.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "c-v101-rl",
		SQL:       "INSERT INTO identity_email_otp_rate_limits(subject_digest,window_start_unix_seconds,count) VALUES(?,?,?)",
		Args:      []any{"s digest", int64(100), int64(3)},
	}); err != nil {
		t.Fatal(err)
	}
}
