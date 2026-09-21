package identity

import (
	"context"
	"crypto/rand"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestExpireUsersBoundariesBatchAndIdempotence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.UnixMilli(10_000).UTC()
	s := scimDeleteStore(t)
	for _, subject := range []string{"expiry-null", "expiry-before", "expiry-equal", "expiry-after", "expiry-zero"} {
		if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "seed-" + subject, Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO identity_users(subject,username,password_phc,user_expires_at_unix_ms,password_generation,password_changed_at_unix_ms) VALUES(?,?,?, ?,1,0)`, Args: []any{subject, subject, "preserved-phc", nil}},
			{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES(?, 'password', 7, 0)`, Args: []any{subject}},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "set-expiry-boundaries", Statements: []rhiza.SQLStatement{
		{SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{now.UnixMilli() - 1, "expiry-before"}},
		{SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{now.UnixMilli(), "expiry-equal"}},
		{SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{now.UnixMilli() + 1, "expiry-after"}},
		{SQL: `UPDATE identity_users SET user_expires_at_unix_ms=0 WHERE subject=?`, Args: []any{"expiry-zero"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.ExpireUsers(ctx, now, 2); err != nil || n != 2 {
		t.Fatalf("first batch count=%d err=%v", n, err)
	}
	if n, err := s.ExpireUsers(ctx, now, 2); err != nil || n != 1 {
		t.Fatalf("second batch count=%d err=%v", n, err)
	}
	if n, err := s.ExpireUsers(ctx, now, 2); err != nil || n != 0 {
		t.Fatalf("idempotent count=%d err=%v", n, err)
	}
	var disabled, generation, modeGeneration int64
	row, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT disabled,password_generation FROM identity_users WHERE subject=?`, Args: []any{"expiry-equal"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("expired row=%v err=%v", row.Rows, err)
	}
	disabled, generation = row.Rows[0][0].(int64), row.Rows[0][1].(int64)
	mode, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT generation FROM identity_authentication_modes WHERE subject=?`, Args: []any{"expiry-equal"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(mode.Rows) != 1 {
		t.Fatalf("mode row=%v err=%v", mode.Rows, err)
	}
	modeGeneration = mode.Rows[0][0].(int64)
	if disabled != 1 || generation != 2 || modeGeneration != 8 {
		t.Fatalf("expiry generations disabled=%d password=%d mode=%d", disabled, generation, modeGeneration)
	}
	active, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT disabled FROM identity_users WHERE subject=?`, Args: []any{"expiry-after"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(active.Rows) != 1 || active.Rows[0][0] != int64(0) {
		t.Fatalf("future account changed: %v err=%v", active.Rows, err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "reopen-expiry", SQL: `UPDATE identity_users SET disabled=0,user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{now.Add(time.Hour).UnixMilli(), "expiry-equal"}}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ExpireUsers(ctx, now, 1); err != nil || n != 0 {
		t.Fatalf("reopened future account count=%d err=%v", n, err)
	}
}

func TestExpireUsersConcurrentWorkersExactlyOne(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := scimDeleteStore(t)
	now := time.UnixMilli(20_000).UTC()
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "seed-concurrent-expiry", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users(subject,username,password_phc,user_expires_at_unix_ms) VALUES(?,?,?,?)`, Args: []any{"expiry-concurrent", "expiry-concurrent", "phc", now.UnixMilli()}},
		{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES(?, 'password', 1, 0)`, Args: []any{"expiry-concurrent"}},
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES('concurrent-session','expiry-concurrent',0,30000,0)`},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('concurrent-session','client','https://rp.example/logout',0,0,0)`},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('expiry-concurrent','client','https://rp.example/logout',0,0,0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	// Both workers must select the candidate before either can commit.
	var arrivals atomic.Int32
	selected := make(chan struct{})
	s.random = func(p []byte) (int, error) {
		if arrivals.Add(1) == 2 {
			close(selected)
		}
		<-selected
		return rand.Read(p)
	}
	counts := make(chan int, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); n, err := s.ExpireUsers(ctx, now, 1); counts <- n; errs <- err }()
	}
	wg.Wait()
	close(counts)
	close(errs)
	total := 0
	for n := range counts {
		total += n
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if total != 1 {
		t.Fatalf("concurrent workers disabled %d times", total)
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
		(SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject='expiry-concurrent' AND sid IS NULL),
		(SELECT COUNT(*) FROM oidc_user_clients WHERE subject='expiry-concurrent'),
		(SELECT generation FROM identity_authentication_modes WHERE subject='expiry-concurrent')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || !reflect.DeepEqual(result.Rows[0], []any{int64(1), int64(0), int64(2)}) {
		t.Fatalf("concurrent effects=%v err=%v", result.Rows, err)
	}
}

func TestDeleteExpiredUsersStrictRetentionBoundary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := scimDeleteStore(t)
	now := time.UnixMilli(3 * 24 * 60 * 60 * 1000).UTC()
	phc, err := credential.Hash([]byte("Password1!"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "seed-retention-expiry", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users(subject,username,password_phc,disabled,user_expires_at_unix_ms) VALUES(?,?,?,1,?)`, Args: []any{"expiry-retention", "expiry-retention", phc, now.Add(-2 * time.Hour).UnixMilli()}},
		{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES(?, 'password', 1, 0)`, Args: []any{"expiry-retention"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteExpiredUsers(ctx, now, 2*time.Hour, 1); err != nil || n != 0 {
		t.Fatalf("strict boundary count=%d err=%v", n, err)
	}
	if n, err := s.DeleteExpiredUsers(ctx, now.Add(time.Millisecond), 2*time.Hour, 1); err != nil || n != 1 {
		t.Fatalf("retention deletion count=%d err=%v", n, err)
	}
	if n, err := s.DeleteExpiredUsers(ctx, now.Add(time.Millisecond), 2*time.Hour, 1); err != nil || n != 0 {
		t.Fatalf("retention idempotence count=%d err=%v", n, err)
	}
}

func TestExpireUsersRevokesSessionsAndOAuthArtifacts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := scimDeleteStore(t)
	now := time.UnixMilli(40_000).UTC()
	subject := "expiry-revoke"
	request := `{"subject":"expiry-revoke","extra":{"act":{"sub":"expiry-revoke"}}}`
	seed := []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users(subject,username,password_phc,user_expires_at_unix_ms) VALUES(?,?,?,?)`, Args: []any{subject, subject, "phc", now.UnixMilli()}},
		{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES(?, 'password', 3, 0)`, Args: []any{subject}},
		{SQL: `INSERT INTO identity_user_profiles(subject,email) VALUES(?,?)`, Args: []any{subject, "expiry-revoke@example.test"}},
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES(?,'retained-role',0)`, Args: []any{subject}},
		{SQL: `INSERT INTO identity_webauthn_credentials(credential_id,subject,name,credential_json,sign_count,credential_version,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES('retained-key',?,'primary','{}',0,0,1,0,0)`, Args: []any{subject}},
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES(?,?,?,?,?),(?,?,?,?,?)`, Args: []any{"session-delete", subject, now.UnixMilli(), now.Add(time.Hour).UnixMilli(), now.UnixMilli(), "session-delete-2", subject, now.UnixMilli(), now.Add(time.Hour).UnixMilli(), now.UnixMilli()}},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,?,?,?),(?,?,?,?,?,?)`, Args: []any{"session-delete", "client", "https://rp.example/logout", int64(0), int64(0), now.UnixMilli(), "session-delete-2", "client", "https://rp.example/logout", int64(0), int64(0), now.UnixMilli()}},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{subject, "client", "https://rp.example/logout", int64(0), int64(0), now.UnixMilli()}},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{subject, "browserless", "https://rp.example/browserless", int64(1), int64(0), now.UnixMilli()}},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('other-user','client','https://rp.example/logout',0,0,?)`, Args: []any{now.UnixMilli()}},
		{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES(?,?,?)`, Args: []any{"expiry-code", request, now.Add(time.Hour).UnixMilli()}},
		{SQL: `INSERT INTO oauth_pkce_requests(signature,request_json,expires_at_unix_ms) VALUES(?,?,?)`, Args: []any{"expiry-code", request, now.Add(time.Hour).UnixMilli()}},
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES(?,?,?,?,?,?,?,?,?)`, Args: []any{"expiry-access", "request", "client", now.UnixMilli(), now.Add(time.Hour).UnixMilli(), "[]", "[]", "[]", "[]"}},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES(?,?)`, Args: []any{"expiry-access", request}},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"expiry-refresh", "expiry-access", "request", request, now.Add(time.Hour).UnixMilli()}},
		{SQL: `INSERT INTO oauth_device_grants(device_code_digest,user_code_digest,client_id,scopes_json,subject,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms) VALUES(?,?,?,?,?,'approved',?,?,?,?)`, Args: []any{"expiry-device", "expiry-user-code", "client", "[]", subject, now.Add(time.Hour).UnixMilli(), int64(5), now.UnixMilli(), now.UnixMilli()}},
	}
	for i, statement := range seed {
		if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "seed-expiry-revoke-" + string(rune('a'+i)), Statements: []rhiza.SQLStatement{statement}}); err != nil {
			t.Fatalf("seed statement %d: %v", i, err)
		}
	}
	for signature, payload := range map[string]string{
		"delegated-access": `{"subject":"different-owner","extra":{"act":{"sub":"expiry-revoke"}}}`,
		"neighbor-access":  `{"subject":"different-owner","extra":{"act":{"sub":"other-actor"}}}`,
	} {
		if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "seed-" + signature, Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO oauth_access_tokens SELECT ?,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience FROM oauth_access_tokens WHERE signature='expiry-access'`, Args: []any{signature}},
			{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES(?,?)`, Args: []any{signature, payload}},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	// Neither a future-deadline edit nor an unlimited-deadline edit after the
	// SELECT may partially revoke anything. Inject at the existing random source,
	// which runs between candidate selection and the atomic write; no sleeps.
	snapshot := func() [][]any {
		t.Helper()
		result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
			(SELECT revoked_at_unix_ms FROM browser_sessions WHERE token_digest='session-delete'),
			(SELECT COUNT(*) FROM oidc_session_clients), (SELECT COUNT(*) FROM oidc_user_clients WHERE subject=?), (SELECT COUNT(*) FROM oidc_backchannel_deliveries),
			(SELECT COUNT(*) FROM oauth_access_tokens), (SELECT active FROM oauth_refresh_tokens WHERE signature='expiry-refresh'),
			(SELECT invalidated FROM oauth_authorize_codes WHERE signature='expiry-code'),
			(SELECT state FROM oauth_device_grants WHERE device_code_digest='expiry-device'),
			(SELECT generation FROM identity_authentication_modes WHERE subject='expiry-revoke'),
			(SELECT disabled FROM identity_users WHERE subject='expiry-revoke')`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			t.Fatal(err)
		}
		return result.Rows
	}
	before := snapshot()
	for i, deadline := range []any{now.Add(time.Hour).UnixMilli(), nil} {
		s.random = func(p []byte) (int, error) {
			_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "edit-expiry-" + string(rune('a'+i)), SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{deadline, subject}})
			if err != nil {
				return 0, err
			}
			return rand.Read(p)
		}
		if n, err := s.ExpireUsers(ctx, now, 1); err != nil || n != 0 {
			t.Fatalf("stale deadline count=%d err=%v", n, err)
		}
		if got := snapshot(); !reflect.DeepEqual(got, before) {
			t.Fatalf("stale selection changed state: before=%v after=%v", before, got)
		}
		if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "restore-expiry-" + string(rune('a'+i)), SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{now.UnixMilli(), subject}}); err != nil {
			t.Fatal(err)
		}
	}
	s.random = rand.Read
	if n, err := s.ExpireUsers(ctx, now, 1); err != nil || n != 1 {
		t.Fatalf("expire count=%d err=%v", n, err)
	}
	// Re-enabling the account does not restore the old login or grant state.
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "reopen-revoked-user", SQL: `UPDATE identity_users SET disabled=0,user_expires_at_unix_ms=NULL WHERE subject=?`, Args: []any{subject}}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ExpireUsers(ctx, now, 1); err != nil || n != 0 {
		t.Fatalf("reopened account count=%d err=%v", n, err)
	}
	checks := []struct {
		name, sql string
		want      int64
	}{
		{"codes", `SELECT COUNT(*) FROM oauth_authorize_codes WHERE json_extract(request_json,'$.subject')=? AND invalidated=1`, 1},
		{"access", `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature='expiry-access'`, 0},
		{"requests", `SELECT COUNT(*) FROM oauth_token_requests WHERE signature='expiry-access'`, 0},
		{"delegated-access", `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature='delegated-access'`, 0},
		{"delegated-request", `SELECT COUNT(*) FROM oauth_token_requests WHERE signature='delegated-access'`, 0},
		{"neighbor-access", `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature='neighbor-access'`, 1},
		{"neighbor-request", `SELECT COUNT(*) FROM oauth_token_requests WHERE signature='neighbor-access'`, 1},
		{"refresh", `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature='expiry-refresh' AND active=0`, 1},
		{"device", `SELECT COUNT(*) FROM oauth_device_grants WHERE subject=? AND state='denied'`, 1},
		{"delivery", `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject=? AND sid IS NULL`, 2},
		{"usermaps", `SELECT COUNT(*) FROM oidc_user_clients WHERE subject=?`, 0},
		{"other-usermap", `SELECT COUNT(*) FROM oidc_user_clients WHERE subject='other-user' AND client_id='client'`, 1},
		{"sessions", `SELECT COUNT(*) FROM browser_sessions WHERE subject=? AND revoked_at_unix_ms=40000`, 2},
		{"pkce", `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature='expiry-code'`, 0},
		{"retained-key", `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id='retained-key'`, 1},
		{"retained-role", `SELECT COUNT(*) FROM rbac_user_roles WHERE subject='expiry-revoke' AND role_id='retained-role'`, 1},
		{"retained-password", `SELECT COUNT(*) FROM identity_users WHERE subject='expiry-revoke' AND password_phc='phc'`, 1},
	}
	for _, check := range checks {
		args := []any(nil)
		if check.name == "codes" || check.name == "device" || check.name == "delivery" || check.name == "usermaps" || check.name == "sessions" {
			args = []any{subject}
		}
		row, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: check.sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != check.want {
			t.Fatalf("%s rows=%v err=%v", check.name, row.Rows, err)
		}
	}
	deliveries, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id,sid,subject,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms FROM oidc_backchannel_deliveries WHERE subject=? ORDER BY client_id`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || !reflect.DeepEqual(deliveries.Rows, [][]any{
		{"browserless", nil, subject, "https://rp.example/browserless", int64(1), int64(0), int64(0), now.UnixMilli(), now.UnixMilli()},
		{"client", nil, subject, "https://rp.example/logout", int64(0), int64(0), int64(0), now.UnixMilli(), now.UnixMilli()},
	}) {
		t.Fatalf("subject deliveries=%#v err=%v", deliveries.Rows, err)
	}
	profile, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT email FROM identity_user_profiles WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(profile.Rows) != 1 || profile.Rows[0][0] != "expiry-revoke@example.test" {
		t.Fatalf("profile changed: %v", profile.Rows)
	}
}

func TestExpireUsersRollsBackAllEffectsOnFinalDisableFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := scimDeleteStore(t)
	now := time.UnixMilli(50_000).UTC()
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "seed-expiry-rollback", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users(subject,username,password_phc,user_expires_at_unix_ms,password_generation) VALUES('expiry-rollback','expiry-rollback','phc',?,3)`, Args: []any{now.UnixMilli()}},
		{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES('expiry-rollback','password',7,0)`},
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES('expiry-rollback-sid','expiry-rollback',0,100000,0)`},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('expiry-rollback-sid','client','https://rp.example/logout',0,0,0)`},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('expiry-rollback','client','https://rp.example/logout',0,0,0)`},
		{SQL: `CREATE TRIGGER expiry_rollback_abort BEFORE UPDATE ON identity_users WHEN NEW.subject='expiry-rollback' AND NEW.disabled=1 BEGIN SELECT RAISE(ABORT,'final disable unavailable'); END`},
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "drop-expiry-rollback", SQL: `DROP TRIGGER expiry_rollback_abort`})
	})
	if n, err := s.ExpireUsers(ctx, now, 1); err == nil || n != 0 {
		t.Fatalf("rollback count=%d err=%v", n, err)
	}
	for sql, want := range map[string]int64{
		`SELECT COUNT(*) FROM identity_users WHERE subject='expiry-rollback' AND disabled=0 AND password_generation=3`: 1,
		`SELECT COUNT(*) FROM identity_authentication_modes WHERE subject='expiry-rollback' AND generation=7`:          1,
		`SELECT COUNT(*) FROM oidc_user_clients WHERE subject='expiry-rollback'`:                                       1,
		`SELECT COUNT(*) FROM browser_sessions WHERE subject='expiry-rollback' AND revoked_at_unix_ms IS NULL`:         1,
		`SELECT COUNT(*) FROM oidc_session_clients WHERE sid='expiry-rollback-sid'`:                                    1,
		`SELECT COUNT(*) FROM oidc_backchannel_deliveries`:                                                             0,
	} {
		row, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: sql, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != want {
			t.Fatalf("rollback query=%q rows=%v err=%v", sql, row.Rows, err)
		}
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "drop-expiry-rollback-now", SQL: `DROP TRIGGER expiry_rollback_abort`}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ExpireUsers(ctx, now, 1); err != nil || n != 1 {
		t.Fatalf("retry count=%d err=%v", n, err)
	}
	row, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT disabled,password_generation,(SELECT generation FROM identity_authentication_modes WHERE subject='expiry-rollback'),(SELECT COUNT(*) FROM oidc_user_clients WHERE subject='expiry-rollback'),(SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject='expiry-rollback' AND sid IS NULL) FROM identity_users WHERE subject='expiry-rollback'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || !reflect.DeepEqual(row.Rows[0], []any{int64(1), int64(4), int64(8), int64(0), int64(1)}) {
		t.Fatalf("retry state=%v err=%v", row.Rows, err)
	}
}

func TestAccountRemovalSkipsEmptyBackchannelURI(t *testing.T) {
	t.Parallel()
	for _, deleting := range []bool{false, true} {
		name := "expire"
		if deleting {
			name = "delete"
		}
		t.Run(name, func(t *testing.T) {
			s := scimDeleteStore(t)
			ctx := t.Context()
			bootstrapPassword(t, s, "target", "target", []byte("CurrentPassword1"))
			_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "empty-uri-seed", Statements: []rhiza.SQLStatement{
				{SQL: `UPDATE identity_users SET user_expires_at_unix_ms=1 WHERE subject='target'`},
				{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('target','empty','',0,0,1),('target','registered','https://rp.example.test/logout',0,0,1)`},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if deleting {
				err = s.DeleteUser(ctx, "target")
			} else {
				var n int
				n, err = s.ExpireUsers(ctx, time.UnixMilli(2), 10)
				if err == nil && n != 1 {
					t.Fatalf("expired=%d", n)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			assertCount(t, s, `SELECT COUNT(*) FROM oidc_user_clients WHERE subject='target'`, 0)
			assertCount(t, s, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE client_id='empty'`, 0)
			assertCount(t, s, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE client_id='registered' AND sid IS NULL`, 1)
		})
	}
}
