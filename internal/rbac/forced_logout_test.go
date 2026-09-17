package rbac

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestForceLogoutAtomicRevocationAndDelivery(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "target")
	insertActive(t, db, "other")
	seed := []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_user_profiles(subject,email) VALUES('target','target@example.test')`},
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES('sid-a','target','pwd',1700000000000,1700003600000,1700000000000),('sid-b','target','pwd',1700000000000,1700003600000,1700000000000),('other-sid','other','pwd',1700000000000,1700003600000,1700000000000)`},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('sid-a','client','https://rp.example.test/logout',0,0,1),('sid-b','client','https://rp.example.test/logout',0,0,1),('other-sid','client','https://rp.example.test/logout',0,0,1)`},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('target','client','https://rp.example.test/logout',0,0,1),('target','browserless','https://rp.example.test/browserless',1,0,2),('other','client','https://rp.example.test/logout',0,0,1)`},
		{SQL: `INSERT INTO browser_authorization_interactions(token_digest,request_id,session_digest,payload,created_at_unix_ms,expires_at_unix_ms) VALUES('interaction','interaction','sid-a','{}',1,4102444800000)`},
		{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES('code-a','{"subject":"target"}',4102444800000)`},
		{SQL: `INSERT INTO oauth_pkce_requests(signature,request_json,expires_at_unix_ms) VALUES('code-a','{}',4102444800000)`},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES('tok-a','{"subject":"target"}'),('other-token','{"subject":"other"}')`},
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES('tok-a','tok-a','client',1700000000000,1700003600000,'','','',''),('other-token','other-token','client',1700000000000,1700003600000,'','','','')`},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES('refresh-a','tok-a','tok-a','{"subject":"target"}',4102444800000)`},
		{SQL: `INSERT INTO oauth_device_grants(device_code_digest,user_code_digest,client_id,scopes_json,subject,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms) VALUES('device-a','user-device','client','[]','target','approved',4102444800000,5,1,1)`},
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "force-seed", Statements: seed}); err != nil {
		t.Fatal(err)
	}
	check := func(sql string, want int64) {
		t.Helper()
		r, err := db.Query(ctx, rhiza.QueryRequest{SQL: sql, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(r.Rows) != 1 || r.Rows[0][0] != want {
			t.Fatalf("query=%q rows=%#v err=%v", sql, r.Rows, err)
		}
	}
	// Authority denial must preserve live state, not merely an already-empty target.
	if err := store.ForceLogout(ctx, "denied-op", "target", "0=1"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unauthorized force logout: %v", err)
	}
	check(`SELECT COUNT(*) FROM browser_sessions WHERE revoked_at_unix_ms IS NULL`, 3)
	check(`SELECT COUNT(*) FROM oauth_access_tokens`, 2)
	check(`SELECT COUNT(*) FROM oidc_session_clients`, 3)
	check(`SELECT COUNT(*) FROM oidc_user_clients`, 3)
	check(`SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 0)
	check(`SELECT COUNT(*) FROM event_log WHERE typ='ForcedLogout'`, 0)
	// An administrator may revoke their own session. Rechecking this predicate
	// after the session UPDATE would incorrectly suppress later work.
	guard := `EXISTS (SELECT 1 FROM browser_sessions WHERE token_digest=? AND subject=? AND auth_method='pwd' AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms>?)`
	if err := store.ForceLogout(ctx, "force-op", "target", guard, "sid-a", "target", store.now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	check(`SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 2)
	check(`SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE event_id='force-op' AND client_id IN ('client','browserless')`, 2)
	check(`SELECT COUNT(*) FROM oidc_session_clients`, 1)
	check(`SELECT COUNT(*) FROM oidc_user_clients WHERE subject='target'`, 0)
	check(`SELECT COUNT(*) FROM oidc_user_clients WHERE subject='other' AND client_id='client'`, 1)
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT event_id,client_id,sid,subject,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms FROM oidc_backchannel_deliveries WHERE event_id='force-op' ORDER BY client_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || !reflect.DeepEqual(rows.Rows, [][]any{
		{"force-op", "browserless", nil, "target", "https://rp.example.test/browserless", int64(1), int64(0), int64(0), int64(1700000000000), int64(1700000000000)},
		{"force-op", "client", nil, "target", "https://rp.example.test/logout", int64(0), int64(0), int64(0), int64(1700000000000), int64(1700000000000)},
	}) {
		t.Fatalf("subject deliveries=%#v err=%v", rows.Rows, err)
	}
	check(`SELECT COUNT(*) FROM browser_sessions WHERE subject='target' AND revoked_at_unix_ms IS NOT NULL`, 2)
	check(`SELECT COUNT(*) FROM browser_sessions WHERE subject='other' AND revoked_at_unix_ms IS NULL`, 1)
	check(`SELECT COUNT(*) FROM browser_authorization_interactions`, 0)
	check(`SELECT COUNT(*) FROM oauth_authorize_codes WHERE invalidated=1`, 1)
	check(`SELECT COUNT(*) FROM oauth_pkce_requests`, 0)
	check(`SELECT COUNT(*) FROM oauth_access_tokens WHERE signature='tok-a'`, 0)
	check(`SELECT COUNT(*) FROM oauth_access_tokens WHERE signature='other-token'`, 1)
	check(`SELECT COUNT(*) FROM oauth_refresh_tokens WHERE active=0`, 1)
	check(`SELECT COUNT(*) FROM oauth_token_requests WHERE signature='tok-a'`, 0)
	check(`SELECT COUNT(*) FROM oauth_token_requests WHERE signature='other-token'`, 1)
	check(`SELECT COUNT(*) FROM oauth_device_grants WHERE state='denied' AND claim_token_digest IS NULL`, 1)
	check(`SELECT COUNT(*) FROM identity_users WHERE subject='target' AND password_phc='phc'`, 1)
	check(`SELECT COUNT(*) FROM event_log WHERE typ='ForcedLogout' AND text='target@example.test'`, 1)

	check(`SELECT COUNT(*) FROM browser_sessions WHERE subject='target' AND revoked_at_unix_ms=1700000000000`, 2)
}

func TestForceLogoutEmailAndInactiveAssociations(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	for _, subject := range []string{"profile", "recovery", "empty"} {
		insertActive(t, db, subject)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "force-email-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_user_profiles(subject,email) VALUES('profile','profile@example.test')`},
		{SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES('profile','fallback@example.test'),('recovery','recovery@example.test')`},
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,revoked_at_unix_ms) VALUES('old-sid','empty','pwd',1,2,1,2)`},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('old-sid','client','https://rp.example.test/logout',0,0,1)`},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('empty','client','https://rp.example.test/logout',0,0,1)`},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ subject, email string }{{"profile", "profile@example.test"}, {"recovery", "recovery@example.test"}, {"empty", ""}} {
		if err := store.ForceLogout(ctx, "force-email-"+tc.subject, tc.subject, "1=1"); err != nil {
			t.Fatal(err)
		}
		count(t, db, `SELECT COUNT(*) FROM event_log WHERE typ='ForcedLogout' AND level=1 AND ip IS NULL AND data IS NULL AND text=?`, tc.email, 1)
	}
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, "old-sid", 0)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject=? AND sid IS NULL`, "empty", 1)
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms=2`, "old-sid", 1)
	// A later independently authorized operation does not enqueue an old association again.
	store.now = func() time.Time { return time.UnixMilli(1_700_000_001_000).UTC() }
	if err := store.ForceLogout(ctx, "force-email-empty-second", "empty", "1=1"); err != nil {
		t.Fatal(err)
	}
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, "old-sid", 0)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject=? AND sid IS NULL`, "empty", 1)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "force-email-empty-reinsert", SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('empty','client','https://rp.example.test/logout',0,0,1)`}); err != nil {
		t.Fatal(err)
	}
	if err := store.ForceLogout(ctx, "force-email-empty-renewed", "empty", "1=1"); err != nil {
		t.Fatal(err)
	}
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject=? AND sid IS NULL`, "empty", 2)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE event_id='force-email-empty-renewed' AND subject=? AND sid IS NULL`, "empty", 1)
}

func TestForceLogoutRollsBackOnEventFailure(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "rollback-target")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "force-rollback-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES('rollback-sid','rollback-target',1,4102444800000,1700000000000)`},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('rollback-sid','client','https://rp.example.test/logout',0,0,1)`},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('rollback-target','client','https://rp.example.test/logout',0,0,1)`},
		{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES('rollback-code','{"subject":"rollback-target"}',1700003600000)`},
		{SQL: `INSERT INTO oauth_pkce_requests(signature,request_json,expires_at_unix_ms) VALUES('rollback-code','{}',1700003600000)`},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES('rollback-token','{"subject":"rollback-target"}')`},
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES('rollback-token','rollback-token','client',1700000000000,1700003600000,'','','','')`},
		{SQL: `CREATE TRIGGER reject_forced_logout BEFORE INSERT ON event_log WHEN NEW.typ='ForcedLogout' BEGIN SELECT RAISE(ABORT,'event sink unavailable'); END`},
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "force-rollback-drop", SQL: `DROP TRIGGER reject_forced_logout`})
	})
	if err := store.ForceLogout(ctx, "rollback-op", "rollback-target", "1=1"); err == nil {
		t.Fatal("event failure unexpectedly committed")
	}
	for sql, want := range map[string]int64{
		`SELECT COUNT(*) FROM browser_sessions WHERE subject='rollback-target' AND revoked_at_unix_ms IS NULL`: 1,
		`SELECT COUNT(*) FROM oidc_session_clients WHERE sid='rollback-sid'`:                                   1,
		`SELECT COUNT(*) FROM oidc_user_clients WHERE subject='rollback-target'`:                               1,
		`SELECT COUNT(*) FROM oidc_backchannel_deliveries`:                                                     0,
		`SELECT COUNT(*) FROM event_log WHERE typ='ForcedLogout'`:                                              0,
		`SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature='rollback-code' AND invalidated=0`:         1,
		`SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature='rollback-code'`:                             1,
		`SELECT COUNT(*) FROM oauth_access_tokens WHERE signature='rollback-token'`:                            1,
		`SELECT COUNT(*) FROM oauth_token_requests WHERE signature='rollback-token'`:                           1,
		`SELECT COUNT(*) FROM event_log_order`:                                                                 0,
	} {
		r, err := db.Query(ctx, rhiza.QueryRequest{SQL: sql, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(r.Rows) != 1 || r.Rows[0][0] != want {
			t.Fatalf("rollback query=%q rows=%#v err=%v", sql, r.Rows, err)
		}
	}
}

func TestForceLogoutConcurrentSameClientSubjects(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "same-client-a")
	insertActive(t, db, "same-client-b")
	seed := []rhiza.SQLStatement{
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES('same-client-a-sid','same-client-a','pwd',1,4102444800000,1),('same-client-b-sid','same-client-b','pwd',1,4102444800000,1)`},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('same-client-a-sid','shared-client','https://rp.example.test/logout',0,0,1),('same-client-b-sid','shared-client','https://rp.example.test/logout',0,0,1)`},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('same-client-a','shared-client','https://rp.example.test/logout',0,0,1),('same-client-b','shared-client','https://rp.example.test/logout',0,0,1)`},
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "force-concurrent-seed", Statements: seed}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	for _, subject := range []string{"same-client-a", "same-client-b"} {
		wg.Add(1)
		go func(subject string) {
			defer wg.Done()
			<-start
			errCh <- store.ForceLogout(ctx, "force-concurrent-"+subject, subject, "1=1")
		}(subject)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid IS NULL AND client_id='shared-client' AND ?`, 1, 2)
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,client_id,sid FROM oidc_backchannel_deliveries ORDER BY subject`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || !reflect.DeepEqual(rows.Rows, [][]any{
		{"same-client-a", "shared-client", nil},
		{"same-client-b", "shared-client", nil},
	}) {
		t.Fatalf("concurrent deliveries=%#v err=%v", rows.Rows, err)
	}
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE revoked_at_unix_ms IS NOT NULL AND ?`, 1, 2)
	count(t, db, `SELECT COUNT(*) FROM oidc_user_clients WHERE ?`, 1, 0)
	count(t, db, `SELECT COUNT(*) FROM event_log WHERE typ='ForcedLogout' AND ?`, 1, 2)
}
