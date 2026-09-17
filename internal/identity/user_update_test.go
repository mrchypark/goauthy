package identity

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const userUpdateNow int64 = 1_800_000_000_000

func userUpdateTestAuthority() (string, []any) { return "1=1", nil }

func userUpdateFixture(t *testing.T) (*Store, UserUpdate) {
	t.Helper()
	s := testResetStore(t, testRules(3))
	s.now = func() time.Time { return time.UnixMilli(userUpdateNow) }
	seedDeterministicRandom(s)
	for _, user := range []struct{ subject, username string }{{"target", "old@example.test"}, {"other", "other@example.test"}, {"admin", "admin"}} {
		bootstrapPassword(t, s, user.subject, user.username, []byte("OriginalPassword1"))
	}
	userUpdateExecute(t, s, "fixture", []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username,given_name,family_name,user_values_json) VALUES
		 ('target','old@example.test',1,'keep-preferred','Old','Family','{"city":"Old City"}'),
		 ('other','other@example.test',1,NULL,NULL,NULL,NULL),('admin','admin@example.test',1,NULL,NULL,NULL,NULL)`},
		{SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES('target','old@example.test'),('other','other@example.test'),('admin','admin@example.test')`},
		{SQL: `INSERT INTO rbac_roles(id,name,created_at_unix_ms,updated_at_unix_ms) VALUES('admin','rauthy_admin',0,0),('viewer','viewer',0,0),('editor','editor',0,0)`},
		{SQL: `INSERT INTO rbac_groups(id,name,created_at_unix_ms,updated_at_unix_ms) VALUES('a','team/a',0,0),('b','team/b',0,0)`},
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('target','viewer',0),('admin','admin',0)`},
		{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) VALUES('target','a',0)`},
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms)
		 VALUES('target-session','target','pwd',1,1900000000000,1),('other-session','other','pwd',1,1900000000000,1)`},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('target-session','client','https://rp.example.test/logout',0,0,1)`},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('target','client','https://rp.example.test/logout',0,0,1)`},
		{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES('target-code','{"subject":"target"}',1900000000000)`},
		{SQL: `INSERT INTO oauth_pkce_requests(signature,request_json,expires_at_unix_ms) VALUES('target-code','{"subject":"target"}',1900000000000)`},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES('target-token','{"subject":"target"}'),('other-token','{"subject":"other"}'),('actor-token','{"subject":"other","extra":{"act":{"sub":"target"}}}')`},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES('target-refresh','target-token','r1','{"subject":"target"}',1900000000000),('other-refresh','other-token','r2','{"subject":"other"}',1900000000000)`},
	})
	return s, UserUpdate{Email: "old@example.test", Roles: []string{"viewer"}, Groups: []string{"team/a"}, Enabled: true, EmailVerified: true}
}

func userUpdateExecute(t *testing.T, s *Store, id string, statements []rhiza.SQLStatement) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), s.db, rhiza.ExecuteRequest{RequestID: "user-update-test/" + id, Statements: statements}); err != nil {
		t.Fatal(err)
	}
}

func userUpdateSnapshot(t *testing.T, s *Store) map[string][][]any {
	t.Helper()
	snapshot := map[string][][]any{}
	for _, table := range []string{"identity_users", "identity_user_profiles", "identity_recovery_emails", "identity_authentication_modes", "identity_password_history", "identity_password_reset_tokens", "rbac_user_roles", "rbac_user_groups", "rbac_principal_versions", "browser_sessions", "oauth_authorize_codes", "oauth_pkce_requests", "oauth_token_requests", "oauth_refresh_tokens", "oidc_session_clients", "oidc_user_clients", "oidc_backchannel_deliveries", "event_log", "event_log_order"} {
		result, err := s.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT * FROM ` + table + ` ORDER BY 1,2`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			t.Fatal(err)
		}
		snapshot[table] = result.Rows
	}
	return snapshot
}

func assertUserUpdateSnapshot(t *testing.T, s *Store, before map[string][][]any) {
	t.Helper()
	after := userUpdateSnapshot(t, s)
	for table, rows := range before {
		if !reflect.DeepEqual(rows, after[table]) {
			t.Errorf("unexpected mutation in %s", table) // Snapshots contain PHCs: don't print.
		}
	}
}

func TestUpdateUserReplacesProfileAndPreservesSeparateState(t *testing.T) {
	s, input := userUpdateFixture(t)
	ctx := context.Background()
	raw, _, err := s.IssuePasswordResetForEmail(ctx, "target", input.Email, time.Hour)
	if err != nil || raw == "" {
		t.Fatal(err)
	}
	language, name, expiry := "ko", "New", userUpdateNow+3600000
	input.Email, input.Language, input.GivenName, input.UserExpires = "new@example.test", &language, &name, &expiry
	input.Roles, input.Groups = []string{"editor", "unknown"}, []string{"team/b", "unknown"}
	input.UserValuesJSON = `{"tz":"Asia/Seoul"}`
	result, err := s.UpdateUserWithGuard(ctx, "target", input, userUpdateTestAuthority)
	if err != nil || result.OldEmail != "old@example.test" || result.Email != input.Email || !result.EmailChanged || result.Language != "ko" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if result.User.ID != "target" || result.User.Email != input.Email || result.User.Language != "ko" || !reflect.DeepEqual(result.User.Roles, []string{"editor"}) || !reflect.DeepEqual(result.User.Groups, []string{"team/b"}) || result.User.UserValues.PreferredUsername == nil || *result.User.UserValues.PreferredUsername != "keep-preferred" || result.User.UserExpires == nil || *result.User.UserExpires != expiry/1000 {
		t.Fatal("mutation did not return its sanitized committed profile")
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_users WHERE subject='target' AND username='new@example.test' AND language='ko' AND password_generation=1 AND user_expires_at_unix_ms=1800003600000`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='target' AND email='new@example.test' AND given_name='New' AND family_name IS NULL AND preferred_username='keep-preferred' AND json_extract(user_values_json,'$.tz')='Asia/Seoul'`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM identity_recovery_emails WHERE subject='target' AND email='new@example.test'`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM rbac_user_roles WHERE subject='target' AND role_id='editor'`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM rbac_user_groups WHERE subject='target' AND group_id='b'`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM rbac_principal_versions WHERE subject='target' AND revision=2`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM browser_sessions WHERE subject='target' AND revoked_at_unix_ms=1800000000000`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM browser_sessions WHERE subject='other' AND revoked_at_unix_ms IS NULL`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE active=1`, 2)
	assertCount(t, s, `SELECT COUNT(*) FROM oidc_user_clients`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 0)
	assertCount(t, s, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject='target'`, 0)
	assertCount(t, s, `SELECT COUNT(*) FROM event_log WHERE typ='UserEmailChange' AND text='Change by admin: old@example.test -> new@example.test' AND ip IS NULL AND data IS NULL AND timestamp=1800000000000`, 1)
	if _, err := s.BeginPasswordReset(ctx, "target", raw); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("old-address link remains usable: %v", err)
	}
	before := userUpdateSnapshot(t, s)
	if result, err := s.UpdateUserWithGuard(ctx, "target", input, userUpdateTestAuthority); err != nil || result.EmailChanged {
		t.Fatalf("same value update=%+v err=%v", result, err)
	}
	assertUserUpdateSnapshot(t, s, before)
	input.Language, input.GivenName, input.UserExpires, input.Groups, input.UserValuesJSON = nil, nil, nil, nil, ""
	if _, err := s.UpdateUserWithGuard(ctx, "target", input, userUpdateTestAuthority); err != nil {
		t.Fatal(err)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_users WHERE subject='target' AND language='ko' AND user_expires_at_unix_ms IS NULL`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='target' AND given_name IS NULL AND user_values_json IS NULL AND preferred_username='keep-preferred'`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM rbac_user_groups WHERE subject='target'`, 0)
}

func TestUpdateUserDenialConflictAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name, change string
		denied       bool
	}{
		{"denied before read", "", true},
		{"email conflict", `UPDATE identity_user_profiles SET email='new@example.test' WHERE subject='other'`, false},
		{"recovery conflict", `UPDATE identity_recovery_emails SET email='new@example.test' WHERE subject='other'`, false},
		{"username conflict", `UPDATE identity_users SET username='new@example.test' WHERE subject='other'`, false},
		{"event rollback", `CREATE TRIGGER reject_update_event BEFORE INSERT ON event_log BEGIN SELECT RAISE(ABORT,'update event unavailable'); END`, false},
		{"profile rollback", `CREATE TRIGGER reject_update_profile BEFORE UPDATE ON identity_user_profiles BEGIN SELECT RAISE(ABORT,'profile unavailable'); END`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, input := userUpdateFixture(t)
			if tc.change != "" {
				userUpdateExecute(t, s, "interpose", []rhiza.SQLStatement{{SQL: tc.change}})
			}
			before := userUpdateSnapshot(t, s)
			guard := "1=1"
			if tc.denied {
				guard = "0=1"
			}
			input.Email, input.Roles, input.Groups = "new@example.test", []string{"editor"}, nil
			if result, err := s.UpdateUserWithGuard(context.Background(), "target", input, func() (string, []any) { return guard, nil }); err == nil || !reflect.DeepEqual(result, UserUpdateResult{}) {
				t.Fatalf("unexpected success/result: %+v err=%v", result, err)
			}
			assertUserUpdateSnapshot(t, s, before)
		})
	}
}

func TestUpdateUserDisableReactivateAndFinalAdministrator(t *testing.T) {
	s, input := userUpdateFixture(t)
	ctx := context.Background()
	input.Enabled = false
	if _, err := s.UpdateUserWithGuard(ctx, "target", input, userUpdateTestAuthority); err != nil {
		t.Fatal(err)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_users WHERE subject='target' AND disabled=1`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature='target-code' AND invalidated=1`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature='target-code'`, 0)
	assertCount(t, s, `SELECT COUNT(*) FROM oauth_token_requests WHERE signature IN('target-token','actor-token')`, 0)
	assertCount(t, s, `SELECT COUNT(*) FROM oauth_token_requests WHERE signature='other-token'`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature='target-refresh' AND active=0`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature='other-refresh' AND active=1`, 1)
	input.Enabled = true
	if _, err := s.UpdateUserWithGuard(ctx, "target", input, userUpdateTestAuthority); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, input.Email, []byte("OriginalPassword1")); err != nil {
		t.Fatal(err)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM browser_sessions WHERE subject='target' AND revoked_at_unix_ms IS NOT NULL`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature='target-refresh' AND active=0`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 0)
	input.Email, input.Roles = "admin@example.test", []string{"rauthy_admin"}
	before := userUpdateSnapshot(t, s)
	for _, variant := range []string{"disable", "demote", "expire"} {
		dangerous := input
		switch variant {
		case "disable":
			dangerous.Enabled = false
		case "demote":
			dangerous.Roles = nil
		case "expire":
			expiry := userUpdateNow
			dangerous.UserExpires = &expiry
		}
		if _, err := s.UpdateUserWithGuard(ctx, "admin", dangerous, userUpdateTestAuthority); !errors.Is(err, ErrUpdateConflict) {
			t.Fatalf("last admin %s: %v", variant, err)
		}
		assertUserUpdateSnapshot(t, s, before)
	}
	input.Email = "new-admin@example.test"
	if _, err := s.UpdateUserWithGuard(ctx, "admin", input, userUpdateTestAuthority); err != nil {
		t.Fatal(err)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_users WHERE subject='admin' AND username='admin'`, 1)
}

func TestUpdateUserRechecksSnapshotAndAuthorityAtCommit(t *testing.T) {
	for _, change := range []string{
		`UPDATE identity_users SET disabled=1 WHERE subject='admin'`,
		`UPDATE identity_user_profiles SET given_name='Concurrent' WHERE subject='target'`,
		`UPDATE identity_recovery_emails SET email='concurrent@example.test' WHERE subject='target'`,
	} {
		s, input := userUpdateFixture(t)
		var before map[string][][]any
		s.now = func() time.Time {
			userUpdateExecute(t, s, "interposed-state", []rhiza.SQLStatement{{SQL: change}})
			before = userUpdateSnapshot(t, s)
			return time.UnixMilli(userUpdateNow)
		}
		input.Email = "new@example.test"
		if _, err := s.UpdateUserWithGuard(context.Background(), "target", input, func() (string, []any) {
			return `EXISTS(SELECT 1 FROM identity_users WHERE subject='admin' AND disabled=0)`, nil
		}); !errors.Is(err, ErrUpdateConflict) {
			t.Fatalf("interposed mutation err=%v", err)
		}
		assertUserUpdateSnapshot(t, s, before)
	}
}

func TestUpdateUserConcurrentEditsHaveOneSnapshotWinner(t *testing.T) {
	s, input := userUpdateFixture(t)
	arrived, release := make(chan struct{}, 2), make(chan struct{})
	s.now = func() time.Time { arrived <- struct{}{}; <-release; return time.UnixMilli(userUpdateNow) }
	results := make(chan error, 2)
	for _, address := range []string{"first@example.test", "second@example.test"} {
		go func() {
			local := input
			local.Email = address
			_, err := s.UpdateUserWithGuard(context.Background(), "target", local, userUpdateTestAuthority)
			results <- err
		}()
	}
	<-arrived
	<-arrived
	close(release)
	a, b := <-results, <-results
	if !((a == nil && errors.Is(b, ErrUpdateConflict)) || (b == nil && errors.Is(a, ErrUpdateConflict))) {
		t.Fatalf("concurrent results %v / %v", a, b)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM event_log WHERE typ='UserEmailChange'`, 1)
}

func TestUpdateUserRefreshesAuthorizationTimeAfterPasswordWork(t *testing.T) {
	s, input := userUpdateFixture(t)
	before := userUpdateSnapshot(t, s)
	clock, calls := int64(10), 0
	authority := func() (string, []any) { calls++; return "? < 11", []any{clock} }
	s.now = func() time.Time { clock = 11; return time.UnixMilli(userUpdateNow) }
	password := "NextPassword2"
	input.Password = &password
	if _, err := s.UpdateUserWithGuard(context.Background(), "target", input, authority); !errors.Is(err, ErrUpdateConflict) || calls != 2 {
		t.Fatalf("expired authority accepted or not refreshed: calls=%d err=%v", calls, err)
	}
	assertUserUpdateSnapshot(t, s, before)
}

func TestUpdateUserCancelsInflightProofsWithoutDeletingPasskeys(t *testing.T) {
	s, input := userUpdateFixture(t)
	code, otherCode, session := strings.Repeat("a", 43), strings.Repeat("b", 43), strings.Repeat("s", 43)
	userUpdateExecute(t, s, "inflight-proofs", []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_webauthn_mfa_proofs(code_digest,subject,session_digest,expires_at_unix_ms) VALUES(?,'target',?,1900000000000),(?,'other',?,1900000000000)`, Args: []any{code, session, otherCode, session}},
		{SQL: `INSERT INTO identity_webauthn_service_proof_purposes(code_digest,purpose) VALUES(?,'PasswordNew'),(?,'PasswordNew')`, Args: []any{code, otherCode}},
		{SQL: `INSERT INTO identity_mfa_mod_tokens(token_digest,subject,session_digest,expires_at_unix_ms) VALUES(?,'target',?,1900000000000),(?,'other',?,1900000000000)`, Args: []any{code, session, otherCode, session}},
		{SQL: `INSERT INTO identity_mfa_mod_token_factors(token_digest,proof_kind) VALUES(?,'password'),(?,'password')`, Args: []any{code, otherCode}},
		{SQL: `INSERT INTO identity_webauthn_credentials(credential_id,subject,name,credential_json,sign_count,credential_version,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES('retained-passkey','target','primary','{}',0,0,1,0,0)`},
	})
	input.Enabled = false
	if _, err := s.UpdateUserWithGuard(context.Background(), "target", input, userUpdateTestAuthority); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"identity_webauthn_mfa_proofs", "identity_mfa_mod_tokens"} {
		assertCount(t, s, `SELECT COUNT(*) FROM `+table+` WHERE subject='target'`, 0)
		assertCount(t, s, `SELECT COUNT(*) FROM `+table+` WHERE subject='other'`, 1)
	}
	for _, table := range []string{"identity_webauthn_service_proof_purposes", "identity_mfa_mod_token_factors"} {
		assertCount(t, s, `SELECT COUNT(*) FROM `+table, 1)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE subject='target'`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM identity_authentication_modes WHERE subject='target' AND generation=2 AND mode='password'`, 1)
}

func TestUpdateUserPromotionEventsRollbackAndRetry(t *testing.T) {
	s, input := userUpdateFixture(t)
	password := "NextPassword2"
	input.Email, input.Roles, input.Password, input.SourceIP = "new@example.test", []string{"rauthy_admin"}, &password, "203.0.113.8"
	userUpdateExecute(t, s, "reject-promotion", []rhiza.SQLStatement{{SQL: `CREATE TRIGGER reject_promotion BEFORE INSERT ON event_log WHEN NEW.typ='NewRauthyAdmin' BEGIN SELECT RAISE(ABORT,'promotion event unavailable'); END`}})
	before := userUpdateSnapshot(t, s)
	if _, err := s.UpdateUserWithGuard(context.Background(), "target", input, userUpdateTestAuthority); err == nil {
		t.Fatal("failed final event committed password/profile/membership writes")
	}
	assertUserUpdateSnapshot(t, s, before)
	userUpdateExecute(t, s, "allow-promotion", []rhiza.SQLStatement{{SQL: `DROP TRIGGER reject_promotion`}})
	if _, err := s.UpdateUserWithGuard(context.Background(), "target", input, userUpdateTestAuthority); err != nil {
		t.Fatal(err)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM event_log WHERE typ='NewRauthyAdmin' AND level=1 AND text='new@example.test' AND ip='203.0.113.8' AND timestamp=1800000000000`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM event_log WHERE typ='UserPasswordReset' AND level=1 AND text='Reset done by admin for user new@example.test' AND ip IS NULL AND data IS NULL`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM event_log WHERE typ='UserEmailChange'`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM event_log WHERE typ='NewUserRegistered'`, 0)
	input.Password = nil
	if _, err := s.UpdateUserWithGuard(context.Background(), "target", input, userUpdateTestAuthority); err != nil {
		t.Fatal(err)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM event_log`, 3)
}

func TestUpdateUserConcurrentDisablePreservesOneAdministrator(t *testing.T) {
	s, input := userUpdateFixture(t)
	input.Roles = []string{"rauthy_admin"}
	if _, err := s.UpdateUserWithGuard(context.Background(), "target", input, userUpdateTestAuthority); err != nil {
		t.Fatal(err)
	}
	arrived, release := make(chan struct{}, 2), make(chan struct{})
	s.now = func() time.Time { arrived <- struct{}{}; <-release; return time.UnixMilli(userUpdateNow) }
	results := make(chan error, 2)
	for _, subject := range []string{"target", "admin"} {
		go func() {
			local := input
			local.Enabled = false
			if subject == "admin" {
				local.Email = "admin@example.test"
			}
			_, err := s.UpdateUserWithGuard(context.Background(), subject, local, userUpdateTestAuthority)
			results <- err
		}()
	}
	<-arrived
	<-arrived
	close(release)
	a, b := <-results, <-results
	if !((a == nil && errors.Is(b, ErrUpdateConflict)) || (b == nil && errors.Is(a, ErrUpdateConflict))) {
		t.Fatalf("concurrent admin disabling: %v / %v", a, b)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id WHERE u.disabled=0 AND r.name='rauthy_admin'`, 1)
}
