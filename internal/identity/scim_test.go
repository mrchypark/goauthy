package identity

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/scim"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestListSCIMUsersIsCompleteOrderedAndCredentialFree(t *testing.T) {
	t.Parallel()
	store := testStore(t)
	ctx := context.Background()
	for _, row := range []struct {
		subject, username, password, mode string
		disabled                          int64
	}{
		{subject: "subject-z", username: "zara", password: "phc-z", mode: "password"},
		{subject: "subject-b", username: "bob", password: "", mode: "password"},
		{subject: "subject-c", username: "carol", password: "", mode: "passkey"},
		{subject: "subject-a", username: "alice", password: "phc-a", mode: "password", disabled: 1},
	} {
		_, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
			RequestID: "identity-scim-seed-" + row.subject,
			Statements: []rhiza.SQLStatement{
				{SQL: `INSERT INTO identity_users (subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation) VALUES (?,?,?,?,0,1)`, Args: []any{row.subject, row.username, row.password, row.disabled}},
				{SQL: `INSERT INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES (?, ?, 1, 0)`, Args: []any{row.subject, row.mode}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	users, err := store.ListSCIMUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []SCIMUser{
		{ExternalID: "subject-a", UserName: "alice", Active: false},
		{ExternalID: "subject-b", UserName: "bob", Active: false},
		{ExternalID: "subject-c", UserName: "carol", Active: true},
		{ExternalID: "subject-z", UserName: "zara", Active: true},
	}
	if len(users) != len(want) {
		t.Fatalf("users=%#v", users)
	}
	for i := range want {
		if users[i] != want[i] {
			t.Fatalf("users[%d]=%#v want=%#v", i, users[i], want[i])
		}
	}
}

func TestDeleteUserTombstonesAndDeletesOwnedRows(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	seedDeterministicRandom(store)
	store.now = func() time.Time { return time.UnixMilli(42_000) }
	ctx := context.Background()
	bootstrapPassword(t, store, "subject-delete", "alice", []byte("CurrentPassword1"))
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-owned-rows", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_recovery_emails (subject,email) VALUES ('subject-delete','alice@example.test')`},
		{SQL: `INSERT INTO identity_user_profiles (subject,email,email_verified) VALUES ('subject-delete','profile@example.test',1)`},
		{SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES ('subject-delete','role-1',0)`},
		{SQL: `INSERT INTO identity_external_links (provider_id,external_key,local_subject,linked_at_unix_ms) VALUES ('google',?,'subject-delete',0)`, Args: []any{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA"}},
		{SQL: `INSERT INTO user_attribute_values (subject,key,value_json,updated_at_unix_ms) VALUES ('subject-delete','department','"engineering"',0)`},
		{SQL: `INSERT INTO browser_sessions (token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES ('session-delete','subject-delete',0,1,0)`},
		{SQL: `INSERT INTO browser_authorization_interactions (token_digest,request_id,session_digest,payload,created_at_unix_ms,expires_at_unix_ms) VALUES ('interaction-delete','request-delete','session-delete','{}',0,1)`},
		{SQL: `INSERT INTO identity_webauthn_users (subject,user_handle,created_at_unix_ms) VALUES ('subject-delete',?,0)`, Args: []any{strings.Repeat("u", 42) + "A"}},
		{SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,credential_version,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES ('credential-delete','subject-delete','primary','{}',0,0,1,0,0)`},
		{SQL: `INSERT INTO identity_webauthn_ceremonies (code_digest,purpose,subject,session_digest,passkey_name,session_json,expires_at_unix_ms) VALUES (?,?,?,?,'passkey','{}',1)`, Args: []any{strings.Repeat("c", 42) + "A", "register", "subject-delete", strings.Repeat("s", 42) + "A"}},
		{SQL: `INSERT INTO identity_webauthn_mfa_ceremonies (code_digest,subject,session_digest,session_json,expires_at_unix_ms,proof_expires_at_unix_ms) VALUES (?,?,?,?,1,1)`, Args: []any{strings.Repeat("m", 42) + "A", "subject-delete", strings.Repeat("t", 42) + "A", "{}"}},
		{SQL: `INSERT INTO identity_webauthn_service_ceremony_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{strings.Repeat("m", 42) + "A", "MfaModToken"}},
		{SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,1)`, Args: []any{strings.Repeat("p", 42) + "A", "subject-delete", strings.Repeat("t", 42) + "A"}},
		{SQL: `INSERT INTO identity_webauthn_service_proof_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{strings.Repeat("p", 42) + "A", "MfaModToken"}},
		{SQL: `INSERT INTO identity_mfa_mod_tokens (token_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,1)`, Args: []any{strings.Repeat("x", 42) + "A", "subject-delete", strings.Repeat("t", 42) + "A"}},
		{SQL: `INSERT INTO identity_mfa_mod_token_factors (token_digest,proof_kind) VALUES (?,?)`, Args: []any{strings.Repeat("x", 42) + "A", "webauthn"}},
		{SQL: `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,link_subject,link_session_digest,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'link',?,?,1,0)`, Args: []any{strings.Repeat("q", 42) + "A", strings.Repeat("b", 42) + "A", "google", "envelope", "https://issuer.example.test", "", "client", `["openid"]`, "https://goauthy.example.test/callback", "subject-delete", strings.Repeat("l", 42) + "A"}},
		{SQL: `INSERT INTO oidc_session_clients (sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES ('session-delete','client-delete','https://rp.example.test/logout',0,0,0)`},
		{SQL: `INSERT INTO oidc_user_clients (subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES ('subject-delete','client-delete','https://rp.example.test/logout',0,0,0)`},
		{SQL: `INSERT INTO scim_user_outbox (job_id,client_id,external_id,request_json,request_digest,status,next_attempt_at_unix_ms,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?, 'client','subject-delete','{"operation":"sync","user":{"externalId":"subject-delete"}}',?,'pending',0,1,0,0), (?, 'client','hashed-user-key','{"operation":"delete","user":{"externalId":"subject-delete"}}',?,'pending',0,1,0,0), (?, 'client','group:subject-delete','{"operation":"sync","user":{"externalId":"subject-delete"},"group":{"externalId":"subject-delete"}}',?,'pending',0,1,0,0)`, Args: []any{strings.Repeat("a", 42) + "A", strings.Repeat("b", 42) + "E", strings.Repeat("c", 42) + "I", strings.Repeat("d", 42) + "M", strings.Repeat("e", 42) + "Q", strings.Repeat("f", 42) + "U"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUser(ctx, "subject-delete"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"identity_users", "identity_authentication_modes", "identity_recovery_emails", "identity_user_profiles", "rbac_user_roles", "identity_external_links", "identity_webauthn_users", "identity_webauthn_credentials", "identity_webauthn_ceremonies", "identity_webauthn_mfa_ceremonies", "identity_webauthn_service_ceremony_purposes", "identity_webauthn_mfa_proofs", "identity_webauthn_service_proof_purposes", "identity_mfa_mod_tokens", "identity_mfa_mod_token_factors", "upstream_provider_transactions"} {
		column := "subject"
		if table == "identity_external_links" {
			column = "local_subject"
		}
		if table == "identity_webauthn_service_ceremony_purposes" || table == "identity_webauthn_service_proof_purposes" || table == "identity_mfa_mod_token_factors" {
			column = "code_digest"
		}
		if table == "identity_mfa_mod_token_factors" {
			column = "token_digest"
		}
		if table == "upstream_provider_transactions" {
			column = "link_subject"
		}
		value := "subject-delete"
		if table == "identity_webauthn_service_ceremony_purposes" {
			value = strings.Repeat("m", 42) + "A"
		}
		if table == "identity_webauthn_service_proof_purposes" {
			value = strings.Repeat("p", 42) + "A"
		}
		if table == "identity_mfa_mod_token_factors" {
			value = strings.Repeat("x", 42) + "A"
		}
		result, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM ` + table + ` WHERE ` + column + ` = ?`, Args: []any{value}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
			t.Fatalf("%s retained rows=%#v err=%v", table, result.Rows, err)
		}
	}
	for _, tc := range []struct{ table, column string }{{"user_attribute_values", "subject"}, {"browser_authorization_interactions", "session_digest"}} {
		result, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM ` + tc.table + ` WHERE ` + tc.column + ` = 'subject-delete'`, Consistency: rhiza.ConsistencyLinearizable})
		if tc.table == "browser_authorization_interactions" {
			result, err = store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM browser_authorization_interactions WHERE session_digest = 'session-delete'`, Consistency: rhiza.ConsistencyLinearizable})
		}
		if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
			t.Fatalf("%s retained rows=%#v err=%v", tc.table, result.Rows, err)
		}
	}
	assertCount(t, store, `SELECT COUNT(*) FROM oidc_session_clients WHERE sid = 'session-delete'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM oidc_user_clients WHERE subject = 'subject-delete'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject = 'subject-delete' AND sid IS NULL`, 1)
	result, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT external_id FROM scim_user_outbox ORDER BY external_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "group:subject-delete" {
		t.Fatalf("SCIM outbox rows=%#v err=%v", result.Rows, err)
	}
	deleted, err := store.ListSCIMDeletedUsers(ctx)
	if err != nil || len(deleted) != 1 || !reflect.DeepEqual(deleted[0], SCIMDeletedUser{ExternalID: "subject-delete", UserName: "alice", Active: true, HardDelete: true, ProviderSnapshotComplete: true, Generation: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), DeletedAtUnixMS: 42_000}) {
		t.Fatalf("deleted=%#v err=%v", deleted, err)
	}
	if _, err := store.BootstrapUser(ctx, "subject-delete", "other", "phc"); !errors.Is(err, ErrBootstrapConflict) {
		t.Fatalf("tombstoned subject recreated: %v", err)
	}
}

func TestDeleteUserSubjectDeliveryIsolationAndRollback(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	store.now = func() time.Time { return time.UnixMilli(42_000) }
	ctx := t.Context()
	for _, subject := range []string{"delete-target", "delete-other"} {
		bootstrapPassword(t, store, subject, subject, []byte("CurrentPassword1"))
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "delete-subject-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES('target-a','delete-target',1,90000,1),('target-b','delete-target',1,90000,1),('other','delete-other',1,90000,1)`},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('target-a','shared','https://rp.example/logout',0,0,1),('target-b','shared','https://rp.example/logout',0,0,1),('other','shared','https://rp.example/logout',0,0,1)`},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('delete-target','shared','https://rp.example/logout',0,0,1),('delete-target','browserless','https://other.example/logout',1,0,1),('delete-other','shared','https://rp.example/logout',0,0,1)`},
	}}); err != nil {
		t.Fatal(err)
	}
	unchanged := func() {
		t.Helper()
		assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='delete-target'`, 1)
		assertCount(t, store, `SELECT COUNT(*) FROM browser_sessions`, 3)
		assertCount(t, store, `SELECT COUNT(*) FROM oidc_session_clients`, 3)
		assertCount(t, store, `SELECT COUNT(*) FROM oidc_user_clients`, 3)
		assertCount(t, store, `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 0)
		assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones`, 0)
	}
	if err := store.DeleteUserWithGuard(ctx, "delete-target", "0=1", nil); !errors.Is(err, ErrDeleteUnauthorized) {
		t.Fatalf("denied deletion: %v", err)
	}
	unchanged()
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "delete-subject-abort", SQL: `CREATE TRIGGER reject_subject_delete BEFORE DELETE ON identity_users WHEN OLD.subject='delete-target' BEGIN SELECT RAISE(ABORT,'delete failure'); END`}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUserWithGuard(ctx, "delete-target", "1=1", nil); err == nil {
		t.Fatal("late deletion failure committed")
	}
	unchanged()
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "delete-subject-unblock", SQL: `DROP TRIGGER reject_subject_delete`}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUserWithGuard(ctx, "delete-target", "1=1", nil); err != nil {
		t.Fatal(err)
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,client_id,sid,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms FROM oidc_backchannel_deliveries ORDER BY client_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || !reflect.DeepEqual(rows.Rows, [][]any{
		{"delete-target", "browserless", nil, "https://other.example/logout", int64(1), int64(0), int64(0), int64(42000), int64(42000)},
		{"delete-target", "shared", nil, "https://rp.example/logout", int64(0), int64(0), int64(0), int64(42000), int64(42000)},
	}) {
		t.Fatalf("subject deliveries=%v err=%v", rows.Rows, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM oidc_user_clients`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oidc_user_clients WHERE subject='delete-other' AND client_id='shared'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oidc_session_clients`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM browser_sessions WHERE subject='delete-other' AND revoked_at_unix_ms IS NULL`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='delete-target'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='delete-target'`, 1)
}

func TestListSCIMDeletedUsersIsOrderedAndDeleteRollsBack(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	ctx := context.Background()
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-tombstone-order", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,deleted_at_unix_ms) VALUES ('subject-z','zara',0,2),('subject-a','alice',1,2),('subject-b','bob',1,1)`},
	}}); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.ListSCIMDeletedUsers(ctx)
	if err != nil || len(deleted) != 3 || deleted[0].ExternalID != "subject-b" || deleted[1].ExternalID != "subject-a" || deleted[2].ExternalID != "subject-z" {
		t.Fatalf("deleted=%#v err=%v", deleted, err)
	}
	bootstrapPassword(t, store, "subject-rollback", "carol", []byte("CurrentPassword1"))
	store.now = func() time.Time { return time.UnixMilli(43_000) }
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-abort-trigger", SQL: `CREATE TRIGGER identity_delete_abort BEFORE DELETE ON identity_users WHEN old.subject = 'subject-rollback' BEGIN SELECT RAISE(ABORT, 'test rollback'); END`}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUser(ctx, "subject-rollback"); err == nil {
		t.Fatal("delete unexpectedly committed")
	}
	result, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_users WHERE subject = 'subject-rollback' UNION ALL SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id = 'subject-rollback'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 2 || result.Rows[0][0] != int64(1) || result.Rows[1][0] != int64(0) {
		t.Fatalf("rollback rows=%#v err=%v", result.Rows, err)
	}
}

func TestDeleteUserSnapshotsConcurrentValidUpdateAtTransactionTime(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	seedDeterministicRandom(store)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(44_000) }
	bootstrapPassword(t, store, "subject-race", "alice", []byte("CurrentPassword1"))
	read := make(chan struct{})
	proceed := make(chan struct{})
	store.deleteUserAfterRead = func() {
		close(read)
		<-proceed
	}
	errCh := make(chan error, 1)
	go func() { errCh <- store.DeleteUser(ctx, "subject-race") }()
	<-read
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-race-update", SQL: `UPDATE identity_users SET username='alice-updated',disabled=1 WHERE subject='subject-race'`}); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	deleted, err := store.ListSCIMDeletedUsers(ctx)
	if err != nil || len(deleted) != 1 || !reflect.DeepEqual(deleted[0], SCIMDeletedUser{ExternalID: "subject-race", UserName: "alice-updated", Active: false, HardDelete: true, ProviderSnapshotComplete: true, Generation: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), DeletedAtUnixMS: 44_000}) {
		t.Fatalf("deleted=%#v err=%v", deleted, err)
	}
	result, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_users WHERE subject='subject-race'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("identity retained rows=%#v err=%v", result.Rows, err)
	}
}

func TestDeleteUserPreservesFinalDirectAdminConcurrently(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(45_000) }
	bootstrapPassword(t, store, "admin-a", "admin-a", []byte("CurrentPassword1"))
	bootstrapPassword(t, store, "admin-b", "admin-b", []byte("CurrentPassword1"))
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-admin-role", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('admin-role','rauthy_admin',1,0,0)`},
		{SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES ('admin-a','admin-role',0),('admin-b','admin-role',0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	store.deleteUserAfterRead = func() { entered <- struct{}{}; <-release }
	errs := make(chan error, 2)
	go func() { errs <- store.DeleteUser(ctx, "admin-a") }()
	<-entered
	go func() { errs <- store.DeleteUser(ctx, "admin-b") }()
	<-entered
	close(release)
	var deleted, blocked int
	for range 2 {
		err := <-errs
		switch {
		case err == nil:
			deleted++
		case errors.Is(err, ErrLastActiveAdmin):
			blocked++
		default:
			t.Fatalf("concurrent delete error=%v", err)
		}
	}
	if deleted != 1 || blocked != 1 {
		t.Fatalf("deleted=%d blocked=%d", deleted, blocked)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-delegated-only", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('delegated-role','rauthy_admin:team',1,0,0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	bootstrapPassword(t, store, "delegated", "delegated", []byte("CurrentPassword1"))
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-delegated-membership", SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES ('delegated','delegated-role',0)`}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUser(ctx, "delegated"); err != nil {
		t.Fatalf("delegated admin role blocked deletion: %v", err)
	}
}

func TestDeleteUserPersistsTombstoneGeneration(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	store.random = func(out []byte) (int, error) {
		for i := range out {
			out[i] = byte(i)
		}
		return len(out), nil
	}
	bootstrapPassword(t, store, "subject-generation", "alice", []byte("CurrentPassword1"))
	if err := store.DeleteUser(context.Background(), "subject-generation"); err != nil {
		t.Fatal(err)
	}
	want := base64.RawURLEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	deleted, err := store.ListSCIMDeletedUsers(context.Background())
	if err != nil || len(deleted) != 1 || deleted[0].Generation != want {
		t.Fatalf("deleted=%#v err=%v", deleted, err)
	}
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT generation FROM scim_user_tombstones WHERE local_external_id='subject-generation'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != want {
		t.Fatalf("generation rows=%#v err=%v", result.Rows, err)
	}
}

func TestDeleteUserRejectsUnavailableTombstoneGeneration(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	bootstrapPassword(t, store, "subject-no-generation", "alice", []byte("CurrentPassword1"))
	store.random = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	if err := store.DeleteUser(context.Background(), "subject-no-generation"); !errors.Is(err, ErrSCIMTombstoneGenerationUnavailable) {
		t.Fatalf("delete err=%v", err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='subject-no-generation'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='subject-no-generation'`, 0)
}

func TestListSCIMDeletedUsersParsesLegacyAndGeneration(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	generation := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "identity-tombstone-generation-parse", SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,generation,deleted_at_unix_ms) VALUES ('legacy','alice',1,'',1),('generated','bob',1,?,2)`, Args: []any{generation}}); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.ListSCIMDeletedUsers(context.Background())
	if err != nil || len(deleted) != 2 || deleted[0].Generation != "" || deleted[1].Generation != generation {
		t.Fatalf("deleted=%#v err=%v", deleted, err)
	}
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "identity-tombstone-generation-invalid", SQL: `UPDATE scim_user_tombstones SET generation=? WHERE local_external_id='generated'`, Args: []any{strings.Repeat("a", 22)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListSCIMDeletedUsers(context.Background()); err == nil {
		t.Fatal("invalid tombstone generation was projected")
	}
}

func TestDeleteUserWithGuardRevalidatesAuthorityAtCommit(t *testing.T) {
	t.Parallel()
	t.Run("authorized final admin remains blocked", func(t *testing.T) {
		store := scimDeleteStore(t)
		ctx := context.Background()
		bootstrapPassword(t, store, "delete-final-admin", "final-admin", []byte("CurrentPassword1"))
		if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-guard-final-admin", Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('delete-final-role','rauthy_admin',1,0,0)`},
			{SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES ('delete-final-admin','delete-final-role',0)`},
		}}); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteUserWithGuard(ctx, "delete-final-admin", "1=1", nil); !errors.Is(err, ErrFinalAdmin) {
			t.Fatalf("delete err=%v", err)
		}
		assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='delete-final-admin'`, 1)
		assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='delete-final-admin'`, 0)
	})

	t.Run("revoked admin", func(t *testing.T) {
		store := scimDeleteStore(t)
		ctx := context.Background()
		bootstrapPassword(t, store, "delete-actor", "actor", []byte("CurrentPassword1"))
		bootstrapPassword(t, store, "delete-target", "target", []byte("CurrentPassword1"))
		if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-guard-revoke-seed", Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('delete-guard-admin','rauthy_admin',1,0,0)`},
			{SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES ('delete-actor','delete-guard-admin',0)`},
		}}); err != nil {
			t.Fatal(err)
		}
		store.deleteUserAfterRead = func() {
			if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-guard-revoke", SQL: `DELETE FROM rbac_user_roles WHERE subject='delete-actor'`}); err != nil {
				t.Fatal(err)
			}
		}
		authority := `EXISTS (SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id WHERE m.subject='delete-actor' AND r.name='rauthy_admin')`
		if err := store.DeleteUserWithGuard(ctx, "delete-target", authority, nil); !errors.Is(err, ErrDeleteUnauthorized) {
			t.Fatalf("delete err=%v", err)
		}
		assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='delete-target'`, 1)
	})

	t.Run("self admin grant", func(t *testing.T) {
		store := scimDeleteStore(t)
		ctx := context.Background()
		bootstrapPassword(t, store, "delete-self", "self", []byte("CurrentPassword1"))
		if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-guard-grant-seed", SQL: `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('delete-self-admin','rauthy_admin',1,0,0)`}); err != nil {
			t.Fatal(err)
		}
		store.deleteUserAfterRead = func() {
			if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-guard-grant", SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES ('delete-self','delete-self-admin',0)`}); err != nil {
				t.Fatal(err)
			}
		}
		authority := `NOT EXISTS (SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id WHERE m.subject='delete-self' AND r.name='rauthy_admin')`
		if err := store.DeleteUserWithGuard(ctx, "delete-self", authority, nil); !errors.Is(err, ErrDeleteUnauthorized) {
			t.Fatalf("delete err=%v", err)
		}
		assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='delete-self'`, 1)
	})
}

// The deletion guard must count only administrators that are still usable, so
// housekeeping timing cannot decide whether the deployment keeps an
// administrator: an expired but unswept administrator is not one.
func TestDeleteUserKeepsExpiredAdministratorOutOfFinalAdminGuard(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	ctx := context.Background()
	now := time.UnixMilli(1_700_000_000_000).UTC()
	store.now = func() time.Time { return now }
	bootstrapPassword(t, store, "usable-admin", "usable-admin", []byte("CurrentPassword1"))
	bootstrapPassword(t, store, "expired-admin", "expired-admin", []byte("CurrentPassword1"))
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "identity-delete-expired-admin-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('expiry-admin-role','rauthy_admin',1,0,0)`},
		{SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES ('usable-admin','expiry-admin-role',0),('expired-admin','expiry-admin-role',0)`},
		{SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject='expired-admin'`, Args: []any{now.UnixMilli()}},
	}}); err != nil {
		t.Fatal(err)
	}
	assertRefused := func(state string) {
		t.Helper()
		if err := store.DeleteUser(ctx, "usable-admin"); !errors.Is(err, ErrFinalAdmin) {
			t.Fatalf("last usable admin deletion (%s)=%v", state, err)
		}
		assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='usable-admin'`, 1)
	}
	assertRefused("expired but unswept")
	swept, err := store.ExpireUsers(ctx, now, 10)
	if err != nil || swept != 1 {
		t.Fatalf("expiry sweep=%d err=%v", swept, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='expired-admin' AND disabled=1`, 1)
	assertRefused("after housekeeping disabled it")
}

func TestCleanupSCIMDeletedUsersRequiresExactSucceededDeletes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	providers := []SCIMTombstoneProvider{{ID: "provider-a", DeletePolicy: scim.UnlinkRemote}}
	for _, tc := range []struct {
		name, status, operation, subject string
		policy                           scim.DeletePolicy
		hard                             bool
	}{
		{"missing", "", "", "subject", scim.UnlinkRemote, false},
		{"pending", "pending", "delete", "subject", scim.UnlinkRemote, false},
		{"processing", "processing", "delete", "subject", scim.UnlinkRemote, false},
		{"dead", "dead", "delete", "subject", scim.UnlinkRemote, false},
		{"wrong operation", "succeeded", "sync", "subject", scim.UnlinkRemote, false},
		{"wrong subject", "succeeded", "delete", "other", scim.UnlinkRemote, false},
		{"wrong policy", "succeeded", "delete", "subject", scim.DeleteRemote, false},
		{"hard delete wrong policy", "succeeded", "delete", "subject", scim.UnlinkRemote, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := scimDeleteStore(t)
			seedDeterministicRandom(store)
			seedSCIMTombstone(t, store, "subject", tc.hard, 1, providers)
			if tc.status != "" {
				seedSCIMTombstoneDeleteJob(t, store, "provider-a", tc.subject, tc.status, tc.operation, tc.policy)
			}
			deleted, err := store.CleanupSCIMDeletedUsers(ctx, 1)
			if err != nil || deleted != 0 {
				t.Fatalf("deleted=%d err=%v", deleted, err)
			}
			assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='subject'`, 1)
		})
	}
}

func TestCleanupSCIMDeletedUsersMatchesHardDeletePolicyAndBoundsOrder(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	seedDeterministicRandom(store)
	ctx := context.Background()
	providers := []SCIMTombstoneProvider{{ID: "provider-unlink", DeletePolicy: scim.UnlinkRemote}, {ID: "provider-delete", DeletePolicy: scim.DeleteRemote}}
	for _, tombstone := range []struct {
		subject string
		hard    bool
		at      int64
	}{
		{"subject-b", false, 1},
		{"subject-a", false, 1},
		{"subject-hard", true, 2},
	} {
		seedSCIMTombstone(t, store, tombstone.subject, tombstone.hard, tombstone.at, providers)
		for _, provider := range providers {
			policy := provider.DeletePolicy
			if tombstone.hard {
				policy = scim.DeleteRemote
			}
			seedSCIMTombstoneDeleteJob(t, store, provider.ID, tombstone.subject, "succeeded", "delete", policy)
		}
	}
	deleted, err := store.CleanupSCIMDeletedUsers(ctx, 2)
	if err != nil || deleted != 2 {
		t.Fatalf("first cleanup deleted=%d err=%v", deleted, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id IN ('subject-a','subject-b')`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='subject-hard'`, 1)
	deleted, err = store.CleanupSCIMDeletedUsers(ctx, 2)
	if err != nil || deleted != 1 {
		t.Fatalf("second cleanup deleted=%d err=%v", deleted, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones`, 0)
}

func TestCleanupSCIMDeletedUsersObservesOutboxProgressAfterEarlierNoop(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	seedDeterministicRandom(store)
	ctx := context.Background()
	providers := []SCIMTombstoneProvider{{ID: "provider", DeletePolicy: scim.UnlinkRemote}}
	seedSCIMTombstone(t, store, "subject", false, 1, providers)
	if deleted, err := store.CleanupSCIMDeletedUsers(ctx, 1); err != nil || deleted != 0 {
		t.Fatalf("initial cleanup deleted=%d err=%v", deleted, err)
	}
	seedSCIMTombstoneDeleteJob(t, store, "provider", "subject", "succeeded", "delete", scim.UnlinkRemote)
	if deleted, err := store.CleanupSCIMDeletedUsers(ctx, 1); err != nil || deleted != 1 {
		t.Fatalf("post-success cleanup deleted=%d err=%v", deleted, err)
	}
}

func TestSCIMTombstoneSnapshotsStartupProviders(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	providers := []SCIMTombstoneProvider{{ID: "provider-z", DeletePolicy: scim.UnlinkRemote}, {ID: "provider-a", DeletePolicy: scim.DeleteRemote}}
	if err := store.ConfigureSCIMTombstoneProviders(providers); err != nil {
		t.Fatal(err)
	}
	bootstrapPassword(t, store, "snapshot-user", "alice", []byte("CurrentPassword1"))
	if err := store.DeleteUser(context.Background(), "snapshot-user"); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.ListSCIMDeletedUsers(context.Background())
	want := []SCIMTombstoneProvider{{ID: "provider-a", DeletePolicy: scim.DeleteRemote}, {ID: "provider-z", DeletePolicy: scim.DeleteRemote}}
	if err != nil || len(deleted) != 1 || !deleted[0].ProviderSnapshotComplete || !reflect.DeepEqual(deleted[0].Providers, want) {
		t.Fatalf("deleted=%#v err=%v", deleted, err)
	}
	providers[0].ID = "mutated"
	if err := store.ConfigureSCIMTombstoneProviders(nil); !errors.Is(err, ErrInvalidSCIMTombstoneCleanup) {
		t.Fatalf("late config err=%v", err)
	}
}

func TestCleanupSCIMDeletedUsersSkipsIncompleteLegacyWithoutBlocking(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	seedDeterministicRandom(store)
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "legacy-incomplete", SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,deleted_at_unix_ms) VALUES ('legacy','alice',1,0)`}); err != nil {
		t.Fatal(err)
	}
	providers := []SCIMTombstoneProvider{{ID: "removed-provider", DeletePolicy: scim.UnlinkRemote}}
	seedSCIMTombstone(t, store, "snapshot", false, 1, providers)
	seedSCIMTombstoneDeleteJob(t, store, "removed-provider", "snapshot", "succeeded", "delete", scim.UnlinkRemote)
	deleted, err := store.CleanupSCIMDeletedUsers(context.Background(), 1)
	if err != nil || deleted != 1 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='legacy'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstone_providers WHERE local_external_id='snapshot'`, 0)
}

func TestCleanupSCIMDeletedUsersRequiresExactTombstoneGeneration(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	seedDeterministicRandom(store)
	providers := []SCIMTombstoneProvider{{ID: "provider", DeletePolicy: scim.UnlinkRemote}}
	seedSCIMTombstone(t, store, "generation", false, 1, providers)
	seedSCIMTombstoneDeleteJobWithGeneration(t, store, "provider", "generation", "succeeded", "delete", scim.UnlinkRemote, "")
	if deleted, err := store.CleanupSCIMDeletedUsers(context.Background(), 1); err != nil || deleted != 0 {
		t.Fatalf("missing generation deleted=%d err=%v", deleted, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='generation'`, 1)
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "cleanup-generation-old", SQL: `UPDATE scim_user_outbox SET request_json=json_set(request_json,'$.tombstoneGeneration',?) WHERE client_id='provider' AND external_id='generation'`, Args: []any{"BBBBBBBBBBBBBBBBBBBBBB"}}); err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.CleanupSCIMDeletedUsers(context.Background(), 1); err != nil || deleted != 0 {
		t.Fatalf("old generation deleted=%d err=%v", deleted, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='generation'`, 1)
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "cleanup-generation-exact", SQL: `UPDATE scim_user_outbox SET request_json=json_set(request_json,'$.tombstoneGeneration',?) WHERE client_id='provider' AND external_id='generation'`, Args: []any{cleanupTombstoneGeneration}}); err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.CleanupSCIMDeletedUsers(context.Background(), 1); err != nil || deleted != 1 {
		t.Fatalf("exact generation deleted=%d err=%v", deleted, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='generation'`, 0)
}

func TestCleanupSCIMDeletedUsersKeepsTamperedHardDeleteSnapshot(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	seedDeterministicRandom(store)
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "tampered-hard-snapshot", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,hard_delete,provider_snapshot_complete,deleted_at_unix_ms) VALUES ('hard','alice',1,1,1,1)`},
		{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES ('hard','provider',?)`, Args: []any{int64(scim.UnlinkRemote)}},
	}}); err != nil {
		t.Fatal(err)
	}
	seedSCIMTombstoneDeleteJob(t, store, "provider", "hard", "succeeded", "delete", scim.UnlinkRemote)
	if deleted, err := store.CleanupSCIMDeletedUsers(context.Background(), 1); err != nil || deleted != 0 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='hard'`, 1)
}

func TestCleanupSCIMDeletedUsersKeepsHardDeleteWithoutProviderSnapshot(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	seedDeterministicRandom(store)
	seedSCIMTombstone(t, store, "hard", true, 1, nil)

	if deleted, err := store.CleanupSCIMDeletedUsers(context.Background(), 1); err != nil || deleted != 0 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='hard'`, 1)
}

func TestCleanupSCIMDeletedUsersRejectsInvalidRequest(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		limit int
	}{
		{"zero limit", 0},
		{"large limit", maxSCIMTombstoneCleanup + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.CleanupSCIMDeletedUsers(ctx, tc.limit); !errors.Is(err, ErrInvalidSCIMTombstoneCleanup) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCleanupSCIMDeletedUsersRejectsShortEntropy(t *testing.T) {
	t.Parallel()
	store := scimDeleteStore(t)
	seedSCIMTombstone(t, store, "subject", false, 1, nil)
	store.random = func(value []byte) (int, error) { return len(value) - 1, nil }
	_, err := store.CleanupSCIMDeletedUsers(context.Background(), 1)
	if !errors.Is(err, ErrSCIMTombstoneCleanupUnavailable) {
		t.Fatalf("err=%v", err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id='subject'`, 1)
}

func seedSCIMTombstone(t *testing.T, store *Store, subject string, hard bool, at int64, providers []SCIMTombstoneProvider) {
	t.Helper()
	hardValue := int64(0)
	if hard {
		hardValue = 1
	}
	statements := []rhiza.SQLStatement{{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,hard_delete,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?, 'alice', 1, ?, 1, ?, ?)`, Args: []any{subject, hardValue, cleanupTombstoneGeneration, at}}}
	for _, provider := range providers {
		policy := provider.DeletePolicy
		if hard {
			policy = scim.DeleteRemote
		}
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: []any{subject, provider.ID, int64(policy)}})
	}
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "identity-cleanup-tombstone-" + subject, Statements: statements}); err != nil {
		t.Fatal(err)
	}
}

func seedSCIMTombstoneDeleteJob(t *testing.T, store *Store, clientID, subject, status, operation string, policy scim.DeletePolicy) {
	seedSCIMTombstoneDeleteJobWithGeneration(t, store, clientID, subject, status, operation, policy, cleanupTombstoneGeneration)
}

const cleanupTombstoneGeneration = "AAAAAAAAAAAAAAAAAAAAAA"

func seedSCIMTombstoneDeleteJobWithGeneration(t *testing.T, store *Store, clientID, subject, status, operation string, policy scim.DeletePolicy, generation string) {
	t.Helper()
	request := fmt.Sprintf(`{"operation":%q,"user":{"externalId":%q,"userName":"alice","active":true},"delete":%t,"deletePolicy":%d`, operation, subject, operation == "delete", policy)
	if generation != "" {
		request += fmt.Sprintf(`,"tombstoneGeneration":%q`, generation)
	}
	request += `}`
	jobID := digestForTest("cleanup-job\x00" + clientID + "\x00" + subject + "\x00" + status + "\x00" + operation + "\x00" + fmt.Sprint(policy) + "\x00" + generation)
	statement := rhiza.SQLStatement{SQL: `INSERT INTO scim_user_outbox (job_id,client_id,external_id,request_json,request_digest,status,attempts,next_attempt_at_unix_ms,revision,created_at_unix_ms,updated_at_unix_ms,completed_at_unix_ms) VALUES (?,?,?,?,?,?,0,0,1,0,0,?)`, Args: []any{jobID, clientID, subject, request, digestForTest(request), status, terminalSCIMStatusTime(status)}}
	if status == "processing" {
		statement = rhiza.SQLStatement{SQL: `INSERT INTO scim_user_outbox (job_id,client_id,external_id,request_json,request_digest,status,attempts,next_attempt_at_unix_ms,revision,lease_token,lease_until_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?,'processing',0,0,1,'lease',1,0,0)`, Args: []any{jobID, clientID, subject, request, digestForTest(request)}}
	}
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "identity-cleanup-job-" + jobID, SQL: statement.SQL, Args: statement.Args}); err != nil {
		t.Fatal(err)
	}
}

func terminalSCIMStatusTime(status string) any {
	if status == "succeeded" || status == "dead" {
		return int64(0)
	}
	return nil
}

func scimDeleteStore(t *testing.T) *Store {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "identity-scim-delete", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestListSCIMUsersRejectsMalformedDurableIdentity(t *testing.T) {
	t.Parallel()
	store := testStore(t)
	ctx := context.Background()
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "identity-scim-invalid",
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO identity_users (subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation) VALUES (?,?,?,?,0,1)`, Args: []any{"subject-invalid", "NotCanonical", "phc", int64(0)}},
			{SQL: `INSERT INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES (?, 'password', 1, 0)`, Args: []any{"subject-invalid"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListSCIMUsers(ctx); err == nil {
		t.Fatal("malformed identity was projected")
	}
}

func TestListSCIMUsersDoesNotSilentlyOmitMissingAuthenticationMode(t *testing.T) {
	t.Parallel()
	store := testStore(t)
	ctx := context.Background()
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "identity-scim-missing-mode",
		SQL:       `INSERT INTO identity_users (subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation) VALUES (?,?,?,?,0,1)`,
		Args:      []any{"subject-without-mode", "alice", "phc", int64(0)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListSCIMUsers(ctx); err == nil {
		t.Fatal("missing authentication mode was silently omitted")
	}
}
