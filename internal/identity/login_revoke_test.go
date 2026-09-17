package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestFindOrCreateLoginRevokeCodeIsSharedAndRecoverable(t *testing.T) {
	store := testResetStore(t, testRules(3))
	keyring := loginRevokeTestKeyring(t)
	subject := "login-revoke-shared"
	bootstrapPassword(t, store, subject, "shared@example.test", []byte("Password1"))

	first, err := store.FindOrCreateLoginRevokeCode(context.Background(), keyring, subject)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.FindOrCreateLoginRevokeCode(context.Background(), keyring, subject)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != loginRevokeCodeLength || !validLoginRevokeCode([]byte(first)) {
		t.Fatal("login revoke code was not a shared 48-character alphanumeric value")
	}
	if got := loginRevokeScalar(t, store, `SELECT COUNT(*) FROM identity_login_revoke WHERE subject=?`, subject); got != 1 {
		t.Fatalf("stored code row count=%d", got)
	}
}

func TestFindOrCreateLoginRevokeCodeRequiresSubject(t *testing.T) {
	store := testResetStore(t, testRules(3))
	if _, err := store.FindOrCreateLoginRevokeCode(context.Background(), loginRevokeTestKeyring(t), "missing"); !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("missing subject error=%v", err)
	}
}

func TestRevokeLoginWrongCodeHasNoEffect(t *testing.T) {
	store := testResetStore(t, testRules(3))
	keyring := loginRevokeTestKeyring(t)
	subject, code := seedLoginRevoke(t, store, keyring, "wrong-code")
	beforeGeneration, beforeEnvelope := loginRevokeSnapshot(t, store, subject)
	wrong := strings.Repeat("x", loginRevokeCodeLength-1) + "!"

	if err := store.RevokeLogin(context.Background(), keyring, subject, wrong, netip.MustParseAddr("192.0.2.10"), nil); !errors.Is(err, ErrInvalidLoginRevokeCode) {
		t.Fatalf("wrong code error=%v", err)
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(wrong)) == 1 {
		t.Fatal("test did not provide a wrong code")
	}
	afterGeneration, afterEnvelope := loginRevokeSnapshot(t, store, subject)
	if beforeGeneration != afterGeneration || !bytes.Equal(beforeEnvelope, afterEnvelope) {
		t.Fatal("wrong code changed the stored revoke code")
	}
	for query, want := range map[string]int64{
		`SELECT COUNT(*) FROM browser_sessions WHERE subject=? AND revoked_at_unix_ms IS NULL`: 1,
		`SELECT COUNT(*) FROM identity_login_locations WHERE subject=?`:                        1,
		`SELECT COUNT(*) FROM oidc_user_clients WHERE subject=?`:                               1,
		`SELECT COUNT(*) FROM oidc_backchannel_deliveries`:                                     0,
		`SELECT COUNT(*) FROM event_log WHERE typ='UserLoginRevoke'`:                           0,
	} {
		args := []any(nil)
		if strings.Contains(query, "subject=?") {
			args = []any{subject}
		}
		if got := loginRevokeScalar(t, store, query, args...); got != want {
			t.Fatalf("wrong code query=%q got=%d want=%d", query, got, want)
		}
	}
}

func TestRevokeLoginAtomicallyRevokesAllState(t *testing.T) {
	store := testResetStore(t, testRules(3))
	keyring := loginRevokeTestKeyring(t)
	subject, code := seedLoginRevoke(t, store, keyring, "atomic")
	ctx := context.Background()
	if err := store.RevokeLogin(ctx, keyring, subject, code, netip.MustParseAddr("192.0.2.11"), stringPointer("Seoul")); err != nil {
		t.Fatal(err)
	}
	for query, want := range map[string]int64{
		`SELECT COUNT(*) FROM identity_login_revoke WHERE subject=?`:                                                 0,
		`SELECT COUNT(*) FROM browser_sessions WHERE subject=? AND revoked_at_unix_ms IS NOT NULL`:                   1,
		`SELECT COUNT(*) FROM browser_authorization_interactions`:                                                    0,
		`SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature='atomic-code' AND invalidated=1`:                 1,
		`SELECT COUNT(*) FROM oauth_pkce_requests`:                                                                   0,
		`SELECT COUNT(*) FROM oauth_refresh_tokens WHERE request_id='atomic-token' AND active=0`:                     1,
		`SELECT COUNT(*) FROM oauth_access_tokens WHERE signature='atomic-token'`:                                    0,
		`SELECT COUNT(*) FROM oauth_token_requests WHERE signature='atomic-token'`:                                   0,
		`SELECT COUNT(*) FROM oauth_device_grants WHERE subject=? AND state='denied' AND claim_token_digest IS NULL`: 1,
		`SELECT COUNT(*) FROM identity_login_locations WHERE subject=?`:                                              0,
		`SELECT COUNT(*) FROM oidc_session_clients`:                                                                  0,
		`SELECT COUNT(*) FROM oidc_user_clients WHERE subject=?`:                                                     0,
		`SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject=? AND sid IS NULL`:                           1,
		`SELECT COUNT(*) FROM event_log WHERE typ='UserLoginRevoke' AND ip='192.0.2.11' AND data IS NULL`:            1,
	} {
		args := []any(nil)
		if strings.Contains(query, "subject=?") {
			args = []any{subject}
		}
		if got := loginRevokeScalar(t, store, query, args...); got != want {
			t.Fatalf("atomic query=%q got=%d want=%d", query, got, want)
		}
	}
	text := loginRevokeText(t, store)
	if text != "User `atomic@example.test` revoked illegal login from 192.0.2.11 (Seoul)" {
		t.Fatal("login revoke event text was not preserved")
	}
}

func TestRevokeLoginConcurrentRedeemHasOneWinner(t *testing.T) {
	store := testResetStore(t, testRules(3))
	keyring := loginRevokeTestKeyring(t)
	subject, code := seedLoginRevoke(t, store, keyring, "concurrent")
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- store.RevokeLogin(context.Background(), keyring, subject, code, netip.MustParseAddr("192.0.2.12"), nil)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	winners := 0
	for err := range errs {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrInvalidLoginRevokeCode):
		default:
			t.Fatalf("concurrent redemption error=%v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent redemption winners=%d", winners)
	}
	if got := loginRevokeScalar(t, store, `SELECT COUNT(*) FROM event_log WHERE typ='UserLoginRevoke'`); got != 1 {
		t.Fatalf("concurrent revoke events=%d", got)
	}
}

func TestRevokeLoginPersistsExactEventTextForLocationForms(t *testing.T) {
	for _, test := range []struct {
		name     string
		location *string
		want     string
	}{
		{name: "nil", want: "User `event-nil@example.test` revoked illegal login from 192.0.2.14 (Unknown Location)"},
		{name: "empty", location: stringPointer(""), want: "User `event-empty@example.test` revoked illegal login from 192.0.2.14 ()"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := testResetStore(t, testRules(3))
			keyring := loginRevokeTestKeyring(t)
			subject, code := seedLoginRevoke(t, store, keyring, "event-"+test.name)
			if err := store.RevokeLogin(context.Background(), keyring, subject, code, netip.MustParseAddr("192.0.2.14"), test.location); err != nil {
				t.Fatal(err)
			}
			if got := loginRevokeText(t, store); got != test.want {
				t.Fatalf("persisted event text=%q want=%q", got, test.want)
			}
		})
	}
}

func TestRevokeLoginRollsBackWhenEventFails(t *testing.T) {
	store := testResetStore(t, testRules(3))
	keyring := loginRevokeTestKeyring(t)
	subject, code := seedLoginRevoke(t, store, keyring, "rollback")
	ctx := context.Background()
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "login-revoke-event-failure", SQL: `CREATE TRIGGER reject_login_revoke_event BEFORE INSERT ON event_log WHEN NEW.typ='UserLoginRevoke' BEGIN SELECT RAISE(ABORT,'event unavailable'); END`}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "login-revoke-event-failure-drop", SQL: `DROP TRIGGER reject_login_revoke_event`})
	})
	if err := store.RevokeLogin(ctx, keyring, subject, code, netip.MustParseAddr("192.0.2.13"), nil); err == nil {
		t.Fatal("event failure unexpectedly committed")
	}
	for query, want := range map[string]int64{
		`SELECT COUNT(*) FROM identity_login_revoke WHERE subject=?`:                           1,
		`SELECT COUNT(*) FROM browser_sessions WHERE subject=? AND revoked_at_unix_ms IS NULL`: 1,
		`SELECT COUNT(*) FROM identity_login_locations WHERE subject=?`:                        1,
		`SELECT COUNT(*) FROM oidc_user_clients WHERE subject=?`:                               1,
		`SELECT COUNT(*) FROM oidc_backchannel_deliveries`:                                     0,
		`SELECT COUNT(*) FROM event_log WHERE typ='UserLoginRevoke'`:                           0,
	} {
		args := []any(nil)
		if strings.Contains(query, "subject=?") {
			args = []any{subject}
		}
		if got := loginRevokeScalar(t, store, query, args...); got != want {
			t.Fatalf("rollback query=%q got=%d want=%d", query, got, want)
		}
	}
}

func seedLoginRevoke(t *testing.T, store *Store, keyring *oidc.Keyring, suffix string) (string, string) {
	t.Helper()
	ctx := context.Background()
	subject := "login-revoke-" + suffix
	email := suffix + "@example.test"
	bootstrapPassword(t, store, subject, email, []byte("Password1"))
	code, err := store.FindOrCreateLoginRevokeCode(ctx, keyring, subject)
	if err != nil {
		t.Fatal(err)
	}
	statements := []rhiza.SQLStatement{
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES('` + suffix + `-sid',?, 'pwd',1,4102444800000,1)`, Args: []any{subject}},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,0,0,1)`, Args: []any{suffix + "-sid", suffix + "-client", "https://rp.example.test/logout"}},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,0,0,1)`, Args: []any{subject, suffix + "-client", "https://rp.example.test/logout"}},
		{SQL: `INSERT INTO browser_authorization_interactions(token_digest,request_id,session_digest,payload,created_at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,'{}',1,4102444800000)`, Args: []any{suffix + "-interaction", suffix + "-interaction", suffix + "-sid"}},
		{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES(?,?,4102444800000)`, Args: []any{suffix + "-code", `{"subject":"` + subject + `"}`}},
		{SQL: `INSERT INTO oauth_pkce_requests(signature,request_json,expires_at_unix_ms) VALUES(?,?,4102444800000)`, Args: []any{suffix + "-code", `{}`}},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES(?,?)`, Args: []any{suffix + "-token", `{"subject":"` + subject + `"}`}},
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES(?,?,?,1,4102444800000,'','','','')`, Args: []any{suffix + "-token", suffix + "-token", suffix + "-client"}},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES(?,?,?,?,4102444800000)`, Args: []any{suffix + "-refresh", suffix + "-token", suffix + "-token", `{"subject":"` + subject + `"}`}},
		{SQL: `INSERT INTO oauth_device_grants(device_code_digest,user_code_digest,client_id,scopes_json,subject,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms,claim_token_digest,claim_until_unix_ms) VALUES(?,?,?,'[]',?,'approved',4102444800000,5,1,1,'claim',4102444800000)`, Args: []any{suffix + "-device", suffix + "-user-code", suffix + "-client", subject}},
		{SQL: `INSERT INTO identity_login_locations(subject,ip_address,first_seen_at_unix_ms,last_seen_at_unix_ms,login_count) VALUES(?,?,1,1,1)`, Args: []any{subject, "192.0.2.99"}},
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "login-revoke-seed-" + suffix, Statements: statements}); err != nil {
		t.Fatal(err)
	}
	return subject, code
}

func loginRevokeSnapshot(t *testing.T, store *Store, subject string) (string, []byte) {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT generation,code_envelope FROM identity_login_revoke WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		t.Fatal("login revoke snapshot unavailable")
	}
	generation, ok := result.Rows[0][0].(string)
	if !ok {
		t.Fatal("login revoke generation unavailable")
	}
	envelope, ok := result.Rows[0][1].([]byte)
	if !ok {
		t.Fatal("login revoke envelope unavailable")
	}
	return generation, append([]byte(nil), envelope...)
}

func loginRevokeScalar(t *testing.T, store *Store, query string, args ...any) int64 {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: query, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("scalar query=%q rows=%#v err=%v", query, result.Rows, err)
	}
	value, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("scalar query=%q returned unexpected type", query)
	}
	return value
}

func loginRevokeText(t *testing.T, store *Store) string {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT text FROM event_log WHERE typ='UserLoginRevoke'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatal("login revoke event unavailable")
	}
	text, ok := result.Rows[0][0].(string)
	if !ok {
		t.Fatal("login revoke event text unavailable")
	}
	return text
}

func loginRevokeTestKeyring(t *testing.T) *oidc.Keyring {
	t.Helper()
	directory := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "master"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(directory, "master")
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func stringPointer(value string) *string { return &value }
