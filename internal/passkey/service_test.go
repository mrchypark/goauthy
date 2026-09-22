package passkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type deterministicReader struct {
	mu sync.Mutex
	n  byte
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range p {
		r.n++
		p[i] = r.n
	}
	return len(p), nil
}

func newTestService(t *testing.T) (*Service, *rhiza.DB, time.Time) {
	t.Helper()
	tmpl := buildPasskeyTemplate(t)
	dir := t.TempDir()
	cpDir(t, tmpl, dir)
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "passkey-test", DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	s, err := New(db, Config{RPID: "example.test", RPDisplayName: "Example", Origins: []string{"https://example.test"}, CookieKey: []byte(strings.Repeat("k", 32)), Keyring: testPasskeyKeyring(t, "master-a")})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.random = &deterministicReader{}
	return s, db, now
}

func digestForTest(b byte) string { return challengeDigest(strings.Repeat(string([]byte{b}), 32)) }

func TestNewSessionIdleTimeoutDefaultsAndRejectsInvalidValues(t *testing.T) {
	service, db, _ := newTestService(t)
	if service.sessionIdleTimeout != browser.DefaultIdleTimeout {
		t.Fatalf("default session idle timeout=%v, want %v", service.sessionIdleTimeout, browser.DefaultIdleTimeout)
	}
	base := Config{RPID: "example.test", RPDisplayName: "Example", Origins: []string{"https://example.test"}, CookieKey: []byte(strings.Repeat("k", 32)), Keyring: testPasskeyKeyring(t, "master-a")}
	configured, err := New(db, Config{RPID: base.RPID, RPDisplayName: base.RPDisplayName, Origins: base.Origins, CookieKey: base.CookieKey, Keyring: base.Keyring, SessionIdleTimeout: 17 * time.Minute})
	if err != nil {
		t.Fatalf("configured idle timeout: %v", err)
	}
	if configured.sessionIdleTimeout != 17*time.Minute {
		t.Fatalf("configured session idle timeout=%v, want 17m", configured.sessionIdleTimeout)
	}
	base.SessionIdleTimeout = -time.Nanosecond
	if _, err := New(db, base); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative idle timeout error=%v, want ErrInvalid", err)
	}
}

func TestBeginRegistrationStoresOnlyEncryptedState(t *testing.T) {
	s, db, now := newTestService(t)
	session := digestForTest('s')
	opts, code, expiry, err := s.BeginRegistration(context.Background(), "subject", "alice", "laptop", session)
	if err != nil {
		t.Fatal(err)
	}
	if opts == nil || len(opts.Response.Challenge) != 32 || !validCode(code) || !expiry.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected ceremony result: opts=%v code=%q expiry=%v", opts != nil, code, expiry)
	}
	q, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT session_json FROM identity_webauthn_ceremonies WHERE code_digest=?`, Args: []any{challengeDigest(code)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 {
		t.Fatalf("ceremony query: rows=%d err=%v", len(q.Rows), err)
	}
	stored, ok := q.Rows[0][0].(string)
	if !ok || strings.Contains(stored, code) || strings.Contains(stored, "subject") || strings.Contains(stored, "laptop") {
		t.Fatalf("ceremony state leaked plaintext")
	}
	if _, err := s.loadCeremony(context.Background(), "register", "subject", "laptop", session, code); err != nil {
		t.Fatalf("encrypted ceremony cannot be read: %v", err)
	}
	credentialPlain := `{"opaque":"credential-json-must-not-be-persisted"}`
	ciphertext, err := s.encrypt([]byte(credentialPlain), credentialAAD("subject"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "passkey-test-credential", SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{"credential-id", "subject", "privacy", base64.RawURLEncoding.EncodeToString(ciphertext), int64(0), int64(0), now.UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	q, err = db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT credential_json FROM identity_webauthn_credentials WHERE credential_id='credential-id'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || strings.Contains(q.Rows[0][0].(string), credentialPlain) {
		t.Fatalf("credential JSON was persisted in plaintext: err=%v", err)
	}
}

func seedRegistrationState(t *testing.T, db *rhiza.DB, now time.Time, sessionSubject, ceremonySubject, method string, expiresAt, lastSeen time.Time, revoked any) (string, string) {
	t.Helper()
	ctx := context.Background()
	sessionDigest := digestForTest('r')
	ceremonyDigest := digestForTest('c')
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "registration-user-" + method + "-" + ceremonySubject, SQL: `INSERT INTO identity_users (subject,username,password_phc,disabled) VALUES (?,?,?,0)`, Args: []any{ceremonySubject, ceremonySubject, "phc"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "registration-session-" + method + "-" + sessionSubject, SQL: `INSERT INTO browser_sessions (token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,revoked_at_unix_ms,peer_ip) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{sessionDigest, sessionSubject, method, now.Add(-time.Minute).UnixMilli(), expiresAt.UnixMilli(), lastSeen.UnixMilli(), revoked, ""}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "registration-ceremony-" + method + "-" + ceremonySubject, SQL: `INSERT INTO identity_webauthn_ceremonies (code_digest,purpose,subject,session_digest,passkey_name,session_json,expires_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{ceremonyDigest, "register", ceremonySubject, sessionDigest, "new-key", "sealed", now.Add(time.Minute).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	return sessionDigest, ceremonyDigest
}

func registrationFinishForTest(t *testing.T, db *rhiza.DB, now time.Time, subject, sessionDigest, ceremonyDigest, credentialID, attempt string) int64 {
	return registrationFinishForTestWithUV(t, db, now, subject, sessionDigest, ceremonyDigest, credentialID, attempt, 1)
}

func registrationFinishForTestWithUV(t *testing.T, db *rhiza.DB, now time.Time, subject, sessionDigest, ceremonyDigest, credentialID, attempt string, userVerified int64) int64 {
	t.Helper()
	statements := registrationFinishStatements(ceremonyDigest, attempt, subject, "new-key", sessionDigest, credentialID, "sealed-credential", 0, userVerified, now, browser.DefaultIdleTimeout)
	response, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "reg-" + attempt, Statements: statements})
	if err != nil {
		t.Fatal(err)
	}
	return response.RowsAffected
}

func TestRegistrationFinishDoesNotUpgradeSessionForNonUVCredential(t *testing.T) {
	_, db, now := newTestService(t)
	sessionDigest, ceremonyDigest := seedRegistrationState(t, db, now, "subject", "subject", "pwd", now.Add(time.Hour), now, nil)
	if got := registrationFinishForTestWithUV(t, db, now, "subject", sessionDigest, ceremonyDigest, "non-uv", strings.Repeat("u", 22), 0); got != 3 {
		t.Fatalf("rows affected=%d, want 3", got)
	}
	q, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT auth_method FROM browser_sessions WHERE token_digest=?`, Args: []any{sessionDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != "pwd" {
		t.Fatalf("session method=%v err=%v, want pwd", q.Rows, err)
	}
}

func TestRegistrationFinishDisableInterpositionLeavesStateUnchanged(t *testing.T) {
	_, db, now := newTestService(t)
	ctx := context.Background()
	sessionDigest, ceremonyDigest := seedRegistrationState(t, db, now, "subject", "subject", "pwd", now.Add(time.Hour), now, nil)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "registration-disable-interposition", SQL: `UPDATE identity_users SET disabled=1 WHERE subject=?`, Args: []any{"subject"}}); err != nil {
		t.Fatal(err)
	}
	if got := registrationFinishForTest(t, db, now, "subject", sessionDigest, ceremonyDigest, "disabled-credential", strings.Repeat("d", 22)); got != 0 {
		t.Fatalf("disabled registration rows affected=%d, want 0", got)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT auth_method FROM browser_sessions WHERE token_digest=?`, Args: []any{sessionDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != "pwd" {
		t.Fatalf("session method=%v err=%v, want pwd", q.Rows, err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_webauthn_ceremonies WHERE code_digest=?`, Args: []any{ceremonyDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != nil {
		t.Fatalf("ceremony state=%v err=%v, want unconsumed", q.Rows, err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE subject=?`, Args: []any{"subject"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(0) {
		t.Fatalf("credential count=%v err=%v, want 0", q.Rows, err)
	}
}

func TestRegistrationFinishCredentialInterpositionLeavesStateUnchanged(t *testing.T) {
	_, db, now := newTestService(t)
	ctx := context.Background()
	sessionDigest, ceremonyDigest := seedRegistrationState(t, db, now, "subject", "subject", "pwd", now.Add(time.Hour), now, nil)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "registration-credential-interposition", SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{"existing-registration", "subject", "new-key", "existing", int64(0), int64(1), now.UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if got := registrationFinishForTest(t, db, now, "subject", sessionDigest, ceremonyDigest, "new-registration", strings.Repeat("d", 22)); got != 0 {
		t.Fatalf("duplicate registration rows affected=%d, want 0", got)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT auth_method FROM browser_sessions WHERE token_digest=?`, Args: []any{sessionDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != "pwd" {
		t.Fatalf("session method=%v err=%v, want pwd", q.Rows, err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_webauthn_ceremonies WHERE code_digest=?`, Args: []any{ceremonyDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != nil {
		t.Fatalf("ceremony state=%v err=%v, want unconsumed", q.Rows, err)
	}
}

func TestRegistrationFinishUpgradesOnlyTheBoundActiveSession(t *testing.T) {
	now := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	for _, tc := range []struct {
		name, method      string
		expires, lastSeen time.Time
		revoked           any
		matchSubject      string
		wantRows          int64
		wantMethod        string
		wantCredential    int64
	}{
		{name: "password upgrades", method: "pwd", expires: now.Add(time.Hour), lastSeen: now, matchSubject: "subject", wantRows: 3, wantMethod: "mfa", wantCredential: 1},
		{name: "webauthn upgrades", method: "webauthn", expires: now.Add(time.Hour), lastSeen: now, matchSubject: "subject", wantRows: 3, wantMethod: "mfa", wantCredential: 1},
		{name: "mfa remains mfa", method: "mfa", expires: now.Add(time.Hour), lastSeen: now, matchSubject: "subject", wantRows: 3, wantMethod: "mfa", wantCredential: 1},
		{name: "external remains truthful", method: "external", expires: now.Add(time.Hour), lastSeen: now, matchSubject: "subject", wantRows: 3, wantMethod: "external", wantCredential: 1},
		{name: "wrong subject", method: "pwd", expires: now.Add(time.Hour), lastSeen: now, matchSubject: "other", wantRows: 0, wantMethod: "pwd", wantCredential: 0},
		{name: "expired", method: "pwd", expires: now, lastSeen: now, matchSubject: "subject", wantRows: 0, wantMethod: "pwd", wantCredential: 0},
		{name: "idle at boundary", method: "pwd", expires: now.Add(time.Hour), lastSeen: now.Add(-browser.DefaultIdleTimeout), matchSubject: "subject", wantRows: 0, wantMethod: "pwd", wantCredential: 0},
		{name: "revoked", method: "pwd", expires: now.Add(time.Hour), lastSeen: now, revoked: now.UnixMilli(), matchSubject: "subject", wantRows: 0, wantMethod: "pwd", wantCredential: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, db, _ := newTestService(t)
			sessionDigest, ceremonyDigest := seedRegistrationState(t, db, now, tc.matchSubject, "subject", tc.method, tc.expires, tc.lastSeen, tc.revoked)
			if got := registrationFinishForTest(t, db, now, "subject", sessionDigest, ceremonyDigest, "credential-"+tc.name, strings.Repeat("a", 22)); got != tc.wantRows {
				t.Fatalf("rows affected=%d, want %d", got, tc.wantRows)
			}
			q, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT auth_method FROM browser_sessions WHERE token_digest=?`, Args: []any{sessionDigest}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != tc.wantMethod {
				t.Fatalf("session method=%v err=%v, want %q", q.Rows, err, tc.wantMethod)
			}
			q, err = db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE subject=?`, Args: []any{"subject"}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != tc.wantCredential {
				t.Fatalf("credential count=%v err=%v, want %d", q.Rows, err, tc.wantCredential)
			}
			q, err = db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_webauthn_ceremonies WHERE code_digest=?`, Args: []any{ceremonyDigest}, Consistency: rhiza.ConsistencyLinearizable})
			consumed := len(q.Rows) == 1 && q.Rows[0][0] != nil
			if tc.wantRows == 3 && !consumed || tc.wantRows == 0 && consumed {
				t.Fatalf("ceremony consumed=%v rows=%v err=%v", consumed, q.Rows, err)
			}
		})
	}
}

func TestRegistrationFinishReplayHasOneAtomicWinner(t *testing.T) {
	_, db, _ := newTestService(t)
	now := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	sessionDigest, ceremonyDigest := seedRegistrationState(t, db, now, "subject", "subject", "pwd", now.Add(time.Hour), now, nil)
	start := make(chan struct{})
	results := make(chan int64, 2)
	for i := range 2 {
		go func(i int) {
			<-start
			results <- registrationFinishForTest(t, db, now, "subject", sessionDigest, ceremonyDigest, "credential-replay-"+string(rune('a'+i)), strings.Repeat(string(rune('a'+i)), 22))
		}(i)
	}
	close(start)
	winners := 0
	for range 2 {
		if <-results == 3 {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("registration winners=%d, want 1", winners)
	}
	q, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE subject=?`, Args: []any{"subject"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(1) {
		t.Fatalf("credential count=%v err=%v, want 1", q.Rows, err)
	}
}

func TestLoginFinishCredentialInterpositionLeavesCeremonyUnconsumed(t *testing.T) {
	_, db, now := newTestService(t)
	ctx := context.Background()
	const subject = "subject"
	const credentialID = "login-credential"
	ceremonyDigest, sessionDigest := digestForTest('l'), digestForTest('s')
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "login-interposition-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{credentialID, subject, "primary", "sealed", int64(0), int64(1), now.UnixMilli(), now.UnixMilli()}},
		{SQL: `INSERT INTO identity_webauthn_ceremonies (code_digest,purpose,subject,session_digest,interaction_digest,session_json,expires_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{ceremonyDigest, loginPurpose, subject, sessionDigest, digestForTest('i'), "sealed", now.Add(time.Minute).UnixMilli()}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "login-interposition", SQL: `UPDATE identity_webauthn_credentials SET credential_version=1 WHERE credential_id=?`, Args: []any{credentialID}}); err != nil {
		t.Fatal(err)
	}
	statements := loginFinishStatements(ceremonyDigest, loginPurpose, subject, sessionDigest, strings.Repeat("a", 22), credentialID, "updated", 1, 0, 0, now)
	res, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "login-interposition-finish", Statements: statements})
	if err != nil {
		t.Fatal(err)
	}
	if res.RowsAffected != 0 {
		t.Fatalf("interposed login rows affected=%d, want 0", res.RowsAffected)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_webauthn_ceremonies WHERE code_digest=?`, Args: []any{ceremonyDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != nil {
		t.Fatalf("ceremony state=%v err=%v, want unconsumed", q.Rows, err)
	}
}

func TestPasswordlessCookieAndModificationTokenAreBoundAndOneUse(t *testing.T) {
	s, _, now := newTestService(t)
	cookie, err := s.PasswordlessCookie("subject")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.SubjectFromCookie(cookie); err != nil || got != "subject" {
		t.Fatalf("cookie subject=%q err=%v", got, err)
	}
	rawCookie, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil {
		t.Fatal(err)
	}
	if keyID, err := s.keyring.PurposeEnvelopeKeyID(passwordlessCookiePurpose, rawCookie); err != nil || keyID != "master-a" {
		t.Fatalf("passwordless cookie key=%q err=%v", keyID, err)
	}
	if _, err := s.SubjectFromCookie(cookie + "x"); err != ErrInvalid {
		t.Fatalf("tampered cookie error=%v", err)
	}
	if _, err := s.SubjectFromCookie(strings.Repeat("A", maxPasswordlessCookieLength+4)); err != ErrInvalid {
		t.Fatalf("oversized cookie error=%v", err)
	}
	s.now = func() time.Time { return now.Add(defaultRenewTTL) }
	if _, err := s.SubjectFromCookie(cookie); err != ErrInvalid {
		t.Fatalf("cookie expiry boundary error=%v", err)
	}
	s.now = func() time.Time { return now }
	session := digestForTest('m')
	raw, exp, err := s.IssueModificationToken(context.Background(), "subject", session)
	if err != nil || len(raw) != 32 || !exp.Equal(now.Add(modificationTTL)) {
		t.Fatalf("issue raw len=%d exp=%v err=%v", len(raw), exp, err)
	}
	if err := s.ConsumeModificationToken(context.Background(), "subject", digestForTest('x'), raw); err == nil {
		t.Fatal("session-mismatched modification token consumed")
	}
	if err := s.ConsumeModificationToken(context.Background(), "subject", session, raw); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := s.ConsumeModificationToken(context.Background(), "subject", session, raw); err == nil {
		t.Fatal("replayed modification token consumed")
	}
}

func TestPasswordlessCookieLegacyDualReadAndGAOPFailClosed(t *testing.T) {
	s, _, now := newTestService(t)
	exp := now.UTC().Add(s.renewTTL).Unix()
	plain := []byte("legacy-subject\x00" + strconv.FormatInt(exp, 10))
	legacyRaw, err := s.encrypt(plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy := base64.RawURLEncoding.EncodeToString(legacyRaw)
	if got, err := s.SubjectFromCookie(legacy); err != nil || got != "legacy-subject" {
		t.Fatalf("legacy cookie subject=%q err=%v", got, err)
	}

	// A valid GAOP cookie must not fall back to CookieKey after tampering.
	gaop, err := s.PasswordlessCookie("gaop-subject")
	if err != nil {
		t.Fatal(err)
	}
	gaopRaw, err := base64.RawURLEncoding.DecodeString(gaop)
	if err != nil {
		t.Fatal(err)
	}
	gaopRaw[len(gaopRaw)-1] ^= 1
	if _, err := s.SubjectFromCookie(base64.RawURLEncoding.EncodeToString(gaopRaw)); err != ErrInvalid {
		t.Fatalf("tampered GAOP error=%v, want ErrInvalid", err)
	}

	// Removing the old key makes an A-issued GAOP cookie unknown, and it still
	// must not be interpreted as a legacy CookieKey ciphertext.
	aCookie, err := s.PasswordlessCookie("old-key-subject")
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := New(s.db, Config{RPID: "example.test", RPDisplayName: "Example", Origins: []string{"https://example.test"}, CookieKey: []byte(strings.Repeat("k", 32)), Keyring: testPasskeyKeyringOnly(t, "master-b")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.SubjectFromCookie(aCookie); err != ErrInvalid {
		t.Fatalf("unknown-key GAOP error=%v, want ErrInvalid", err)
	}
}

func TestModificationTokenConcurrentConsumeHasOneWinner(t *testing.T) {
	s, _, _ := newTestService(t)
	session := digestForTest('c')
	raw, _, err := s.IssueModificationToken(context.Background(), "subject", session)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- s.ConsumeModificationToken(context.Background(), "subject", session, raw)
		}()
	}
	close(start)
	success := 0
	for range 2 {
		if <-results == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful consumes = %d, want 1", success)
	}
}

func TestNewRejectsUntrustedOrigin(t *testing.T) {
	_, db, _ := newTestService(t)
	_, err := New(db, Config{RPID: "example.test", RPDisplayName: "Example", Origins: []string{"http://example.test"}, CookieKey: []byte(strings.Repeat("k", 32)), Keyring: testPasskeyKeyring(t, "master-a")})
	if err != ErrInvalid {
		t.Fatalf("http origin error = %v", err)
	}
}

func TestValidNameMatchesRauthyUnicodeCharacterClass(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"laptop-01's", true},
		{"Éléonore À-ȏ", true},
		{"a\u00a0b", true}, // Unicode whitespace is accepted like Rust regex \s.
		{strings.Repeat("é", 32), true},
		{strings.Repeat("é", 33), false},
		{"", false},
		{"name!", false},
		{"한글", false},
		{"e\u0301", false}, // combining marks are outside À-ɏ.
		{string([]byte{'a', 0xff}), false},
	} {
		if got := validName(tc.name); got != tc.valid {
			t.Errorf("validName(%q)=%v, want %v", tc.name, got, tc.valid)
		}
	}
}

func seedPasskey(t *testing.T, s *Service, db *rhiza.DB, subject, name string, verified bool) string {
	t.Helper()
	handle := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("h", 32)))
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: rid("seed-user", subject), SQL: `INSERT OR IGNORE INTO identity_webauthn_users (subject,user_handle,created_at_unix_ms) VALUES (?,?,0)`, Args: []any{subject, handle}}); err != nil {
		t.Fatal(err)
	}
	idBytes := []byte("credential-" + subject + "-" + name)
	credential := wa.Credential{ID: idBytes, PublicKey: []byte("public-key")}
	raw, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.encrypt(raw, credentialAAD(subject))
	if err != nil {
		t.Fatal(err)
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: rid("seed-credential", subject, name), SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,0,0)`, Args: []any{id, subject, name, base64.RawURLEncoding.EncodeToString(sealed), int64(0), boolInt(verified)}}); err != nil {
		t.Fatal(err)
	}
	return id
}

func setMode(t *testing.T, db *rhiza.DB, subject, mode string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: rid("seed-mode", subject), SQL: `INSERT INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES (?,?,1,0)`, Args: []any{subject, mode}}); err != nil {
		t.Fatal(err)
	}
}

func TestPasskeyOnlyOptionsUseRegistrationUVSnapshot(t *testing.T) {
	s, db, _ := newTestService(t)
	verifiedID := seedPasskey(t, s, db, "subject", "verified", true)
	_ = seedPasskey(t, s, db, "subject", "not-verified", false)
	setMode(t, db, "subject", "passkey")
	session := digestForTest('p')
	registration, _, _, err := s.BeginRegistration(context.Background(), "subject", "alice", "new", session)
	if err != nil {
		t.Fatal(err)
	}
	if got := registration.Response.AuthenticatorSelection.UserVerification; got != protocol.VerificationRequired {
		t.Fatalf("registration UV=%q, want required", got)
	}
	login, _, _, err := s.BeginLogin(context.Background(), "subject", "alice", "interaction", session)
	if err != nil {
		t.Fatal(err)
	}
	if got := login.Response.UserVerification; got != protocol.VerificationRequired {
		t.Fatalf("login UV=%q, want required", got)
	}
	if got := login.Response.AllowedCredentials; len(got) != 1 || string(got[0].CredentialID) != string(mustDecodeID(t, verifiedID)) {
		t.Fatalf("allowCredentials=%v, want only registration-verified credential", got)
	}
	mfa, _, _, err := s.BeginModificationProof(context.Background(), "subject", "alice", digestForTest('q'))
	if err != nil || mfa.Response.UserVerification != protocol.VerificationRequired || len(mfa.Response.AllowedCredentials) != 1 {
		t.Fatalf("passkey-only MFA options=%+v err=%v", mfa, err)
	}
}

func TestPasswordModeKeepsAllCredentialsAndDefaultUV(t *testing.T) {
	s, db, _ := newTestService(t)
	verifiedID := seedPasskey(t, s, db, "subject", "verified", true)
	notVerifiedID := seedPasskey(t, s, db, "subject", "not-verified", false)
	setMode(t, db, "subject", "password")
	login, _, _, err := s.BeginLogin(context.Background(), "subject", "alice", "interaction", digestForTest('d'))
	if err != nil {
		t.Fatal(err)
	}
	if got := login.Response.UserVerification; got != protocol.VerificationPreferred {
		t.Fatalf("password-mode UV=%q, want preferred", got)
	}
	if got := login.Response.AllowedCredentials; len(got) != 2 || string(got[0].CredentialID) != string(mustDecodeID(t, verifiedID)) || string(got[1].CredentialID) != string(mustDecodeID(t, notVerifiedID)) {
		t.Fatalf("password-mode allowCredentials=%v, want both", got)
	}
	forced, forcedCode, _, err := s.BeginMFALogin(context.Background(), "subject", "alice", "forced-interaction", digestForTest('f'))
	if err != nil || forced.Response.UserVerification != protocol.VerificationRequired || len(forced.Response.AllowedCredentials) != 1 || string(forced.Response.AllowedCredentials[0].CredentialID) != string(mustDecodeID(t, verifiedID)) {
		t.Fatalf("forced-MFA options=%+v err=%v", forced, err)
	}
	forcedCeremony, err := s.loadCeremony(context.Background(), loginPurpose, "", "", digestForTest('f'), forcedCode)
	if err != nil || forcedCeremony.authenticationMethod != "mfa" || forcedCeremony.interaction != "forced-interaction" {
		t.Fatalf("forced-MFA ceremony method=%q interaction=%q err=%v", forcedCeremony.authenticationMethod, forcedCeremony.interaction, err)
	}
	mfa, _, _, err := s.BeginModificationProof(context.Background(), "subject", "alice", digestForTest('x'))
	if err != nil || mfa.Response.UserVerification != protocol.VerificationPreferred || len(mfa.Response.AllowedCredentials) != 2 {
		t.Fatalf("password-mode MFA options=%+v err=%v", mfa, err)
	}
	passwordNew, _, _, err := s.BeginPasswordNewProof(context.Background(), "subject", "alice", digestForTest('w'))
	if err != nil || passwordNew.Response.UserVerification != protocol.VerificationRequired || len(passwordNew.Response.AllowedCredentials) != 1 || string(passwordNew.Response.AllowedCredentials[0].CredentialID) != string(mustDecodeID(t, verifiedID)) {
		t.Fatalf("password-mode PasswordNew options=%+v err=%v", passwordNew, err)
	}
	s.forceUV = true
	mfa, _, _, err = s.BeginModificationProof(context.Background(), "subject", "alice", digestForTest('y'))
	if err != nil || mfa.Response.UserVerification != protocol.VerificationRequired || len(mfa.Response.AllowedCredentials) != 1 {
		t.Fatalf("ForceUV MFA options=%+v err=%v", mfa, err)
	}
	if err := s.Delete(context.Background(), "subject", "verified"); err != nil {
		t.Fatalf("password mode must allow deleting the final registration-verified credential: %v", err)
	}
}

func mustDecodeID(t *testing.T, id string) []byte {
	t.Helper()
	v, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPasskeyOnlyDeleteKeepsARegistrationVerifiedCredential(t *testing.T) {
	s, db, _ := newTestService(t)
	seedPasskey(t, s, db, "subject", "verified", true)
	seedPasskey(t, s, db, "subject", "not-verified", false)
	setMode(t, db, "subject", "passkey")
	if err := s.Delete(context.Background(), "subject", "not-verified"); err != nil {
		t.Fatalf("delete non-UV credential: %v", err)
	}
	if err := s.Delete(context.Background(), "subject", "verified"); err != ErrConflict {
		t.Fatalf("delete last UV error=%v, want conflict", err)
	}
	items, err := s.List(context.Background(), "subject")
	if err != nil || len(items) != 1 || !items[0].UserVerified {
		t.Fatalf("remaining credentials=%+v err=%v", items, err)
	}
}

// TestDeleteRejectedFinalCredentialRetriesAfterEligibilityChanges covers
// GA-BR-13: a rejected final-key delete commits a zero-row receipt under its
// request ID, and enrolling another credential does not change this
// credential's CAS version, so the retry must carry a fresh operation identity
// instead of replaying the stored rejection.
func TestDeleteRejectedFinalCredentialRetriesAfterEligibilityChanges(t *testing.T) {
	s, db, _ := newTestService(t)
	seedPasskey(t, s, db, "subject", "verified", true)
	setMode(t, db, "subject", "passkey")
	if err := s.Delete(context.Background(), "subject", "verified"); err != ErrConflict {
		t.Fatalf("delete of the final verified credential error=%v, want conflict", err)
	}
	// The retained passkey makes the original deletable; the original's
	// credential_version is untouched by the enrollment.
	seedPasskey(t, s, db, "subject", "second", true)
	if err := s.Delete(context.Background(), "subject", "verified"); err != nil {
		t.Fatalf("delete after eligibility changed error=%v", err)
	}
	items, err := s.List(context.Background(), "subject")
	if err != nil || len(items) != 1 || items[0].Name != "second" {
		t.Fatalf("remaining credentials=%+v err=%v", items, err)
	}
}

func TestModificationProofCeremonyIsEncryptedBoundAndExpiresAtBoundary(t *testing.T) {
	s, db, now := newTestService(t)
	seedPasskey(t, s, db, "subject", "primary", true)
	setMode(t, db, "subject", "password")
	session := digestForTest('q')
	opts, code, exp, err := s.BeginModificationProof(context.Background(), "subject", "alice", session)
	if err != nil || opts == nil || !validCode(code) || !exp.Equal(now.Add(defaultCeremonyTTL)) {
		t.Fatalf("begin opts=%v code=%q exp=%v err=%v", opts != nil, code, exp, err)
	}
	c, err := s.loadModificationCeremony(context.Background(), "subject", session, code)
	if err != nil || !validCode(c.proof) {
		t.Fatalf("load err=%v proof=%q", err, c.proof)
	}
	q, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT session_json,proof_expires_at_unix_ms FROM identity_webauthn_mfa_ceremonies WHERE code_digest=?`, Args: []any{challengeDigest(code)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || len(q.Rows[0]) != 2 || strings.Contains(q.Rows[0][0].(string), c.proof) || strings.Contains(q.Rows[0][0].(string), "subject") || q.Rows[0][1] != now.Add(defaultMfaCodeTTL).UnixMilli() {
		t.Fatalf("MFA ceremony leaked proof/subject: rows=%v err=%v", q.Rows, err)
	}
	// A process restart with a changed local TTL must still honor the durable
	// proof expiry generated by the node that began the ceremony.
	s.mfaCodeTTL = time.Nanosecond
	c, err = s.loadModificationCeremony(context.Background(), "subject", session, code)
	if err != nil || !c.proofExpiry.Equal(now.Add(defaultMfaCodeTTL)) {
		t.Fatalf("durable proof expiry=%v err=%v", c.proofExpiry, err)
	}
	if _, err := s.loadModificationCeremony(context.Background(), "other", session, code); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong subject error=%v", err)
	}
	if _, err := s.loadModificationCeremony(context.Background(), "subject", digestForTest('r'), code); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong session error=%v", err)
	}
	s.now = func() time.Time { return exp }
	if _, err := s.loadModificationCeremony(context.Background(), "subject", session, code); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expiry boundary error=%v", err)
	}
}

func TestModificationProofExchangeAndPasswordFactorAreExactlyBound(t *testing.T) {
	s, db, now := newTestService(t)
	ctx := context.Background()
	session := digestForTest('m')
	passwordToken, _, err := s.IssuePasswordModificationToken(ctx, "subject", session)
	if err != nil {
		t.Fatal(err)
	}
	seedPasskey(t, s, db, "subject", "primary", true)
	if err := s.ConsumeModificationToken(ctx, "subject", session, passwordToken); !errors.Is(err, ErrConflict) {
		t.Fatalf("password token survived passkey registration: %v", err)
	}
	if _, _, err := s.IssuePasswordModificationToken(ctx, "subject", session); !errors.Is(err, ErrInvalid) {
		t.Fatalf("password issuance with passkey error=%v", err)
	}

	proof := strings.Repeat("a", 48)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-proof-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{challengeDigest(proof), "subject", session, now.Add(defaultMfaCodeTTL).UnixMilli()}},
		{SQL: `INSERT INTO identity_webauthn_service_proof_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{challengeDigest(proof), modificationPurpose}},
	}}); err != nil {
		t.Fatal(err)
	}
	token, exp, err := s.ExchangeModificationProof(ctx, "subject", session, proof)
	if err != nil || len(token) != 32 || !exp.Equal(now.Add(modificationTTL)) || !s.modificationFactor(ctx, challengeDigest(token), "webauthn") {
		t.Fatalf("exchange token=%q exp=%v err=%v", token, exp, err)
	}
	if _, _, err := s.ExchangeModificationProof(ctx, "subject", session, proof); !errors.Is(err, ErrConflict) {
		t.Fatalf("proof replay error=%v", err)
	}
	if err := s.ConsumeModificationToken(ctx, "subject", session, token); err != nil {
		t.Fatalf("webauthn token consume: %v", err)
	}
}

func TestServiceProofPurposesAreExactAndLegacyRowsFailClosed(t *testing.T) {
	s, db, now := newTestService(t)
	ctx := context.Background()
	seedPasskey(t, s, db, "subject", "primary", true)
	session := digestForTest('p')
	if _, code, _, err := s.BeginPasswordNewProof(ctx, "subject", "alice", session); err != nil {
		t.Fatal(err)
	} else {
		q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT purpose FROM identity_webauthn_service_ceremony_purposes WHERE code_digest=?`, Args: []any{challengeDigest(code)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != passwordNewPurpose {
			t.Fatalf("PasswordNew marker=%v err=%v", q.Rows, err)
		}
	}
	for _, tc := range []struct {
		name, proof, purpose string
	}{
		{"PasswordNew", strings.Repeat("n", 48), passwordNewPurpose},
		{"legacy", strings.Repeat("l", 48), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			digest := challengeDigest(tc.proof)
			statements := []rhiza.SQLStatement{{SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{digest, "subject", session, now.Add(defaultMfaCodeTTL).UnixMilli()}}}
			if tc.purpose != "" {
				statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO identity_webauthn_service_proof_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{digest, tc.purpose}})
			}
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "service-purpose-" + tc.name, Statements: statements}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.ExchangeModificationProof(ctx, "subject", session, tc.proof); !errors.Is(err, ErrConflict) {
				t.Fatalf("ExchangeModificationProof(%s) error=%v", tc.name, err)
			}
		})
	}
}

func TestModificationProofExchangeConcurrentOneWinnerAndExpiry(t *testing.T) {
	s, db, now := newTestService(t)
	ctx := context.Background()
	seedPasskey(t, s, db, "subject", "primary", true)
	session, proof := digestForTest('u'), strings.Repeat("b", 48)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-proof-concurrent", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{challengeDigest(proof), "subject", session, now.Add(defaultMfaCodeTTL).UnixMilli()}},
		{SQL: `INSERT INTO identity_webauthn_service_proof_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{challengeDigest(proof), modificationPurpose}},
	}}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, _, err := s.ExchangeModificationProof(ctx, "subject", session, proof)
			results <- err
		}()
	}
	close(start)
	winners := 0
	for range 2 {
		if <-results == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("proof exchange winners=%d", winners)
	}
	expired := strings.Repeat("c", 48)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-proof-expired", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{challengeDigest(expired), "subject", session, now.UnixMilli()}},
		{SQL: `INSERT INTO identity_webauthn_service_proof_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{challengeDigest(expired), modificationPurpose}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ExchangeModificationProof(ctx, "subject", session, expired); !errors.Is(err, ErrConflict) {
		t.Fatalf("proof expiry boundary error=%v", err)
	}
}

func TestModificationProofCASLoserCannotCreateProof(t *testing.T) {
	s, db, now := newTestService(t)
	ctx := context.Background()
	credentialID := seedPasskey(t, s, db, "subject", "primary", true)
	session := digestForTest('m')
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-finish-expired-proof", SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{digestForTest('z'), "subject", session, now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	ceremonies := []string{digestForTest('a'), digestForTest('b')}
	for _, digest := range ceremonies {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-finish-ceremony-" + digest, Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO identity_webauthn_mfa_ceremonies (code_digest,subject,session_digest,session_json,expires_at_unix_ms,proof_expires_at_unix_ms) VALUES (?,?,?,?,?,?)`, Args: []any{digest, "subject", session, "sealed", now.Add(time.Minute).UnixMilli(), now.Add(defaultMfaCodeTTL).UnixMilli()}},
			{SQL: `INSERT INTO identity_webauthn_service_ceremony_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{digest, modificationPurpose}},
		}}); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	results := make(chan error, len(ceremonies))
	const credentialJSON = "credential-update"
	const signCount int64 = 1
	for i, ceremonyDigest := range ceremonies {
		go func(i int, ceremonyDigest string) {
			<-start
			_, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-finish-cas-" + ceremonyDigest, Statements: mfaFinishStatements(ceremonyDigest, digestForTest(byte('c'+i)), modificationPurpose, "subject", session, strings.Repeat(string(rune('a'+i)), 22), credentialID, credentialJSON, signCount, 0, 0, now, now.Add(defaultMfaCodeTTL))})
			results <- err
		}(i, ceremonyDigest)
	}
	close(start)
	for range ceremonies {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}

	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE subject=?`, Args: []any{"subject"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 {
		t.Fatalf("CAS loser created a proof: rows=%d err=%v", len(q.Rows), err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential_version FROM identity_webauthn_credentials WHERE credential_id=?`, Args: []any{credentialID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(1) {
		t.Fatalf("credential CAS version=%v err=%v", q.Rows, err)
	}
}

func TestModificationProofCredentialInterpositionLeavesCeremonyUnconsumed(t *testing.T) {
	s, db, now := newTestService(t)
	ctx := context.Background()
	credentialID := seedPasskey(t, s, db, "subject", "primary", true)
	session := digestForTest('q')
	ceremonyDigest, proofDigest := digestForTest('e'), digestForTest('f')
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-interposition-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_webauthn_mfa_ceremonies (code_digest,subject,session_digest,session_json,expires_at_unix_ms,proof_expires_at_unix_ms) VALUES (?,?,?,?,?,?)`, Args: []any{ceremonyDigest, "subject", session, "sealed", now.Add(time.Minute).UnixMilli(), now.Add(defaultMfaCodeTTL).UnixMilli()}},
		{SQL: `INSERT INTO identity_webauthn_service_ceremony_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{ceremonyDigest, modificationPurpose}},
		{SQL: `UPDATE identity_webauthn_credentials SET credential_version=1 WHERE credential_id=?`, Args: []any{credentialID}},
	}}); err != nil {
		t.Fatal(err)
	}
	statements := mfaFinishStatements(ceremonyDigest, proofDigest, modificationPurpose, "subject", session, strings.Repeat("e", 22), credentialID, "updated", 1, 0, 0, now, now.Add(defaultMfaCodeTTL))
	res, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-interposition-finish", Statements: statements})
	if err != nil {
		t.Fatal(err)
	}
	if res.RowsAffected != 0 {
		t.Fatalf("interposed MFA finish rows affected=%d, want 0", res.RowsAffected)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_webauthn_mfa_ceremonies WHERE code_digest=?`, Args: []any{ceremonyDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != nil {
		t.Fatalf("ceremony state=%v err=%v, want unconsumed", q.Rows, err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_webauthn_mfa_proofs WHERE code_digest=?`, Args: []any{proofDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(0) {
		t.Fatalf("proof rows=%v err=%v, want 0", q.Rows, err)
	}
}

func TestModificationProofExchangeCredentialInterpositionLeavesProofUnconsumed(t *testing.T) {
	s, db, now := newTestService(t)
	ctx := context.Background()
	session := digestForTest('x')
	proofDigest, tokenDigest := digestForTest('g'), digestForTest('h')
	credentialID := seedPasskey(t, s, db, "subject", "primary", true)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-exchange-interposition-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{proofDigest, "subject", session, now.Add(defaultMfaCodeTTL).UnixMilli()}},
		{SQL: `INSERT INTO identity_webauthn_service_proof_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{proofDigest, modificationPurpose}},
		{SQL: `DELETE FROM identity_webauthn_credentials WHERE credential_id=?`, Args: []any{credentialID}},
	}}); err != nil {
		t.Fatal(err)
	}
	statements := modificationProofExchangeStatements(proofDigest, tokenDigest, "subject", session, strings.Repeat("g", 22), now, now.Add(modificationTTL))
	res, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-exchange-interposition", Statements: statements})
	if err != nil {
		t.Fatal(err)
	}
	if res.RowsAffected != 0 {
		t.Fatalf("interposed MFA exchange rows affected=%d, want 0", res.RowsAffected)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_webauthn_mfa_proofs WHERE code_digest=?`, Args: []any{proofDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != nil {
		t.Fatalf("proof state=%v err=%v, want unconsumed", q.Rows, err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_mfa_mod_tokens WHERE token_digest=?`, Args: []any{tokenDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(0) {
		t.Fatalf("token rows=%v err=%v, want 0", q.Rows, err)
	}
}
