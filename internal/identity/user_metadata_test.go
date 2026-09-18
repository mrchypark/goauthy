package identity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUserCreationMetadataPreservesOriginalTime(t *testing.T) {
	store := testResetStore(t, testRules(2))
	ctx := context.Background()
	created := time.UnixMilli(1_700_000_000_123)
	store.now = func() time.Time { return created }
	bootstrapPassword(t, store, "alice", "alice", []byte("CurrentPassword1"))
	assertUserMetadata(t, store, "alice", created.UnixMilli(), nil)
	registered, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "new@example.test", TTL: time.Hour})
	if err != nil || !registered.Created {
		t.Fatalf("registration created=%v err=%v", registered.Created, err)
	}
	assertUserMetadata(t, store, registered.Subject, created.UnixMilli(), nil)
	store.now = func() time.Time { return created.Add(time.Minute) }
	// Rebootstrap and duplicate registration must not rewrite creation time.
	bootstrapPassword(t, store, "alice", "alice", []byte("OtherPassword2"))
	duplicate, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "new@example.test", TTL: time.Hour})
	if err != nil || duplicate.Created || duplicate.Subject != registered.Subject {
		t.Fatalf("duplicate created=%v subject=%q err=%v", duplicate.Created, duplicate.Subject, err)
	}
	assertUserMetadata(t, store, "alice", created.UnixMilli(), nil)
	assertUserMetadata(t, store, registered.Subject, created.UnixMilli(), nil)
	if err := store.ChangePassword(ctx, "alice", []byte("CurrentPassword1"), []byte("ChangedPassword2")); err != nil {
		t.Fatal(err)
	}
	assertUserMetadata(t, store, "alice", created.UnixMilli(), nil)
}

func TestRecordLoginForSessionUsesDurableMonotonicTime(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.UnixMilli(1_700_000_010_987)
	store.now = func() time.Time { return now }
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "metadata-browser-schema", Statements: browser.SchemaStatements()}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "metadata-user", SQL: `INSERT INTO identity_users(subject,username,password_phc,created_at_unix_ms) VALUES ('alice','alice','',123)`}); err != nil {
		t.Fatal(err)
	}
	insertSession := func(name, subject, method string, created, expires int64, revoked any) string {
		t.Helper()
		digest := sha256.Sum256([]byte(name))
		id := base64.RawURLEncoding.EncodeToString(digest[:])
		_, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "metadata-session-" + name,
			SQL:  `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,revoked_at_unix_ms) VALUES (?,?,?,?,?,?,?)`,
			Args: []any{id, subject, method, created, expires, created, revoked}})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	latest := now.Add(-time.Second).UnixMilli()
	laterExpiry := now.Add(time.Hour).UnixMilli()
	valid := insertSession("valid", "alice", "pwd", latest, laterExpiry, nil)
	if err := store.RecordLoginForSession(ctx, "alice", valid); err != nil {
		t.Fatal(err)
	}
	assertUserMetadata(t, store, "alice", 123, latest)
	for i, method := range []string{"mfa", "webauthn", "external"} {
		older := insertSession(method, "alice", method, latest-int64(i+1), laterExpiry, nil)
		if err := store.RecordLoginForSession(ctx, "alice", older); err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		assertUserMetadata(t, store, "alice", 123, latest)
	}
	for _, tc := range []struct{ name, id string }{
		{"malformed", "not-a-session"},
		{"absent", base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		{"wrong-subject", insertSession("wrong", "bob", "pwd", latest+1, laterExpiry, nil)},
		{"anonymous", insertSession("anonymous", "", "", latest+1, laterExpiry, nil)},
		{"expired", insertSession("expired", "alice", "pwd", latest+1, now.UnixMilli(), nil)},
		{"revoked", insertSession("revoked", "alice", "pwd", latest+1, laterExpiry, latest+2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.RecordLoginForSession(ctx, "alice", tc.id); err != ErrInvalidCredentials {
				t.Fatalf("err=%v", err)
			}
			assertUserMetadata(t, store, "alice", 123, latest)
		})
	}
	// A repeated invocation must not replay the first successful mutation receipt.
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "metadata-revoke", SQL: `UPDATE browser_sessions SET revoked_at_unix_ms=? WHERE token_digest=?`, Args: []any{now.UnixMilli(), valid}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordLoginForSession(ctx, "alice", valid); err != ErrInvalidCredentials {
		t.Fatalf("repeated revoked session err=%v", err)
	}
	active := insertSession("disabled", "alice", "pwd", latest+1, laterExpiry, nil)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "metadata-disable", SQL: `UPDATE identity_users SET disabled=1 WHERE subject='alice'`}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordLoginForSession(ctx, "alice", active); err != ErrInvalidCredentials {
		t.Fatalf("disabled identity err=%v", err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "metadata-cleanup", SQL: `DELETE FROM browser_sessions`}); err != nil {
		t.Fatal(err)
	}
	assertUserMetadata(t, store, "alice", 123, latest)
}

func assertUserMetadata(t *testing.T, store *Store, subject string, created int64, login any) {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT created_at_unix_ms,last_login_at_unix_ms FROM identity_users WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 || result.Rows[0][0] != created || result.Rows[0][1] != login {
		t.Fatalf("metadata=%v want=(%d,%v) err=%v", result.Rows, created, login, err)
	}
}

func TestRecordPasswordLoginFencesCredentials(t *testing.T) {
	store := testResetStore(t, testRules(2))
	bootstrapPassword(t, store, "alice", "alice", []byte("CurrentPassword1"))
	auth, err := store.Authenticate(t.Context(), "alice", []byte("CurrentPassword1"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1900000000000)
	store.now = func() time.Time { return now }
	if err := store.RecordPasswordLogin(t.Context(), auth); err != nil {
		t.Fatal(err)
	}
	read := func() int64 {
		t.Helper()
		q, err := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT last_login_at_unix_ms FROM identity_users WHERE subject='alice'`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			t.Fatal(err)
		}
		return q.Rows[0][0].(int64)
	}
	if read() != now.UnixMilli() {
		t.Fatal("login not recorded")
	}
	now = now.Add(-time.Minute)
	if err := store.RecordPasswordLogin(t.Context(), auth); err != nil {
		t.Fatal(err)
	}
	if read() != 1900000000000 {
		t.Fatal("login time moved backwards")
	}
	if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "password-login-generation", SQL: `UPDATE identity_users SET password_generation=password_generation+1 WHERE subject='alice'`}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := store.RecordPasswordLogin(t.Context(), auth); err != ErrInvalidCredentials {
		t.Fatalf("stale credential accepted: %v", err)
	}
	if read() != 1900000000000 {
		t.Fatal("rejected login changed timestamp")
	}
}

func TestRecordPasswordLoginRejectsInactiveAuthentication(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"disabled", `UPDATE identity_users SET disabled=1 WHERE subject='alice'`},
		{"expiry boundary", `UPDATE identity_users SET user_expires_at_unix_ms=1900000000000 WHERE subject='alice'`},
		{"authentication generation", `UPDATE identity_authentication_modes SET generation=generation+1 WHERE subject='alice'`},
		{"passkey mode", `UPDATE identity_authentication_modes SET mode='passkey' WHERE subject='alice'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := testResetStore(t, testRules(2))
			bootstrapPassword(t, store, "alice", "alice", []byte("CurrentPassword1"))
			auth, err := store.Authenticate(t.Context(), "alice", []byte("CurrentPassword1"))
			if err != nil {
				t.Fatal(err)
			}
			store.now = func() time.Time { return time.UnixMilli(1900000000000) }
			if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "password-login-inactive", SQL: tc.sql}); err != nil {
				t.Fatal(err)
			}
			if err := store.RecordPasswordLogin(t.Context(), auth); err != ErrInvalidCredentials {
				t.Fatalf("inactive authentication accepted: %v", err)
			}
			q, err := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT last_login_at_unix_ms FROM identity_users WHERE subject='alice'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != nil {
				t.Fatal("rejected authentication recorded login")
			}
		})
	}
}

func TestFailureMetadataUserResponse(t *testing.T) {
	store := testResetStore(t, testRules(2))
	bootstrapPassword(t, store, "alice", "alice", []byte("CurrentPassword1"))
	if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "failure-response", SQL: `UPDATE identity_users SET last_failed_login_at_unix_ms=1900000000123,failed_login_attempts=3 WHERE subject='alice'`}); err != nil {
		t.Fatal(err)
	}
	q, err := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: UserResponseJSONSQL, Args: []any{"alice"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 {
		t.Fatal("failure metadata query")
	}
	var response UserResponse
	raw, ok := q.Rows[0][0].(string)
	if !ok || json.Unmarshal([]byte(raw), &response) != nil || response.LastFailedLogin == nil || *response.LastFailedLogin != 1900000000 || response.FailedLoginAttempts == nil || *response.FailedLoginAttempts != 3 {
		t.Fatal("failure metadata projection")
	}
}

func TestPasswordGrantFailureCountAndCredentialFence(t *testing.T) {
	store := testResetStore(t, testRules(2))
	bootstrapPassword(t, store, "alice", "alice", []byte("CurrentPassword1"))
	auth, err := store.Authenticate(t.Context(), "alice", []byte("CurrentPassword1"))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := store.AuthenticatePasswordGrant(t.Context(), "alice", []byte("wrong"), nil); err != ErrInvalidCredentials {
			t.Fatalf("bad password: %v", err)
		}
	}
	if _, err := store.Authenticate(t.Context(), "alice", []byte("wrong")); err != ErrInvalidCredentials {
		t.Fatal(err)
	}
	if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "stale-failure", SQL: `UPDATE identity_users SET password_generation=password_generation+1 WHERE subject='alice'`}); err != nil {
		t.Fatal(err)
	}
	if err := store.recordPasswordFailure(t.Context(), auth); err != nil {
		t.Fatal(err)
	}
	q, err := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT failed_login_attempts FROM identity_users WHERE subject='alice'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(2) {
		t.Fatal("failure count or stale-generation fence")
	}
}

func TestPasswordFailureAccountBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, sql, password string
		wantCount           any
		wantErr             error
	}{
		{"disabled", `UPDATE identity_users SET disabled=1`, "wrong", nil, ErrInvalidCredentials},
		{"account expired", `UPDATE identity_users SET user_expires_at_unix_ms=1900000000000`, "wrong", nil, ErrInvalidCredentials},
		{"no password", `UPDATE identity_users SET password_phc=''`, "wrong", int64(1), ErrInvalidCredentials},
		{"password expired correct", `UPDATE identity_users SET password_changed_at_unix_ms=1`, "CurrentPassword1", int64(1), ErrPasswordExpired},
		{"password expired wrong", `UPDATE identity_users SET password_changed_at_unix_ms=1`, "wrong", int64(1), ErrInvalidCredentials},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := testRules(2)
			rules.ValidDays = 1
			store := testResetStore(t, rules)
			store.now = func() time.Time { return time.UnixMilli(1900000000000) }
			bootstrapPassword(t, store, "alice", "alice", []byte("CurrentPassword1"))
			if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "failure-boundary", SQL: tc.sql}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.AuthenticatePasswordGrant(t.Context(), "alice", []byte(tc.password), nil); err != tc.wantErr {
				t.Fatalf("authentication error=%v want=%v", err, tc.wantErr)
			}
			q, err := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT failed_login_attempts FROM identity_users WHERE subject='alice'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != tc.wantCount {
				t.Fatal("failure boundary count")
			}
		})
	}
}

func TestConcurrentPasswordFailuresDoNotLoseIncrements(t *testing.T) {
	store := testResetStore(t, testRules(2))
	bootstrapPassword(t, store, "alice", "alice", []byte("CurrentPassword1"))
	auth, err := store.Authenticate(t.Context(), "alice", []byte("CurrentPassword1"))
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 4)
	for range 4 {
		go func() {
			results <- store.recordPasswordFailure(t.Context(), auth)
		}()
	}
	for range 4 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.AuthenticatePasswordGrant(t.Context(), "missing-user", []byte("wrong"), nil); err != ErrInvalidCredentials {
		t.Fatal(err)
	}
	q, err := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT failed_login_attempts FROM identity_users WHERE subject='alice'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(4) {
		t.Fatal("concurrent failure count")
	}
}

func TestPasswordExpiredRecoveryPrecedesFailureRecord(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			rules := testRules(2)
			rules.ValidDays = 1
			store := testResetStore(t, rules)
			store.now = func() time.Time { return time.UnixMilli(1900000000000) }
			bootstrapPassword(t, store, "alice", "alice", []byte("CurrentPassword1"))
			if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "expire-for-recovery", SQL: `UPDATE identity_users SET password_changed_at_unix_ms=1`}); err != nil {
				t.Fatal(err)
			}
			calls := 0
			auth, err := store.AuthenticatePasswordGrant(t.Context(), "alice", []byte("CurrentPassword1"), func(ctx context.Context, subject string) error {
				calls++
				if subject != "alice" {
					t.Fatalf("recovery subject=%q", subject)
				}
				q, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT failed_login_attempts FROM identity_users WHERE subject='alice'`, Consistency: rhiza.ConsistencyLinearizable})
				if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != nil {
					t.Fatalf("failure recorded before recovery: %+v %v", q, err)
				}
				if fail {
					return context.DeadlineExceeded
				}
				return nil
			})
			want := ErrPasswordExpired
			if fail {
				want = ErrPasswordResetUnavailable
			}
			if err != want || calls != 1 {
				t.Fatalf("error=%v calls=%d", err, calls)
			}
			if fail && auth.Subject != "" {
				t.Fatal("failed recovery returned authenticated subject")
			}
			q, queryErr := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT failed_login_attempts FROM identity_users WHERE subject='alice'`, Consistency: rhiza.ConsistencyLinearizable})
			if queryErr != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(1) {
				t.Fatalf("failure count: %+v %v", q, queryErr)
			}
		})
	}
}
