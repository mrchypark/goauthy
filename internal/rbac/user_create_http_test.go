package rbac

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/recovery"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type userCreateTestSender struct {
	messages []recovery.Message
	changes  []recovery.EmailChangeMessage
}

func TestCreateUserHTTPPreferredUsernamePolicy(t *testing.T) {
	custom, err := identity.NewPreferredUsernamePolicy("required", `^Team_[0-9]{2}$`, []string{"team_12"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		policy   *identity.PreferredUsernamePolicy
		reserved string
		invalid  string
	}{{"default", nil, "root", "Alice.Name"}, {"custom", custom, "Team_12", "alice"}} {
		t.Run(tc.name, func(t *testing.T) {
			h, store, sender, _, cookie := userCreateHTTPFixture(t)
			if err := h.SetUserValuesPolicy(identity.UserValuesPolicy{PreferredUsername: tc.policy}); err != nil {
				t.Fatal(err)
			}
			for _, invalid := range []string{tc.invalid, ""} {
				body, _ := json.Marshal(map[string]any{"email": "invalid@example.test", "language": "en", "roles": []string{}, "preferred_username": invalid})
				w := httptest.NewRecorder()
				h.CreateUser(w, userCreateRequest(cookie, string(body)))
				if w.Code != http.StatusBadRequest || len(sender.messages) != 0 || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE email='invalid@example.test'`) != 0 {
					t.Fatalf("invalid username status=%d mail=%d", w.Code, len(sender.messages))
				}
			}
			// Required and blacklist are deliberately exempt, but submitted syntax is not.
			for i, value := range []*string{nil, &tc.reserved} {
				email := []string{"absent@example.test", "reserved@example.test"}[i]
				body, _ := json.Marshal(map[string]any{"email": email, "language": "en", "roles": []string{}, "preferred_username": value})
				w := httptest.NewRecorder()
				h.CreateUser(w, userCreateRequest(cookie, string(body)))
				if w.Code != http.StatusOK || len(sender.messages) != i+1 {
					t.Fatalf("exempt username status=%d mail=%d", w.Code, len(sender.messages))
				}
				var got UserResponse
				if json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Email != email {
					t.Fatal("invalid created profile")
				}
				if value == nil && got.UserValues.PreferredUsername != nil || value != nil && (got.UserValues.PreferredUsername == nil || *got.UserValues.PreferredUsername != *value) {
					t.Fatal("created preferred username was not preserved")
				}
			}
		})
	}
}

func (s *userCreateTestSender) SendEmailChange(_ context.Context, message recovery.EmailChangeMessage) error {
	s.changes = append(s.changes, message)
	return nil
}

func (s *userCreateTestSender) SendPasswordReset(context.Context, recovery.Message) error { return nil }
func (s *userCreateTestSender) SendAlreadyRegistered(context.Context, recovery.Message) error {
	return nil
}
func (s *userCreateTestSender) SendPasswordNew(_ context.Context, message recovery.Message) error {
	s.messages = append(s.messages, message)
	return nil
}

func userCreateHTTPFixture(t *testing.T) (*Handler, *Store, *userCreateTestSender, *apikey.Store, *http.Cookie) {
	t.Helper()
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateRole(ctx, "admin", "viewer", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateGroup(ctx, "admin", "team/a", nil); err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStoreWithPasswordReset(db, mustUserCreateHasher(t), credential.DefaultRules(), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sender := &userCreateTestSender{}
	pow, err := recovery.NewProofOfWork(db, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := recovery.NewService(db, identities, sender, "https://issuer.example.test", credential.DefaultRules(), loginpolicy.NewStore(db), pow, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sessions := storeBrowserForUserCreate(t, db)
	issued, err := sessions.CreateSession(ctx, "admin", "pwd", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browserCookieForUserCreate("https://issuer.example.test", issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(store, sessions, identities, "https://issuer.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.BindUserCreation(service, time.Hour); err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	return h, store, sender, keys, cookie
}

// Small wrappers keep the fixture imports local to this file and avoid changing
// the shared browser helper's semantics.
func storeBrowserForUserCreate(t *testing.T, db *rhiza.DB) *browser.Store {
	s, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func browserCookieForUserCreate(issuer, token string, expires time.Time) (*http.Cookie, error) {
	return browser.SessionCookie(issuer, token, expires)
}
func mustUserCreateHasher(t *testing.T) *credential.Hasher {
	h, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func userCreateRequest(cookie *http.Cookie, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/users", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
		if csrf, err := browser.DeriveCSRFToken(cookie.Value); err == nil {
			r.Header.Set("X-CSRF-Token", csrf)
		}
	}
	return r
}

func TestCreateUserHTTPBrowserAndCreateOnlyAPIKey(t *testing.T) {
	h, store, sender, keys, cookie := userCreateHTTPFixture(t)
	body := `{"email":"New@Example.TEST","language":"en","roles":["viewer","missing"],"groups":["team/a","missing"],"preferred_username":"unicode-user","given_name":"José Name","family_name":"Family","tz":"Asia/Seoul"}`
	if _, err := decodeUserCreate(httptest.NewRecorder(), userCreateRequest(cookie, body), nil); err != nil {
		t.Fatalf("decode=%v", err)
	}
	w := httptest.NewRecorder()
	h.CreateUser(w, userCreateRequest(cookie, body))
	if w.Code != http.StatusOK {
		t.Fatalf("browser status=%d body=%s", w.Code, w.Body.String())
	}
	var got UserResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Email != "new@example.test" || len(got.Roles) != 1 || got.Roles[0] != "viewer" || len(got.Groups) != 1 || got.Groups[0] != "team/a" || got.UserValues.Timezone == nil || *got.UserValues.Timezone != "Asia/Seoul" || len(sender.messages) != 1 {
		t.Fatalf("response=%+v mail=%+v", got, sender.messages)
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "create-only", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Create}}}})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	req := userCreateRequest(nil, `{"email":"key@example.test","language":"en","roles":[]}`)
	req.Header.Set("Authorization", "API-Key "+token)
	h.CreateUser(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("key status=%d body=%s", w.Code, w.Body.String())
	}
	if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE email='key@example.test'`) != 1 {
		t.Fatal("create-only key did not create")
	}
}

func TestCreateUserHTTPStrictJSON(t *testing.T) {
	h, _, _, _, cookie := userCreateHTTPFixture(t)
	for _, body := range []string{
		`{}`, `{"email":null,"language":"en","roles":[]}`, `{"email":"x@example.test","language":"en"}`,
		`{"email":"x@example.test","language":"en","roles":[],"unknown":1}`, `{"email":"x@example.test","language":"en","roles":[],"roles":[]}`,
		`{"email":"x@example.test","language":"EN","roles":[]}`, `{"email":"x@example.test","language":"en","roles":["viewer"],"given_name":"` + strings.Repeat("a", 33) + `"}`,
		`{"email":"x@example.test","language":"en","roles":[],"tz":"Not/AZone"}`,
	} {
		w := httptest.NewRecorder()
		h.CreateUser(w, userCreateRequest(cookie, body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("body=%s status=%d", body, w.Code)
		}
	}
}

func TestCreateUserHTTPGuardSnapshotPreventsWritesAndMail(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		api       bool
	}{
		{"role", `DELETE FROM rbac_user_roles WHERE subject='admin'`, false},
		{"session", `UPDATE browser_sessions SET revoked_at_unix_ms=1 WHERE subject='admin'`, false},
		{"expiry", `UPDATE identity_users SET user_expires_at_unix_ms=1 WHERE subject='admin'`, false},
		{"grant", `DELETE FROM api_key_access WHERE key_name='hook-key'`, true},
		{"key", `DELETE FROM api_keys WHERE name='hook-key'`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, store, sender, keys, cookie := userCreateHTTPFixture(t)
			var token string
			if tc.api {
				var err error
				_, token, err = keys.Create(context.Background(), nil, apikey.Request{Name: "hook-key", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Create}}}})
				if err != nil {
					t.Fatal(err)
				}
			}
			called := false
			h.beforeUserCreate = func() {
				called = true
				if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "create-hook-" + tc.name, SQL: tc.sql}); err != nil {
					t.Errorf("hook SQL: %v", err)
				}
			}
			req := userCreateRequest(cookie, `{"email":"blocked-`+tc.name+`@example.test","language":"en","roles":[]}`)
			if tc.api {
				req.Header.Set("Authorization", "API-Key "+token)
				req = userCreateRequest(nil, `{"email":"blocked-`+tc.name+`@example.test","language":"en","roles":[]}`)
				req.Header.Set("Authorization", "API-Key "+token)
			}
			w := httptest.NewRecorder()
			h.CreateUser(w, req)
			if !called || w.Code != http.StatusForbidden {
				t.Fatalf("called=%t status=%d body=%s", called, w.Code, w.Body.String())
			}
			if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles`) != 0 || len(sender.messages) != 0 {
				t.Fatalf("write/mail after hook rows/mail=%d", len(sender.messages))
			}
		})
	}
}

func TestCreateUserHTTPDelegatedExactWildcardAndRejections(t *testing.T) {
	h, store, sender, _, _ := userCreateHTTPFixture(t)
	ctx := context.Background()
	insertActive(t, store.db, "delegated")
	role, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "create-delegated-role", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_principal_versions(subject,revision,updated_at_unix_ms) VALUES('delegated',1,0)`},
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('delegated',?,0)`, Args: []any{role.ID}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateGroup(ctx, "admin", "team/exact", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateGroup(ctx, "admin", "other/x", nil); err != nil {
		t.Fatal(err)
	}
	exactRole, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/exact", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "create-delegated-exact-role", SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('delegated',?,0)`, Args: []any{exactRole.ID}}); err != nil {
		t.Fatal(err)
	}
	issued, err := h.browser.CreateSession(ctx, "delegated", "pwd", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.CreateUser(w, userCreateRequest(cookie, `{"email":"delegated@example.test","language":"en","roles":[],"groups":["team/a"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("wildcard status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "remove-delegated-wildcard", SQL: `DELETE FROM rbac_user_roles WHERE subject='delegated' AND role_id=?`, Args: []any{role.ID}}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.CreateUser(w, userCreateRequest(cookie, `{"email":"delegated-exact@example.test","language":"en","roles":[],"groups":["team/exact"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("exact status=%d body=%s", w.Code, w.Body.String())
	}
	for _, body := range []string{
		`{"email":"role-denied@example.test","language":"en","roles":["viewer"],"groups":[]}`,
		`{"email":"wildcard-now-denied@example.test","language":"en","roles":[],"groups":["team/a"]}`,
		`{"email":"scope-denied@example.test","language":"en","roles":[],"groups":["other/x"]}`,
		`{"email":"unknown-denied@example.test","language":"en","roles":[],"groups":["missing-group"]}`,
	} {
		w = httptest.NewRecorder()
		beforeRows, beforeMail := countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles`), len(sender.messages)
		h.CreateUser(w, userCreateRequest(cookie, body))
		if w.Code != http.StatusForbidden || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles`) != beforeRows || len(sender.messages) != beforeMail {
			t.Errorf("body=%s status=%d response=%s", body, w.Code, w.Body.String())
		}
	}
}

func countRows(t *testing.T, store *Store, sql string) int64 {
	t.Helper()
	r, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: sql, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 {
		t.Fatalf("query=%v rows=%#v", err, r.Rows)
	}
	return r.Rows[0][0].(int64)
}
