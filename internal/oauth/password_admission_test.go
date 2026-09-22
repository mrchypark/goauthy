package oauth

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestPasswordHTTPAdmission(t *testing.T) {
	db := oauthTestDB(t)
	users, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = users.BootstrapUser(t.Context(), "admission-user", "alice", hash); err != nil {
		t.Fatal(err)
	}
	managed := clients.NewStore(db, &oidc.Keyring{})
	guard := func() (string, []any) { return "1", nil }
	c, err := managed.CreateWithGuard(t.Context(), clients.NewRequest{ID: "admission-client", RedirectURIs: []string{testRedirectURI}}, guard)
	if err != nil {
		t.Fatal(err)
	}
	_, err = managed.UpdateWithGuard(t.Context(), c.ID, c.Revision, clients.UpdateRequest{Enabled: true, Scopes: []string{"profile"}, DefaultScopes: []string{"profile"}, GrantTypes: []string{"password"}}, guard)
	if err != nil {
		t.Fatal(err)
	}
	key := oidcTestKey(t)
	s, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{Issuer: "https://issuer.example.test", PasswordUsers: users, ManagedClients: managed, LoadSigningKey: func(ctx context.Context) (oidc.SigningKey, error) { return key, nil }})
	if err != nil {
		t.Fatal(err)
	}
	request := func(peer, password string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{"grant_type": {"password"}, "client_id": {c.ID}, "username": {"alice"}, "password": {password}}
		r := httptest.NewRequest("POST", "https://issuer.example.test/oidc/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(browser.ContextWithPeerIP(r.Context(), peer))
		w := httptest.NewRecorder()
		s.TokenHandler().ServeHTTP(&passwordDeadlineRecorder{ResponseRecorder: w}, r)
		return w
	}
	policy := loginpolicy.NewStore(db)
	lockdown := loginpolicy.NewLockdownStore(db)
	t.Run("control", func(t *testing.T) {
		if w := request("192.0.2.1", "correct password"); w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("shared attempt budget blocks before password verification", func(t *testing.T) {
		for i := 0; i < loginpolicy.DefaultAttemptLimit; i++ {
			if ok, err := policy.Allow(t.Context(), "192.0.2.2", time.Now()); err != nil || !ok {
				t.Fatalf("seed %v %v", ok, err)
			}
		}
		if w := request("192.0.2.2", "wrong password"); w.Code == 200 || !strings.Contains(w.Body.String(), "access_denied") {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		status, err := policy.Check(t.Context(), "192.0.2.2", time.Now())
		if err != nil || status.Failures != 0 {
			t.Fatalf("password checked despite budget: %+v %v", status, err)
		}
	})
	t.Run("failures reach shared enforcement", func(t *testing.T) {
		if w := request("192.0.2.3", "wrong password"); w.Code == 200 {
			t.Fatal("accepted wrong password")
		}
		status, err := policy.Check(t.Context(), "192.0.2.3", time.Now())
		if err != nil || status.Failures != 1 {
			t.Fatalf("%+v %v", status, err)
		}
	})
	t.Run("account failures reach shared detector", func(t *testing.T) {
		result, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM login_account_ip_failures WHERE account_hash=?", Args: []any{loginpolicy.AccountStuffingDigest("alice")}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
			t.Fatalf("account failures=%v err=%v", result.Rows, err)
		}
	})
	t.Run("lockdown denies ordinary user", func(t *testing.T) {
		if err := lockdown.SetLockdown(t.Context(), true, "test", time.Time{}); err != nil {
			t.Fatal(err)
		}
		if w := request("192.0.2.4", "correct password"); w.Code == 200 || !strings.Contains(w.Body.String(), "access_denied") {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("lockdown admin exception", func(t *testing.T) {
		_, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "admission-admin", Statements: []rhiza.SQLStatement{
			{SQL: "INSERT INTO rbac_roles(id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('admission-admin','rauthy_admin',NULL,1,0,0)"},
			{SQL: "INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES ('admission-user','admission-admin',0)"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if w := request("192.0.2.5", "correct password"); w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("lockdown read error fails closed", func(t *testing.T) {
		if err := lockdown.SetLockdown(t.Context(), false, "", time.Time{}); err != nil {
			t.Fatal(err)
		}
		_, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "break-lockdown", SQL: "DROP TABLE system_lockdown"})
		if err != nil {
			t.Fatal(err)
		}
		if w := request("192.0.2.6", "correct password"); w.Code == 200 || !strings.Contains(w.Body.String(), "server_error") {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
}
