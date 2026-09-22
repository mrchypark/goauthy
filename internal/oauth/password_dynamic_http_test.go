package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDynamicPasswordHTTPAndRefresh(t *testing.T) {
	t.Parallel()
	for _, method := range []string{dcr.TokenEndpointAuthNone, dcr.TokenEndpointAuthClientBasic, dcr.TokenEndpointAuthClientPost} {
		t.Run(method, func(t *testing.T) {
			env := map[string]string{"GOAUTHY_RHIZA_PROFILE": "standalone", "GOAUTHY_CLUSTER_ID": "password-recovery", "GOAUTHY_NODE_ID": "password-restart", "GOAUTHY_DATA_DIR": t.TempDir(), "GOAUTHY_RHIZA_OBJECT_STORE_BUCKET": "test", "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX": "password-recovery"}
			cfg, err := storage.RhizaConfigFromEnv(func(name string) string { return env[name] })
			if err != nil {
				t.Fatal(err)
			}
			cfg.ObjStoreProvider, cfg.ObjStoreDir = rhiza.ObjectStoreProviderFilesystem, t.TempDir()
			db, err := rhiza.Open(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if db != nil {
					_ = db.Close()
				}
			})
			if err := storage.Migrate(t.Context(), db); err != nil {
				t.Fatal(err)
			}
			users, err := identity.NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			phc, err := credential.Hash([]byte("correct password"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := users.BootstrapUser(t.Context(), "dynamic-password-user", "alice", phc); err != nil {
				t.Fatal(err)
			}
			resetSubject := ""
			var resetErr error
			key := oidcTestKey(t)
			hmacSecret := randomSecret(t)
			s, err := NewServerWithOIDC(t.Context(), db, hmacSecret, testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{PasswordExpired: func(_ context.Context, subject string) error { resetSubject = subject; return resetErr }, Issuer: oidcTestIssuer, PasswordUsers: users, ValidateSubject: users.ValidateSubject, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil }})
			if err != nil {
				t.Fatal(err)
			}
			c, err := s.store.dynamicClients.Create(t.Context(), dcr.CreateRequest{ClientID: "dynamic-password-http", Name: "Password HTTP", TokenEndpointAuthMethod: method, GrantTypes: []string{"password", "refresh_token"}, Scopes: []string{"profile"}, DefaultScopes: []string{"profile"}})
			if err != nil {
				t.Fatal(err)
			}
			post := func(form url.Values) *httptest.ResponseRecorder {
				form.Set("client_id", c.ClientID)
				if method == dcr.TokenEndpointAuthClientPost {
					form.Set("client_secret", c.ClientSecret)
				}
				r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if method == dcr.TokenEndpointAuthClientBasic {
					r.SetBasicAuth(c.ClientID, c.ClientSecret)
				}
				w := httptest.NewRecorder()
				s.TokenHandler().ServeHTTP(&passwordDeadlineRecorder{ResponseRecorder: w}, r)
				return w
			}
			loginTime := func() int64 {
				t.Helper()
				q, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COALESCE(last_login_at_unix_ms,0) FROM identity_users WHERE subject='dynamic-password-user'`, Consistency: rhiza.ConsistencyLinearizable})
				if err != nil || len(q.Rows) != 1 {
					t.Fatal("read login timestamp")
				}
				return q.Rows[0][0].(int64)
			}
			failureState := func() []any {
				t.Helper()
				q, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT last_failed_login_at_unix_ms,failed_login_attempts FROM identity_users WHERE subject='dynamic-password-user'`, Consistency: rhiza.ConsistencyLinearizable})
				if err != nil || len(q.Rows) != 1 {
					t.Fatal("read failure state")
				}
				return q.Rows[0]
			}
			bad := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"incorrect"}})
			if bad.Code != http.StatusBadRequest {
				t.Fatalf("bad password status=%d", bad.Code)
			}
			if state := failureState(); state[0] == nil || state[1] != int64(1) {
				t.Fatal("password failure not recorded")
			}
			if loginTime() != 0 {
				t.Fatal("failed password recorded a successful login")
			}
			if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "reject-login-state", SQL: `CREATE TRIGGER reject_password_login_state BEFORE INSERT ON oidc_user_clients BEGIN SELECT RAISE(ABORT,'login state unavailable'); END`}); err != nil {
				t.Fatal(err)
			}
			rejected := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}})
			if rejected.Code != http.StatusInternalServerError || strings.Contains(rejected.Body.String(), "access_token") {
				t.Fatalf("login-state failure status=%d", rejected.Code)
			}
			artifacts, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens),(SELECT COUNT(*) FROM oauth_refresh_tokens),(SELECT COUNT(*) FROM oauth_token_requests),(SELECT COUNT(*) FROM oidc_user_clients)`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(artifacts.Rows) != 1 {
				t.Fatal("read rolled back artifacts", err)
			}
			for _, count := range artifacts.Rows[0] {
				if count != int64(0) {
					t.Fatal("login-state failure left token artifacts")
				}
			}
			if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "restore-login-state", SQL: `DROP TRIGGER reject_password_login_state`}); err != nil {
				t.Fatal(err)
			}
			issued := decodeOIDCToken(t, post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}}))
			if issued.IDToken == "" || issued.RefreshToken == "" {
				t.Fatal("password tokens missing")
			}
			if state := failureState(); state[0] != nil || state[1] != nil {
				t.Fatal("successful login did not clear failures")
			}
			associations, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT client_id,logout_uri FROM oidc_user_clients WHERE subject='dynamic-password-user'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(associations.Rows) != 1 || associations.Rows[0][0] != c.ClientID || associations.Rows[0][1] != "" {
				t.Fatalf("password login association missing: %+v %v", associations, err)
			}
			lastLogin := loginTime()
			if lastLogin <= 0 {
				t.Fatal("successful password did not record login")
			}
			lastUsed := dynamicLastUsed(t, db, c.ClientID)
			if lastUsed <= 0 {
				t.Fatal("usage not recorded")
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db = nil
			cfg.DataDir = t.TempDir() // Recover from objects without access to the previous data directory.
			db, err = rhiza.Open(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			users, err = identity.NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			s, err = NewServerWithOIDC(t.Context(), db, hmacSecret, testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{PasswordExpired: func(_ context.Context, subject string) error { resetSubject = subject; return resetErr }, Issuer: oidcTestIssuer, PasswordUsers: users, ValidateSubject: users.ValidateSubject, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil }})
			if err != nil {
				t.Fatal(err)
			}
			refreshed := decodeOIDCToken(t, post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}))
			if refreshed.IDToken == "" || refreshed.RefreshToken == "" {
				t.Fatal("refresh tokens missing")
			}
			if dynamicLastUsed(t, db, c.ClientID) != lastUsed {
				t.Fatal("refresh changed login usage")
			}
			if loginTime() != lastLogin {
				t.Fatal("recovery or refresh changed login timestamp")
			}
			var authTime time.Time
			for _, token := range []string{issued.IDToken, refreshed.IDToken} {
				claims, err := oidc.VerifyIDToken(token, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, oidcTestIssuer, c.ClientID, time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				if claims.Subject != "dynamic-password-user" || claims.SessionID != "" || claims.AuthTime.IsZero() || len(claims.AuthenticationMethods) != 1 || claims.AuthenticationMethods[0] != "pwd" {
					t.Fatal("incorrect password identity claims")
				}
				if !authTime.IsZero() && !authTime.Equal(claims.AuthTime) {
					t.Fatal("refresh advanced auth time")
				}
				authTime = claims.AuthTime
			}

			if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "expire-http-password", SQL: `UPDATE identity_users SET password_changed_at_unix_ms=1 WHERE subject='dynamic-password-user'`}); err != nil {
				t.Fatal(err)
			}
			expired := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}})
			if expired.Code != http.StatusForbidden || resetSubject != "dynamic-password-user" || strings.Contains(expired.Body.String(), "access_token") {
				t.Fatalf("expired password recovery status=%d callback=%t", expired.Code, resetSubject != "")
			}
			if state := failureState(); state[1] != int64(1) {
				t.Fatal("expired password failure not recorded")
			}

			resetSubject = ""
			resetErr = context.DeadlineExceeded
			failedRecovery := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}})
			if failedRecovery.Code != http.StatusInternalServerError || resetSubject != "dynamic-password-user" || !strings.Contains(failedRecovery.Body.String(), `"server_error"`) {
				t.Fatalf("failed recovery status=%d callback=%t", failedRecovery.Code, resetSubject != "")
			}
			for _, field := range []string{"access_token", "refresh_token", "id_token"} {
				if strings.Contains(failedRecovery.Body.String(), field) {
					t.Fatalf("failed recovery returned %s", field)
				}
			}
			if state := failureState(); state[1] != int64(2) {
				t.Fatal("failed recovery did not record failure")
			}

		})
	}
}
