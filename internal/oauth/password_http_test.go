package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestPasswordHTTPManagedClientAndRefresh(t *testing.T) {
	t.Parallel()
	for _, confidential := range []bool{false, true} {
		name := "public"
		if confidential {
			name = "confidential"
		}
		t.Run(name, func(t *testing.T) { testPasswordHTTP(t, confidential) })
	}
}

func testPasswordHTTP(t *testing.T, confidential bool) {
	t.Helper()
	db := oauthTestDB(t)
	users, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.BootstrapUser(t.Context(), "password-user", "alice", phc); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "password-groups", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_groups(id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('password-group','team/blue',1,0,0)`},
		{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) VALUES ('password-user','password-group',0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	setMembership := func(present bool) {
		t.Helper()
		sql := `DELETE FROM rbac_user_groups WHERE subject='password-user'`
		if present {
			sql = `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) VALUES ('password-user','password-group',0)`
		}
		if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "password-group-" + base64.RawURLEncoding.EncodeToString(randomSecret(t)), Statements: []rhiza.SQLStatement{{SQL: sql}, {SQL: `UPDATE rbac_principal_versions SET revision=revision+1 WHERE subject='password-user'`}}}); err != nil {
			t.Fatal(err)
		}
	}
	prefix := "team/"
	logoutURI := "https://managed-rp.example.test/logout"
	keyring := &oidc.Keyring{}
	if confidential {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "master"), []byte(base64.RawURLEncoding.EncodeToString(randomSecret(t))), 0600); err != nil {
			t.Fatal(err)
		}
		keyring, err = oidc.LoadKeyring(dir, "master")
		if err != nil {
			t.Fatal(err)
		}
	}
	managed := clients.NewStore(db, keyring)
	guard := func() (string, []any) { return "1", nil }
	client, err := managed.CreateWithGuard(t.Context(), clients.NewRequest{ID: "password-public", RedirectURIs: []string{testRedirectURI}}, guard)
	if err != nil {
		t.Fatal(err)
	}
	client, err = managed.UpdateWithGuard(t.Context(), client.ID, client.Revision, clients.UpdateRequest{BackchannelLogoutURI: &logoutURI, RestrictGroupPrefix: &prefix, Confidential: confidential, Enabled: true, Scopes: []string{"profile"}, DefaultScopes: []string{"profile"}, GrantTypes: []string{"password", "refresh_token"}}, guard)
	if err != nil {
		t.Fatal(err)
	}
	key := oidcTestKey(t)
	s, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{BackChannelLogoutURI: "https://bootstrap-rp.example.test/logout", ResolvePrincipal: func(ctx context.Context, subject string) (PrincipalClaims, error) {
		q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT p.revision,g.name FROM rbac_principal_versions p LEFT JOIN rbac_user_groups ug ON ug.subject=p.subject LEFT JOIN rbac_groups g ON g.id=ug.group_id WHERE p.subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return PrincipalClaims{}, err
		}
		claims := PrincipalClaims{}
		for _, row := range q.Rows {
			claims.Revision = row[0].(int64)
			if name, ok := row[1].(string); ok {
				claims.Groups = append(claims.Groups, name)
			}
		}
		return claims, nil
	}, Issuer: oidcTestIssuer, PasswordUsers: users, ManagedClients: managed, ValidateSubject: users.ValidateSubject, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil }})
	if err != nil {
		t.Fatal(err)
	}
	clientSecret := ""
	if confidential {
		clientSecret, err = managed.ReadSecretWithGuard(t.Context(), client.ID, guard)
		if err != nil {
			t.Fatal(err)
		}
	}
	suppliedSecret := clientSecret
	proof := ""
	post := func(form url.Values) *httptest.ResponseRecorder {
		form.Set("client_id", client.ID)
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if proof != "" {
			r.Header.Set("DPoP", proof)
		}
		if suppliedSecret != "" {
			r.SetBasicAuth(client.ID, suppliedSecret)
		}
		w := httptest.NewRecorder()
		s.TokenHandler().ServeHTTP(&passwordDeadlineRecorder{ResponseRecorder: w}, r)
		return w
	}
	if confidential {
		for _, secret := range []string{"", "incorrect-client-secret"} {
			suppliedSecret = secret
			denied := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}})
			if denied.Code != http.StatusUnauthorized {
				t.Fatalf("invalid client credentials status=%d", denied.Code)
			}
		}
		suppliedSecret = clientSecret
	}
	bad := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"wrong password"}})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid password status=%d", bad.Code)
	}
	setMembership(false)
	deniedGroup := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}})
	if deniedGroup.Code < 400 || !strings.Contains(deniedGroup.Body.String(), "access_denied") {
		t.Fatalf("missing group admitted: status=%d", deniedGroup.Code)
	}
	setMembership(true)
	issued := decodeOIDCToken(t, post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}, "scope": {"offline_access"}, "resource": {"https://ignored.example.test"}}))
	association, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT client_id,logout_uri FROM oidc_user_clients WHERE subject='password-user'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(association.Rows) != 1 || association.Rows[0][0] != client.ID || association.Rows[0][1] != logoutURI {
		t.Fatalf("managed endpoint isolation: %+v %v", association, err)
	}
	verify := func(token string) oidc.IDTokenClaims {
		claims, err := oidc.VerifyIDToken(token, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, oidcTestIssuer, client.ID, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		return claims
	}
	claims := verify(issued.IDToken)
	if claims.Subject != "password-user" || claims.SessionID != "" || claims.AuthTime.IsZero() || len(claims.AuthenticationMethods) != 1 || claims.AuthenticationMethods[0] != "pwd" || issued.RefreshToken == "" {
		t.Fatal("incorrect password tokens")
	}
	setMembership(false)
	deniedRefresh := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}})
	if deniedRefresh.Code < 400 || !strings.Contains(deniedRefresh.Body.String(), "access_denied") {
		t.Fatalf("refresh ignored missing group: status=%d", deniedRefresh.Code)
	}
	setMembership(true)
	refreshed := decodeOIDCToken(t, post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}))
	refreshClaims := verify(refreshed.IDToken)
	if !refreshClaims.AuthTime.Equal(claims.AuthTime) || refreshClaims.SessionID != "" {
		t.Fatal("refresh lost password origin")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	passwordForm := url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}}
	proof = dpopTestProof(t, private, http.MethodPost, "/oidc/token", "password-challenge-abcdefghijkl", "", "")
	challenge := post(passwordForm)
	if challenge.Code != http.StatusBadRequest || tokenError(t, challenge) != "use_dpop_nonce" {
		t.Fatalf("missing password DPoP challenge: status=%d error=%s", challenge.Code, tokenError(t, challenge))
	}
	nonce := challenge.Header().Get("DPoP-Nonce")
	proof = dpopTestProof(t, private, http.MethodPost, "/oidc/token", "password-issued-abcdefghijkl", nonce, "")
	bound := decodeToken(t, post(passwordForm))
	if bound.TokenType != "DPoP" {
		t.Fatal("password token not DPoP bound")
	}
	boundClaims := jwtPayload(t, bound.AccessToken)
	if replay := post(passwordForm); replay.Code != http.StatusBadRequest || tokenError(t, replay) != "use_dpop_nonce" || strings.Contains(replay.Body.String(), "access_token") {
		t.Fatal("replayed password DPoP proof accepted")
	}
	proof = ""
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {bound.RefreshToken}}
	if denied := post(refreshForm); denied.Code == http.StatusOK {
		t.Fatal("unbound refresh accepted")
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof = dpopTestProof(t, otherKey, http.MethodPost, "/oidc/token", "password-wrong-key-abcdefghijkl", nonce, "")
	if denied := post(refreshForm); denied.Code != http.StatusBadRequest || tokenError(t, denied) != "invalid_dpop_proof" {
		t.Fatal("different DPoP key accepted for password refresh")
	}
	proof = dpopTestProof(t, private, http.MethodPost, "/oidc/token", "password-refresh-abcdefghijkl", nonce, "")
	refreshChallenge := post(refreshForm)
	if refreshChallenge.Code != http.StatusBadRequest || tokenError(t, refreshChallenge) != "use_dpop_nonce" {
		t.Fatal("missing refresh nonce challenge")
	}
	proof = dpopTestProof(t, private, http.MethodPost, "/oidc/token", "password-refresh-final-abcdefghijkl", refreshChallenge.Header().Get("DPoP-Nonce"), "")
	rotated := decodeToken(t, post(refreshForm))
	if rotated.TokenType != "DPoP" || !reflect.DeepEqual(boundClaims["cnf"], jwtPayload(t, rotated.AccessToken)["cnf"]) {
		t.Fatal("refresh changed DPoP binding")
	}
	proof = ""
	counts := func() [][]any {
		rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens),(SELECT COUNT(*) FROM oauth_token_requests),(SELECT COUNT(*) FROM oauth_refresh_tokens)`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			t.Fatal(err)
		}
		return rows.Rows
	}
	before := counts()
	emitted := 0
	s.SetTokenIssued(func(context.Context, string, string, string) error { emitted++; return nil })
	s.beforeTokenIssue = func() { setMembership(false) }
	groupRace := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}})
	if groupRace.Code < 400 || strings.Contains(groupRace.Body.String(), "access_token") || emitted != 0 || !reflect.DeepEqual(before, counts()) {
		t.Fatalf("membership change not fenced: status=%d", groupRace.Code)
	}
	setMembership(true)
	s.beforeTokenIssue = func() {
		_, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "password-http-change", SQL: `UPDATE identity_users SET password_generation=password_generation+1 WHERE subject='password-user'`})
		if err != nil {
			t.Fatal(err)
		}
	}
	denied := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}})
	if denied.Code < 400 || strings.Contains(denied.Body.String(), "access_token") || emitted != 0 || !reflect.DeepEqual(before, counts()) {
		t.Fatalf("credential change was not fenced: status=%d emitted=%d", denied.Code, emitted)
	}
	if confidential {
		rotated := false
		s.beforeTokenIssue = func() {
			var err error
			client, err = managed.RotateSecretWithGuard(t.Context(), client.ID, client.Revision, guard)
			if err != nil {
				t.Fatal(err)
			}
			rotated = true
		}
		denied := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}})
		if !rotated || denied.Code < 400 || strings.Contains(denied.Body.String(), "access_token") || emitted != 0 || !reflect.DeepEqual(before, counts()) {
			t.Fatal("client secret rotation was not fenced")
		}
		s.beforeTokenIssue = nil
		if stale := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}}); stale.Code != http.StatusUnauthorized {
			t.Fatal("old client secret remained usable")
		}
		suppliedSecret, err = managed.ReadSecretWithGuard(t.Context(), client.ID, guard)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, enabled := range []bool{true, false} {
		changed := false
		s.beforeTokenIssue = func() {
			var err error
			client, err = managed.UpdateWithGuard(t.Context(), client.ID, client.Revision, clients.UpdateRequest{Confidential: confidential, Enabled: enabled, Scopes: client.Scopes, DefaultScopes: client.DefaultScopes, GrantTypes: client.GrantTypes}, guard)
			if err != nil {
				t.Fatal(err)
			}
			changed = true
		}
		denied := post(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}})
		if !changed || denied.Code < 400 || strings.Contains(denied.Body.String(), "access_token") || emitted != 0 || !reflect.DeepEqual(before, counts()) {
			t.Fatalf("client change was not fenced: enabled=%t changed=%t status=%d", enabled, changed, denied.Code)
		}
	}
}
