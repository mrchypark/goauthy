package oauth

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"strings"
)

func TestPasswordHandlerDefaultsAndAuthenticationSnapshot(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "access only"
		if enabled {
			name = "access and refresh"
		}
		t.Run(name, func(t *testing.T) { testPasswordHandlerIssuance(t, enabled) })
	}
}

func testPasswordHandlerIssuance(t *testing.T, refreshEnabled bool) {
	t.Helper()
	db := oauthTestDB(t)
	s := oauthTestServer(t, db, randomSecret(t))
	users, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.BootstrapUser(t.Context(), "password-subject", "alice", phc); err != nil {
		t.Fatal(err)
	}
	client := seedManagedClient(t, db, 1, "password-client-generation", true)
	client.GrantTypes = []string{"password"}
	if refreshEnabled {
		client.GrantTypes = append(client.GrantTypes, "refresh_token")
	}
	h := newPasswordGrantHandler(s.store, users, s.accessTokens.(oauth2.CoreStrategy), &fosite.Config{AccessTokenLifespan: time.Hour, RefreshTokenLifespan: time.Hour})
	for _, password := range []string{"wrong password", "correct password"} {
		r := fosite.NewAccessRequest(&fosite.DefaultSession{})
		r.GrantTypes = fosite.Arguments{"password"}
		r.Client = client
		r.Form = url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {password}, "scope": {"offline_access"}, "resource": {"https://ignored.example.test"}}
		r.SetRequestedScopes(fosite.Arguments{"offline_access"})
		err := h.HandleTokenEndpointRequest(t.Context(), r)
		if password == "wrong password" {
			if err == nil || r.GetSession().GetSubject() != "" {
				t.Fatal("invalid credentials authenticated")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if r.GetSession().GetSubject() != "password-subject" || !r.GetGrantedScopes().ExactOne("goauthy.read") || r.Form.Has("password") || r.Form.Has("resource") {
			t.Fatal("wrong password grant projection")
		}
		auth, ok := r.GetSession().(*fosite.DefaultSession).Extra[passwordSnapshotExtra].(identity.Authentication)
		if !ok || auth.PasswordGeneration < 1 || auth.AuthenticationGeneration < 1 {
			t.Fatal("missing authentication snapshot")
		}
		response := fosite.NewAccessResponse()
		if err := h.PopulateTokenEndpointResponse(t.Context(), r, response); err != nil {
			t.Fatal(err)
		}
		refresh, ok := response.GetExtra("refresh_token").(string)
		if response.AccessToken == "" || (ok && refresh != "") != refreshEnabled || (!refreshEnabled && response.GetExtra("refresh_token") != nil) {
			t.Fatal("missing token pair")
		}
		wantRefresh := int64(0)
		if refreshEnabled {
			wantRefresh = 1
		}
		rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens),(SELECT COUNT(*) FROM oauth_refresh_tokens),request_json FROM oauth_token_requests`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) || rows.Rows[0][1] != wantRefresh {
			t.Fatalf("token artifacts=%v err=%v", rows.Rows, err)
		}
		encoded, ok := rows.Rows[0][2].(string)
		if !ok || strings.Contains(encoded, passwordSnapshotExtra) || strings.Contains(encoded, "correct password") {
			t.Fatal("credential snapshot persisted")
		}
	}
}

func TestPasswordGrantExpiredPasswordReturnsAccessDenied(t *testing.T) {
	for _, withCallback := range []bool{false, true} {
		name := "without callback"
		if withCallback {
			name = "with callback"
		}
		t.Run(name, func(t *testing.T) { testPasswordGrantExpired(t, withCallback) })
	}
}

func testPasswordGrantExpired(t *testing.T, withCallback bool) {
	t.Helper()
	db := oauthTestDB(t)
	s := oauthTestServer(t, db, randomSecret(t))
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	rules := credential.DefaultRules()
	rules.ValidDays = 1
	users, err := identity.NewStoreWithPolicies(db, hasher, rules)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.BootstrapUser(t.Context(), "expired-subject", "expired-user", phc); err != nil {
		t.Fatal(err)
	}
	// Set password_changed_at_unix_ms to 1 to make it expired (ValidDays=1, now >> 1ms + 1 day)
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{
		RequestID: "expire-password",
		SQL:       `UPDATE identity_users SET password_changed_at_unix_ms=1 WHERE subject='expired-subject'`,
	}); err != nil {
		t.Fatal(err)
	}

	client := seedManagedClient(t, db, 1, "expired-client-generation", true)
	client.GrantTypes = []string{"password"}

	var callbackCalled bool
	var callbackSubject string
	var onExpired func(context.Context, string) error
	if withCallback {
		onExpired = func(_ context.Context, subject string) error {
			callbackCalled = true
			callbackSubject = subject
			return nil
		}
	}

	h := newPasswordGrantHandler(s.store, users, s.accessTokens.(oauth2.CoreStrategy), &fosite.Config{AccessTokenLifespan: time.Hour, RefreshTokenLifespan: time.Hour})
	h.onPasswordExpired = onExpired

	r := fosite.NewAccessRequest(&fosite.DefaultSession{})
	r.GrantTypes = fosite.Arguments{"password"}
	r.Client = client
	r.Form = url.Values{"grant_type": {"password"}, "username": {"expired-user"}, "password": {"correct password"}, "scope": {"goauthy.read"}}
	r.SetRequestedScopes(fosite.Arguments{"goauthy.read"})

	err = h.HandleTokenEndpointRequest(t.Context(), r)
	if err == nil {
		t.Fatal("expired password should return error")
	}

	// Should return ErrAccessDenied with hint, not ErrServerError
	if !errors.Is(err, fosite.ErrAccessDenied) {
		t.Fatalf("expected ErrAccessDenied, got %v", err)
	}
	if !strings.Contains(fosite.ErrorToRFC6749Error(err).HintField, "Password reset required") {
		t.Fatalf("expected 'Password reset required' hint, got %v", err)
	}

	if withCallback {
		if !callbackCalled {
			t.Fatal("onPasswordExpired callback was not called")
		}
		if callbackSubject != "expired-subject" {
			t.Fatalf("callback subject=%q, want 'expired-subject'", callbackSubject)
		}
	}
}

// TestPasswordGrantRejectsForceMFAClient covers finding GA-OAUTH-005. A managed
// client may not hold force_mfa together with the password grant, and a row that
// already carries both must not reach password-only issuance.
func TestPasswordGrantRejectsForceMFAClient(t *testing.T) {
	db := oauthTestDB(t)
	s := oauthTestServer(t, db, randomSecret(t))
	users, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.BootstrapUser(t.Context(), "force-mfa-subject", "force-mfa-user", phc); err != nil {
		t.Fatal(err)
	}

	guard := func() (string, []any) { return "1", nil }
	managed := clients.NewStore(db, &oidc.Keyring{})
	in := clients.NewRequest{ID: "force-mfa-password", RedirectURIs: []string{"https://rp.example.test/callback"}, Scopes: []string{"goauthy.read"}, DefaultScopes: []string{"goauthy.read"}, GrantTypes: []string{"password"}, ForceMFA: true}
	if _, err := managed.CreateWithGuard(t.Context(), in, guard); !errors.Is(err, clients.ErrInvalid) {
		t.Fatalf("force_mfa password client admitted: %v", err)
	}
	in.ForceMFA = false
	created, err := managed.CreateWithGuard(t.Context(), in, guard)
	if err != nil {
		t.Fatalf("password client without force_mfa rejected: %v", err)
	}
	update := clients.UpdateRequest{Confidential: created.Confidential, RedirectURIs: created.RedirectURIs, Enabled: true, Scopes: created.Scopes, DefaultScopes: created.DefaultScopes, GrantTypes: []string{"password"}, ForceMFA: true}
	if _, err := managed.UpdateWithGuard(t.Context(), created.ID, created.Revision, update, guard); !errors.Is(err, clients.ErrInvalid) {
		t.Fatalf("force_mfa password client update admitted: %v", err)
	}
	update.GrantTypes = []string{"authorization_code"}
	if _, err := managed.UpdateWithGuard(t.Context(), created.ID, created.Revision, update, guard); err != nil {
		t.Fatalf("force_mfa authorization_code client rejected: %v", err)
	}

	client := seedManagedClient(t, db, 1, "force-mfa-password-generation", true)
	client.GrantTypes = []string{"password"}
	client.ForceMFA = true
	h := newPasswordGrantHandler(s.store, users, s.accessTokens.(oauth2.CoreStrategy), &fosite.Config{AccessTokenLifespan: time.Hour, RefreshTokenLifespan: time.Hour})
	attempt := func() error {
		r := fosite.NewAccessRequest(&fosite.DefaultSession{})
		r.GrantTypes = fosite.Arguments{"password"}
		r.Client = client
		r.Form = url.Values{"grant_type": {"password"}, "username": {"force-mfa-user"}, "password": {"correct password"}, "scope": {"goauthy.read"}}
		r.SetRequestedScopes(fosite.Arguments{"goauthy.read"})
		return h.HandleTokenEndpointRequest(t.Context(), r)
	}
	if err := attempt(); !errors.Is(err, fosite.ErrUnauthorizedClient) {
		t.Fatalf("force_mfa client reached password issuance: %v", err)
	}
	client.ForceMFA = false
	if err := attempt(); err != nil {
		t.Fatalf("password grant broke without force_mfa: %v", err)
	}
}

// TestPasswordGrantRefusesLockedAccount covers finding GA-OAUTH-006. The direct
// password grant must honor the credential-stuffing account lock that the
// browser login path already enforces.
func TestPasswordGrantRefusesLockedAccount(t *testing.T) {
	db := oauthTestDB(t)
	s := oauthTestServer(t, db, randomSecret(t))
	users, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.BootstrapUser(t.Context(), "locked-subject", "locked-user", phc); err != nil {
		t.Fatal(err)
	}
	client := seedManagedClient(t, db, 1, "locked-client-generation", true)
	client.GrantTypes = []string{"password"}
	h := newPasswordGrantHandler(s.store, users, s.accessTokens.(oauth2.CoreStrategy), &fosite.Config{AccessTokenLifespan: time.Hour, RefreshTokenLifespan: time.Hour})

	stuffing := loginpolicy.NewStore(db)
	digest := loginpolicy.AccountStuffingDigest("locked-user")
	lockedAt := time.Now().UTC()
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"} {
		if _, _, err := stuffing.RecordAccountFailure(t.Context(), digest, ip, lockedAt); err != nil {
			t.Fatal(err)
		}
	}
	if locked, _, err := stuffing.CheckAccountLock(t.Context(), digest, lockedAt); err != nil || !locked {
		t.Fatalf("lock fixture not established: locked=%t err=%v", locked, err)
	}

	attempt := func() error {
		r := fosite.NewAccessRequest(&fosite.DefaultSession{})
		r.GrantTypes = fosite.Arguments{"password"}
		r.Client = client
		r.Form = url.Values{"grant_type": {"password"}, "username": {"locked-user"}, "password": {"correct password"}, "scope": {"goauthy.read"}}
		r.SetRequestedScopes(fosite.Arguments{"goauthy.read"})
		return h.HandleTokenEndpointRequest(t.Context(), r)
	}
	if err := attempt(); !errors.Is(err, fosite.ErrAccessDenied) {
		t.Fatalf("locked account authenticated through the password grant: %v", err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
		t.Fatalf("token issued for a locked account: rows=%#v err=%v", rows.Rows, err)
	}
	if err := stuffing.ClearAccountLock(t.Context(), digest); err != nil {
		t.Fatal(err)
	}
	if err := attempt(); err != nil {
		t.Fatalf("unlocked account refused: %v", err)
	}
}
