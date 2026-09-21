package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestLockdownEnforcementAllAuthMethods(t *testing.T) {
	t.Parallel()
	h, db := testHandlerWithDB(t, false)
	ctx := context.Background()

	// Bootstrap an admin user with rauthy_admin role.
	adminPW, _ := testHash(ctx, []byte("correct password"))
	if _, err := h.identity.BootstrapUser(ctx, "admin-1", "adminuser", adminPW); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "lockdown-test-admin-role",
		SQL:       "INSERT INTO rbac_roles (id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('lockdown-admin-role','rauthy_admin',NULL,1,0,0)",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "lockdown-test-admin-grant",
		SQL:       "INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) SELECT 'admin-1',id,0 FROM rbac_roles WHERE name='rauthy_admin'",
	}); err != nil {
		t.Fatal(err)
	}

	lockdown := loginpolicy.NewLockdownStore(db)
	h.SetLockdownStore(lockdown)

	t.Run("password_denied_for_nonadmin", func(t *testing.T) {
		if err := lockdown.SetLockdown(ctx, true, "maintenance", time.Time{}); err != nil {
			t.Fatal(err)
		}
		defer lockdown.SetLockdown(ctx, false, "", time.Time{})

		resp := httptest.NewRecorder()
		h.Login(resp, postLoginViaAuthorize(t, h, "alice", "correct password"))
		if resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d body=%q", resp.Code, resp.Body.String())
		}
	})

	t.Run("password_allowed_for_admin", func(t *testing.T) {
		if err := lockdown.SetLockdown(ctx, true, "maintenance", time.Time{}); err != nil {
			t.Fatal(err)
		}
		defer lockdown.SetLockdown(ctx, false, "", time.Time{})

		resp := httptest.NewRecorder()
		h.Login(resp, postLoginViaAuthorize(t, h, "adminuser", "correct password"))
		if resp.Code != http.StatusSeeOther {
			t.Fatalf("admin should complete login during lockdown, got %d body=%q", resp.Code, resp.Body.String())
		}
	})

	t.Run("lockdown_lookup_error_denies_password", func(t *testing.T) {
		// The previous subtest lifted the lockdown; a failed unlock would leave
		// the control below denying.
		if locked, _, _, err := lockdown.IsLockedDown(ctx); err != nil || locked {
			t.Fatalf("lockdown must be lifted before the control: locked=%v err=%v", locked, err)
		}

		// Control: the same call authenticates while the store answers, so the
		// 503 below is the failed lockdown lookup and not a blanket failure.
		control := httptest.NewRecorder()
		if _, _, _, ok := h.authenticatePassword(control, loginRequest(), "alice", "correct password"); !ok {
			t.Fatalf("control login failed: %d body=%q", control.Code, control.Body.String())
		}

		// A real store without a database fails every lockdown lookup.
		h.lockdown = loginpolicy.NewLockdownStore(nil)
		defer func() { h.lockdown = lockdown }()

		resp := httptest.NewRecorder()
		if _, _, _, ok := h.authenticatePassword(resp, loginRequest(), "alice", "correct password"); ok || resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("lockdown lookup error must fail closed: ok=%v status=%d body=%q", ok, resp.Code, resp.Body.String())
		}
	})

	t.Run("malformed_reason_still_locked", func(t *testing.T) {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
			RequestID: "lockdown-test-malformed",
			SQL:       "INSERT INTO system_lockdown (id,enabled,reason,until_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES (1,1,'!!!not-base64!!!',0,0,0) ON CONFLICT(id) DO UPDATE SET enabled=1,reason='!!!not-base64!!!',until_unix_ms=0",
		}); err != nil {
			t.Fatal(err)
		}
		defer lockdown.SetLockdown(ctx, false, "", time.Time{})

		resp := httptest.NewRecorder()
		h.Login(resp, postLoginViaAuthorize(t, h, "alice", "correct password"))
		if resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("malformed reason should still deny, got %d body=%q", resp.Code, resp.Body.String())
		}
	})

	t.Run("passkey_completion_denied_for_nonadmin", func(t *testing.T) {
		if err := lockdown.SetLockdown(ctx, true, "maintenance", time.Time{}); err != nil {
			t.Fatal(err)
		}
		defer lockdown.SetLockdown(ctx, false, "", time.Time{})

		// The passkey transition is the shared completion path WebAuthnFinish
		// uses; only the verified assertion is replaced here.
		init, interaction, _ := externalAuthorization(t, h)
		resp := httptest.NewRecorder()
		h.completeAuthentication(resp, loginRequest(), init.Value, interaction, "user-1", "webauthn", nil)
		if resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d body=%q", resp.Code, resp.Body.String())
		}
	})

	t.Run("external_completion_denied_for_nonadmin", func(t *testing.T) {
		if err := lockdown.SetLockdown(ctx, true, "maintenance", time.Time{}); err != nil {
			t.Fatal(err)
		}
		defer lockdown.SetLockdown(ctx, false, "", time.Time{})

		init, _, digest := externalAuthorization(t, h)
		resp := httptest.NewRecorder()
		h.CompleteExternalAuthentication(resp, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, digest, "user-1")
		if resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d body=%q", resp.Code, resp.Body.String())
		}
	})

	t.Run("external_completion_allowed_for_admin", func(t *testing.T) {
		if err := lockdown.SetLockdown(ctx, true, "maintenance", time.Time{}); err != nil {
			t.Fatal(err)
		}
		defer lockdown.SetLockdown(ctx, false, "", time.Time{})

		init, _, digest := externalAuthorization(t, h)
		resp := httptest.NewRecorder()
		h.CompleteExternalAuthentication(resp, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, digest, "admin-1")
		if resp.Code != http.StatusSeeOther {
			t.Fatalf("admin should complete external login during lockdown, got %d body=%q", resp.Code, resp.Body.String())
		}
	})

	t.Run("account_lock_error_denies_password", func(t *testing.T) {
		if err := lockdown.SetLockdown(ctx, false, "", time.Time{}); err != nil {
			t.Fatal(err)
		}
		accountHash := loginpolicy.AccountStuffingDigest("alice")
		if locked, _, err := h.policy.CheckAccountLock(ctx, accountHash, time.Now().UTC()); err != nil || locked {
			t.Fatalf("absent lock must read as unlocked: locked=%v err=%v", locked, err)
		}

		// Control: an absent lock row authenticates rather than denying.
		control := httptest.NewRecorder()
		h.Login(control, postLoginViaAuthorize(t, h, "alice", "correct password"))
		if control.Code != http.StatusSeeOther {
			t.Fatalf("control login status=%d body=%q", control.Code, control.Body.String())
		}

		// Real seam: the lock table is gone, so CheckAccountLock fails while the
		// IP-level checks earlier in the same request still succeed.
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
			RequestID: "lockdown-test-drop-account-locks",
			SQL:       "DROP TABLE login_account_locks",
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := h.policy.CheckAccountLock(ctx, accountHash, time.Now().UTC()); err == nil {
			t.Fatal("expected CheckAccountLock to fail without the lock table")
		}

		resp := httptest.NewRecorder()
		h.Login(resp, postLoginViaAuthorize(t, h, "alice", "correct password"))
		if resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 on CheckAccountLock error, got %d body=%q", resp.Code, resp.Body.String())
		}
	})
}

// loginRequest builds a same-origin password POST for the direct handler calls.
func loginRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/auth/login", nil)
}

func postLoginViaAuthorize(t *testing.T, h *Handler, username, password string) *http.Request {
	t.Helper()
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	cookie := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())
	form := url.Values{"interaction": {interaction}, "username": {username}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(cookie)
	return req
}
