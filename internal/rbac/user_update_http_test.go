package rbac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func userUpdateHTTPReq(cookie *http.Cookie, subject, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/auth/v1/users/"+subject, strings.NewReader(body))
	r.SetPathValue("subject", subject)
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
		// Keep this helper consistent with the create fixture's browser request.
		if csrf, err := browser.DeriveCSRFToken(cookie.Value); err == nil {
			r.Header.Set("X-CSRF-Token", csrf)
		}
	}
	return r
}

func TestUpdateUserHTTPUpdateOnlyKeyReturnsCommittedUser(t *testing.T) {
	h, store, _, keys, cookie := userCreateHTTPFixture(t)
	create := userCreateRequest(cookie, `{"email":"target@example.test","language":"en","roles":["viewer"],"given_name":"Target"}`)
	w := httptest.NewRecorder()
	h.CreateUser(w, create)
	if w.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var created identity.UserResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "update-only", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"email":"changed@example.test","given_name":"Changed","roles":["viewer"],"enabled":true,"email_verified":true}`
	req := userUpdateHTTPReq(nil, created.ID, body)
	req.Header.Set("Authorization", "API-Key "+token)
	w = httptest.NewRecorder()
	h.UpdateUser(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", w.Code, w.Body.String())
	}
	var got identity.UserResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != created.ID || got.Email != "changed@example.test" {
		t.Fatalf("response=%+v", got)
	}
	if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE email='changed@example.test'`) != 1 {
		t.Fatal("update was not committed")
	}
}

func TestUpdateUserHTTPRevokedAtBarrierDoesNotWrite(t *testing.T) {
	h, store, _, keys, cookie := userCreateHTTPFixture(t)
	create := userCreateRequest(cookie, `{"email":"barrier@example.test","language":"en","roles":["viewer"],"given_name":"Barrier"}`)
	w := httptest.NewRecorder()
	h.CreateUser(w, create)
	if w.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var created identity.UserResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "barrier-key", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	h.beforeUserUpdate = func() {
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "revoke-update-key", SQL: `DELETE FROM api_key_access WHERE key_name='barrier-key'`}); err != nil {
			t.Errorf("revoke key: %v", err)
		}
	}
	req := userUpdateHTTPReq(nil, created.ID, `{"email":"blocked@example.test","given_name":"Blocked","roles":["viewer"],"enabled":true,"email_verified":true}`)
	req.Header.Set("Authorization", "API-Key "+token)
	w = httptest.NewRecorder()
	h.UpdateUser(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE email='blocked@example.test'`) != 0 {
		t.Fatal("revoked update wrote data")
	}
}

func TestUpdateUserHTTPSelfEmailReturnsSnapshotAndNoticesAfterCommit(t *testing.T) {
	h, store, sender, _, cookie := userCreateHTTPFixture(t)
	ctx := context.Background()
	if err := h.userCreation.BindEmail(ctx, "admin", "old-admin@example.test"); err != nil {
		t.Fatal(err)
	}
	wakes := 0
	h.OnUserUpdated = func(ctx context.Context, result identity.UserUpdateResult) {
		wakes++
		if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='admin' AND email='new-admin@example.test'`) != 1 {
			t.Fatal("callback preceded commit")
		}
		h.userCreation.NotifyUserUpdate(ctx, result)
		// Simulate a later committed edit before serialization: the first
		// response must keep its transaction's profile, not re-read this row.
		if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "later-profile-edit", SQL: `UPDATE identity_user_profiles SET given_name='Later' WHERE subject='admin'`}); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	h.UpdateUser(w, userUpdateHTTPReq(cookie, "admin", `{"email":"new-admin@example.test","given_name":"Committed","language":"ko","roles":["rauthy_admin"],"enabled":true,"email_verified":true,"user_values":{"tz":"Asia/Seoul"}}`))
	var user UserResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &user) != nil {
		t.Fatalf("self status=%d", w.Code)
	}
	if user.GivenName == nil || *user.GivenName != "Committed" || user.Email != "new-admin@example.test" || user.Language != "ko" || user.UserValues.Timezone == nil || *user.UserValues.Timezone != "Asia/Seoul" || wakes != 1 {
		t.Fatal("incorrect committed response")
	}
	if len(sender.changes) != 2 || sender.changes[0].To != "new-admin@example.test" || sender.changes[1].To != "old-admin@example.test" || sender.changes[0].Language != "ko" {
		t.Fatal("missing two-address notice")
	}
	if _, err := h.browser.LoadSessionForPeer(ctx, cookie.Value, ""); err == nil {
		t.Fatal("old browser session survived email change")
	}
	for _, secret := range []string{"password_phc", "password_changed", "password_generation", "token_digest"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("private field %s in response", secret)
		}
	}
}

func TestUpdateUserHTTPDelegatedLastGroupAndTargetBoundary(t *testing.T) {
	h, store, _, _, admin := userCreateHTTPFixture(t)
	ctx := context.Background()
	insertActive(t, store.db, "delegated")
	role, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "update-delegated-role", SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('delegated',?,0)`, Args: []any{role.ID}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.CreateUser(w, userCreateRequest(admin, `{"email":"managed@example.test","language":"en","roles":["viewer"],"groups":["team/a"],"given_name":"Managed"}`))
	var created UserResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &created) != nil {
		t.Fatalf("create status=%d", w.Code)
	}
	cookie := detailSession(t, h, "delegated")
	wakes := 0
	h.OnUserUpdated = func(context.Context, identity.UserUpdateResult) { wakes++ }
	body := `{"email":"managed@example.test","given_name":"Managed","roles":["viewer"],"enabled":true,"email_verified":true}`
	w = httptest.NewRecorder()
	h.UpdateUser(w, userUpdateHTTPReq(cookie, created.ID, body))
	var updated UserResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &updated) != nil || len(updated.Groups) != 0 || wakes != 1 {
		t.Fatalf("last-group removal status=%d", w.Code)
	}
	for _, tc := range []struct {
		target string
		status int
	}{{created.ID, 428}, {"admin", 403}, {"missing", 404}} {
		w = httptest.NewRecorder()
		h.UpdateUser(w, userUpdateHTTPReq(cookie, tc.target, body))
		if w.Code != tc.status || wakes != 1 {
			t.Fatalf("target=%s status=%d want=%d wakes=%d", tc.target, w.Code, tc.status, wakes)
		}
	}
}

func TestUpdateUserHTTPInvalidRequestsHaveNoEffects(t *testing.T) {
	h, store, _, keys, cookie := userCreateHTTPFixture(t)
	insertActive(t, store.db, "ordinary")
	ordinary := detailSession(t, h, "ordinary")
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "read-only", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"email":"new-admin@example.test","given_name":"Admin","roles":["rauthy_admin"],"enabled":true,"email_verified":true}`
	wakes := 0
	h.OnUserUpdated = func(context.Context, identity.UserUpdateResult) { wakes++ }
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{"csrf", func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 401},
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 401},
		{"key precedence", func(r *http.Request) { r.Header.Set("Authorization", "Bearer invalid") }, 401},
		{"read-only key", func(r *http.Request) { r.Header.Set("Authorization", "API-Key "+token) }, 403},
		{"query", func(r *http.Request) { r.URL.RawQuery = "unexpected=1" }, 400},
		{"media", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400},
		{"ordinary", func(r *http.Request) { r.Header.Del("Cookie"); r.AddCookie(ordinary) }, 401},
		{"method", func(r *http.Request) { r.Method = "POST" }, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := userUpdateHTTPReq(cookie, "admin", body)
			tc.mutate(r)
			w := httptest.NewRecorder()
			h.UpdateUser(w, r)
			if w.Code != tc.status || wakes != 0 || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles`) != 0 || countRows(t, store, `SELECT COUNT(*) FROM event_log`) != 0 {
				t.Fatalf("status=%d want=%d effects=%d", w.Code, tc.status, wakes)
			}
		})
	}
}

func TestUpdateUserHTTPUserValuesPolicy(t *testing.T) {
	t.Run("default given name required", func(t *testing.T) {
		for _, given := range []string{``, `,"given_name":null`, `,"given_name":""`} {
			h, store, _, _, cookie := userCreateHTTPFixture(t)
			called := 0
			h.OnUserUpdated = func(context.Context, identity.UserUpdateResult) { called++ }
			body := `{"email":"policy-default@example.test","roles":["rauthy_admin"],"enabled":true,"email_verified":true` + given + `}`
			w := httptest.NewRecorder()
			h.UpdateUser(w, userUpdateHTTPReq(cookie, "admin", body))
			if w.Code != http.StatusBadRequest || called != 0 || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE email='policy-default@example.test'`) != 0 {
				t.Fatalf("given=%q status=%d callback=%d", given, w.Code, called)
			}
		}
	})

	for _, tc := range []struct {
		name, email string
		policy      identity.UserValuesPolicy
		body        string
		status      int
		wantName    string
	}{
		{"optional omitted", "policy-optional@example.test", identity.UserValuesPolicy{GivenName: "optional"}, `{"email":"policy-optional@example.test","roles":["rauthy_admin"],"enabled":true,"email_verified":true}`, http.StatusOK, ""},
		{"hidden submitted", "policy-hidden@example.test", identity.UserValuesPolicy{GivenName: "hidden"}, `{"email":"policy-hidden@example.test","given_name":"Hidden","roles":["rauthy_admin"],"enabled":true,"email_verified":true}`, http.StatusOK, "Hidden"},
		{"required family supplied empty object", "policy-family@example.test", identity.UserValuesPolicy{FamilyName: "required"}, `{"email":"policy-family@example.test","given_name":"Given","roles":["rauthy_admin"],"enabled":true,"email_verified":true,"user_values":{}}`, http.StatusBadRequest, ""},
		{"required city supplied empty object", "policy-city@example.test", identity.UserValuesPolicy{City: "required"}, `{"email":"policy-city@example.test","given_name":"Given","roles":["rauthy_admin"],"enabled":true,"email_verified":true,"user_values":{}}`, http.StatusBadRequest, ""},
		{"required city null object", "policy-city-null@example.test", identity.UserValuesPolicy{City: "required"}, `{"email":"policy-city-null@example.test","given_name":"Given","roles":["rauthy_admin"],"enabled":true,"email_verified":true,"user_values":null}`, http.StatusOK, "Given"},
		{"required family null", "policy-family-null@example.test", identity.UserValuesPolicy{FamilyName: "required"}, `{"email":"policy-family-null@example.test","given_name":"Given","family_name":null,"roles":["rauthy_admin"],"enabled":true,"email_verified":true}`, http.StatusBadRequest, ""},
		{"required city provided", "policy-city-valid@example.test", identity.UserValuesPolicy{City: "required"}, `{"email":"policy-city-valid@example.test","given_name":"Given","roles":["rauthy_admin"],"enabled":true,"email_verified":true,"user_values":{"city":"Seoul"}}`, http.StatusOK, "Given"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, store, _, _, cookie := userCreateHTTPFixture(t)
			if err := h.SetUserValuesPolicy(tc.policy); err != nil {
				t.Fatal(err)
			}
			if err := h.SetUserValuesPolicy(identity.UserValuesPolicy{GivenName: "typo"}); err == nil {
				t.Fatal("invalid configuration replaced the current policy")
			}
			called := 0
			h.OnUserUpdated = func(context.Context, identity.UserUpdateResult) { called++ }
			w := httptest.NewRecorder()
			h.UpdateUser(w, userUpdateHTTPReq(cookie, "admin", tc.body))
			if w.Code != tc.status || (tc.status != http.StatusOK && called != 0) {
				t.Fatalf("status=%d want=%d callback=%d", w.Code, tc.status, called)
			}
			if tc.status == http.StatusOK {
				var got UserResponse
				if json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Email != tc.email || called != 1 {
					t.Fatalf("response=%s callback=%d", w.Body.String(), called)
				}
				if tc.wantName != "" && (got.GivenName == nil || *got.GivenName != tc.wantName) {
					t.Fatalf("given_name=%v", got.GivenName)
				}
				if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE email='`+tc.email+`'`) != 1 {
					t.Fatal("successful policy update did not commit")
				}
			}
		})
	}
}

func TestCreateUserHTTPExemptsRequiredUserValuesPolicy(t *testing.T) {
	h, store, _, _, cookie := userCreateHTTPFixture(t)
	if err := h.SetUserValuesPolicy(identity.UserValuesPolicy{GivenName: "required", FamilyName: "required"}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.CreateUser(w, userCreateRequest(cookie, `{"email":"policy-create@example.test","language":"en","roles":[]}`))
	if w.Code != http.StatusOK || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE email='policy-create@example.test'`) != 1 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
