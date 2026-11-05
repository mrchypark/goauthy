package rbac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCanonicalAdminBootstrapIsIdempotent(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	insertActive(t, db, "ordinary")
	if AdminRole != "goauthy_admin" {
		t.Fatalf("canonical role=%q", AdminRole)
	}
	admin, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil)
	if err != nil || !equalNames(admin.Roles, []string{"goauthy_admin"}) {
		t.Fatalf("fresh bootstrap=%+v err=%v", admin, err)
	}
	ordinary, err := store.ResolvePrincipal(ctx, "ordinary")
	if err != nil || len(ordinary.Roles) != 0 {
		t.Fatalf("ordinary auto-grant=%+v err=%v", ordinary, err)
	}
	want := []string{"goauthy_admin", "goauthy_admin:team/*", "viewer"}
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", want, nil); err != nil {
		t.Fatal(err)
	}
	if admin, err = store.ResolvePrincipal(ctx, "admin"); err != nil || !equalNames(admin.Roles, want) {
		t.Fatalf("canonical configuration=%+v err=%v", admin, err)
	}
	before := admin.Revision
	if admin, err = store.EnsureBootstrapPrincipal(ctx, "admin", want, nil); err != nil || admin.Revision != before {
		t.Fatalf("repeated canonical bootstrap=%+v err=%v", admin, err)
	}
}

func TestCanonicalAdminWebGrantAndOrdinaryDenial(t *testing.T) {
	h, store, admin, csrf := membershipHTTPFixture(t)
	ctx := context.Background()
	member := detailSession(t, h, "member")
	request := httptest.NewRequest(http.MethodGet, "/auth/v1/roles", nil)
	request.AddCookie(member)
	w := httptest.NewRecorder()
	h.Roles(w, request)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary admin API status=%d body=%s", w.Code, w.Body)
	}
	memberCSRF, err := browser.DeriveCSRFToken(member.Value)
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.PatchUserMembership(w, membershipRequest(t, member, memberCSRF, `{"put":[{"key":"roles","value":["goauthy_admin"]}],"del":[]}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary escalation status=%d body=%s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	h.PatchUserMembership(w, membershipRequest(t, admin, csrf, `{"put":[{"key":"roles","value":["goauthy_admin"]}],"del":[]}`))
	var got membershipDocument
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || len(got.Roles) != 1 || got.Roles[0] != "goauthy_admin" {
		t.Fatalf("web grant status=%d body=%s", w.Code, w.Body)
	}
	request = httptest.NewRequest(http.MethodGet, "/auth/v1/roles", nil)
	request.AddCookie(member)
	w = httptest.NewRecorder()
	h.Roles(w, request)
	if w.Code != http.StatusOK {
		t.Fatalf("granted admin API status=%d body=%s", w.Code, w.Body)
	}
	if _, err := store.PatchPrincipal(ctx, "admin", "member", nil, nil, true, false); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	r := membershipRequest(t, admin, csrf, `{"put":[],"del":["roles"]}`)
	r.SetPathValue("subject", "admin")
	h.PatchUserMembership(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("last admin removal status=%d body=%s", w.Code, w.Body)
	}
}

func TestOtherAdminRoleIsNotAuthorization(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "ordinary-admin-lookalike")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "other-admin-no-authority", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_roles(id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES('lookalike','other_admin',1,0,0),('lookalike-delegate','other_admin:*',1,0,0)`},
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('ordinary-admin-lookalike','lookalike',0),('ordinary-admin-lookalike','lookalike-delegate',0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListRolesForAdmin(ctx, "ordinary-admin-lookalike"); err != ErrUnauthorized {
		t.Fatalf("lookalike direct role authorized=%v", err)
	}
	if delegated, err := store.isDelegatedAdmin(context.Background(), "ordinary-admin-lookalike"); err != nil || delegated {
		t.Fatalf("lookalike delegated role authorized=%t err=%v", delegated, err)
	}
}

func TestCanonicalAdminBootstrapIDCollisionFailsClosed(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "bootstrap-id-collision", SQL: `INSERT INTO rbac_roles(id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES(?,'ordinary',1,0,0)`, Args: []any{bootstrapID("role", AdminRole)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err == nil {
		t.Fatal("bootstrap succeeded without canonical administrator role")
	}
	count(t, db, `SELECT COUNT(*) FROM rbac_user_roles WHERE subject=?`, "admin", 0)
	count(t, db, `SELECT COUNT(*) FROM rbac_principal_versions WHERE subject=?`, "admin", 0)
}

func TestCanonicalAdminWebUserCreateAndPUTRoleAssignment(t *testing.T) {
	h, store, _, _, admin := userCreateHTTPFixture(t)
	w := httptest.NewRecorder()
	h.CreateUser(w, userCreateRequest(admin, `{"email":"ordinary-role@example.test","language":"en","roles":[]}`))
	var ordinary identity.UserResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &ordinary) != nil || len(ordinary.Roles) != 0 {
		t.Fatalf("ordinary creation status=%d body=%s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	h.UpdateUser(w, userUpdateHTTPReq(admin, ordinary.ID, `{"email":"ordinary-role@example.test","given_name":"Ordinary","language":"en","roles":["goauthy_admin"],"enabled":true,"email_verified":true}`))
	var granted identity.UserResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &granted) != nil || len(granted.Roles) != 1 || granted.Roles[0] != AdminRole {
		t.Fatalf("web PUT assignment status=%d body=%s", w.Code, w.Body)
	}
	if _, err := store.ListRolesForAdmin(context.Background(), ordinary.ID); err != nil {
		t.Fatalf("web-granted user lacks current canonical authority: %v", err)
	}
}
