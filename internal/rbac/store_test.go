package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAPIKeyRoleMutationUsesCurrentRightAndGuard(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "roles-writer", Access: []apikey.Access{{Group: "Roles", AccessRights: []apikey.Right{apikey.Create}}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateRoleAPIKey(ctx, p, "reader", nil)
	if err != nil || created.Name != "reader" {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	if _, err := store.CreateGroupAPIKey(ctx, p, "team/a", nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong group=%v", err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_key_mutation_guards`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(0) {
		t.Fatalf("guards=%#v err=%v", rows.Rows, err)
	}
}

func TestAPIKeyUserMembershipMutationUsesCurrentRightAndGuard(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "member")
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "membership-writer", Access: []apikey.Access{
		{Group: "Roles", AccessRights: []apikey.Right{apikey.Create}},
		{Group: "Users", AccessRights: []apikey.Right{apikey.Update}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateRoleAPIKey(ctx, key, "viewer", nil); err != nil {
		t.Fatal(err)
	}
	principal, err := store.PatchPrincipalAPIKey(ctx, key, "member", []string{"viewer"}, nil, true, false)
	if err != nil || principal.Revision != 2 || !equalNames(principal.Roles, []string{"viewer"}) {
		t.Fatalf("api membership=%+v err=%v", principal, err)
	}
}

func TestCRUDUsesCurrentAdminAndCanonicalMetadata(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", []string{AdminRole}, nil); err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateRole(ctx, "admin", "reader", json.RawMessage(`{"z":1,"a":true}`))
	if err != nil || created.ID == "" || string(created.Meta) != `{"a":true,"z":1}` || created.Revision != 1 {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	updated, err := store.UpdateRole(ctx, "admin", created.ID, created.Revision, "reader.v2", json.RawMessage(`{"x":[2,1]}`))
	if err != nil || updated.Revision != 2 || updated.Name != "reader.v2" {
		t.Fatalf("update=%+v err=%v", updated, err)
	}
	if _, err := store.UpdateRole(ctx, "admin", created.ID, created.Revision, "reader.v2", json.RawMessage(`{"x":[1,2]}`)); !errors.Is(err, ErrConflict) {
		t.Fatalf("same CAS different metadata=%v", err)
	}
	current, err := store.GetRole(ctx, created.ID)
	if err != nil || current.Revision != updated.Revision || string(current.Meta) != `{"x":[2,1]}` {
		t.Fatalf("metadata conflict changed state=%+v err=%v", current, err)
	}
	if _, err := store.UpdateRole(ctx, "admin", created.ID, 1, "reader.v3", nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update=%v", err)
	}
	if _, err := store.UpdateRole(ctx, "admin", created.ID, updated.Revision, AdminRole, nil); err != nil && !errors.Is(err, ErrConflict) {
		t.Fatalf("reserved name conflict=%v", err)
	}
	if _, err := store.CreateRole(ctx, "admin", AdminRole, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reserved create=%v", err)
	}
}

func TestGroupNameUsesCanonicalASCIIGrammar(t *testing.T) {
	for _, name := range []string{"team/a", "ops:blue", "a*"} {
		if err := ValidateGroupName(name); err != nil {
			t.Fatalf("valid group %q: %v", name, err)
		}
	}
	for _, name := range []string{"a", "team space", "team\tspace", "team\nspace", "team\\space", "팀/a", "team.a"} {
		if err := ValidateGroupName(name); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid group %q: %v", name, err)
		}
	}
}

func TestBootstrapClientLoginRestrictionCASAndAdminGuard(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetBootstrapClientLoginRestriction(ctx, "bootstrap-client"); err != nil || got.Revision != 0 || got.RestrictGroupPrefix != nil {
		t.Fatalf("unrestricted=%+v err=%v", got, err)
	}
	prefix := "team/a"
	created, err := store.UpdateBootstrapClientLoginRestriction(ctx, "admin", "bootstrap-client", 0, &prefix)
	if err != nil || created.Revision != 1 || created.RestrictGroupPrefix == nil || *created.RestrictGroupPrefix != prefix {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	if retried, err := store.UpdateBootstrapClientLoginRestriction(ctx, "admin", "bootstrap-client", 0, &prefix); err != nil || retried.Revision != created.Revision {
		t.Fatalf("idempotent retry=%+v err=%v", retried, err)
	}
	if _, err := store.UpdateBootstrapClientLoginRestriction(ctx, "admin", "bootstrap-client", 0, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale create=%v", err)
	}
	updated, err := store.UpdateBootstrapClientLoginRestriction(ctx, "admin", "bootstrap-client", 1, nil)
	if err != nil || updated.Revision != 2 || updated.RestrictGroupPrefix != nil {
		t.Fatalf("clear=%+v err=%v", updated, err)
	}
	if _, err := store.UpdateBootstrapClientLoginRestriction(ctx, "admin", "bootstrap-client", 1, &prefix); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update=%v", err)
	}
	adminID := roleByName(t, db, AdminRole)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "restriction-revoke-admin", SQL: `DELETE FROM rbac_user_roles WHERE subject=? AND role_id=?`, Args: []any{"admin", adminID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateBootstrapClientLoginRestriction(ctx, "admin", "bootstrap-client", 2, &prefix); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked update=%v", err)
	}
}

func TestAPIKeyBootstrapClientLoginRestrictionMutation(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "client-policy-writer", Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "team/a"
	policy, err := store.UpdateBootstrapClientLoginRestrictionAPIKey(ctx, key, "bootstrap-client", 0, &prefix)
	if err != nil || policy.Revision != 1 || policy.RestrictGroupPrefix == nil || *policy.RestrictGroupPrefix != prefix {
		t.Fatalf("api restriction=%+v err=%v", policy, err)
	}
}

func TestLoginRestrictionFailedGuardUsesNewAttemptIDOnRetry(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	prefix := "team/a"
	store.beforeLoginRestrictionExecute = func() {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "restriction-disable-before-attempt", SQL: `UPDATE identity_users SET disabled=1 WHERE subject='admin'`}); err != nil {
			t.Errorf("disable actor: %v", err)
		}
	}
	if _, err := store.UpdateBootstrapClientLoginRestriction(ctx, "admin", "bootstrap-client", 0, &prefix); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("guarded attempt=%v", err)
	}
	store.beforeLoginRestrictionExecute = nil
	if got, err := store.GetBootstrapClientLoginRestriction(ctx, "bootstrap-client"); err != nil || got.Revision != 0 {
		t.Fatalf("failed attempt changed policy=%+v err=%v", got, err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "restriction-enable-before-retry", SQL: `UPDATE identity_users SET disabled=0 WHERE subject='admin'`}); err != nil {
		t.Fatal(err)
	}
	got, err := store.UpdateBootstrapClientLoginRestriction(ctx, "admin", "bootstrap-client", 0, &prefix)
	if err != nil || got.Revision != 1 || got.RestrictGroupPrefix == nil || *got.RestrictGroupPrefix != prefix {
		t.Fatalf("retry policy=%+v err=%v", got, err)
	}
}

func TestValidateGroupPrefixUsesUpstreamGrammarWithoutTrimming(t *testing.T) {
	for _, prefix := range []string{"team/a", " team", "team\tblue", "a*"} {
		if err := ValidateGroupPrefix(prefix); err != nil {
			t.Fatalf("valid prefix %q: %v", prefix, err)
		}
	}
	for _, prefix := range []string{"a", "team\\a", "팀/a", strings.Repeat("a", 65)} {
		if err := ValidateGroupPrefix(prefix); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid prefix %q: %v", prefix, err)
		}
	}
}

func TestRenameAndDeleteBumpAffectedPrincipalVersions(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	insertActive(t, db, "member")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	group, err := store.CreateGroup(ctx, "admin", "team/a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rbac-member-group", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,1,1)`, Args: []any{"member"}},
		{SQL: `INSERT INTO rbac_user_groups (subject,group_id,granted_at_unix_ms) VALUES (?, ?, 1)`, Args: []any{"member", group.ID}},
	}}); err != nil {
		t.Fatal(err)
	}
	metadataUpdated, err := store.UpdateGroup(ctx, "admin", group.ID, group.Revision, "team/a", json.RawMessage(`{"source":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	count(t, db, `SELECT revision FROM rbac_principal_versions WHERE subject=?`, "member", 1)
	updated, err := store.UpdateGroup(ctx, "admin", group.ID, metadataUpdated.Revision, "team/b", metadataUpdated.Meta)
	if err != nil {
		t.Fatal(err)
	}
	count(t, db, `SELECT revision FROM rbac_principal_versions WHERE subject=?`, "member", 2)
	if err := store.DeleteGroup(ctx, "admin", group.ID, updated.Revision); err != nil {
		t.Fatal(err)
	}
	count(t, db, `SELECT revision FROM rbac_principal_versions WHERE subject=?`, "member", 3)
	count(t, db, `SELECT COUNT(*) FROM rbac_user_groups WHERE group_id=?`, group.ID, 0)
}

func TestMutationRechecksActorAndDeleteCascades(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	insertActive(t, db, "other")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	role, err := store.CreateRole(ctx, "admin", "viewer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rbac-test-membership", Statements: []rhiza.SQLStatement{{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,1,1)`, Args: []any{"other"}}, {SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES (?, ?, 1)`, Args: []any{"other", role.ID}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateGroup(ctx, "other", "team/a", nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("non-admin mutation=%v", err)
	}
	if err := store.DeleteRole(ctx, "admin", role.ID, role.Revision); err != nil {
		t.Fatal(err)
	}
	count(t, db, `SELECT COUNT(*) FROM rbac_user_roles WHERE role_id=?`, role.ID, 0)
	count(t, db, `SELECT revision FROM rbac_principal_versions WHERE subject=?`, "other", 2)
	if _, err := store.GetRole(ctx, role.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted role=%v", err)
	}
	admin, err := store.GetRole(ctx, roleByName(t, db, AdminRole))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRole(ctx, "admin", admin.ID, admin.Revision); !errors.Is(err, ErrReserved) {
		t.Fatalf("delete reserved=%v", err)
	}
}

func TestRevokedAdminCannotMutate(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	role, err := store.CreateRole(ctx, "admin", "viewer", nil)
	if err != nil {
		t.Fatal(err)
	}
	adminID := roleByName(t, db, AdminRole)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rbac-revoke-admin", SQL: `DELETE FROM rbac_user_roles WHERE subject=? AND role_id=?`, Args: []any{"admin", adminID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateGroup(ctx, "admin", "team/a", nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked create=%v", err)
	}
	if _, err := store.UpdateRole(ctx, "admin", role.ID, role.Revision, "viewer-v2", nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked update=%v", err)
	}
	current, err := store.GetRole(ctx, role.ID)
	if err != nil || current.Revision != role.Revision || current.Name != role.Name {
		t.Fatalf("revoked update changed state=%+v err=%v", current, err)
	}
	count(t, db, `SELECT COUNT(*) FROM rbac_groups WHERE ?=0`, int64(0), int64(0))
}

func TestGuardedReadsHideEntitiesAfterAdminRevocation(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	role, err := store.CreateRole(ctx, "admin", "viewer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rbac-revoke-read-admin", SQL: `DELETE FROM rbac_user_roles WHERE subject=? AND role_id=?`, Args: []any{"admin", roleByName(t, db, AdminRole)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListRolesForAdmin(ctx, "admin"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("list after revoke=%v", err)
	}
	if _, err := store.GetRoleForAdmin(ctx, "admin", role.ID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("existing lookup after revoke=%v", err)
	}
	if _, err := store.GetRoleForAdmin(ctx, "admin", "missing"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("missing lookup after revoke=%v", err)
	}
}

func TestBootstrapInactiveLeavesNoStateAndConcurrentSeedReconciles(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	if _, err := store.EnsureBootstrapPrincipal(ctx, "missing", []string{"viewer"}, []string{"team/a"}); !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("inactive=%v", err)
	}
	count(t, db, `SELECT COUNT(*) FROM rbac_roles WHERE ?=0`, int64(0), int64(0))
	count(t, db, `SELECT COUNT(*) FROM rbac_groups WHERE ?=0`, int64(0), int64(0))
	insertActive(t, db, "admin")
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.EnsureBootstrapPrincipal(ctx, "admin", []string{"viewer"}, []string{"team/a"})
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	replica := NewStore(db)
	replica.now = func() time.Time { return time.UnixMilli(9_999_999_999_999).UTC() }
	replica.random = func([]byte) (int, error) { return 0, errors.New("bootstrap must not use randomness") }
	if _, err := replica.EnsureBootstrapPrincipal(ctx, "admin", []string{"viewer"}, []string{"team/a"}); err != nil {
		t.Fatalf("replica bootstrap was not byte-deterministic: %v", err)
	}
	principal, err := store.ResolvePrincipal(ctx, "admin")
	if err != nil || len(principal.Roles) != 2 || len(principal.Groups) != 1 {
		t.Fatalf("principal=%+v err=%v", principal, err)
	}
	count(t, db, `SELECT COUNT(*) FROM rbac_roles WHERE ?=0`, int64(0), int64(2))
	count(t, db, `SELECT COUNT(*) FROM rbac_groups WHERE ?=0`, int64(0), int64(1))
}

func TestResolveFailsClosedAtMembershipBound(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 65; i++ {
		name := fmtName(i)
		id := fmtName(i + 100)
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rbac-bound-" + id, Statements: []rhiza.SQLStatement{{SQL: `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?, ?, 1, 1, 1)`, Args: []any{id, name}}, {SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES (?, ?, 1)`, Args: []any{"admin", id}}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.ResolvePrincipal(ctx, "admin"); !errors.Is(err, ErrTooManyMemberships) {
		t.Fatalf("bound=%v", err)
	}
}

func TestPatchPrincipalReplacesMembershipsAndOnlyBumpsOnChange(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	insertActive(t, db, "member")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	seedPrincipalVersion(t, db, "member")
	if _, err := store.CreateRole(ctx, "admin", "viewer", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateRole(ctx, "admin", "auditor", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateGroup(ctx, "admin", "team/a", nil); err != nil {
		t.Fatal(err)
	}

	principal, err := store.PatchPrincipal(ctx, "admin", "member", []string{"viewer"}, []string{"team/a"}, true, true)
	if err != nil || principal.Revision != 2 || !equalNames(principal.Roles, []string{"viewer"}) || !equalNames(principal.Groups, []string{"team/a"}) {
		t.Fatalf("first patch principal=%+v err=%v", principal, err)
	}
	unchanged, err := store.PatchPrincipal(ctx, "admin", "member", []string{"viewer"}, []string{"team/a"}, true, true)
	if err != nil || unchanged.Revision != principal.Revision {
		t.Fatalf("no-op patch principal=%+v err=%v", unchanged, err)
	}
	partial, err := store.PatchPrincipal(ctx, "admin", "member", nil, []string{}, false, true)
	if err != nil || partial.Revision != 3 || !equalNames(partial.Roles, []string{"viewer"}) || len(partial.Groups) != 0 {
		t.Fatalf("partial patch principal=%+v err=%v", partial, err)
	}
	changed, err := store.PatchPrincipal(ctx, "admin", "member", []string{"auditor"}, nil, true, false)
	if err != nil || changed.Revision != 4 || !equalNames(changed.Roles, []string{"auditor"}) || len(changed.Groups) != 0 {
		t.Fatalf("role replacement principal=%+v err=%v", changed, err)
	}
	count(t, db, `SELECT revision FROM rbac_principal_versions WHERE subject=?`, "member", 4)
}

func TestPatchPrincipalFailsClosedForAdminTargetRevisionAndEntities(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	insertActive(t, db, "member")
	insertActive(t, db, "operator")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	seedPrincipalVersion(t, db, "member")
	viewer, err := store.CreateRole(ctx, "admin", "viewer", nil)
	if err != nil {
		t.Fatal(err)
	}
	beforeLastAdmin, err := store.ResolvePrincipal(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PatchPrincipal(ctx, "operator", "member", []string{"viewer"}, nil, true, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("non-admin patch=%v", err)
	}
	if _, err := store.PatchPrincipal(ctx, "admin", "missing", []string{"viewer"}, nil, true, false); !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("inactive target patch=%v", err)
	}
	if _, err := store.PatchPrincipal(ctx, "admin", "member", []string{"missing"}, nil, true, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing role patch=%v", err)
	}
	if _, err := store.PatchPrincipal(ctx, "admin", "admin", []string{}, nil, true, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("last admin removal=%v", err)
	}
	admin, err := store.ResolvePrincipal(ctx, "admin")
	if err != nil || !equalNames(admin.Roles, []string{AdminRole}) || admin.Revision != beforeLastAdmin.Revision {
		t.Fatalf("last admin changed principal=%+v err=%v", admin, err)
	}
	changed, err := store.PatchPrincipal(ctx, "admin", "member", []string{"viewer"}, nil, true, false)
	if err != nil || changed.Revision != 2 {
		t.Fatalf("seed membership=%+v err=%v", changed, err)
	}
	if _, err := store.replaceMemberships(ctx, "admin", nil, "member", 1, []string{}, nil, true, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision mutation=%v", err)
	}
	current, err := store.ResolvePrincipal(ctx, "member")
	if err != nil || current.Revision != 2 || !equalNames(current.Roles, []string{viewer.Name}) {
		t.Fatalf("stale CAS changed principal=%+v err=%v", current, err)
	}
}

func TestPatchPrincipalSelfDemotionAndRevocationInterpositionAreAtomic(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	insertActive(t, db, "backup")
	insertActive(t, db, "member")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureBootstrapPrincipal(ctx, "backup", nil, nil); err != nil {
		t.Fatal(err)
	}
	seedPrincipalVersion(t, db, "member")
	if _, err := store.CreateRole(ctx, "admin", "viewer", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateGroup(ctx, "admin", "team/a", nil); err != nil {
		t.Fatal(err)
	}
	seed, err := store.PatchPrincipal(ctx, "admin", "admin", []string{AdminRole, "viewer"}, []string{"team/a"}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	demoted, err := store.PatchPrincipal(ctx, "admin", "admin", []string{"viewer"}, []string{"team/a"}, true, true)
	if err != nil || demoted.Revision != seed.Revision+1 || !equalNames(demoted.Roles, []string{"viewer"}) || !equalNames(demoted.Groups, []string{"team/a"}) {
		t.Fatalf("self demotion principal=%+v err=%v", demoted, err)
	}
	if _, err := store.PatchPrincipal(ctx, "backup", "backup", []string{}, nil, true, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("second admin demotion=%v", err)
	}

	if _, err := store.PatchPrincipal(ctx, "backup", "member", []string{"viewer"}, []string{"team/a"}, true, true); err != nil {
		t.Fatal(err)
	}
	before, err := store.ResolvePrincipal(ctx, "member")
	if err != nil {
		t.Fatal(err)
	}
	store.beforeMembershipExecute = func() {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rbac-revoke-before-membership", SQL: `UPDATE identity_users SET disabled=1 WHERE subject='backup'`}); err != nil {
			t.Errorf("revoke actor: %v", err)
		}
	}
	defer func() { store.beforeMembershipExecute = nil }()
	if _, err := store.PatchPrincipal(ctx, "backup", "member", []string{}, []string{}, true, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked interposition=%v", err)
	}
	after, err := store.ResolvePrincipal(ctx, "member")
	if err != nil || after.Revision != before.Revision || !equalNames(after.Roles, entityNames(before.Roles)) || !equalNames(after.Groups, entityNames(before.Groups)) {
		t.Fatalf("revoked interposition changed principal before=%+v after=%+v err=%v", before, after, err)
	}
}

func TestPatchPrincipalFailedGuardUsesNewAttemptIDOnRetry(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	insertActive(t, db, "member")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateRole(ctx, "admin", "viewer", nil); err != nil {
		t.Fatal(err)
	}
	store.beforeMembershipExecute = func() {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rbac-disable-before-attempt", SQL: `UPDATE identity_users SET disabled=1 WHERE subject='admin'`}); err != nil {
			t.Errorf("disable actor: %v", err)
		}
	}
	if _, err := store.PatchPrincipal(ctx, "admin", "member", []string{"viewer"}, nil, true, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("guarded attempt=%v", err)
	}
	store.beforeMembershipExecute = nil
	count(t, db, `SELECT COUNT(*) FROM rbac_principal_versions WHERE subject=?`, "member", 0)
	count(t, db, `SELECT COUNT(*) FROM rbac_user_roles WHERE subject=?`, "member", 0)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rbac-enable-before-retry", SQL: `UPDATE identity_users SET disabled=0 WHERE subject='admin'`}); err != nil {
		t.Fatal(err)
	}
	principal, err := store.PatchPrincipal(ctx, "admin", "member", []string{"viewer"}, nil, true, false)
	if err != nil || principal.Revision != 2 || !equalNames(principal.Roles, []string{"viewer"}) {
		t.Fatalf("retry principal=%+v err=%v", principal, err)
	}
}

func TestDelegatedPatchPreservesUnmanagedGroupsAndEscalationGuards(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	insertActive(t, db, "delegated")
	insertActive(t, db, "member")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"team/a", "team/b", "other/x"} {
		if _, err := store.CreateGroup(ctx, "admin", name, nil); err != nil {
			t.Fatal(err)
		}
	}
	delegatedRole, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rbac-delegated-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,1,0)`, Args: []any{"delegated"}},
		{SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES (?, ?, 0)`, Args: []any{"delegated", delegatedRole.ID}},
		{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,1,0)`, Args: []any{"member"}},
		{SQL: `INSERT INTO rbac_user_groups (subject,group_id,granted_at_unix_ms) SELECT ?,id,0 FROM rbac_groups WHERE name IN ('team/a','other/x')`, Args: []any{"member"}},
	}}); err != nil {
		t.Fatal(err)
	}
	changed, err := store.PatchPrincipal(ctx, "delegated", "member", nil, []string{"team/b", "other/x"}, false, true)
	if err != nil || !equalNames(changed.Groups, []string{"other/x", "team/b"}) {
		t.Fatalf("delegated patch=%+v err=%v", changed, err)
	}
	before, err := store.ResolvePrincipal(ctx, "member")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PatchPrincipal(ctx, "delegated", "member", nil, []string{"other/x", "other/new"}, false, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unmanaged addition=%v", err)
	}
	after, err := store.ResolvePrincipal(ctx, "member")
	if err != nil || after.Revision != before.Revision || !equalNames(after.Groups, entityNames(before.Groups)) {
		t.Fatalf("unmanaged addition changed state before=%+v after=%+v err=%v", before, after, err)
	}
	if _, err := store.PatchPrincipal(ctx, "delegated", "member", []string{"viewer"}, nil, true, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("role replacement=%v", err)
	}
	if _, err := store.PatchPrincipal(ctx, "delegated", "delegated", nil, []string{}, false, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("self target=%v", err)
	}
}

func TestDelegatedPatchRevocationInterpositionIsAtomic(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	insertActive(t, db, "delegated")
	insertActive(t, db, "member")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	group, err := store.CreateGroup(ctx, "admin", "team/a", nil)
	if err != nil {
		t.Fatal(err)
	}
	role, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rbac-delegated-revoke-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,1,0)`, Args: []any{"delegated"}},
		{SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES (?, ?, 0)`, Args: []any{"delegated", role.ID}},
		{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,1,0)`, Args: []any{"member"}},
	}}); err != nil {
		t.Fatal(err)
	}
	before, err := store.ResolvePrincipal(ctx, "member")
	if err != nil {
		t.Fatal(err)
	}
	store.beforeMembershipExecute = func() {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rbac-delegated-disable", SQL: `UPDATE identity_users SET disabled=1 WHERE subject='delegated'`}); err != nil {
			t.Errorf("disable actor: %v", err)
		}
	}
	defer func() { store.beforeMembershipExecute = nil }()
	if _, err := store.PatchPrincipal(ctx, "delegated", "member", nil, []string{group.Name}, false, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked delegated patch=%v", err)
	}
	after, err := store.ResolvePrincipal(ctx, "member")
	if err != nil || after.Revision != before.Revision || len(after.Groups) != 0 {
		t.Fatalf("revoked delegated patch changed state before=%+v after=%+v err=%v", before, after, err)
	}
}

func rbacTestStore(t *testing.T) (context.Context, *Store, *rhiza.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "rbac-store-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := NewStore(db)
	store.now = func() time.Time { return time.UnixMilli(1_700_000_000_000).UTC() }
	var randomMu sync.Mutex
	var randomByte byte
	store.random = func(dst []byte) (int, error) {
		randomMu.Lock()
		defer randomMu.Unlock()
		for i := range dst {
			randomByte++
			dst[i] = randomByte
		}
		return len(dst), nil
	}
	return ctx, store, db
}
func insertActive(t *testing.T, db *rhiza.DB, subject string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "rbac-active-" + subject, SQL: `INSERT INTO identity_users (subject,username,password_phc) VALUES (?, ?, 'phc')`, Args: []any{subject, subject}}); err != nil {
		t.Fatal(err)
	}
}
func seedPrincipalVersion(t *testing.T, db *rhiza.DB, subject string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "rbac-version-" + subject, SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,1,0)`, Args: []any{subject}}); err != nil {
		t.Fatal(err)
	}
}
func count(t *testing.T, db *rhiza.DB, sql string, arg any, want int64) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: sql, Args: []any{arg}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != want {
		t.Fatalf("count rows=%#v err=%v want=%d", result.Rows, err, want)
	}
}
func roleByName(t *testing.T, db *rhiza.DB, name string) string {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT id FROM rbac_roles WHERE name=?`, Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("role=%#v err=%v", result.Rows, err)
	}
	id, ok := result.Rows[0][0].(string)
	if !ok {
		t.Fatal("role id type")
	}
	return id
}
func fmtName(i int) string { return fmt.Sprintf("r%02d", i) }
