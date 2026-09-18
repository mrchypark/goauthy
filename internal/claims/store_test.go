package claims

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAPIKeyScopeAndUserAttributeMutationsAreGuarded(t *testing.T) {
	ctx, store := claimsTestStore(t)
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "claims-writer", Access: []apikey.Access{{Group: "UserAttributes", AccessRights: []apikey.Right{apikey.Create}}, {Group: "Scopes", AccessRights: []apikey.Right{apikey.Create}}, {Group: "Users", AccessRights: []apikey.Right{apikey.Update, apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	p, err := store.AuthenticateAPIKey(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateAttributeAPIKey(ctx, p, 0, Attribute{Name: "employee-id"}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateScopeAPIKey(ctx, p, 1, Scope{Name: "employee", AttributeIncludeID: []string{"employee-id"}}); err != nil {
		t.Fatal(err)
	}
	if rev, err := store.PutUserValuesAPIKey(ctx, p, "member", 1, map[string]json.RawMessage{"employee-id": json.RawMessage(`"E-42"`)}); err != nil || rev != 2 {
		t.Fatalf("revision=%d err=%v", rev, err)
	}
	if err = keys.Delete(ctx, nil, "claims-writer"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateAttributeAPIKey(ctx, p, 2, Attribute{Name: "blocked"}); err == nil {
		t.Fatal("revoked key mutated catalog")
	}
}

func TestBootstrapClientCredentialsClaimsCASAndAPIKeyGuard(t *testing.T) {
	ctx, store := claimsTestStore(t)
	initial, err := store.BootstrapClientCredentialsClaims(ctx, "bootstrap-client")
	if err != nil || initial.Revision != 0 || initial.Values != nil || initial.AtRoot {
		t.Fatalf("initial=%+v err=%v", initial, err)
	}
	updated, err := store.UpdateBootstrapClientCredentialsClaims(ctx, "admin", "bootstrap-client", 0, map[string]json.RawMessage{"sub": json.RawMessage(`"accepted-at-policy-time"`), "nested": json.RawMessage(`{"n":1}`)}, true)
	if err != nil || updated.Revision != 1 || !updated.AtRoot || string(updated.Values["sub"]) != `"accepted-at-policy-time"` {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	if _, err := store.UpdateBootstrapClientCredentialsClaims(ctx, "admin", "bootstrap-client", 0, map[string]json.RawMessage{}, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update err=%v", err)
	}
	cleared, err := store.UpdateBootstrapClientCredentialsClaims(ctx, "admin", "bootstrap-client", 1, nil, false)
	if err != nil || cleared.Revision != 2 || cleared.Values != nil || cleared.AtRoot {
		t.Fatalf("cleared=%+v err=%v", cleared, err)
	}
	empty, err := store.UpdateBootstrapClientCredentialsClaims(ctx, "admin", "bootstrap-client", 2, map[string]json.RawMessage{}, false)
	if err != nil || empty.Revision != 3 || empty.Values == nil || len(empty.Values) != 0 {
		t.Fatalf("empty=%+v err=%v", empty, err)
	}
	if _, err := store.UpdateBootstrapClientCredentialsClaims(ctx, "admin", "bootstrap-client", 3, map[string]json.RawMessage{"large": json.RawMessage(`"` + strings.Repeat("x", 1024) + `"`)}, false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("large claim err=%v", err)
	}

	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "client-claims", Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	principal, err := store.AuthenticateAPIKey(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateBootstrapClientCredentialsClaimsAPIKey(ctx, principal, "bootstrap-client", 3, map[string]json.RawMessage{"role": json.RawMessage(`"service"`)}, false); err != nil {
		t.Fatal(err)
	}
	if err := keys.Delete(ctx, nil, "client-claims"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateBootstrapClientCredentialsClaimsAPIKey(ctx, principal, "bootstrap-client", 4, map[string]json.RawMessage{"role": json.RawMessage(`"blocked"`)}, false); err == nil {
		t.Fatal("revoked API key updated client claims")
	}
}

func TestStoreResolvesValuesAndCascadesPolicy(t *testing.T) {
	ctx, store := claimsTestStore(t)
	attribute, err := store.CreateAttribute(ctx, "admin", 0, Attribute{Name: "employee-id", Default: json.RawMessage(`"E-0"`)})
	if err != nil || attribute.Revision != 1 {
		t.Fatalf("attribute=%+v err=%v", attribute, err)
	}
	scope, err := store.CreateScope(ctx, "admin", 1, Scope{Name: "employee", AttributeIncludeID: []string{"employee-id"}})
	if err != nil || scope.Revision != 1 {
		t.Fatalf("scope=%+v err=%v", scope, err)
	}
	if _, err := store.UpdateBootstrapClientScopes(ctx, "admin", "bootstrap-client", 0, []string{"openid", "employee"}, []string{"employee"}); err != nil {
		t.Fatal(err)
	}
	revision, err := store.PutUserValues(ctx, "admin", "member", 1, map[string]json.RawMessage{"employee-id": json.RawMessage(`"E-42"`)})
	if err != nil || revision != 2 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
	resolved, err := store.Resolve(ctx, "member", []string{"employee"})
	if err != nil || string(resolved.ID["employee-id"]) != `"E-42"` || len(resolved.Access) != 0 {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	if err := store.DeleteAttribute(ctx, "admin", "employee-id", 2); err != nil {
		t.Fatal(err)
	}
	resolved, err = store.Resolve(ctx, "member", []string{"employee"})
	if err != nil || len(resolved.ID) != 0 {
		t.Fatalf("after attribute delete=%+v err=%v", resolved, err)
	}
	policy, err := store.BootstrapClientScopes(ctx, "bootstrap-client")
	if err != nil || len(policy.Allowed) != 2 {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	if err := store.DeleteScope(ctx, "admin", "employee", 3); err != nil {
		t.Fatal(err)
	}
	policy, err = store.BootstrapClientScopes(ctx, "bootstrap-client")
	if err != nil || len(policy.Allowed) != 1 || policy.Allowed[0] != "openid" || len(policy.Default) != 0 {
		t.Fatalf("cascade policy=%+v err=%v", policy, err)
	}
}

func TestStorePersistsEmptyDefaultClientScopesAsJSONArray(t *testing.T) {
	ctx, store := claimsTestStore(t)
	if _, err := store.CreateAttribute(ctx, "admin", 0, Attribute{Name: "employee-id"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateScope(ctx, "admin", 1, Scope{Name: "employee", AttributeIncludeID: []string{"employee-id"}}); err != nil {
		t.Fatal(err)
	}
	policy, err := store.UpdateBootstrapClientScopes(ctx, "admin", "bootstrap-client", 0, []string{"employee"}, []string{})
	if err != nil || len(policy.Allowed) != 1 || policy.Allowed[0] != "employee" || policy.Default == nil || len(policy.Default) != 0 {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
}

func TestStoreUpdatesExistingUserAttributeValue(t *testing.T) {
	ctx, store := claimsTestStore(t)
	if _, err := store.CreateAttribute(ctx, "admin", 0, Attribute{Name: "employee-id"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutUserValues(ctx, "admin", "member", 1, map[string]json.RawMessage{"employee-id": json.RawMessage(`"E-123"`)}); err != nil {
		t.Fatal(err)
	}
	if revision, err := store.PutUserValues(ctx, "admin", "member", 2, map[string]json.RawMessage{"employee-id": json.RawMessage(`"E-456"`)}); err != nil || revision != 3 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
	values, revision, err := store.GetUserValues(ctx, "admin", "member")
	if err != nil || revision != 3 || string(values["employee-id"]) != `"E-456"` {
		t.Fatalf("values=%v revision=%d err=%v", values, revision, err)
	}
}

func TestStoreSelfEditableUserValuesOnlyMutateEditableKeys(t *testing.T) {
	ctx, store := claimsTestStore(t)
	if _, err := store.CreateAttribute(ctx, "admin", 0, Attribute{Name: "employee-id", Default: json.RawMessage(`"E-0"`), UserEditable: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAttribute(ctx, "admin", 1, Attribute{Name: "department"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutUserValues(ctx, "admin", "member", 1, map[string]json.RawMessage{"department": json.RawMessage(`"security"`)}); err != nil {
		t.Fatal(err)
	}
	items, err := store.EditableUserAttributes(ctx, "member")
	if err != nil || len(items) != 1 || items[0].Name != "employee-id" || string(items[0].Default) != `"E-0"` || items[0].Value != nil {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	if revision, err := store.PutSelfUserValues(ctx, "member", "member", 2, map[string]json.RawMessage{"employee-id": json.RawMessage(`"E-42"`), "department": json.RawMessage(`"engineering"`), "unknown-attr": json.RawMessage(`true`)}); err != nil || revision != 3 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
	values, revision, err := store.GetUserValues(ctx, "admin", "member")
	if err != nil || revision != 3 || string(values["employee-id"]) != `"E-42"` || string(values["department"]) != `"security"` || values["unknown-attr"] != nil {
		t.Fatalf("values=%v revision=%d err=%v", values, revision, err)
	}
	if revision, err := store.PutSelfUserValues(ctx, "member", "member", 3, map[string]json.RawMessage{"employee-id": json.RawMessage(`"E-42"`), "department": json.RawMessage(`"engineering"`)}); err != nil || revision != 3 {
		t.Fatalf("no-op revision=%d err=%v", revision, err)
	}
	if revision, err := store.PutSelfUserValues(ctx, "member", "member", 3, map[string]json.RawMessage{"employee-id": json.RawMessage(`""`)}); err != nil || revision != 4 {
		t.Fatalf("delete revision=%d err=%v", revision, err)
	}
	items, err = store.EditableUserAttributes(ctx, "member")
	if err != nil || len(items) != 1 || items[0].Value != nil {
		t.Fatalf("after delete items=%+v err=%v", items, err)
	}
}

func TestStoreSelfEditableUserValuesRejectsOtherSubjectAndStaleRevision(t *testing.T) {
	ctx, store := claimsTestStore(t)
	if _, err := store.CreateAttribute(ctx, "admin", 0, Attribute{Name: "employee-id", UserEditable: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSelfUserValues(ctx, "member", "admin", 1, map[string]json.RawMessage{"employee-id": json.RawMessage(`"E-42"`)}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("other subject err=%v", err)
	}
	if _, err := store.PutSelfUserValues(ctx, "member", "member", 2, map[string]json.RawMessage{"employee-id": json.RawMessage(`"E-42"`)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision err=%v", err)
	}
}

func TestStoreScopeExistsIsLinearizableAndUnauthenticated(t *testing.T) {
	ctx, store := claimsTestStore(t)
	exists, err := store.ScopeExists(ctx, "employee")
	if err != nil || exists {
		t.Fatalf("before create exists=%t err=%v", exists, err)
	}
	if _, err := store.CreateAttribute(ctx, "admin", 0, Attribute{Name: "employee-id"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateScope(ctx, "admin", 1, Scope{Name: "employee", AttributeIncludeID: []string{"employee-id"}}); err != nil {
		t.Fatal(err)
	}
	exists, err = store.ScopeExists(ctx, "employee")
	if err != nil || !exists {
		t.Fatalf("after create exists=%t err=%v", exists, err)
	}
	if exists, err := store.ScopeExists(ctx, "openid"); err != nil || exists {
		t.Fatalf("default exists=%t err=%v", exists, err)
	}
}

func TestStoreRejectsStaleCatalogAndPrincipalCAS(t *testing.T) {
	ctx, store := claimsTestStore(t)
	if _, err := store.CreateAttribute(ctx, "admin", 1, Attribute{Name: "employee-id"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale catalog err=%v", err)
	}
	if _, err := store.CreateAttribute(ctx, "admin", 0, Attribute{Name: "employee-id"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutUserValues(ctx, "admin", "member", 2, map[string]json.RawMessage{"employee-id": json.RawMessage(`"E-42"`)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale principal err=%v", err)
	}
	if _, err := store.PutUserValues(ctx, "admin", "member", 1, map[string]json.RawMessage{"employee-id": json.RawMessage(`{"department":"security"}`)}); err != nil {
		t.Fatal(err)
	}
}

func TestStoreCreateConflictDoesNotAdvanceCatalog(t *testing.T) {
	ctx, store := claimsTestStore(t)
	if _, err := store.CreateAttribute(ctx, "admin", 0, Attribute{Name: "employee-id"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAttribute(ctx, "admin", 1, Attribute{Name: "employee-id"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate attribute err=%v", err)
	}
	if revision, err := store.CatalogRevision(ctx); err != nil || revision != 1 {
		t.Fatalf("attribute catalog revision=%d err=%v", revision, err)
	}
	if _, err := store.CreateScope(ctx, "admin", 1, Scope{Name: "employee", AttributeIncludeID: []string{"employee-id"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateScope(ctx, "admin", 2, Scope{Name: "employee", AttributeIncludeID: []string{"employee-id"}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate scope err=%v", err)
	}
	if revision, err := store.CatalogRevision(ctx); err != nil || revision != 2 {
		t.Fatalf("scope catalog revision=%d err=%v", revision, err)
	}
}

func TestStoreAllowsPermissionOnlyScopesAndStillValidatesAttributes(t *testing.T) {
	ctx, store := claimsTestStore(t)
	scope, err := store.CreateScope(ctx, "admin", 0, Scope{Name: "permission-only"})
	if err != nil || scope.Name != "permission-only" || len(scope.AttributeIncludeID) != 0 || len(scope.AttributeIncludeAccess) != 0 {
		t.Fatalf("scope=%+v err=%v", scope, err)
	}
	if _, err := store.UpdateScope(ctx, "admin", "permission-only", 1, Scope{Name: "permission-only", AttributeIncludeID: []string{"missing"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing attribute err=%v", err)
	}
	if _, err := store.CreateScope(ctx, "admin", 1, Scope{Name: "openid"}); !errors.Is(err, ErrReserved) {
		t.Fatalf("reserved scope err=%v", err)
	}
	if _, err := store.UpdateScope(ctx, "admin", "permission-only", 1, Scope{Name: "permission-only", AttributeIncludeID: []string{}, AttributeIncludeAccess: []string{}}); err != nil {
		t.Fatalf("empty projection update: %v", err)
	}
	resolved, err := store.Resolve(ctx, "member", []string{"permission-only"})
	if err != nil || len(resolved.ID) != 0 || len(resolved.IDRoot) != 0 || len(resolved.Access) != 0 || len(resolved.AccessRoot) != 0 {
		t.Fatalf("permission-only scope emitted claims: %+v err=%v", resolved, err)
	}
}

func TestStoreRenamesAttributeAndScopeAtomically(t *testing.T) {
	ctx, store := claimsTestStore(t)
	if _, err := store.CreateAttribute(ctx, "admin", 0, Attribute{Name: "employee-id"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAttribute(ctx, "admin", 1, Attribute{Name: "department"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateScope(ctx, "admin", 2, Scope{Name: "employee", AttributeIncludeID: []string{"employee-id"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutUserValues(ctx, "admin", "member", 1, map[string]json.RawMessage{"employee-id": json.RawMessage(`"E-42"`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateAttribute(ctx, "admin", "employee-id", 3, Attribute{Name: "staff-id"}); err != nil {
		t.Fatal(err)
	}
	values, _, err := store.GetUserValues(ctx, "admin", "member")
	if err != nil || string(values["staff-id"]) != `"E-42"` || values["employee-id"] != nil {
		t.Fatalf("renamed values=%v err=%v", values, err)
	}
	scope, err := store.GetScope(ctx, "admin", "employee")
	if err != nil || len(scope.AttributeIncludeID) != 1 || scope.AttributeIncludeID[0] != "staff-id" {
		t.Fatalf("renamed attribute scope=%+v err=%v", scope, err)
	}
	if _, err := store.UpdateAttribute(ctx, "admin", "staff-id", 4, Attribute{Name: "department"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("attribute target conflict err=%v", err)
	}
	if revision, err := store.CatalogRevision(ctx); err != nil || revision != 4 {
		t.Fatalf("attribute conflict catalog=%d err=%v", revision, err)
	}
	if _, err := store.UpdateBootstrapClientScopes(ctx, "admin", "bootstrap-client", 0, []string{"openid", "employee"}, []string{"employee"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateScope(ctx, "admin", "employee", 4, Scope{Name: "staff", AttributeIncludeID: []string{"staff-id"}}); err != nil {
		t.Fatal(err)
	}
	policy, err := store.BootstrapClientScopes(ctx, "bootstrap-client")
	if err != nil || !equalStrings(policy.Allowed, []string{"staff", "openid"}) || !equalStrings(policy.Default, []string{"staff"}) {
		t.Fatalf("renamed scope policy=%+v err=%v", policy, err)
	}
	if _, err := store.CreateScope(ctx, "admin", 5, Scope{Name: "other", AttributeIncludeID: []string{"staff-id"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateScope(ctx, "admin", "staff", 6, Scope{Name: "other", AttributeIncludeID: []string{"staff-id"}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("scope target conflict err=%v", err)
	}
	policy, err = store.BootstrapClientScopes(ctx, "bootstrap-client")
	if err != nil || !equalStrings(policy.Allowed, []string{"staff", "openid"}) || !equalStrings(policy.Default, []string{"staff"}) {
		t.Fatalf("scope conflict policy=%+v err=%v", policy, err)
	}
}

func TestStoreReadErrorsAndJSONDuplicates(t *testing.T) {
	ctx, store := claimsTestStore(t)
	for _, value := range []json.RawMessage{json.RawMessage(`{"a":1,"a":2}`), json.RawMessage(`{"a":{"b":1,"b":2}}`), json.RawMessage(`[{"a":1,"a":2}]`)} {
		if _, err := canonicalJSON(value); !errors.Is(err, ErrInvalid) {
			t.Fatalf("duplicate JSON %s err=%v", value, err)
		}
	}
	if got, err := store.BootstrapClientScopes(ctx, "bootstrap-client"); err != nil || got.ClientID != "bootstrap-client" || got.Revision != 0 {
		t.Fatalf("missing bootstrap scopes=%+v err=%v", got, err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapClientScopes(ctx, "bootstrap-client"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("closed bootstrap read err=%v", err)
	}
	if _, err := store.scope(ctx, "employee"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("closed scope read err=%v", err)
	}
}

func TestStoreResolveSeparatesRootClaimBindings(t *testing.T) {
	ctx, store := claimsTestStore(t)
	if _, err := store.CreateAttribute(ctx, "admin", 0, Attribute{Name: "employee-id", Default: json.RawMessage(`"E-42"`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAttribute(ctx, "admin", 1, Attribute{Name: "department", Default: json.RawMessage(`"security"`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateScope(ctx, "admin", 2, Scope{Name: "nested", AttributeIncludeID: []string{"employee-id"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateScope(ctx, "admin", 3, Scope{Name: "root", AttributeIncludeAccess: []string{"department"}, ClaimsAtRoot: true}); err != nil {
		t.Fatal(err)
	}
	resolved, err := store.Resolve(ctx, "member", []string{"nested", "root"})
	if err != nil || string(resolved.ID["employee-id"]) != `"E-42"` || len(resolved.IDRoot) != 0 || string(resolved.AccessRoot["department"]) != `"security"` || len(resolved.Access) != 0 {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func claimsTestStore(t *testing.T) (context.Context, *Store) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "claims-store-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "claims-store-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users (subject,username,password_phc) VALUES ('admin','admin','phc'),('member','member','phc')`},
		{SQL: `INSERT INTO rbac_roles (id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('admin-role','rauthy_admin',NULL,1,0,0)`},
		{SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES ('admin','admin-role',0)`},
		{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES ('admin',1,0),('member',1,0)`},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, NewStore(db)
}
