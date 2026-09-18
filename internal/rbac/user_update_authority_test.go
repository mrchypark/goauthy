package rbac

import (
	"context"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func userUpdateAuthorityFixture(t *testing.T) (context.Context, *rhiza.DB) {
	t.Helper()
	ctx, _, db := rbacTestStore(t)
	for _, subject := range []string{"admin", "delegate", "exact", "wildcard", "literal", "member", "unmanaged", "other-admin", "other-delegate", "empty", "bare", "inactive"} {
		insertActive(t, db, subject)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "update-authority-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_roles(id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES
		 ('admin-role','rauthy_admin',1,0,0),('delegate-role','rauthy_admin:team/*',1,0,0),
		 ('exact-role','rauthy_admin:team/a',1,0,0),('wildcard-role','rauthy_admin:*',1,0,0),
		 ('literal-role','rauthy_admin:team_*',1,0,0),('viewer-role','viewer',1,0,0)`},
		{SQL: `INSERT INTO rbac_groups(id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES
		 ('a','team/a',1,0,0),('b','team/b',1,0,0),('out','outside',1,0,0),('lookalike','teamish/a',1,0,0)`},
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES
		 ('admin','admin-role',0),('delegate','delegate-role',0),('exact','exact-role',0),
		 ('wildcard','wildcard-role',0),('literal','literal-role',0),('member','viewer-role',0),('unmanaged','viewer-role',0),
		 ('other-admin','admin-role',0),('other-delegate','delegate-role',0)`},
		{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) VALUES
		 ('member','a',0),('member','out',0),('unmanaged','out',0),
		 ('other-admin','a',0),('other-delegate','a',0),('bare','a',0),('inactive','a',0)`},
		{SQL: `UPDATE identity_users SET disabled=1 WHERE subject='inactive'`},
	}}); err != nil {
		t.Fatal(err)
	}
	return ctx, db
}

func TestUserUpdateAuthorityMatchesPUTScope(t *testing.T) {
	ctx, db := userUpdateAuthorityFixture(t)
	for _, tc := range []struct {
		name, actor, target string
		roles, groups       []string
		want                int64
	}{
		{"direct admin", "admin", "member", nil, nil, 1},
		{"missing target", "admin", "missing", nil, nil, 0},
		{"ordinary caller", "member", "member", []string{"viewer"}, []string{"team/a", "outside"}, 0},
		{"managed profile", "delegate", "member", []string{"viewer"}, []string{"team/a", "outside"}, 1},
		{"add managed group", "delegate", "member", []string{"viewer"}, []string{"team/a", "team/b", "outside"}, 1},
		{"remove last managed group", "delegate", "member", []string{"viewer"}, []string{"outside"}, 1},
		{"remove outside group", "delegate", "member", []string{"viewer"}, []string{"team/a"}, 0},
		{"omitted groups removes outside", "delegate", "member", []string{"viewer"}, nil, 0},
		{"replace role", "delegate", "member", []string{"rauthy_admin"}, []string{"team/a", "outside"}, 0},
		{"remove role", "delegate", "member", nil, []string{"team/a", "outside"}, 0},
		{"unknown role is still a role change", "delegate", "member", []string{"viewer", "unknown"}, []string{"team/a", "outside"}, 0},
		{"unknown outside group denied before sanitization", "delegate", "member", []string{"viewer"}, []string{"team/a", "outside", "unknown"}, 0},
		{"unknown managed group permitted before sanitization", "delegate", "member", []string{"viewer"}, []string{"team/a", "outside", "team/new"}, 1},
		{"prefix is not substring", "delegate", "member", []string{"viewer"}, []string{"team/a", "outside", "teamish/a"}, 0},
		{"underscore is literal", "literal", "member", []string{"viewer"}, []string{"team/a", "outside"}, 0},
		{"exact scope permits its own removal", "exact", "member", []string{"viewer"}, []string{"outside"}, 1},
		{"exact scope cannot add sibling", "exact", "member", []string{"viewer"}, []string{"team/a", "team/b", "outside"}, 0},
		{"wildcard can remove outside", "wildcard", "member", []string{"viewer"}, nil, 1},
		{"PUT cannot claim an unmanaged user", "delegate", "unmanaged", []string{"viewer"}, []string{"outside", "team/a"}, 0},
		{"other direct admin protected", "delegate", "other-admin", []string{"rauthy_admin"}, []string{"team/a"}, 0},
		{"other delegated admin protected", "delegate", "other-delegate", []string{"rauthy_admin:team/*"}, []string{"team/a"}, 0},
		{"self without any managed group", "delegate", "delegate", []string{"rauthy_admin:team/*"}, nil, 1},
		{"self cannot drop role", "delegate", "delegate", nil, nil, 0},
		{"self cannot add role", "delegate", "delegate", []string{"rauthy_admin:team/*", "rauthy_admin"}, nil, 0},
		{"self cannot add outside group", "delegate", "delegate", []string{"rauthy_admin:team/*"}, []string{"outside"}, 0},
		{"self can add managed group", "delegate", "delegate", []string{"rauthy_admin:team/*"}, []string{"team/a"}, 1},
		{"unmanaged empty roles and groups", "delegate", "empty", nil, nil, 0},
		{"managed user with no roles", "delegate", "bare", nil, []string{"team/a"}, 1},
		{"managed user with no roles removes last group", "delegate", "bare", nil, nil, 1},
		{"disabled user can be administered", "delegate", "inactive", nil, []string{"team/a"}, 1},
		{"direct admin can reactivate", "admin", "inactive", nil, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guard, args := userUpdateAuthority(tc.actor, tc.target, tc.roles, tc.groups)
			result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT (` + guard + `)`, Args: args, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != tc.want {
				t.Fatalf("decision=%v err=%v want=%d", result.Rows, err, tc.want)
			}
		})
	}
}

func TestUserUpdateAuthoritySnapshotSurvivesManagedGroupRemoval(t *testing.T) {
	ctx, db := userUpdateAuthorityFixture(t)
	guard, args := userUpdateAuthority("delegate", "bare", nil, nil)
	one := int64(1)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "allowed-update-authority", Statements: []rhiza.SQLStatement{
		{SQL: `SELECT subject FROM identity_users WHERE subject='bare' AND (` + guard + `)`, Args: args, WantRows: true, ExpectedReturnedRows: &one},
		{SQL: `DELETE FROM rbac_user_groups WHERE subject='bare'`},
		{SQL: `UPDATE identity_users SET language='ko' WHERE subject='bare'`},
	}}); err != nil {
		t.Fatal(err)
	}
	count(t, db, `SELECT COUNT(*) FROM identity_users WHERE subject=? AND language='ko'`, "bare", 1)
	count(t, db, `SELECT COUNT(*) FROM rbac_user_groups WHERE subject=?`, "bare", 0)
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT (` + guard + `)`, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("subsequent request no longer has scope: %v err=%v", result.Rows, err)
	}
}

func TestUserUpdateAuthorityRechecksCurrentRowsAtMutation(t *testing.T) {
	for _, tc := range []struct{ name, change string }{
		{"actor role revoked", `DELETE FROM rbac_user_roles WHERE subject='delegate'`},
		{"actor disabled", `UPDATE identity_users SET disabled=1 WHERE subject='delegate'`},
		{"target no longer managed", `DELETE FROM rbac_user_groups WHERE subject='member' AND group_id='a'`},
		{"target promoted", `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('member','admin-role',0)`},
		{"target role changed", `DELETE FROM rbac_user_roles WHERE subject='member'`},
		{"outside group changed", `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) VALUES('member','lookalike',0)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, db := userUpdateAuthorityFixture(t)
			guard, args := userUpdateAuthority("delegate", "member", []string{"viewer"}, []string{"team/a", "outside"})
			before, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT (` + guard + `)`, Args: args, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(before.Rows) != 1 || before.Rows[0][0] != int64(1) {
				t.Fatalf("preflight=%v err=%v", before.Rows, err)
			}
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "interpose-update-authority", SQL: tc.change}); err != nil {
				t.Fatal(err)
			}
			// This is a storage-boundary check, not the not-yet-wired HTTP PUT.
			// The stale preflight cannot authorize either of the subsequent writes.
			one := int64(1)
			result, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "denied-update-authority", Statements: []rhiza.SQLStatement{
				{SQL: `SELECT subject FROM identity_users WHERE subject='member' AND (` + guard + `)`, Args: args, WantRows: true, ExpectedReturnedRows: &one},
				{SQL: `UPDATE identity_users SET language='ko' WHERE subject='member'`},
				{SQL: `DELETE FROM rbac_user_groups WHERE subject='member'`},
			}})
			if err == nil || result.ErrorCode != rhiza.MutationErrorCodePreconditionFailed {
				t.Fatalf("mutation status=%s code=%s err=%v", result.Status, result.ErrorCode, err)
			}
			count(t, db, `SELECT COUNT(*) FROM identity_users WHERE subject=? AND language IS NULL`, "member", 1)
			count(t, db, `SELECT COUNT(*) FROM rbac_user_groups WHERE subject=? AND group_id='out'`, "member", 1)
		})
	}
}
