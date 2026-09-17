package rbac

import "encoding/json"

// userUpdateAuthority is the browser administrator's PUT policy, evaluated
// against current rows at the mutation barrier, before changing memberships.
// The caller must additionally supply its live session/MFA guard. API keys use
// their own current Users/update guard, not this browser-role policy.
// Unlike the narrow PATCH flow, PUT cannot bring an unmanaged user into scope.
func userUpdateAuthority(actor, target string, roles, groups []string) (string, []any) {
	roleJSON, _ := json.Marshal(append([]string{}, roles...))
	groupJSON, _ := json.Marshal(append([]string{}, groups...))
	guard := `EXISTS (SELECT 1 FROM identity_users WHERE subject=?) AND (` + adminGuard() + ` OR (` + delegatedAdminGuard() + `
	 AND (?=? OR (
	  NOT EXISTS (SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id
	   WHERE m.subject=? AND (r.name='rauthy_admin' OR substr(r.name,1,13)='rauthy_admin:'))
	  AND EXISTS (SELECT 1 FROM rbac_user_groups m JOIN rbac_groups g ON g.id=m.group_id
	   WHERE m.subject=? AND ` + userUpdateGroupScope("g.name") + `)
	 ))
	 AND NOT EXISTS (SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id
	  WHERE m.subject=? AND r.name NOT IN (SELECT value FROM json_each(?)))
	 AND NOT EXISTS (SELECT 1 FROM json_each(?) requested WHERE NOT EXISTS (
	  SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id
	  WHERE m.subject=? AND r.name=requested.value))
	 AND NOT EXISTS (SELECT 1 FROM rbac_user_groups m JOIN rbac_groups g ON g.id=m.group_id
	  WHERE m.subject=? AND g.name NOT IN (SELECT value FROM json_each(?))
	  AND NOT (` + userUpdateGroupScope("g.name") + `))
	 AND NOT EXISTS (SELECT 1 FROM json_each(?) requested WHERE NOT EXISTS (
	  SELECT 1 FROM rbac_user_groups m JOIN rbac_groups g ON g.id=m.group_id
	  WHERE m.subject=? AND g.name=requested.value)
	  AND NOT (` + userUpdateGroupScope("requested.value") + `))
	))`
	return guard, []any{target, actor, actor, actor, target, target, target, actor,
		target, string(roleJSON), string(roleJSON), target,
		target, string(groupJSON), actor, string(groupJSON), target, actor}
}

// groupSQL is one of the server-owned column expressions above, never input.
// Literal/prefix matching deliberately avoids LIKE: '_' is a valid group name.
func userUpdateGroupScope(groupSQL string) string {
	return `EXISTS (SELECT 1 FROM rbac_user_roles am JOIN rbac_roles ar ON ar.id=am.role_id
	 WHERE am.subject=? AND substr(ar.name,1,13)='rauthy_admin:' AND
	 (substr(ar.name,14)=` + groupSQL + ` OR
	  (substr(ar.name,-1)='*' AND substr(` + groupSQL + `,1,length(ar.name)-14)=substr(ar.name,14,length(ar.name)-14))))`
}
