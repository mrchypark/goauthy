package rbac

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/rhiza"
)

// Preserve the existing API names while sharing the safe read/mutation projection.
type UserResponse = identity.UserResponse
type UserValuesResponse = identity.UserValuesResponse

// detailUser reads authority, target scope, and the projection in one snapshot.
// guard is trusted server SQL for the exact session or API key, never request input.
func (s *Store) detailUser(ctx context.Context, actor, target, guard string, args []any, api bool) (UserResponse, int64, int, error) {
	if !validSubjectID(target) || strings.TrimSpace(guard) == "" {
		return UserResponse{}, 0, 0, ErrInvalid
	}
	// Resource existence is checked only after the caller can ask about this ID.
	status := `CASE WHEN NOT (` + guard + `) THEN 401 `
	queryArgs := append([]any{}, args...)
	if !api {
		status += `WHEN NOT (?=? OR ` + adminGuard() + ` OR ` + delegatedAdminGuard() + `) THEN 403 `
		queryArgs = append(queryArgs, actor, target, actor, actor)
	}
	status += `WHEN NOT EXISTS (SELECT 1 FROM identity_users WHERE subject=?) THEN 404 `
	queryArgs = append(queryArgs, target)
	if !api {
		status += `WHEN ?=? OR ` + adminGuard() + ` THEN 200
		WHEN EXISTS (SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id WHERE m.subject=? AND (r.name='rauthy_admin' OR substr(r.name,1,13)='rauthy_admin:')) THEN 403
		WHEN NOT EXISTS (
		 SELECT 1 FROM rbac_user_groups tm JOIN rbac_groups g ON g.id=tm.group_id
		 JOIN rbac_user_roles am ON am.subject=? JOIN rbac_roles ar ON ar.id=am.role_id
		 WHERE tm.subject=? AND substr(ar.name,1,13)='rauthy_admin:'
		 AND (substr(ar.name,14)=g.name OR (substr(ar.name,-1)='*' AND substr(g.name,1,length(ar.name)-14)=substr(ar.name,14,length(ar.name)-14)))
		) THEN 428 `
		queryArgs = append(queryArgs, actor, target, actor, target, actor, target)
	}
	status += `ELSE 200 END`
	queryArgs = append(queryArgs, target)
	result, err := s.db.Query(ctx, rhiza.QueryRequest{Consistency: rhiza.ConsistencyLinearizable, Args: queryArgs, SQL: `WITH decision AS (SELECT ` + status + ` AS status),
	profile AS (SELECT CASE WHEN status=200 THEN (` + identity.UserResponseJSONSQL + `) END AS body FROM decision)
SELECT decision.status,profile.body FROM decision CROSS JOIN profile`})
	if err != nil {
		return UserResponse{}, 0, 0, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return UserResponse{}, 0, 0, errors.New("invalid user detail result")
	}
	code, ok := result.Rows[0][0].(int64)
	if !ok {
		return UserResponse{}, 0, 0, errors.New("invalid user detail decision")
	}
	if code != http.StatusOK {
		return UserResponse{}, 0, int(code), nil
	}
	raw, ok := result.Rows[0][1].(string)
	if !ok {
		return UserResponse{}, 0, 0, errors.New("invalid user detail projection")
	}
	user, changed, err := identity.DecodeUserResponse(raw)
	return user, changed, http.StatusOK, err
}
