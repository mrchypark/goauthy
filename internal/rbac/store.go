// Package rbac persists roles, groups, and their current subject memberships.
package rbac

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/scim"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	AdminRole       = "rauthy_admin"
	maxMemberships  = 64
	maxMetadataSize = 8192
)

var (
	ErrInvalid            = errors.New("invalid RBAC input")
	ErrNotFound           = errors.New("RBAC entity not found")
	ErrConflict           = errors.New("RBAC revision conflict")
	ErrReserved           = errors.New("reserved RBAC role")
	ErrUnauthorized       = errors.New("RBAC administrator required")
	ErrInactiveSubject    = errors.New("inactive RBAC subject")
	ErrTooManyMemberships = errors.New("too many RBAC memberships")
)

var (
	bootstrapClientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	groupPrefixPattern       = regexp.MustCompile(`^[a-zA-Z0-9-_/,:*\s]{2,64}$`)
)

// Entity is an immutable-ID role or group. Revision changes on updates only.
type Entity struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Meta     json.RawMessage `json:"meta,omitempty"`
	Revision int64           `json:"revision"`
}

// Principal contains the live, linearly-read membership snapshot.
type Principal struct {
	Roles    []Entity `json:"roles"`
	Groups   []Entity `json:"groups"`
	Revision int64    `json:"revision"`
}

// BootstrapClientLoginRestriction is the durable, static-client group gate.
// A missing row is unrestricted and has revision zero.
type BootstrapClientLoginRestriction struct {
	ClientID            string  `json:"client_id"`
	RestrictGroupPrefix *string `json:"restrict_group_prefix"`
	Revision            int64   `json:"revision"`
}

type Store struct {
	db                            *rhiza.DB
	now                           func() time.Time
	random                        func([]byte) (int, error)
	beforeMembershipExecute       func()
	beforeLoginRestrictionExecute func()
	apiKeys                       *apikey.Store
}

func NewStore(db *rhiza.DB) *Store {
	return &Store{db: db, now: time.Now, random: rand.Read}
}

// BindAPIKeys enables the explicit API-key administrator methods. It is a
// startup-only seam: browser requests continue to use the existing session
// and CSRF boundary.
func (s *Store) BindAPIKeys(keys *apikey.Store) { s.apiKeys = keys }

func (s *Store) authorize(ctx context.Context, actor string, key *apikey.Principal, group string, right apikey.Right) error {
	if key == nil {
		ok, err := s.IsAdmin(ctx, actor)
		if err != nil {
			return err
		}
		if !ok {
			return ErrUnauthorized
		}
		return nil
	}
	if s.apiKeys == nil {
		return ErrUnauthorized
	}
	if err := s.apiKeys.Authorize(ctx, *key, group, right); err != nil {
		if errors.Is(err, apikey.ErrForbidden) || errors.Is(err, apikey.ErrUnauthorized) {
			return ErrUnauthorized
		}
		return err
	}
	return nil
}

// run keeps the authorization decision and every write in one Rhiza command.
// For an API key, replacing the browser-admin predicate with the durable
// mutation guard prevents a revoked key from committing a stale write.
func (s *Store) run(ctx context.Context, key *apikey.Principal, group string, right apikey.Right, id string, statements []rhiza.SQLStatement) error {
	if key == nil {
		_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: id, Statements: statements})
		return err
	}
	if s.apiKeys == nil {
		return ErrUnauthorized
	}
	guarded := make([]rhiza.SQLStatement, len(statements))
	for i, statement := range statements {
		if index := strings.Index(statement.SQL, adminGuard()); index >= 0 {
			if strings.Count(statement.SQL, adminGuard()) != 1 {
				return ErrInvalid
			}
			// The actor placeholder is not necessarily the final argument: the
			// membership CAS appends entity/change guards after it.
			actorArg := strings.Count(statement.SQL[:index], "?")
			if actorArg >= len(statement.Args) {
				return ErrInvalid
			}
			statement.SQL = strings.Replace(statement.SQL, adminGuard(), "1=1", 1)
			statement.Args = append(statement.Args[:actorArg], statement.Args[actorArg+1:]...)
		}
		statement.SQL += " AND " + apikey.GuardExistsSQL()
		statement.Args = append(statement.Args, id)
		guarded[i] = statement
	}
	_, ok, err := s.apiKeys.RunMutation(ctx, key, group, right, id, guarded)
	if err != nil {
		return err
	}
	if !ok {
		return ErrUnauthorized
	}
	return nil
}

func ValidateRoleName(name string) error  { return validateName(name, false) }
func ValidateGroupName(name string) error { return validateName(name, true) }

// ValidateGroupPrefix preserves Rauthy's published prefix grammar exactly.
// Unlike group names, whitespace is permitted and the raw value is significant.
func ValidateGroupPrefix(prefix string) error {
	if !groupPrefixPattern.MatchString(prefix) {
		return ErrInvalid
	}
	return nil
}

func validateName(name string, group bool) error {
	if len(name) > 128 || len([]rune(name)) < 2 || len([]rune(name)) > 64 {
		return ErrInvalid
	}
	for _, r := range name {
		// Groups deliberately use the same ASCII grammar as claims. In
		// particular, whitespace and backslashes make prefix policies ambiguous.
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_/,:*", r)
		if !group && r == '.' {
			ok = true
		}
		if !ok {
			return ErrInvalid
		}
	}
	return nil
}

func canonicalMeta(meta json.RawMessage) (any, error) {
	if len(meta) == 0 || string(meta) == "null" {
		return nil, nil
	}
	if len(meta) > maxMetadataSize || !json.Valid(meta) {
		return nil, ErrInvalid
	}
	var value any
	if err := json.Unmarshal(meta, &value); err != nil {
		return nil, ErrInvalid
	}
	if value == nil {
		return nil, nil
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > maxMetadataSize {
		return nil, ErrInvalid
	}
	return string(canonical), nil
}

func (s *Store) CreateRole(ctx context.Context, actor, name string, meta json.RawMessage) (Entity, error) {
	return s.create(ctx, actor, nil, "rbac_roles", false, name, meta)
}
func (s *Store) CreateGroup(ctx context.Context, actor, name string, meta json.RawMessage) (Entity, error) {
	return s.create(ctx, actor, nil, "rbac_groups", true, name, meta)
}

func (s *Store) CreateRoleAPIKey(ctx context.Context, key apikey.Principal, name string, meta json.RawMessage) (Entity, error) {
	return s.create(ctx, "", &key, "rbac_roles", false, name, meta)
}
func (s *Store) CreateGroupAPIKey(ctx context.Context, key apikey.Principal, name string, meta json.RawMessage) (Entity, error) {
	return s.create(ctx, "", &key, "rbac_groups", true, name, meta)
}

func (s *Store) create(ctx context.Context, actor string, key *apikey.Principal, table string, group bool, name string, meta json.RawMessage) (Entity, error) {
	if s == nil || s.db == nil || validateName(name, group) != nil || (!group && name == AdminRole) {
		return Entity{}, ErrInvalid
	}
	value, err := canonicalMeta(meta)
	if err != nil {
		return Entity{}, err
	}
	access := apikey.Create
	resource := "Groups"
	if !group {
		resource = "Roles"
	}
	if err := s.authorize(ctx, actor, key, resource, access); err != nil {
		return Entity{}, err
	}
	id, err := s.randomID()
	if err != nil {
		return Entity{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond).UnixMilli()
	requestID := requestID("rbac-create", table, actor, id, name, metaKey(value))
	executeErr := s.run(ctx, key, resource, access, requestID, []rhiza.SQLStatement{{SQL: fmt.Sprintf(`INSERT INTO %s (id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms)
		SELECT ?,?,?,1,?,? WHERE %s`, table, adminGuard()), Args: []any{id, name, value, now, now, actor}}})
	entity, found, loadErr := s.get(ctx, table, id)
	if loadErr != nil {
		return Entity{}, loadErr
	}
	if found && entity.Name == name && equalMeta(entity.Meta, value) {
		return entity, nil
	}
	if found {
		return Entity{}, ErrConflict
	}
	if existing, exists, err := s.getByName(ctx, table, name); err != nil {
		return Entity{}, err
	} else if exists {
		_ = existing
		return Entity{}, ErrConflict
	}
	if executeErr != nil {
		return Entity{}, executeErr
	}
	return Entity{}, ErrUnauthorized
}

func (s *Store) ListRoles(ctx context.Context) ([]Entity, error)  { return s.list(ctx, "rbac_roles") }
func (s *Store) ListGroups(ctx context.Context) ([]Entity, error) { return s.list(ctx, "rbac_groups") }
func (s *Store) ListRolesForAdmin(ctx context.Context, actor string) ([]Entity, error) {
	return s.listForAdmin(ctx, actor, "rbac_roles")
}
func (s *Store) ListGroupsForAdmin(ctx context.Context, actor string) ([]Entity, error) {
	return s.listForAdmin(ctx, actor, "rbac_groups")
}
func (s *Store) ListRolesAPIKey(ctx context.Context, key apikey.Principal) ([]Entity, error) {
	if err := s.authorize(ctx, "", &key, "Roles", apikey.Read); err != nil {
		return nil, err
	}
	return s.list(ctx, "rbac_roles")
}
func (s *Store) ListGroupsAPIKey(ctx context.Context, key apikey.Principal) ([]Entity, error) {
	if err := s.authorize(ctx, "", &key, "Groups", apikey.Read); err != nil {
		return nil, err
	}
	return s.list(ctx, "rbac_groups")
}
func (s *Store) GetRole(ctx context.Context, id string) (Entity, error) {
	return s.getPublic(ctx, "rbac_roles", id)
}
func (s *Store) GetGroup(ctx context.Context, id string) (Entity, error) {
	return s.getPublic(ctx, "rbac_groups", id)
}
func (s *Store) GetRoleForAdmin(ctx context.Context, actor, id string) (Entity, error) {
	return s.getForAdmin(ctx, actor, "rbac_roles", id)
}
func (s *Store) GetGroupForAdmin(ctx context.Context, actor, id string) (Entity, error) {
	return s.getForAdmin(ctx, actor, "rbac_groups", id)
}
func (s *Store) GetRoleAPIKey(ctx context.Context, key apikey.Principal, id string) (Entity, error) {
	if err := s.authorize(ctx, "", &key, "Roles", apikey.Read); err != nil {
		return Entity{}, err
	}
	return s.GetRole(ctx, id)
}
func (s *Store) GetGroupAPIKey(ctx context.Context, key apikey.Principal, id string) (Entity, error) {
	if err := s.authorize(ctx, "", &key, "Groups", apikey.Read); err != nil {
		return Entity{}, err
	}
	return s.GetGroup(ctx, id)
}

func (s *Store) list(ctx context.Context, table string) ([]Entity, error) {
	if s == nil || s.db == nil {
		return nil, ErrInvalid
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: fmt.Sprintf(`SELECT id,name,meta_json,revision FROM %s ORDER BY name,id`, table), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) > 1024 {
		return nil, ErrInvalid
	}
	entities := make([]Entity, 0, len(result.Rows))
	for _, row := range result.Rows {
		entity, err := rowEntity(row)
		if err != nil {
			return nil, err
		}
		entities = append(entities, entity)
	}
	return entities, nil
}
func (s *Store) listForAdmin(ctx context.Context, actor, table string) ([]Entity, error) {
	if s == nil || s.db == nil || !validSubject(actor) {
		return nil, ErrUnauthorized
	}
	// The sentinel makes an empty authorized list distinguishable from a
	// revoked actor, within the same linearizable read.
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: fmt.Sprintf(`WITH authorized AS (SELECT 1 WHERE %s)
		SELECT 0 AS kind, '' AS id, '' AS name, NULL AS meta_json, 0 AS revision FROM authorized
		UNION ALL
		SELECT 1, id, name, meta_json, revision FROM %s WHERE EXISTS (SELECT 1 FROM authorized)
		ORDER BY kind, name, id`, adminGuard(), table), Args: []any{actor}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, ErrUnauthorized
	}
	entities := make([]Entity, 0, len(result.Rows)-1)
	for index, row := range result.Rows {
		if len(row) != 5 {
			return nil, ErrInvalid
		}
		kind, ok := row[0].(int64)
		if !ok || (index == 0 && kind != 0) || (index > 0 && kind != 1) {
			return nil, ErrInvalid
		}
		if index == 0 {
			continue
		}
		entity, err := rowEntity(row[1:])
		if err != nil {
			return nil, err
		}
		entities = append(entities, entity)
	}
	return entities, nil
}
func (s *Store) getForAdmin(ctx context.Context, actor, table, id string) (Entity, error) {
	if s == nil || s.db == nil || !validSubject(actor) || id == "" || len(id) > 64 {
		return Entity{}, ErrUnauthorized
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: fmt.Sprintf(`WITH authorized AS (SELECT 1 WHERE %s)
		SELECT 0 AS kind, '' AS id, '' AS name, NULL AS meta_json, 0 AS revision FROM authorized
		UNION ALL
		SELECT 1, id, name, meta_json, revision FROM %s WHERE id=? AND EXISTS (SELECT 1 FROM authorized)
		ORDER BY kind`, adminGuard(), table), Args: []any{actor, id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Entity{}, err
	}
	if len(result.Rows) == 0 {
		return Entity{}, ErrUnauthorized
	}
	if len(result.Rows) == 1 {
		return Entity{}, ErrNotFound
	}
	if len(result.Rows) != 2 || result.Rows[0][0] != int64(0) || result.Rows[1][0] != int64(1) {
		return Entity{}, ErrInvalid
	}
	return rowEntity(result.Rows[1][1:])
}
func (s *Store) getPublic(ctx context.Context, table, id string) (Entity, error) {
	entity, found, err := s.get(ctx, table, id)
	if err != nil {
		return Entity{}, err
	}
	if !found {
		return Entity{}, ErrNotFound
	}
	return entity, nil
}
func (s *Store) get(ctx context.Context, table, id string) (Entity, bool, error) {
	if s == nil || s.db == nil || id == "" || len(id) > 64 {
		return Entity{}, false, ErrInvalid
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: fmt.Sprintf(`SELECT id,name,meta_json,revision FROM %s WHERE id=?`, table), Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Entity{}, false, err
	}
	if len(result.Rows) == 0 {
		return Entity{}, false, nil
	}
	if len(result.Rows) != 1 {
		return Entity{}, false, ErrInvalid
	}
	entity, err := rowEntity(result.Rows[0])
	return entity, err == nil, err
}
func (s *Store) getByName(ctx context.Context, table, name string) (Entity, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: fmt.Sprintf(`SELECT id,name,meta_json,revision FROM %s WHERE name=?`, table), Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Entity{}, false, err
	}
	if len(result.Rows) == 0 {
		return Entity{}, false, nil
	}
	if len(result.Rows) != 1 {
		return Entity{}, false, ErrInvalid
	}
	entity, err := rowEntity(result.Rows[0])
	return entity, err == nil, err
}
func rowEntity(row []any) (Entity, error) {
	if len(row) != 4 {
		return Entity{}, ErrInvalid
	}
	id, a := row[0].(string)
	name, b := row[1].(string)
	revision, c := row[3].(int64)
	if !a || !b || !c || revision < 1 {
		return Entity{}, ErrInvalid
	}
	entity := Entity{ID: id, Name: name, Revision: revision}
	if row[2] != nil {
		meta, ok := row[2].(string)
		if !ok || !json.Valid([]byte(meta)) {
			return Entity{}, ErrInvalid
		}
		entity.Meta = json.RawMessage(meta)
	}
	return entity, nil
}

func (s *Store) UpdateRole(ctx context.Context, actor, id string, revision int64, name string, meta json.RawMessage) (Entity, error) {
	return s.update(ctx, actor, nil, "rbac_roles", false, id, revision, name, meta)
}
func (s *Store) UpdateGroup(ctx context.Context, actor, id string, revision int64, name string, meta json.RawMessage) (Entity, error) {
	return s.update(ctx, actor, nil, "rbac_groups", true, id, revision, name, meta)
}
func (s *Store) UpdateRoleAPIKey(ctx context.Context, key apikey.Principal, id string, revision int64, name string, meta json.RawMessage) (Entity, error) {
	return s.update(ctx, "", &key, "rbac_roles", false, id, revision, name, meta)
}
func (s *Store) UpdateGroupAPIKey(ctx context.Context, key apikey.Principal, id string, revision int64, name string, meta json.RawMessage) (Entity, error) {
	return s.update(ctx, "", &key, "rbac_groups", true, id, revision, name, meta)
}
func (s *Store) update(ctx context.Context, actor string, key *apikey.Principal, table string, group bool, id string, revision int64, name string, meta json.RawMessage) (Entity, error) {
	if s == nil || s.db == nil || id == "" || revision < 1 || validateName(name, group) != nil {
		return Entity{}, ErrInvalid
	}
	value, err := canonicalMeta(meta)
	if err != nil {
		return Entity{}, err
	}
	resource := "Groups"
	if !group {
		resource = "Roles"
	}
	if err := s.authorize(ctx, actor, key, resource, apikey.Update); err != nil {
		return Entity{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond).UnixMilli()
	reserved := ""
	if !group {
		reserved = ` AND name <> 'rauthy_admin'`
	}
	members, column := "rbac_user_groups", "group_id"
	if !group {
		members, column = "rbac_user_roles", "role_id"
	}
	requestID := requestID("rbac-update", table, actor, id, fmt.Sprint(revision), name, metaKey(value))
	executeErr := s.run(ctx, key, resource, apikey.Update, requestID, []rhiza.SQLStatement{
		{SQL: fmt.Sprintf(`UPDATE rbac_principal_versions SET revision=revision+1,updated_at_unix_ms=? WHERE subject IN (SELECT subject FROM %s WHERE %s=?) AND EXISTS (SELECT 1 FROM %s WHERE id=? AND revision=?%s AND name<>?) AND %s`, members, column, table, reserved, adminGuard()), Args: []any{now, id, id, revision, name, actor}},
		{SQL: fmt.Sprintf(`UPDATE %s SET name=?,meta_json=?,revision=revision+1,updated_at_unix_ms=? WHERE id=? AND revision=?%s AND %s`, table, reserved, adminGuard()), Args: []any{name, value, now, id, revision, actor}},
	})
	entity, found, loadErr := s.get(ctx, table, id)
	if loadErr != nil {
		return Entity{}, loadErr
	}
	if found && entity.Revision == revision+1 && entity.Name == name && equalMeta(entity.Meta, value) {
		return entity, nil
	}
	if found && !group && entity.Name == AdminRole {
		return Entity{}, ErrReserved
	}
	if !found {
		return Entity{}, ErrNotFound
	}
	if owner, exists, err := s.getByName(ctx, table, name); err != nil {
		return Entity{}, err
	} else if exists && owner.ID != id {
		return Entity{}, ErrConflict
	}
	if executeErr != nil {
		return Entity{}, executeErr
	}
	return Entity{}, ErrConflict
}

func (s *Store) DeleteRole(ctx context.Context, actor, id string, revision int64) error {
	return s.delete(ctx, actor, nil, "rbac_roles", "rbac_user_roles", "role_id", true, id, revision)
}
func (s *Store) DeleteGroup(ctx context.Context, actor, id string, revision int64) error {
	return s.delete(ctx, actor, nil, "rbac_groups", "rbac_user_groups", "group_id", false, id, revision)
}
func (s *Store) DeleteRoleAPIKey(ctx context.Context, key apikey.Principal, id string, revision int64) error {
	return s.delete(ctx, "", &key, "rbac_roles", "rbac_user_roles", "role_id", true, id, revision)
}
func (s *Store) DeleteGroupAPIKey(ctx context.Context, key apikey.Principal, id string, revision int64) error {
	return s.delete(ctx, "", &key, "rbac_groups", "rbac_user_groups", "group_id", false, id, revision)
}
func (s *Store) delete(ctx context.Context, actor string, key *apikey.Principal, table, members, column string, role bool, id string, revision int64) error {
	if s == nil || s.db == nil || id == "" || revision < 1 {
		return ErrInvalid
	}
	resource := "Groups"
	if role {
		resource = "Roles"
	}
	if err := s.authorize(ctx, actor, key, resource, apikey.Delete); err != nil {
		return err
	}
	reserved := ""
	if role {
		reserved = ` AND name <> 'rauthy_admin'`
	}
	guard := fmt.Sprintf(`EXISTS (SELECT 1 FROM %s WHERE id=? AND revision=?%s) AND %s`, table, reserved, adminGuard())
	now := s.now().UTC().Truncate(time.Millisecond).UnixMilli()
	requestID := requestID("rbac-delete", table, actor, id, fmt.Sprint(revision))
	statements := []rhiza.SQLStatement{{SQL: fmt.Sprintf(`UPDATE rbac_principal_versions SET revision=revision+1,updated_at_unix_ms=? WHERE subject IN (SELECT subject FROM %s WHERE %s=?) AND %s`, members, column, guard), Args: []any{now, id, id, revision, actor}}, {SQL: fmt.Sprintf(`DELETE FROM %s WHERE %s=? AND %s`, members, column, guard), Args: []any{id, id, revision, actor}}}
	// Roles and groups both project as SCIM groups, and a queued projection is
	// the durable evidence that a remote group exists. Superseding it with a
	// provider-scoped delete in this same transaction is what keeps a local
	// removal from leaving the remote group and its memberships behind.
	// The entity row still exists here, so this precedes its delete.
	projection, err := s.scimProjectionRemoval(ctx, role, id, guard, []any{id, revision, actor}, time.UnixMilli(now).UTC())
	if err != nil {
		return err
	}
	if projection != nil {
		statements = append(statements, *projection)
	}
	statements = append(statements, rhiza.SQLStatement{SQL: fmt.Sprintf(`DELETE FROM %s WHERE id=? AND revision=?%s AND %s`, table, reserved, adminGuard()), Args: []any{id, revision, actor}})
	executeErr := s.run(ctx, key, resource, apikey.Delete, requestID, statements)
	entity, found, loadErr := s.get(ctx, table, id)
	if loadErr != nil {
		return loadErr
	}
	if !found {
		return nil
	}
	if role && entity.Name == AdminRole {
		return ErrReserved
	}
	if executeErr != nil {
		return executeErr
	}
	return ErrConflict
}

// scimProjectionRemoval returns the statement that supersedes the queued SCIM
// projection of a removed group or role with a provider-scoped delete. The
// queued row is the only source of an already accepted display name, and its
// absence means the entity was never projected to any provider, so there is
// nothing to remove remotely.
func (s *Store) scimProjectionRemoval(ctx context.Context, role bool, id, guard string, guardArgs []any, now time.Time) (*rhiza.SQLStatement, error) {
	kind := "group"
	if role {
		kind = "role"
	}
	externalID := identity.SCIMGroupExternalID(kind, id)
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT json_extract(request_json,'$.group.displayName') FROM scim_user_outbox WHERE json_type(request_json,'$.group')='object' AND json_extract(request_json,'$.group.externalId')=? LIMIT 1`, Args: []any{externalID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return nil, ErrInvalid
	}
	displayName, ok := result.Rows[0][0].(string)
	if !ok {
		return nil, ErrInvalid
	}
	statement, err := scim.SupersedeGroupProjection(externalID, displayName, guard, guardArgs, now)
	if err != nil {
		return nil, err
	}
	return &statement, nil
}

func (s *Store) EnsureBootstrapPrincipal(ctx context.Context, subject string, roles, groups []string) (Principal, error) {
	if s == nil || s.db == nil || !validSubject(subject) {
		return Principal{}, ErrInvalid
	}
	var err error
	if roles, err = canonicalNames(roles, false); err != nil {
		return Principal{}, err
	}
	if !containsName(roles, AdminRole) {
		roles = append(roles, AdminRole)
		sort.Strings(roles)
	}
	if groups, err = canonicalNames(groups, true); err != nil {
		return Principal{}, err
	}
	// Bootstrap is submitted independently by every replica. Keep the command
	// byte-identical so Rhiza can deduplicate it instead of materializing one
	// logically equivalent mutation per pod.
	const now int64 = 0
	stmts := make([]rhiza.SQLStatement, 0, len(roles)+len(groups)+4)
	requestParts := []string{"rbac-bootstrap", subject, strings.Join(roles, "\x00"), strings.Join(groups, "\x00")}
	for _, name := range roles {
		id := bootstrapID("role", name)
		stmts = append(stmts, rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO rbac_roles (id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) SELECT ?, ?, NULL, 1, ?, ? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)`, Args: []any{id, name, now, now, subject}})
	}
	for _, name := range groups {
		id := bootstrapID("group", name)
		stmts = append(stmts, rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO rbac_groups (id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) SELECT ?, ?, NULL, 1, ?, ? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)`, Args: []any{id, name, now, now, subject}})
	}
	stmts = append(stmts, rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) SELECT ?,1,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)`, Args: []any{subject, now, subject}})
	roleNames := namesPlaceholders(roles)
	groupNames := namesPlaceholders(groups)
	missing := fmt.Sprintf(`EXISTS (SELECT 1 FROM rbac_roles r WHERE r.name IN (%s) AND NOT EXISTS (SELECT 1 FROM rbac_user_roles m WHERE m.subject=? AND m.role_id=r.id)) OR EXISTS (SELECT 1 FROM rbac_groups g WHERE g.name IN (%s) AND NOT EXISTS (SELECT 1 FROM rbac_user_groups m WHERE m.subject=? AND m.group_id=g.id))`, roleNames, groupNames)
	missingArgs := append(stringsAny(roles), subject)
	missingArgs = append(missingArgs, stringsAny(groups)...)
	missingArgs = append(missingArgs, subject)
	bootstrapUpdate := `UPDATE rbac_principal_versions SET revision=revision+1,updated_at_unix_ms=? WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0) AND (` + missing + `)`
	stmts = append(stmts, rhiza.SQLStatement{SQL: bootstrapUpdate, Args: append([]any{now, subject, subject}, missingArgs...)})
	for _, name := range roles {
		stmts = append(stmts, rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) SELECT ?,id,? FROM rbac_roles WHERE name=? AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)`, Args: []any{subject, now, name, subject}})
	}
	for _, name := range groups {
		stmts = append(stmts, rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO rbac_user_groups (subject,group_id,granted_at_unix_ms) SELECT ?,id,? FROM rbac_groups WHERE name=? AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)`, Args: []any{subject, now, name, subject}})
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID(requestParts...), Statements: stmts}); err != nil {
		return Principal{}, err
	}
	principal, err := s.ResolvePrincipal(ctx, subject)
	return principal, err
}

// PatchPrincipal applies the role/group portion of Rauthy's user PATCH
// operation. It reads one revision, then uses that revision as a one-shot CAS
// inside the Rhiza command; a concurrent membership change is a conflict, not
// an unbounded retry.
func (s *Store) PatchPrincipal(ctx context.Context, actor, target string, roles, groups []string, replaceRoles, replaceGroups bool) (Principal, error) {
	return s.patchPrincipal(ctx, actor, nil, target, roles, groups, replaceRoles, replaceGroups)
}
func (s *Store) PatchPrincipalAPIKey(ctx context.Context, key apikey.Principal, target string, roles, groups []string, replaceRoles, replaceGroups bool) (Principal, error) {
	return s.patchPrincipal(ctx, "", &key, target, roles, groups, replaceRoles, replaceGroups)
}
func (s *Store) patchPrincipal(ctx context.Context, actor string, key *apikey.Principal, target string, roles, groups []string, replaceRoles, replaceGroups bool) (Principal, error) {
	if s == nil || s.db == nil || !validSubject(actor) || !validSubject(target) {
		if key == nil || s == nil || s.db == nil || !validSubject(target) {
			return Principal{}, ErrInvalid
		}
	}
	delegated := false
	if key == nil {
		var err error
		delegated, err = s.isDelegatedAdmin(ctx, actor)
		if err != nil {
			return Principal{}, err
		}
		if !delegated {
			if err := s.authorize(ctx, actor, nil, "Users", apikey.Update); err != nil {
				return Principal{}, err
			}
		}
	} else if err := s.authorize(ctx, actor, key, "Users", apikey.Update); err != nil {
		return Principal{}, err
	}
	if replaceRoles {
		var err error
		if roles, err = canonicalNames(roles, false); err != nil {
			return Principal{}, err
		}
	}
	if replaceGroups {
		var err error
		if groups, err = canonicalNames(groups, true); err != nil {
			return Principal{}, err
		}
	}
	var targetPrincipal Principal
	var err error
	if key == nil {
		actorPrincipal, resolveErr := s.ResolvePrincipal(ctx, actor)
		if resolveErr != nil {
			if errors.Is(resolveErr, ErrInactiveSubject) {
				return Principal{}, ErrUnauthorized
			}
			return Principal{}, resolveErr
		}
		if !containsName(entityNames(actorPrincipal.Roles), AdminRole) && !delegated {
			return Principal{}, ErrUnauthorized
		}
		if containsName(entityNames(actorPrincipal.Roles), AdminRole) {
			delegated = false
		}
	}
	targetPrincipal, err = s.ResolvePrincipal(ctx, target)
	if err != nil {
		return Principal{}, err
	}
	if !replaceRoles {
		roles = entityNames(targetPrincipal.Roles)
	}
	if !replaceGroups {
		groups = entityNames(targetPrincipal.Groups)
	}
	if delegated {
		if replaceRoles || delegatedAdminTarget(targetPrincipal.Roles) {
			return Principal{}, ErrUnauthorized
		}
		managed, err := s.managedGroups(ctx, actor)
		if err != nil {
			return Principal{}, err
		}
		if replaceGroups {
			current := make(map[string]struct{}, len(targetPrincipal.Groups))
			for _, group := range targetPrincipal.Groups {
				current[group.Name] = struct{}{}
			}
			requested := make(map[string]struct{}, len(groups))
			for _, group := range groups {
				requested[group] = struct{}{}
				if !managed(group) {
					if _, exists := current[group]; !exists {
						return Principal{}, ErrUnauthorized
					}
				}
			}
			for group := range current {
				if !managed(group) {
					if _, exists := requested[group]; exists {
						continue
					}
					groups = append(groups, group)
				}
			}
			var sortErr error
			groups, sortErr = canonicalNames(groups, true)
			if sortErr != nil {
				return Principal{}, sortErr
			}
		}
	}
	if equalNames(targetPrincipal.Roles, roles) && equalNames(targetPrincipal.Groups, groups) {
		return targetPrincipal, nil
	}
	if err := s.ensureMembershipEntities(ctx, roles, groups); err != nil {
		return Principal{}, err
	}
	if replaceRoles && !containsName(roles, AdminRole) && s.isLastActiveAdmin(ctx, target) {
		return Principal{}, ErrConflict
	}
	return s.replaceMembershipsMode(ctx, actor, key, target, targetPrincipal.Revision, roles, groups, replaceRoles, replaceGroups, delegated)
}

func (s *Store) replaceMemberships(ctx context.Context, actor string, key *apikey.Principal, target string, expected int64, roles, groups []string, replaceRoles, replaceGroups bool) (Principal, error) {
	delegated := false
	if key == nil {
		delegated, _ = s.isDelegatedAdmin(ctx, actor)
	}
	return s.replaceMembershipsMode(ctx, actor, key, target, expected, roles, groups, replaceRoles, replaceGroups, delegated)
}

func (s *Store) replaceMembershipsMode(ctx context.Context, actor string, key *apikey.Principal, target string, expected int64, roles, groups []string, replaceRoles, replaceGroups, delegated bool) (Principal, error) {
	now := s.now().UTC().Truncate(time.Millisecond).UnixMilli()
	oldMarker, found, err := s.principalMarker(ctx, target)
	if err != nil {
		return Principal{}, err
	}
	if found && expected != oldMarker.revision {
		return Principal{}, ErrConflict
	}
	if !found {
		if expected != 1 {
			return Principal{}, ErrConflict
		}
		oldMarker.updatedAt = now
	}
	attempt, err := s.randomID()
	if err != nil {
		return Principal{}, err
	}
	newMarker := now
	if newMarker <= oldMarker.updatedAt {
		newMarker = oldMarker.updatedAt + 1
	}
	guard, guardArgs := membershipGuard(actor, key != nil, target, roles, groups, replaceRoles, replaceGroups, delegated)
	change, changeArgs := membershipChangeGuard(target, roles, groups, replaceRoles, replaceGroups)
	lastAdmin, lastAdminArgs := lastAdminGuard(target, roles, replaceRoles, now)
	authGuard, authArgs := membershipAuthorizationGuard(actor, key != nil, target, groups, replaceRoles, replaceGroups, delegated)
	one := int64(1)
	statements := []rhiza.SQLStatement{{
		SQL: `INSERT OR IGNORE INTO rbac_principal_versions (subject,revision,updated_at_unix_ms)
			SELECT ?,1,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0) AND ` + authGuard,
		Args: append([]any{target, oldMarker.updatedAt, target}, authArgs...),
	}, {
		SQL: `UPDATE rbac_principal_versions SET revision=revision+1,updated_at_unix_ms=?
			WHERE subject=? AND revision=? AND updated_at_unix_ms=? AND ` + guard + ` AND (` + change + `) AND ` + lastAdmin,
		Args: append(append(append([]any{newMarker, target, expected, oldMarker.updatedAt}, guardArgs...), changeArgs...), lastAdminArgs...),
		// This CAS is the admission for the membership statements that follow.
		// A predicted revision/marker alone cannot identify the admitted
		// operation: two callers holding the same snapshot compute the same
		// pair, so the loser would match the winner's row and rewrite
		// memberships from its stale snapshot. Requiring one affected row
		// rejects the whole command when admission is lost.
		ExpectedRowsAffected: &one,
	}}
	if replaceRoles {
		statements = append(statements, membershipStatements("rbac_roles", "rbac_user_roles", "role_id", target, expected+1, newMarker, roles, now)...)
	}
	if replaceGroups {
		statements = append(statements, membershipStatements("rbac_groups", "rbac_user_groups", "group_id", target, expected+1, newMarker, groups, now)...)
	}
	if s.beforeMembershipExecute != nil {
		s.beforeMembershipExecute()
	}
	id := requestID("rbac-membership", actor, target, fmt.Sprint(expected), strings.Join(roles, "\x00"), strings.Join(groups, "\x00"), fmt.Sprint(replaceRoles), fmt.Sprint(replaceGroups), attempt)
	err = s.run(ctx, key, "Users", apikey.Update, id, statements)
	// A rejected admission precondition is a lost CAS, so fall through to the
	// post-commit checks: they keep reporting a stale snapshot as a conflict and
	// a caller whose authority was removed as unauthorized.
	if err != nil && !admissionRejected(err) {
		return Principal{}, err
	}
	principal, err := s.ResolvePrincipal(ctx, target)
	if err != nil {
		return Principal{}, err
	}
	if delegated && delegatedAdminTarget(principal.Roles) {
		return Principal{}, ErrUnauthorized
	}
	if principal.Revision == expected+1 && equalNames(principal.Roles, roles) && equalNames(principal.Groups, groups) {
		return principal, nil
	}
	if key != nil {
		if err := s.authorize(ctx, actor, key, "Users", apikey.Update); err != nil {
			return Principal{}, ErrUnauthorized
		}
	} else {
		admin, adminErr := s.IsAdmin(ctx, actor)
		delegatedNow, delegatedErr := s.isDelegatedAdmin(ctx, actor)
		if adminErr != nil || delegatedErr != nil || (!admin && !delegatedNow) {
			return Principal{}, ErrUnauthorized
		}
	}
	if err := s.ensureMembershipEntities(ctx, roles, groups); err != nil {
		return Principal{}, err
	}
	if replaceRoles && !containsName(roles, AdminRole) && s.isLastActiveAdmin(ctx, target) {
		return Principal{}, ErrConflict
	}
	return Principal{}, ErrConflict
}

func membershipGuard(actor string, api bool, target string, roles, groups []string, replaceRoles, replaceGroups, delegated bool) (string, []any) {
	parts := []string{`EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)`}
	args := []any{target}
	auth, authArgs := membershipAuthorizationGuard(actor, api, target, groups, replaceRoles, replaceGroups, delegated)
	parts, args = append(parts, auth), append(args, authArgs...)
	if replaceRoles {
		guard, values := namesGuard("rbac_roles", roles)
		parts, args = append(parts, guard), append(args, values...)
	}
	if replaceGroups {
		guard, values := namesGuard("rbac_groups", groups)
		parts, args = append(parts, guard), append(args, values...)
	}
	return strings.Join(parts, " AND "), args
}

func membershipAuthorizationGuard(actor string, api bool, target string, groups []string, replaceRoles, replaceGroups, delegated bool) (string, []any) {
	if api || !delegated {
		return adminGuard(), []any{actor}
	}
	delegatedGuard, args := delegatedMembershipGuard(actor, target, groups, replaceRoles, replaceGroups)
	return "(" + adminGuard() + " OR (" + delegatedGuard + "))", append([]any{actor}, args...)
}

func delegatedMembershipGuard(actor, target string, groups []string, replaceRoles, replaceGroups bool) (string, []any) {
	parts := []string{
		`EXISTS (SELECT 1 FROM identity_users au JOIN rbac_user_roles am ON am.subject=au.subject JOIN rbac_roles ar ON ar.id=am.role_id WHERE au.subject=? AND au.disabled=0 AND substr(ar.name,1,13)='rauthy_admin:')`,
		`NOT EXISTS (SELECT 1 FROM rbac_user_roles tm JOIN rbac_roles tr ON tr.id=tm.role_id WHERE tm.subject=? AND (tr.name='rauthy_admin' OR substr(tr.name,1,13)='rauthy_admin:'))`,
	}
	args := []any{actor, target}
	if replaceRoles {
		parts = append(parts, "0=1")
	}
	if replaceGroups {
		placeholders := namesPlaceholders(groups)
		parts = append(parts, fmt.Sprintf(`NOT EXISTS (
			SELECT 1 FROM rbac_groups dg
			WHERE dg.name IN (%s)
			AND NOT EXISTS (SELECT 1 FROM rbac_user_groups dm WHERE dm.subject=? AND dm.group_id=dg.id)
			AND NOT EXISTS (
				SELECT 1 FROM rbac_user_roles am JOIN rbac_roles ar ON ar.id=am.role_id
				JOIN identity_users au ON au.subject=am.subject
				WHERE am.subject=? AND au.disabled=0 AND substr(ar.name,1,13)='rauthy_admin:'
				AND (ar.name='rauthy_admin:*' OR
					(substr(ar.name,-1)='*' AND substr(dg.name,1,length(ar.name)-14)=substr(ar.name,14,length(ar.name)-14)) OR
					(substr(ar.name,-1)<>'*' AND substr(ar.name,14)=dg.name))
			)
		)`, placeholders))
		args = append(args, stringsAny(groups)...)
		args = append(args, target, actor)
	}
	return strings.Join(parts, " AND "), args
}

func membershipChangeGuard(target string, roles, groups []string, replaceRoles, replaceGroups bool) (string, []any) {
	var parts []string
	var args []any
	if replaceRoles {
		part, values := membershipChanged("rbac_roles", "rbac_user_roles", "role_id", target, roles)
		parts, args = append(parts, part), append(args, values...)
	}
	if replaceGroups {
		part, values := membershipChanged("rbac_groups", "rbac_user_groups", "group_id", target, groups)
		parts, args = append(parts, part), append(args, values...)
	}
	return strings.Join(parts, " OR "), args
}

func membershipChanged(entities, members, column, target string, names []string) (string, []any) {
	placeholders := namesPlaceholders(names)
	return fmt.Sprintf(`EXISTS (SELECT 1 FROM %s m WHERE m.subject=? AND m.%s NOT IN (SELECT id FROM %s WHERE name IN (%s))) OR EXISTS (SELECT 1 FROM %s e WHERE e.name IN (%s) AND NOT EXISTS (SELECT 1 FROM %s m WHERE m.subject=? AND m.%s=e.id))`, members, column, entities, placeholders, entities, placeholders, members, column), append(append([]any{target}, stringsAny(names)...), append(stringsAny(names), target)...)
}

func membershipStatements(entities, members, column, target string, revision, marker int64, names []string, now int64) []rhiza.SQLStatement {
	placeholders := namesPlaceholders(names)
	// The version/marker pair is set by the guarded statement immediately
	// before these statements. Do not re-evaluate adminGuard here: an admin may
	// intentionally remove their own admin role while another active admin
	// remains, and all requested memberships must still commit atomically.
	versionGuard := `EXISTS (SELECT 1 FROM rbac_principal_versions WHERE subject=? AND revision=? AND updated_at_unix_ms=?)`
	deleteArgs := append([]any{target}, stringsAny(names)...)
	deleteArgs = append(deleteArgs, target, revision, marker)
	insertArgs := append([]any{target, now}, stringsAny(names)...)
	insertArgs = append(insertArgs, target, revision, marker)
	return []rhiza.SQLStatement{
		{SQL: fmt.Sprintf(`DELETE FROM %s WHERE subject=? AND %s NOT IN (SELECT id FROM %s WHERE name IN (%s)) AND %s`, members, column, entities, placeholders, versionGuard), Args: deleteArgs},
		{SQL: fmt.Sprintf(`INSERT OR IGNORE INTO %s (subject,%s,granted_at_unix_ms) SELECT ?,id,? FROM %s WHERE name IN (%s) AND %s`, members, column, entities, placeholders, versionGuard), Args: insertArgs},
	}
}

type principalVersionMarker struct {
	revision  int64
	updatedAt int64
}

func (s *Store) principalMarker(ctx context.Context, subject string) (principalVersionMarker, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT revision,updated_at_unix_ms FROM rbac_principal_versions WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return principalVersionMarker{}, false, err
	}
	if len(result.Rows) == 0 {
		return principalVersionMarker{}, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return principalVersionMarker{}, false, ErrInvalid
	}
	revision, first := result.Rows[0][0].(int64)
	updatedAt, second := result.Rows[0][1].(int64)
	if !first || !second || revision < 1 || updatedAt < 0 {
		return principalVersionMarker{}, false, ErrInvalid
	}
	return principalVersionMarker{revision: revision, updatedAt: updatedAt}, true, nil
}

// lastAdminGuard protects the final usable administrator. Expired accounts are
// not usable for authentication, so an unswept expired administrator must not
// count here, and demoting one is not a loss of administrative access.
func lastAdminGuard(target string, roles []string, replaceRoles bool, now int64) (string, []any) {
	if !replaceRoles || containsName(roles, AdminRole) {
		return "1=1", nil
	}
	return `NOT (EXISTS (SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id WHERE r.name='rauthy_admin' AND u.subject=? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?)) AND (SELECT COUNT(DISTINCT u.subject) FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id WHERE u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?) AND r.name='rauthy_admin')=1)`, []any{target, now, now}
}

func (s *Store) ensureMembershipEntities(ctx context.Context, roles, groups []string) error {
	for _, name := range roles {
		if _, found, err := s.getByName(ctx, "rbac_roles", name); err != nil {
			return err
		} else if !found {
			return ErrNotFound
		}
	}
	for _, name := range groups {
		if _, found, err := s.getByName(ctx, "rbac_groups", name); err != nil {
			return err
		} else if !found {
			return ErrNotFound
		}
	}
	return nil
}

func (s *Store) isLastActiveAdmin(ctx context.Context, target string) bool {
	now := s.now().UTC().Truncate(time.Millisecond).UnixMilli()
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(DISTINCT u.subject) FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id WHERE u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?) AND r.name='rauthy_admin' AND EXISTS (SELECT 1 FROM identity_users tu JOIN rbac_user_roles tm ON tm.subject=tu.subject JOIN rbac_roles tr ON tr.id=tm.role_id WHERE tu.subject=? AND tu.disabled=0 AND (tu.user_expires_at_unix_ms IS NULL OR tu.user_expires_at_unix_ms>?) AND tr.name='rauthy_admin')`, Args: []any{now, target, now}, Consistency: rhiza.ConsistencyLinearizable})
	return err == nil && len(result.Rows) == 1 && len(result.Rows[0]) == 1 && result.Rows[0][0] == int64(1)
}

// admissionRejected reports whether a mutation was rejected because a
// statement precondition was not satisfied. Rhiza rolls such a command back
// completely, so only the admission CAS can report this after a membership
// attempt.
func admissionRejected(err error) bool {
	return err != nil && strings.Contains(err.Error(), "error_code="+string(rhiza.MutationErrorCodePreconditionFailed))
}

func entityNames(entities []Entity) []string {
	names := make([]string, len(entities))
	for i, entity := range entities {
		names[i] = entity.Name
	}
	return names
}

func (s *Store) ResolvePrincipal(ctx context.Context, subject string) (Principal, error) {
	if s == nil || s.db == nil || !validSubject(subject) {
		return Principal{}, ErrInvalid
	}
	// One linearizable query prevents a principal revision from being paired with
	// memberships from a different replicated state.
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `WITH active AS (
		SELECT 1 AS ok FROM identity_users WHERE subject=? AND disabled=0
	), rows AS (
		SELECT 0 AS kind, '' AS id, '' AS name, NULL AS meta_json,
			COALESCE((SELECT revision FROM rbac_principal_versions WHERE subject=?), 1) AS revision
		FROM active
		UNION ALL
		SELECT 1, id, name, meta_json, revision FROM (
			SELECT e.id,e.name,e.meta_json,e.revision FROM active
			JOIN rbac_user_roles m ON 1=1 JOIN rbac_roles e ON e.id=m.role_id
			WHERE m.subject=? ORDER BY e.name,e.id LIMIT 65
		)
		UNION ALL
		SELECT 2, id, name, meta_json, revision FROM (
			SELECT e.id,e.name,e.meta_json,e.revision FROM active
			JOIN rbac_user_groups m ON 1=1 JOIN rbac_groups e ON e.id=m.group_id
			WHERE m.subject=? ORDER BY e.name,e.id LIMIT 65
		)
	) SELECT kind,id,name,meta_json,revision FROM rows ORDER BY kind,name,id`, Args: []any{subject, subject, subject, subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Principal{}, err
	}
	if len(result.Rows) == 0 {
		return Principal{}, ErrInactiveSubject
	}
	principal := Principal{}
	for index, row := range result.Rows {
		if len(row) != 5 {
			return Principal{}, ErrInvalid
		}
		kind, ok := row[0].(int64)
		if !ok {
			return Principal{}, ErrInvalid
		}
		if index == 0 {
			if kind != 0 {
				return Principal{}, ErrInvalid
			}
			revision, ok := row[4].(int64)
			if !ok || revision < 1 {
				return Principal{}, ErrInvalid
			}
			principal.Revision = revision
			continue
		}
		entity, err := rowEntity(row[1:])
		if err != nil {
			return Principal{}, err
		}
		switch kind {
		case 1:
			principal.Roles = append(principal.Roles, entity)
		case 2:
			principal.Groups = append(principal.Groups, entity)
		default:
			return Principal{}, ErrInvalid
		}
	}
	if len(principal.Roles) > maxMemberships || len(principal.Groups) > maxMemberships {
		return Principal{}, ErrTooManyMemberships
	}
	return principal, nil
}

// GetBootstrapClientLoginRestriction reads one static-client policy. A missing
// row deliberately means unrestricted and revision zero.
func (s *Store) GetBootstrapClientLoginRestriction(ctx context.Context, clientID string) (BootstrapClientLoginRestriction, error) {
	if s == nil || s.db == nil || !bootstrapClientIDPattern.MatchString(clientID) {
		return BootstrapClientLoginRestriction{}, ErrInvalid
	}
	return s.getBootstrapClientLoginRestriction(ctx, clientID)
}

// GetBootstrapClientLoginRestrictionForAdmin reads the policy only while the
// actor remains an active administrator in the same linearizable snapshot.
func (s *Store) GetBootstrapClientLoginRestrictionForAdmin(ctx context.Context, actor, clientID string) (BootstrapClientLoginRestriction, error) {
	if s == nil || s.db == nil || !validSubject(actor) || !bootstrapClientIDPattern.MatchString(clientID) {
		return BootstrapClientLoginRestriction{}, ErrUnauthorized
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `WITH authorized AS (SELECT 1 WHERE ` + adminGuard() + `)
		SELECT 0 AS kind, '' AS client_id, NULL AS restrict_group_prefix, 0 AS revision FROM authorized
		UNION ALL
		SELECT 1, client_id, restrict_group_prefix, revision
		FROM bootstrap_client_login_restrictions WHERE client_id=? AND EXISTS (SELECT 1 FROM authorized)
		ORDER BY kind`, Args: []any{actor, clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return BootstrapClientLoginRestriction{}, err
	}
	if len(result.Rows) == 0 {
		return BootstrapClientLoginRestriction{}, ErrUnauthorized
	}
	if len(result.Rows) == 1 {
		return BootstrapClientLoginRestriction{ClientID: clientID}, nil
	}
	if len(result.Rows) != 2 || result.Rows[0][0] != int64(0) || result.Rows[1][0] != int64(1) {
		return BootstrapClientLoginRestriction{}, ErrInvalid
	}
	return loginRestrictionRow(result.Rows[1][1:])
}

// UpdateBootstrapClientLoginRestriction creates revision one when expected is
// zero, or CAS-updates the exact expected revision. The mutation repeats the
// active-admin guard so a revoked browser session cannot win a TOCTOU race.
func (s *Store) UpdateBootstrapClientLoginRestriction(ctx context.Context, actor, clientID string, expectedRevision int64, prefix *string) (BootstrapClientLoginRestriction, error) {
	return s.updateBootstrapClientLoginRestriction(ctx, actor, nil, clientID, expectedRevision, prefix)
}
func (s *Store) UpdateBootstrapClientLoginRestrictionAPIKey(ctx context.Context, key apikey.Principal, clientID string, expectedRevision int64, prefix *string) (BootstrapClientLoginRestriction, error) {
	return s.updateBootstrapClientLoginRestriction(ctx, "", &key, clientID, expectedRevision, prefix)
}
func (s *Store) updateBootstrapClientLoginRestriction(ctx context.Context, actor string, key *apikey.Principal, clientID string, expectedRevision int64, prefix *string) (BootstrapClientLoginRestriction, error) {
	if s == nil || s.db == nil || (key == nil && !validSubject(actor)) || !bootstrapClientIDPattern.MatchString(clientID) || expectedRevision < 0 {
		return BootstrapClientLoginRestriction{}, ErrInvalid
	}
	if prefix != nil && ValidateGroupPrefix(*prefix) != nil {
		return BootstrapClientLoginRestriction{}, ErrInvalid
	}
	if err := s.authorize(ctx, actor, key, "Clients", apikey.Update); err != nil {
		return BootstrapClientLoginRestriction{}, err
	}
	attempt, err := s.randomID()
	if err != nil {
		return BootstrapClientLoginRestriction{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond).UnixMilli()
	prefixKey := ""
	var prefixValue any
	if prefix != nil {
		prefixKey = *prefix
		prefixValue = *prefix
	}
	var executeErr error
	if s.beforeLoginRestrictionExecute != nil {
		s.beforeLoginRestrictionExecute()
	}
	if expectedRevision == 0 {
		id := requestID("bootstrap-client-login-restriction-create", actor, clientID, prefixKey, attempt)
		executeErr = s.run(ctx, key, "Clients", apikey.Update, id, []rhiza.SQLStatement{{SQL: `INSERT INTO bootstrap_client_login_restrictions (client_id,restrict_group_prefix,revision,updated_at_unix_ms)
			SELECT ?,?,1,? WHERE NOT EXISTS (SELECT 1 FROM bootstrap_client_login_restrictions WHERE client_id=?) AND ` + adminGuard(), Args: []any{clientID, prefixValue, now, clientID, actor}}})
	} else {
		id := requestID("bootstrap-client-login-restriction-update", actor, clientID, fmt.Sprint(expectedRevision), prefixKey, attempt)
		executeErr = s.run(ctx, key, "Clients", apikey.Update, id, []rhiza.SQLStatement{{SQL: `UPDATE bootstrap_client_login_restrictions SET restrict_group_prefix=?,revision=revision+1,updated_at_unix_ms=?
			WHERE client_id=? AND revision=? AND ` + adminGuard(), Args: []any{prefixValue, now, clientID, expectedRevision, actor}}})
	}
	var current BootstrapClientLoginRestriction
	var readErr error
	if key == nil {
		current, readErr = s.GetBootstrapClientLoginRestrictionForAdmin(ctx, actor, clientID)
	} else {
		current, readErr = s.GetBootstrapClientLoginRestriction(ctx, clientID)
	}
	if readErr != nil {
		return BootstrapClientLoginRestriction{}, readErr
	}
	if current.Revision == expectedRevision+1 && equalPrefix(current.RestrictGroupPrefix, prefix) {
		return current, nil
	}
	if executeErr != nil {
		return BootstrapClientLoginRestriction{}, executeErr
	}
	return BootstrapClientLoginRestriction{}, ErrConflict
}

func (s *Store) getBootstrapClientLoginRestriction(ctx context.Context, clientID string) (BootstrapClientLoginRestriction, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id,restrict_group_prefix,revision FROM bootstrap_client_login_restrictions WHERE client_id=?`, Args: []any{clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return BootstrapClientLoginRestriction{}, err
	}
	if len(result.Rows) == 0 {
		return BootstrapClientLoginRestriction{ClientID: clientID}, nil
	}
	if len(result.Rows) != 1 {
		return BootstrapClientLoginRestriction{}, ErrInvalid
	}
	return loginRestrictionRow(result.Rows[0])
}

func loginRestrictionRow(row []any) (BootstrapClientLoginRestriction, error) {
	if len(row) != 3 {
		return BootstrapClientLoginRestriction{}, ErrInvalid
	}
	clientID, clientOK := row[0].(string)
	revision, revisionOK := row[2].(int64)
	if !clientOK || !bootstrapClientIDPattern.MatchString(clientID) || !revisionOK || revision < 1 {
		return BootstrapClientLoginRestriction{}, ErrInvalid
	}
	policy := BootstrapClientLoginRestriction{ClientID: clientID, Revision: revision}
	if row[1] != nil {
		prefix, ok := row[1].(string)
		if !ok || ValidateGroupPrefix(prefix) != nil {
			return BootstrapClientLoginRestriction{}, ErrInvalid
		}
		policy.RestrictGroupPrefix = &prefix
	}
	return policy, nil
}

func equalPrefix(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func (s *Store) IsAdmin(ctx context.Context, subject string) (bool, error) {
	if s == nil || s.db == nil || !validSubject(subject) {
		return false, ErrInvalid
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 WHERE ` + adminGuard(), Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	return len(result.Rows) == 1, nil
}

func (s *Store) isDelegatedAdmin(ctx context.Context, subject string) (bool, error) {
	if s == nil || s.db == nil || !validSubject(subject) {
		return false, ErrInvalid
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 WHERE ` + delegatedAdminGuard(), Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	return len(result.Rows) == 1, nil
}

func delegatedAdminGuard() string {
	return `EXISTS (
		SELECT 1 FROM identity_users u
		JOIN rbac_user_roles m ON m.subject=u.subject
		JOIN rbac_roles r ON r.id=m.role_id
		WHERE u.subject=? AND u.disabled=0 AND substr(r.name,1,13)='rauthy_admin:'
	)`
}

func (s *Store) managedGroups(ctx context.Context, actor string) (func(string) bool, error) {
	principal, err := s.ResolvePrincipal(ctx, actor)
	if err != nil {
		return nil, err
	}
	roles := entityNames(principal.Roles)
	return func(group string) bool {
		for _, role := range roles {
			if !strings.HasPrefix(role, AdminRole+":") {
				continue
			}
			scope := strings.TrimPrefix(role, AdminRole+":")
			if scope == "*" {
				return true
			}
			if strings.HasSuffix(scope, "*") {
				if strings.HasPrefix(group, strings.TrimSuffix(scope, "*")) {
					return true
				}
			} else if group == scope {
				return true
			}
		}
		return false
	}, nil
}

func delegatedAdminTarget(roles []Entity) bool {
	for _, role := range roles {
		if role.Name == AdminRole || strings.HasPrefix(role.Name, AdminRole+":") {
			return true
		}
	}
	return false
}

func adminGuard() string {
	return `EXISTS (SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id WHERE u.subject=? AND u.disabled=0 AND r.name='rauthy_admin')`
}
func validSubject(v string) bool { return v != "" && len(v) <= 512 }
func (s *Store) randomID() (string, error) {
	raw := make([]byte, 18)
	n, err := s.random(raw)
	if err != nil || n != len(raw) {
		return "", ErrInvalid
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func bootstrapID(kind, name string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + name))
	return base64.RawURLEncoding.EncodeToString(sum[:18])
}
func requestID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "rbac/" + base64.RawURLEncoding.EncodeToString(sum[:])
}
func metaKey(value any) string {
	if value == nil {
		return ""
	}
	return value.(string)
}
func equalMeta(meta json.RawMessage, value any) bool { return string(meta) == metaKey(value) }
func canonicalNames(values []string, group bool) ([]string, error) {
	if len(values) > maxMemberships {
		return nil, ErrTooManyMemberships
	}
	seen := map[string]struct{}{}
	out := append([]string(nil), values...)
	for _, v := range out {
		if validateName(v, group) != nil {
			return nil, ErrInvalid
		}
		if _, ok := seen[v]; ok {
			return nil, ErrInvalid
		}
		seen[v] = struct{}{}
	}
	sort.Strings(out)
	return out, nil
}
func namesPlaceholders(values []string) string {
	if len(values) == 0 {
		return `''`
	}
	return strings.TrimRight(strings.Repeat("?,", len(values)), ",")
}
func stringsAny(values []string) []any {
	out := make([]any, len(values))
	for i := range values {
		out[i] = values[i]
	}
	return out
}
func namesGuard(table string, names []string) (string, []any) {
	return fmt.Sprintf(`(SELECT COUNT(*) FROM %s WHERE name IN (%s))=%d`, table, namesPlaceholders(names), len(names)), stringsAny(names)
}
func equalNames(values []Entity, names []string) bool {
	if len(values) != len(names) {
		return false
	}
	for i := range values {
		if values[i].Name != names[i] {
			return false
		}
	}
	return true
}

func containsName(values []string, name string) bool {
	i := sort.SearchStrings(values, name)
	return i < len(values) && values[i] == name
}
