package claims

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const maxJSON = 8192

var (
	attributeNamePattern = regexp.MustCompile(`^[A-Za-z0-9-_/]{2,32}$`)
	scopeNamePattern     = regexp.MustCompile(`^[A-Za-z0-9-_/,:*.]{2,64}$`)
)

type Store struct {
	db      *rhiza.DB
	apiKeys *apikey.Store
}

func NewStore(db *rhiza.DB) *Store { return &Store{db: db} }

// BindAPIKeys enables API-key authorization for the explicit administrator
// methods below. It is called once during startup before serving requests.
func (s *Store) BindAPIKeys(keys *apikey.Store) { s.apiKeys = keys }

func (s *Store) AuthenticateAPIKey(ctx context.Context, header string) (apikey.Principal, error) {
	if s.apiKeys == nil {
		return apikey.Principal{}, apikey.ErrUnauthorized
	}
	return s.apiKeys.Authenticate(ctx, header)
}
func (s *Store) AuthorizeAPIKey(ctx context.Context, key apikey.Principal, group string, right apikey.Right) error {
	if s.apiKeys == nil {
		return apikey.ErrUnauthorized
	}
	return s.apiKeys.Authorize(ctx, key, group, right)
}

func (s *Store) authorize(ctx context.Context, actor string, key *apikey.Principal, group string, right apikey.Right) error {
	if key != nil {
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
	return s.admin(ctx, actor)
}

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
		if strings.Contains(statement.SQL, adminGuard()) {
			statement.SQL = strings.ReplaceAll(statement.SQL, " AND "+adminGuard(), "")
			statement.Args = statement.Args[:len(statement.Args)-1] // actor is the SQL guard's final argument.
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

// EditableAttribute is the public, self-service view of one custom attribute.
// Value is absent when the configured default has not been materialized.
type EditableAttribute struct {
	Attribute
	Value json.RawMessage
}

func (s *Store) CatalogRevision(ctx context.Context) (int64, error) {
	row, err := s.one(ctx, `SELECT revision FROM claims_catalog WHERE id=1`, nil)
	if err != nil || len(row) != 1 {
		return 0, err
	}
	v, ok := row[0].(int64)
	if !ok {
		return 0, ErrInvalid
	}
	return v, nil
}

func (s *Store) ListAttributes(ctx context.Context, actor string) ([]Attribute, error) {
	return s.listAttributes(ctx, actor, nil)
}
func (s *Store) ListAttributesAPIKey(ctx context.Context, key apikey.Principal) ([]Attribute, error) {
	return s.listAttributes(ctx, "", &key)
}
func (s *Store) listAttributes(ctx context.Context, actor string, key *apikey.Principal) ([]Attribute, error) {
	if err := s.authorize(ctx, actor, key, "UserAttributes", apikey.Read); err != nil {
		return nil, err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name,desc,default_value_json,typ,user_editable,revision FROM user_attribute_configs ORDER BY name`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	out := make([]Attribute, 0, len(result.Rows))
	for _, row := range result.Rows {
		a, ok := attributeRow(row)
		if !ok {
			return nil, ErrInvalid
		}
		out = append(out, a)
	}
	return out, nil
}
func (s *Store) GetAttribute(ctx context.Context, actor, name string) (Attribute, error) {
	if err := s.admin(ctx, actor); err != nil {
		return Attribute{}, err
	}
	if !validAttributeName(name) {
		return Attribute{}, ErrInvalid
	}
	return s.attribute(ctx, name)
}
func (s *Store) attribute(ctx context.Context, name string) (Attribute, error) {
	row, err := s.one(ctx, `SELECT name,desc,default_value_json,typ,user_editable,revision FROM user_attribute_configs WHERE name=?`, []any{name})
	if err != nil {
		return Attribute{}, err
	}
	a, ok := attributeRow(row)
	if !ok {
		return Attribute{}, ErrNotFound
	}
	return a, nil
}
func (s *Store) CreateAttribute(ctx context.Context, actor string, expected int64, value Attribute) (Attribute, error) {
	return s.createAttribute(ctx, actor, nil, expected, value)
}
func (s *Store) CreateAttributeAPIKey(ctx context.Context, key apikey.Principal, expected int64, value Attribute) (Attribute, error) {
	return s.createAttribute(ctx, "", &key, expected, value)
}
func (s *Store) createAttribute(ctx context.Context, actor string, key *apikey.Principal, expected int64, value Attribute) (Attribute, error) {
	if err := s.authorize(ctx, actor, key, "UserAttributes", apikey.Create); err != nil {
		return Attribute{}, err
	}
	if err := validateAttribute(value); err != nil {
		return Attribute{}, err
	}
	def := nullable(value.Default)
	id := requestID("attr-create", actor, fmt.Sprint(expected), value.Name, jsonKey(def))
	err := s.run(ctx, key, "UserAttributes", apikey.Create, id, []rhiza.SQLStatement{
		{SQL: `UPDATE claims_catalog SET revision=revision+1 WHERE id=1 AND revision=? AND NOT EXISTS (SELECT 1 FROM user_attribute_configs WHERE name=?) AND ` + adminGuard(), Args: []any{expected, value.Name, actor}},
		{SQL: `INSERT INTO user_attribute_configs (name,desc,default_value_json,typ,user_editable,revision,created_at_unix_ms,updated_at_unix_ms) SELECT ?,?,?,?,?,1,0,0 WHERE EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?)`, Args: []any{value.Name, nullableString(value.Description), def, nullableString(value.Type), boolInt(value.UserEditable), expected + 1}},
	})
	if err != nil {
		return Attribute{}, err
	}
	if key == nil {
		return s.createdAttribute(ctx, actor, value.Name, expected+1)
	}
	if revision, err := s.CatalogRevision(ctx); err != nil || revision != expected+1 {
		return Attribute{}, ErrConflict
	}
	return s.attribute(ctx, value.Name)
}
func (s *Store) UpdateAttribute(ctx context.Context, actor, name string, expected int64, value Attribute) (Attribute, error) {
	return s.updateAttribute(ctx, actor, nil, name, expected, value)
}
func (s *Store) UpdateAttributeAPIKey(ctx context.Context, key apikey.Principal, name string, expected int64, value Attribute) (Attribute, error) {
	return s.updateAttribute(ctx, "", &key, name, expected, value)
}
func (s *Store) updateAttribute(ctx context.Context, actor string, key *apikey.Principal, name string, expected int64, value Attribute) (Attribute, error) {
	if err := s.authorize(ctx, actor, key, "UserAttributes", apikey.Update); err != nil {
		return Attribute{}, err
	}
	if !validAttributeName(name) {
		return Attribute{}, ErrInvalid
	}
	if err := validateAttribute(value); err != nil {
		return Attribute{}, err
	}
	def := nullable(value.Default)
	id := requestID("attr-update", actor, name, value.Name, fmt.Sprint(expected), jsonKey(def))
	err := s.run(ctx, key, "UserAttributes", apikey.Update, id, []rhiza.SQLStatement{
		{SQL: `UPDATE claims_catalog SET revision=revision+1 WHERE id=1 AND revision=? AND EXISTS (SELECT 1 FROM user_attribute_configs WHERE name=?) AND (?=? OR NOT EXISTS (SELECT 1 FROM user_attribute_configs WHERE name=?)) AND ` + adminGuard(), Args: []any{expected, name, name, value.Name, value.Name, actor}},
		{SQL: `UPDATE user_attribute_configs SET name=?,desc=?,default_value_json=?,typ=?,user_editable=?,revision=revision+1,updated_at_unix_ms=0 WHERE name=? AND EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?)`, Args: []any{value.Name, nullableString(value.Description), def, nullableString(value.Type), boolInt(value.UserEditable), name, expected + 1}},
		{SQL: `UPDATE user_attribute_values SET key=? WHERE key=? AND EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?)`, Args: []any{value.Name, name, expected + 1}},
		{SQL: `UPDATE custom_scopes SET attr_include_access_json=coalesce((SELECT json_group_array(CASE WHEN value=? THEN ? ELSE value END) FROM json_each(attr_include_access_json)), '[]'),attr_include_id_json=coalesce((SELECT json_group_array(CASE WHEN value=? THEN ? ELSE value END) FROM json_each(attr_include_id_json)), '[]'),revision=revision+1 WHERE EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?) AND (attr_include_access_json LIKE ? OR attr_include_id_json LIKE ?)`, Args: []any{name, value.Name, name, value.Name, expected + 1, "%\"" + name + "\"%", "%\"" + name + "\"%"}},
	})
	if err != nil {
		return Attribute{}, err
	}
	if key == nil {
		return s.updatedAttribute(ctx, actor, value.Name, expected)
	}
	if revision, err := s.CatalogRevision(ctx); err != nil || revision != expected+1 {
		return Attribute{}, ErrConflict
	}
	return s.attribute(ctx, value.Name)
}
func (s *Store) DeleteAttribute(ctx context.Context, actor, name string, expected int64) error {
	return s.deleteAttribute(ctx, actor, nil, name, expected)
}
func (s *Store) DeleteAttributeAPIKey(ctx context.Context, key apikey.Principal, name string, expected int64) error {
	return s.deleteAttribute(ctx, "", &key, name, expected)
}
func (s *Store) deleteAttribute(ctx context.Context, actor string, key *apikey.Principal, name string, expected int64) error {
	if err := s.authorize(ctx, actor, key, "UserAttributes", apikey.Delete); err != nil {
		return err
	}
	if !validAttributeName(name) {
		return ErrInvalid
	}
	id := requestID("attr-delete", actor, name, fmt.Sprint(expected))
	err := s.run(ctx, key, "UserAttributes", apikey.Delete, id, []rhiza.SQLStatement{
		{SQL: `UPDATE claims_catalog SET revision=revision+1 WHERE id=1 AND revision=? AND EXISTS (SELECT 1 FROM user_attribute_configs WHERE name=?) AND ` + adminGuard(), Args: []any{expected, name, actor}},
		{SQL: `DELETE FROM user_attribute_values WHERE key=? AND EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?)`, Args: []any{name, expected + 1}},
		{SQL: `DELETE FROM user_attribute_configs WHERE name=? AND EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?)`, Args: []any{name, expected + 1}},
		{SQL: `UPDATE custom_scopes SET attr_include_access_json=coalesce((SELECT json_group_array(value) FROM json_each(attr_include_access_json) WHERE value<>?), '[]'),attr_include_id_json=coalesce((SELECT json_group_array(value) FROM json_each(attr_include_id_json) WHERE value<>?), '[]'),revision=revision+1 WHERE EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?) AND (attr_include_access_json LIKE ? OR attr_include_id_json LIKE ?)`, Args: []any{name, name, expected + 1, "%\"" + name + "\"%", "%\"" + name + "\"%"}},
	})
	if err != nil {
		return err
	}
	rev, e := s.CatalogRevision(ctx)
	if e != nil {
		return e
	}
	if rev != expected+1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) ListScopes(ctx context.Context, actor string) ([]Scope, error) {
	return s.listScopesAuthorized(ctx, actor, nil)
}
func (s *Store) ListScopesAPIKey(ctx context.Context, key apikey.Principal) ([]Scope, error) {
	return s.listScopesAuthorized(ctx, "", &key)
}
func (s *Store) listScopesAuthorized(ctx context.Context, actor string, key *apikey.Principal) ([]Scope, error) {
	if err := s.authorize(ctx, actor, key, "Scopes", apikey.Read); err != nil {
		return nil, err
	}
	return s.listScopes(ctx)
}
func (s *Store) GetScope(ctx context.Context, actor, name string) (Scope, error) {
	if err := s.admin(ctx, actor); err != nil {
		return Scope{}, err
	}
	return s.scope(ctx, name)
}
func (s *Store) CreateScope(ctx context.Context, actor string, expected int64, value Scope) (Scope, error) {
	return s.createScope(ctx, actor, nil, expected, value)
}
func (s *Store) CreateScopeAPIKey(ctx context.Context, key apikey.Principal, expected int64, value Scope) (Scope, error) {
	return s.createScope(ctx, "", &key, expected, value)
}
func (s *Store) createScope(ctx context.Context, actor string, key *apikey.Principal, expected int64, value Scope) (Scope, error) {
	if err := s.authorize(ctx, actor, key, "Scopes", apikey.Create); err != nil {
		return Scope{}, err
	}
	if err := s.validateScope(ctx, value); err != nil {
		return Scope{}, err
	}
	a, b := scopeJSON(value)
	id := requestID("scope-create", actor, fmt.Sprint(expected), value.Name, a, b)
	err := s.run(ctx, key, "Scopes", apikey.Create, id, []rhiza.SQLStatement{{SQL: `UPDATE claims_catalog SET revision=revision+1 WHERE id=1 AND revision=? AND NOT EXISTS (SELECT 1 FROM custom_scopes WHERE name=?) AND ` + adminGuard(), Args: []any{expected, value.Name, actor}}, {SQL: `INSERT INTO custom_scopes (name,attr_include_access_json,attr_include_id_json,claims_at_root,revision) SELECT ?,?,?,?,1 WHERE EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?)`, Args: []any{value.Name, a, b, boolInt(value.ClaimsAtRoot), expected + 1}}})
	if err != nil {
		return Scope{}, err
	}
	if key == nil {
		return s.createdScope(ctx, actor, value.Name, expected+1)
	}
	if revision, err := s.CatalogRevision(ctx); err != nil || revision != expected+1 {
		return Scope{}, ErrConflict
	}
	return s.scope(ctx, value.Name)
}
func (s *Store) UpdateScope(ctx context.Context, actor, name string, expected int64, value Scope) (Scope, error) {
	return s.updateScope(ctx, actor, nil, name, expected, value)
}
func (s *Store) UpdateScopeAPIKey(ctx context.Context, key apikey.Principal, name string, expected int64, value Scope) (Scope, error) {
	return s.updateScope(ctx, "", &key, name, expected, value)
}
func (s *Store) updateScope(ctx context.Context, actor string, key *apikey.Principal, name string, expected int64, value Scope) (Scope, error) {
	if err := s.authorize(ctx, actor, key, "Scopes", apikey.Update); err != nil {
		return Scope{}, err
	}
	if err := s.validateScope(ctx, value); err != nil {
		return Scope{}, err
	}
	a, b := scopeJSON(value)
	id := requestID("scope-update", actor, name, value.Name, fmt.Sprint(expected), a, b)
	err := s.run(ctx, key, "Scopes", apikey.Update, id, []rhiza.SQLStatement{{SQL: `UPDATE claims_catalog SET revision=revision+1 WHERE id=1 AND revision=? AND EXISTS (SELECT 1 FROM custom_scopes WHERE name=?) AND (?=? OR NOT EXISTS (SELECT 1 FROM custom_scopes WHERE name=?)) AND ` + adminGuard(), Args: []any{expected, name, name, value.Name, value.Name, actor}}, {SQL: `UPDATE custom_scopes SET name=?,attr_include_access_json=?,attr_include_id_json=?,claims_at_root=?,revision=revision+1 WHERE name=? AND EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?)`, Args: []any{value.Name, a, b, boolInt(value.ClaimsAtRoot), name, expected + 1}}, {SQL: `UPDATE bootstrap_client_claim_scopes SET allowed_scopes_json=coalesce((SELECT json_group_array(CASE WHEN value=? THEN ? ELSE value END) FROM json_each(allowed_scopes_json)), '[]'),default_scopes_json=coalesce((SELECT json_group_array(CASE WHEN value=? THEN ? ELSE value END) FROM json_each(default_scopes_json)), '[]'),revision=revision+1 WHERE EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?) AND (allowed_scopes_json LIKE ? OR default_scopes_json LIKE ?)`, Args: []any{name, value.Name, name, value.Name, expected + 1, "%\"" + name + "\"%", "%\"" + name + "\"%"}}})
	if err != nil {
		return Scope{}, err
	}
	if key == nil {
		return s.updatedScope(ctx, actor, value.Name, expected)
	}
	if revision, err := s.CatalogRevision(ctx); err != nil || revision != expected+1 {
		return Scope{}, ErrConflict
	}
	return s.scope(ctx, value.Name)
}
func (s *Store) DeleteScope(ctx context.Context, actor, name string, expected int64) error {
	return s.deleteScope(ctx, actor, nil, name, expected)
}
func (s *Store) DeleteScopeAPIKey(ctx context.Context, key apikey.Principal, name string, expected int64) error {
	return s.deleteScope(ctx, "", &key, name, expected)
}
func (s *Store) deleteScope(ctx context.Context, actor string, key *apikey.Principal, name string, expected int64) error {
	if err := s.authorize(ctx, actor, key, "Scopes", apikey.Delete); err != nil {
		return err
	}
	if !validScopeName(name) || isDefaultScope(name) {
		return ErrInvalid
	}
	id := requestID("scope-delete", actor, name, fmt.Sprint(expected))
	err := s.run(ctx, key, "Scopes", apikey.Delete, id, []rhiza.SQLStatement{{SQL: `UPDATE claims_catalog SET revision=revision+1 WHERE id=1 AND revision=? AND EXISTS (SELECT 1 FROM custom_scopes WHERE name=?) AND ` + adminGuard(), Args: []any{expected, name, actor}}, {SQL: `UPDATE bootstrap_client_claim_scopes SET allowed_scopes_json=coalesce((SELECT json_group_array(value) FROM json_each(allowed_scopes_json) WHERE value<>?), '[]'),default_scopes_json=coalesce((SELECT json_group_array(value) FROM json_each(default_scopes_json) WHERE value<>?), '[]'),revision=revision+1 WHERE EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?) AND (allowed_scopes_json LIKE ? OR default_scopes_json LIKE ?)`, Args: []any{name, name, expected + 1, "%\"" + name + "\"%", "%\"" + name + "\"%"}}, {SQL: `DELETE FROM custom_scopes WHERE name=? AND EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?)`, Args: []any{name, expected + 1}}})
	if err != nil {
		return err
	}
	rev, e := s.CatalogRevision(ctx)
	if e != nil {
		return e
	}
	if rev != expected+1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) GetUserValues(ctx context.Context, actor, subject string) (map[string]json.RawMessage, int64, error) {
	if err := s.admin(ctx, actor); err != nil {
		return nil, 0, err
	}
	return s.userValues(ctx, subject)
}
func (s *Store) GetUserValuesAPIKey(ctx context.Context, key apikey.Principal, subject string) (map[string]json.RawMessage, int64, error) {
	if err := s.authorize(ctx, "", &key, "Users", apikey.Read); err != nil {
		return nil, 0, err
	}
	return s.userValues(ctx, subject)
}

// EditableUserAttributes returns only attributes a subject may edit. It is
// deliberately not administrator-gated; the HTTP boundary binds subject to
// the authenticated browser session.
func (s *Store) EditableUserAttributes(ctx context.Context, subject string) ([]EditableAttribute, error) {
	if !validSubject(subject) {
		return nil, ErrInvalid
	}
	if _, _, err := s.userValues(ctx, subject); err != nil {
		return nil, err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT c.name,c.desc,c.default_value_json,c.typ,c.user_editable,c.revision,v.value_json FROM user_attribute_configs c LEFT JOIN user_attribute_values v ON v.subject=? AND v.key=c.name WHERE c.user_editable=1 ORDER BY c.name`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	out := make([]EditableAttribute, 0, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) != 7 {
			return nil, ErrInvalid
		}
		attribute, ok := attributeRow(row[:6])
		if !ok {
			return nil, ErrInvalid
		}
		item := EditableAttribute{Attribute: attribute}
		if row[6] != nil {
			value, ok := row[6].(string)
			if !ok || !json.Valid([]byte(value)) {
				return nil, ErrInvalid
			}
			item.Value = json.RawMessage(value)
		}
		out = append(out, item)
	}
	return out, nil
}

// ScopeExists is intentionally available without administrator authorization:
// OAuth uses it to reject a stale dynamic-client custom scope before issuance.
func (s *Store) ScopeExists(ctx context.Context, name string) (bool, error) {
	if !validScopeName(name) || isDefaultScope(name) {
		return false, nil
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM custom_scopes WHERE name=?`, Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	return len(result.Rows) == 1 && len(result.Rows[0]) == 1, nil
}

func (s *Store) selfUserValues(ctx context.Context, actor, subject string) (map[string]json.RawMessage, int64, error) {
	if actor != subject {
		return nil, 0, ErrUnauthorized
	}
	return s.userValues(ctx, subject)
}

// PutSelfUserValues accepts only currently editable keys. Unknown and
// non-editable valid keys are intentionally ignored to match Rauthy.
func (s *Store) PutSelfUserValues(ctx context.Context, actor, subject string, expected int64, values map[string]json.RawMessage) (int64, error) {
	if actor != subject || !validSubject(subject) || len(values) > 64 {
		return 0, ErrUnauthorized
	}
	canon := make(map[string]string, len(values))
	for name, value := range values {
		if !validAttributeName(name) {
			return 0, ErrInvalid
		}
		encoded, err := canonicalJSON(value)
		if err != nil {
			return 0, err
		}
		if encoded == `""` {
			encoded = "null"
		}
		canon[name] = encoded
	}
	current, revision, err := s.selfUserValues(ctx, actor, subject)
	if err != nil {
		return 0, err
	}
	if revision != expected {
		return 0, ErrConflict
	}
	configs, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM user_attribute_configs WHERE user_editable=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return 0, err
	}
	editable := make(map[string]struct{}, len(configs.Rows))
	for _, row := range configs.Rows {
		if len(row) != 1 {
			return 0, ErrInvalid
		}
		name, ok := row[0].(string)
		if !ok {
			return 0, ErrInvalid
		}
		editable[name] = struct{}{}
	}
	names := make([]string, 0, len(canon))
	for name, encoded := range canon {
		if _, ok := editable[name]; !ok {
			continue
		}
		if old, exists := current[name]; (encoded == "null" && !exists) || (encoded != "null" && exists && string(old) == encoded) {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return expected, nil
	}
	sort.Strings(names)
	placeholders := strings.TrimRight(strings.Repeat("?,", len(names)), ",")
	args := []any{subject, expected, subject, actor, actor}
	for _, name := range names {
		args = append(args, name)
	}
	stmts := []rhiza.SQLStatement{{SQL: `UPDATE rbac_principal_versions SET revision=revision+1,updated_at_unix_ms=updated_at_unix_ms+1 WHERE subject=? AND revision=? AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0) AND ?=? AND EXISTS (SELECT 1 FROM user_attribute_configs WHERE user_editable=1 AND name IN (` + placeholders + `))`, Args: args}}
	for _, name := range names {
		if encoded := canon[name]; encoded != "null" {
			stmts = append(stmts, rhiza.SQLStatement{SQL: `INSERT INTO user_attribute_values (subject,key,value_json,updated_at_unix_ms) SELECT ?,?,?,0 WHERE EXISTS (SELECT 1 FROM user_attribute_configs WHERE name=? AND user_editable=1) AND EXISTS (SELECT 1 FROM rbac_principal_versions WHERE subject=? AND revision=?) ON CONFLICT(subject,key) DO UPDATE SET value_json=excluded.value_json,updated_at_unix_ms=user_attribute_values.updated_at_unix_ms+1`, Args: []any{subject, name, encoded, name, subject, expected + 1}})
		} else {
			stmts = append(stmts, rhiza.SQLStatement{SQL: `DELETE FROM user_attribute_values WHERE subject=? AND key=? AND EXISTS (SELECT 1 FROM user_attribute_configs WHERE name=? AND user_editable=1) AND EXISTS (SELECT 1 FROM rbac_principal_versions WHERE subject=? AND revision=?)`, Args: []any{subject, name, name, subject, expected + 1}})
		}
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID("self-values", actor, subject, fmt.Sprint(expected), strings.Join(names, "\x00")), Statements: stmts}); err != nil {
		return 0, err
	}
	_, revision, err = s.selfUserValues(ctx, actor, subject)
	if err != nil {
		return 0, err
	}
	if revision != expected+1 {
		return 0, ErrConflict
	}
	return revision, nil
}
func (s *Store) PutUserValues(ctx context.Context, actor, subject string, expected int64, values map[string]json.RawMessage) (int64, error) {
	return s.putUserValues(ctx, actor, nil, subject, expected, values)
}
func (s *Store) PutUserValuesAPIKey(ctx context.Context, key apikey.Principal, subject string, expected int64, values map[string]json.RawMessage) (int64, error) {
	return s.putUserValues(ctx, "", &key, subject, expected, values)
}
func (s *Store) putUserValues(ctx context.Context, actor string, key *apikey.Principal, subject string, expected int64, values map[string]json.RawMessage) (int64, error) {
	if err := s.authorize(ctx, actor, key, "Users", apikey.Update); err != nil {
		return 0, err
	}
	if !validSubject(subject) || len(values) > 64 {
		return 0, ErrInvalid
	}
	names := make([]string, 0, len(values))
	canon := map[string]string{}
	for n, v := range values {
		if !validAttributeName(n) {
			return 0, ErrInvalid
		}
		c, e := canonicalJSON(v)
		if e != nil {
			return 0, e
		}
		names = append(names, n)
		if c != "null" {
			canon[n] = c
		}
	}
	sort.Strings(names)
	_, current, e := s.userValues(ctx, subject)
	if e != nil {
		return 0, e
	}
	if current != expected {
		return 0, ErrConflict
	}
	stmts := []rhiza.SQLStatement{{SQL: `UPDATE rbac_principal_versions SET revision=revision+1,updated_at_unix_ms=updated_at_unix_ms+1 WHERE subject=? AND revision=? AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0) AND ` + adminGuard(), Args: []any{subject, expected, subject, actor}}}
	for _, n := range names {
		if c, ok := canon[n]; ok {
			stmts = append(stmts, rhiza.SQLStatement{SQL: `INSERT INTO user_attribute_values (subject,key,value_json,updated_at_unix_ms) SELECT ?,?,?,0 WHERE EXISTS (SELECT 1 FROM user_attribute_configs WHERE name=?) AND EXISTS (SELECT 1 FROM rbac_principal_versions WHERE subject=? AND revision=?) ON CONFLICT(subject,key) DO UPDATE SET value_json=excluded.value_json,updated_at_unix_ms=user_attribute_values.updated_at_unix_ms+1`, Args: []any{subject, n, c, n, subject, expected + 1}})
		} else {
			stmts = append(stmts, rhiza.SQLStatement{SQL: `DELETE FROM user_attribute_values WHERE subject=? AND key=? AND EXISTS (SELECT 1 FROM rbac_principal_versions WHERE subject=? AND revision=?)`, Args: []any{subject, n, subject, expected + 1}})
		}
	}
	id := requestID("values", actor, subject, fmt.Sprint(expected), strings.Join(names, "\x00"))
	e = s.run(ctx, key, "Users", apikey.Update, id, stmts)
	if e != nil {
		return 0, e
	}
	_, rev, e := s.userValues(ctx, subject)
	if e != nil {
		return 0, e
	}
	if rev != expected+1 {
		return 0, ErrConflict
	}
	return rev, nil
}

func (s *Store) GetBootstrapClientScopes(ctx context.Context, actor, clientID string) (ClientScopes, error) {
	if err := s.admin(ctx, actor); err != nil {
		return ClientScopes{}, err
	}
	return s.BootstrapClientScopes(ctx, clientID)
}
func (s *Store) GetBootstrapClientScopesAPIKey(ctx context.Context, key apikey.Principal, clientID string) (ClientScopes, error) {
	if err := s.authorize(ctx, "", &key, "Clients", apikey.Read); err != nil {
		return ClientScopes{}, err
	}
	return s.BootstrapClientScopes(ctx, clientID)
}
func (s *Store) BootstrapClientScopes(ctx context.Context, clientID string) (ClientScopes, error) {
	if !validClientID(clientID) {
		return ClientScopes{}, ErrInvalid
	}
	row, e := s.one(ctx, `SELECT client_id,allowed_scopes_json,default_scopes_json,revision FROM bootstrap_client_claim_scopes WHERE client_id=?`, []any{clientID})
	if errors.Is(e, ErrNotFound) {
		return ClientScopes{ClientID: clientID}, nil
	}
	if e != nil {
		return ClientScopes{}, e
	}
	v, ok := clientRow(row)
	if !ok {
		return ClientScopes{ClientID: clientID}, nil
	}
	return v, nil
}
func (s *Store) UpdateBootstrapClientScopes(ctx context.Context, actor, clientID string, expected int64, allowed, defaults []string) (ClientScopes, error) {
	return s.updateBootstrapClientScopes(ctx, actor, nil, clientID, expected, allowed, defaults)
}
func (s *Store) UpdateBootstrapClientScopesAPIKey(ctx context.Context, key apikey.Principal, clientID string, expected int64, allowed, defaults []string) (ClientScopes, error) {
	return s.updateBootstrapClientScopes(ctx, "", &key, clientID, expected, allowed, defaults)
}
func (s *Store) updateBootstrapClientScopes(ctx context.Context, actor string, key *apikey.Principal, clientID string, expected int64, allowed, defaults []string) (ClientScopes, error) {
	if err := s.authorize(ctx, actor, key, "Clients", apikey.Update); err != nil {
		return ClientScopes{}, err
	}
	if !validClientID(clientID) {
		return ClientScopes{}, ErrInvalid
	}
	allowed, e := canonicalScopes(allowed)
	if e != nil {
		return ClientScopes{}, e
	}
	defaults, e = canonicalScopes(defaults)
	if e != nil {
		return ClientScopes{}, e
	}
	if !subset(defaults, allowed) {
		return ClientScopes{}, ErrInvalid
	}
	for _, n := range allowed {
		if !isDefaultScope(n) {
			if _, e := s.scope(ctx, n); e != nil {
				if errors.Is(e, ErrNotFound) {
					return ClientScopes{}, ErrNotFound
				}
				return ClientScopes{}, fmt.Errorf("validate bootstrap client scope %q: %w", n, e)
			}
		}
	}
	a, _ := json.Marshal(allowed)
	d, _ := json.Marshal(defaults)
	existing, e := s.BootstrapClientScopes(ctx, clientID)
	if e != nil {
		return ClientScopes{}, fmt.Errorf("read bootstrap client scopes before update: %w", e)
	}
	if existing.Revision != expected {
		return ClientScopes{}, ErrConflict
	}
	next := int64(1)
	if expected > 0 {
		next = expected + 1
	}
	statements := []rhiza.SQLStatement{{SQL: `UPDATE bootstrap_client_claim_scopes SET allowed_scopes_json=?,default_scopes_json=?,revision=revision+1 WHERE client_id=? AND revision=? AND ` + adminGuard(), Args: []any{string(a), string(d), clientID, expected, actor}}}
	if expected == 0 {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO bootstrap_client_claim_scopes (client_id,allowed_scopes_json,default_scopes_json,revision) SELECT ?,?,?,1 WHERE NOT EXISTS (SELECT 1 FROM bootstrap_client_claim_scopes WHERE client_id=?) AND ` + adminGuard(), Args: []any{clientID, string(a), string(d), clientID, actor}})
	}
	id := requestID("client-scopes", actor, clientID, fmt.Sprint(expected), string(a), string(d))
	e = s.run(ctx, key, "Clients", apikey.Update, id, statements)
	if e != nil {
		return ClientScopes{}, fmt.Errorf("update bootstrap client scopes: %w", e)
	}
	out, e := s.BootstrapClientScopes(ctx, clientID)
	if e != nil {
		return ClientScopes{}, fmt.Errorf("read bootstrap client scopes after update: %w", e)
	}
	if out.Revision != next {
		return ClientScopes{}, ErrConflict
	}
	return out, nil
}

// GetBootstrapClientCredentialsClaims reads the explicit policy after checking
// the browser administrator boundary.
func (s *Store) GetBootstrapClientCredentialsClaims(ctx context.Context, actor, clientID string) (ClientCredentialsClaims, error) {
	if err := s.admin(ctx, actor); err != nil {
		return ClientCredentialsClaims{}, err
	}
	return s.BootstrapClientCredentialsClaims(ctx, clientID)
}

func (s *Store) GetBootstrapClientCredentialsClaimsAPIKey(ctx context.Context, key apikey.Principal, clientID string) (ClientCredentialsClaims, error) {
	if err := s.authorize(ctx, "", &key, "Clients", apikey.Read); err != nil {
		return ClientCredentialsClaims{}, err
	}
	return s.BootstrapClientCredentialsClaims(ctx, clientID)
}

// BootstrapClientCredentialsClaims is intentionally unprivileged so token
// issuance can read policy without an administrator principal.
func (s *Store) BootstrapClientCredentialsClaims(ctx context.Context, clientID string) (ClientCredentialsClaims, error) {
	if !validClientID(clientID) {
		return ClientCredentialsClaims{}, ErrInvalid
	}
	row, err := s.one(ctx, `SELECT client_id,claims_json,claims_at_root,revision FROM bootstrap_client_credentials_claims WHERE client_id=?`, []any{clientID})
	if errors.Is(err, ErrNotFound) {
		return ClientCredentialsClaims{ClientID: clientID}, nil
	}
	if err != nil {
		return ClientCredentialsClaims{}, err
	}
	value, ok := clientCredentialsClaimsRow(row)
	if !ok {
		return ClientCredentialsClaims{}, ErrInvalid
	}
	return value, nil
}

func (s *Store) UpdateBootstrapClientCredentialsClaims(ctx context.Context, actor, clientID string, expected int64, values map[string]json.RawMessage, atRoot bool) (ClientCredentialsClaims, error) {
	return s.updateBootstrapClientCredentialsClaims(ctx, actor, nil, clientID, expected, values, atRoot)
}

func (s *Store) UpdateBootstrapClientCredentialsClaimsAPIKey(ctx context.Context, key apikey.Principal, clientID string, expected int64, values map[string]json.RawMessage, atRoot bool) (ClientCredentialsClaims, error) {
	return s.updateBootstrapClientCredentialsClaims(ctx, "", &key, clientID, expected, values, atRoot)
}

func (s *Store) updateBootstrapClientCredentialsClaims(ctx context.Context, actor string, key *apikey.Principal, clientID string, expected int64, values map[string]json.RawMessage, atRoot bool) (ClientCredentialsClaims, error) {
	if err := s.authorize(ctx, actor, key, "Clients", apikey.Update); err != nil {
		return ClientCredentialsClaims{}, err
	}
	if !validClientID(clientID) || expected < 0 {
		return ClientCredentialsClaims{}, ErrInvalid
	}
	claims, err := canonicalClientCredentialsClaims(values)
	if err != nil {
		return ClientCredentialsClaims{}, err
	}
	existing, err := s.BootstrapClientCredentialsClaims(ctx, clientID)
	if err != nil {
		return ClientCredentialsClaims{}, fmt.Errorf("read bootstrap client credentials claims before update: %w", err)
	}
	if existing.Revision != expected {
		return ClientCredentialsClaims{}, ErrConflict
	}
	next := expected + 1
	statements := []rhiza.SQLStatement{{SQL: `UPDATE bootstrap_client_credentials_claims SET claims_json=?,claims_at_root=?,revision=revision+1,updated_at_unix_ms=updated_at_unix_ms+1 WHERE client_id=? AND revision=? AND ` + adminGuard(), Args: []any{claims, boolInt(atRoot), clientID, expected, actor}}}
	if expected == 0 {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO bootstrap_client_credentials_claims (client_id,claims_json,claims_at_root,revision,updated_at_unix_ms) SELECT ?,?,?,1,0 WHERE NOT EXISTS (SELECT 1 FROM bootstrap_client_credentials_claims WHERE client_id=?) AND ` + adminGuard(), Args: []any{clientID, claims, boolInt(atRoot), clientID, actor}})
	}
	id := requestID("client-credentials-claims", actor, clientID, fmt.Sprint(expected), fmt.Sprint(claims), fmt.Sprint(atRoot))
	if err := s.run(ctx, key, "Clients", apikey.Update, id, statements); err != nil {
		return ClientCredentialsClaims{}, fmt.Errorf("update bootstrap client credentials claims: %w", err)
	}
	out, err := s.BootstrapClientCredentialsClaims(ctx, clientID)
	if err != nil {
		return ClientCredentialsClaims{}, fmt.Errorf("read bootstrap client credentials claims after update: %w", err)
	}
	if out.Revision != next {
		return ClientCredentialsClaims{}, ErrConflict
	}
	return out, nil
}

func (s *Store) Resolve(ctx context.Context, subject string, granted []string) (Resolved, error) {
	if !validSubject(subject) {
		return Resolved{}, ErrInvalid
	}
	_, _, e := s.userValues(ctx, subject)
	if e != nil {
		return Resolved{}, e
	}
	cat, e := s.CatalogRevision(ctx)
	if e != nil {
		return Resolved{}, e
	}
	set := map[string]struct{}{}
	for _, v := range granted {
		set[v] = struct{}{}
	}
	out := Resolved{
		ID:              map[string]json.RawMessage{},
		IDRoot:          map[string]json.RawMessage{},
		Access:          map[string]json.RawMessage{},
		AccessRoot:      map[string]json.RawMessage{},
		CatalogRevision: cat,
	}
	scopes, e := s.listScopes(ctx)
	if e != nil {
		return Resolved{}, e
	}
	values, _, e := s.userValues(ctx, subject)
	if e != nil {
		return Resolved{}, e
	}
	attrs, e := s.attributes(ctx)
	if e != nil {
		return Resolved{}, e
	}
	for _, sc := range scopes {
		if _, ok := set[sc.Name]; !ok {
			continue
		}
		for _, name := range sc.AttributeIncludeID {
			if v, ok := valueFor(name, values, attrs); ok {
				if sc.ClaimsAtRoot {
					out.IDRoot[name] = v
				} else {
					out.ID[name] = v
				}
			}
		}
		for _, name := range sc.AttributeIncludeAccess {
			if v, ok := valueFor(name, values, attrs); ok {
				if sc.ClaimsAtRoot {
					out.AccessRoot[name] = v
				} else {
					out.Access[name] = v
				}
			}
		}
	}
	return out, nil
}

func (s *Store) admin(ctx context.Context, actor string) error {
	if !validSubject(actor) || s == nil || s.db == nil {
		return ErrUnauthorized
	}
	row, e := s.one(ctx, `SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id WHERE u.subject=? AND u.disabled=0 AND r.name='rauthy_admin'`, []any{actor})
	if e != nil {
		return ErrUnauthorized
	}
	if len(row) != 1 {
		return ErrUnauthorized
	}
	return nil
}
func (s *Store) one(ctx context.Context, sql string, args []any) ([]any, error) {
	if s == nil || s.db == nil {
		return nil, ErrInvalid
	}
	r, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return nil, e
	}
	if len(r.Rows) == 0 {
		return nil, ErrNotFound
	}
	if len(r.Rows) != 1 {
		return nil, ErrInvalid
	}
	return r.Rows[0], nil
}
func (s *Store) attributes(ctx context.Context) (map[string]Attribute, error) {
	r, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name,desc,default_value_json,typ,user_editable,revision FROM user_attribute_configs`, Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return nil, e
	}
	out := map[string]Attribute{}
	for _, row := range r.Rows {
		a, ok := attributeRow(row)
		if !ok {
			return nil, ErrInvalid
		}
		out[a.Name] = a
	}
	return out, nil
}
func (s *Store) userValues(ctx context.Context, subject string) (map[string]json.RawMessage, int64, error) {
	if !validSubject(subject) {
		return nil, 0, ErrInvalid
	}
	row, e := s.one(ctx, `SELECT revision FROM rbac_principal_versions WHERE subject=? AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)`, []any{subject, subject})
	if e != nil {
		return nil, 0, ErrInactiveSubject
	}
	rev, ok := row[0].(int64)
	if !ok {
		return nil, 0, ErrInvalid
	}
	r, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT key,value_json FROM user_attribute_values WHERE subject=? ORDER BY key`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return nil, 0, e
	}
	out := map[string]json.RawMessage{}
	for _, x := range r.Rows {
		if len(x) != 2 {
			return nil, 0, ErrInvalid
		}
		n, a := x[0].(string)
		v, b := x[1].(string)
		if !a || !b {
			return nil, 0, ErrInvalid
		}
		out[n] = json.RawMessage(v)
	}
	return out, rev, nil
}
func (s *Store) listScopes(ctx context.Context) ([]Scope, error) {
	r, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name,attr_include_access_json,attr_include_id_json,claims_at_root,revision FROM custom_scopes ORDER BY name`, Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return nil, e
	}
	out := make([]Scope, 0, len(r.Rows))
	for _, x := range r.Rows {
		v, ok := scopeRow(x)
		if !ok {
			return nil, ErrInvalid
		}
		out = append(out, v)
	}
	return out, nil
}
func (s *Store) scope(ctx context.Context, name string) (Scope, error) {
	if !validScopeName(name) {
		return Scope{}, ErrInvalid
	}
	row, e := s.one(ctx, `SELECT name,attr_include_access_json,attr_include_id_json,claims_at_root,revision FROM custom_scopes WHERE name=?`, []any{name})
	if e != nil {
		return Scope{}, e
	}
	v, ok := scopeRow(row)
	if !ok {
		return Scope{}, ErrInvalid
	}
	return v, nil
}
func (s *Store) createdAttribute(ctx context.Context, actor, name string, rev int64) (Attribute, error) {
	cat, e := s.CatalogRevision(ctx)
	if e != nil {
		return Attribute{}, e
	}
	if cat != rev {
		return Attribute{}, ErrConflict
	}
	v, e := s.GetAttribute(ctx, actor, name)
	if e != nil {
		return Attribute{}, e
	}
	if v.Revision != 1 {
		return Attribute{}, ErrConflict
	}
	return v, nil
}
func (s *Store) updatedAttribute(ctx context.Context, actor, name string, old int64) (Attribute, error) {
	v, e := s.GetAttribute(ctx, actor, name)
	if e != nil {
		return Attribute{}, e
	}
	cat, e := s.CatalogRevision(ctx)
	if e != nil {
		return Attribute{}, e
	}
	if cat != old+1 {
		return Attribute{}, ErrConflict
	}
	return v, nil
}
func (s *Store) createdScope(ctx context.Context, actor, name string, rev int64) (Scope, error) {
	cat, e := s.CatalogRevision(ctx)
	if e != nil {
		return Scope{}, e
	}
	if cat != rev {
		return Scope{}, ErrConflict
	}
	v, e := s.GetScope(ctx, actor, name)
	if e != nil {
		return Scope{}, e
	}
	return v, nil
}
func (s *Store) updatedScope(ctx context.Context, actor, name string, old int64) (Scope, error) {
	v, e := s.GetScope(ctx, actor, name)
	if e != nil {
		return Scope{}, e
	}
	cat, e := s.CatalogRevision(ctx)
	if e != nil {
		return Scope{}, e
	}
	if cat != old+1 {
		return Scope{}, ErrConflict
	}
	return v, nil
}

func validateAttribute(v Attribute) error {
	if !validAttributeName(v.Name) || len(v.Description) > 128 || (v.Type != "" && v.Type != "email") {
		return ErrInvalid
	}
	_, e := canonicalJSON(v.Default)
	return e
}
func (s *Store) validateScope(ctx context.Context, v Scope) error {
	if !validScopeName(v.Name) {
		return ErrInvalid
	}
	if isDefaultScope(v.Name) {
		if len(v.AttributeIncludeAccess) > 0 || len(v.AttributeIncludeID) > 0 || v.ClaimsAtRoot {
			return ErrReserved
		}
		return ErrReserved
	}
	a, e := canonicalAttrs(v.AttributeIncludeAccess)
	if e != nil {
		return e
	}
	b, e := canonicalAttrs(v.AttributeIncludeID)
	if e != nil {
		return e
	}
	attrs, e := s.attributes(ctx)
	if e != nil {
		return e
	}
	for _, n := range append(a, b...) {
		if _, ok := attrs[n]; !ok {
			return ErrNotFound
		}
	}
	return nil
}
func canonicalJSON(v json.RawMessage) (string, error) {
	if len(v) == 0 {
		return "null", nil
	}
	if len(v) > maxJSON || !json.Valid(v) || validateJSON(v) != nil {
		return "", ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(v))
	d.UseNumber()
	var x any
	if d.Decode(&x) != nil || ensureJSONEOF(d) != nil {
		return "", ErrInvalid
	}
	b, e := json.Marshal(x)
	if e != nil || len(b) > maxJSON {
		return "", ErrInvalid
	}
	return string(b), nil
}

func canonicalClientCredentialsClaims(values map[string]json.RawMessage) (any, error) {
	if values == nil {
		return nil, nil
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return nil, ErrInvalid
	}
	canonical, err := canonicalJSON(raw)
	if err != nil || len(canonical) > 1024 {
		return nil, ErrInvalid
	}
	return canonical, nil
}

// validateJSON rejects duplicate object keys at every depth before decoding
// into a map, which would otherwise silently keep the final key.
func validateJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := validateJSONValue(d); err != nil {
		return err
	}
	return ensureJSONEOF(d)
}

func validateJSONValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return ErrInvalid
			}
			if _, duplicate := seen[name]; duplicate {
				return ErrInvalid
			}
			seen[name] = struct{}{}
			if err := validateJSONValue(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case '[':
		for d.More() {
			if err := validateJSONValue(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	default:
		return ErrInvalid
	}
}

func ensureJSONEOF(d *json.Decoder) error {
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return ErrInvalid
		}
		return err
	}
	return nil
}
func nullable(v json.RawMessage) any {
	c, _ := canonicalJSON(v)
	if c == "null" {
		return nil
	}
	return c
}
func jsonKey(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return "null"
}
func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func boolInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func validAttributeName(v string) bool { return attributeNamePattern.MatchString(v) }
func validScopeName(v string) bool     { return scopeNamePattern.MatchString(v) }
func validSubject(v string) bool       { return v != "" && len(v) <= 512 }
func validClientID(v string) bool      { return len(v) > 0 && len(v) <= 64 }
func isDefaultScope(v string) bool     { _, ok := defaultScopes[v]; return ok }
func canonicalAttrs(v []string) ([]string, error) {
	if len(v) > 64 {
		return nil, ErrInvalid
	}
	out := append([]string(nil), v...)
	sort.Strings(out)
	for i, n := range out {
		if !validAttributeName(n) || (i > 0 && n == out[i-1]) {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func canonicalScopes(v []string) ([]string, error) {
	if len(v) > 64 {
		return nil, ErrInvalid
	}
	out := append([]string{}, v...)
	sort.Strings(out)
	for i, n := range out {
		if !validScopeName(n) || (i > 0 && n == out[i-1]) {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func subset(a, b []string) bool {
	set := map[string]struct{}{}
	for _, v := range b {
		set[v] = struct{}{}
	}
	for _, v := range a {
		if _, ok := set[v]; !ok {
			return false
		}
	}
	return true
}
func scopeJSON(v Scope) (string, string) {
	a, _ := canonicalAttrs(v.AttributeIncludeAccess)
	b, _ := canonicalAttrs(v.AttributeIncludeID)
	if a == nil {
		a = []string{}
	}
	if b == nil {
		b = []string{}
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x), string(y)
}
func attributeRow(r []any) (Attribute, bool) {
	if len(r) != 6 {
		return Attribute{}, false
	}
	n, a := r[0].(string)
	edit, b := r[4].(int64)
	rev, c := r[5].(int64)
	if !a || !b || !c {
		return Attribute{}, false
	}
	v := Attribute{Name: n, UserEditable: edit == 1, Revision: rev}
	if r[1] != nil {
		v.Description, a = r[1].(string)
		if !a {
			return Attribute{}, false
		}
	}
	if r[2] != nil {
		x, a := r[2].(string)
		if !a {
			return Attribute{}, false
		}
		v.Default = json.RawMessage(x)
	}
	if r[3] != nil {
		v.Type, a = r[3].(string)
		if !a {
			return Attribute{}, false
		}
	}
	return v, true
}
func scopeRow(r []any) (Scope, bool) {
	if len(r) != 5 {
		return Scope{}, false
	}
	n, a := r[0].(string)
	x, b := r[1].(string)
	y, c := r[2].(string)
	root, d := r[3].(int64)
	rev, e := r[4].(int64)
	if !a || !b || !c || !d || !e {
		return Scope{}, false
	}
	v := Scope{Name: n, ClaimsAtRoot: root == 1, Revision: rev}
	return v, json.Unmarshal([]byte(x), &v.AttributeIncludeAccess) == nil && json.Unmarshal([]byte(y), &v.AttributeIncludeID) == nil
}
func clientRow(r []any) (ClientScopes, bool) {
	if len(r) != 4 {
		return ClientScopes{}, false
	}
	id, a := r[0].(string)
	x, b := r[1].(string)
	y, c := r[2].(string)
	rev, d := r[3].(int64)
	if !a || !b || !c || !d {
		return ClientScopes{}, false
	}
	v := ClientScopes{ClientID: id, Revision: rev}
	return v, json.Unmarshal([]byte(x), &v.Allowed) == nil && json.Unmarshal([]byte(y), &v.Default) == nil
}
func clientCredentialsClaimsRow(r []any) (ClientCredentialsClaims, bool) {
	if len(r) != 4 {
		return ClientCredentialsClaims{}, false
	}
	id, ok := r[0].(string)
	if !ok {
		return ClientCredentialsClaims{}, false
	}
	root, ok := r[2].(int64)
	if !ok || (root != 0 && root != 1) {
		return ClientCredentialsClaims{}, false
	}
	revision, ok := r[3].(int64)
	if !ok || revision < 1 {
		return ClientCredentialsClaims{}, false
	}
	value := ClientCredentialsClaims{ClientID: id, AtRoot: root == 1, Revision: revision}
	if r[1] == nil {
		return value, true
	}
	raw, ok := r[1].(string)
	if !ok || len(raw) > 1024 || raw == "null" || json.Unmarshal([]byte(raw), &value.Values) != nil || value.Values == nil {
		return ClientCredentialsClaims{}, false
	}
	return value, true
}
func valueFor(n string, values map[string]json.RawMessage, attrs map[string]Attribute) (json.RawMessage, bool) {
	if v, ok := values[n]; ok {
		return append(json.RawMessage(nil), v...), true
	}
	if a, ok := attrs[n]; ok && len(a.Default) > 0 {
		return append(json.RawMessage(nil), a.Default...), true
	}
	return nil, false
}
func adminGuard() string {
	return `EXISTS (SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id WHERE u.subject=? AND u.disabled=0 AND r.name='rauthy_admin')`
}
func requestID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "claims/" + base64.RawURLEncoding.EncodeToString(sum[:])
}
