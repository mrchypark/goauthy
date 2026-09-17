// Package authcollection stores administrator-defined authentication metadata
// and user-owned draft connections. It deliberately stores no credentials.
package authcollection

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrInvalid          = errors.New("invalid auth collection")
	ErrConflict         = errors.New("auth collection revision conflict")
	ErrUnauthorized     = errors.New("auth collection unauthorized")
	ErrNotFound         = errors.New("auth collection not found")
	idPattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$`)
	connectionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{1,127}$`)
	fieldPattern        = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
	providerIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

const maxList = 1000 // bounded result; callers receive ErrConflict when exceeded.

type Field struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Required  bool     `json:"required"`
	MaxLength int      `json:"max_length"`
	Options   []string `json:"options,omitempty"`
}
type Definition struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	AuthMethod  string   `json:"auth_method"`
	Enabled     bool     `json:"enabled"`
	Revision    int64    `json:"revision"`
	Fields      []Field  `json:"fields"`
	ProviderIDs []string `json:"provider_ids"`
}
type DefinitionInput struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	AuthMethod  string   `json:"auth_method"`
	Enabled     bool     `json:"enabled"`
	Fields      []Field  `json:"fields"`
	ProviderIDs []string `json:"provider_ids"`
}
type Connection struct {
	ID                 string          `json:"id"`
	CollectionID       string          `json:"collection_id"`
	OwnerSubject       string          `json:"owner_subject"`
	State              string          `json:"state"`
	Revision           int64           `json:"revision"`
	DefinitionRevision int64           `json:"definition_revision"`
	Metadata           json.RawMessage `json:"metadata"`
}
type Store struct {
	db  *rhiza.DB
	now func() time.Time
}

func NewStore(db *rhiza.DB) *Store { return &Store{db: db, now: time.Now} }
func guard(fn func() (string, []any)) (string, []any) {
	if fn == nil {
		return "0", nil
	}
	g, a := fn()
	if strings.TrimSpace(g) == "" {
		return "0", nil
	}
	return g, a
}
func randomID() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) CreateDefinition(ctx context.Context, in DefinitionInput, authority func() (string, []any)) (Definition, error) {
	if in.Fields == nil {
		in.Fields = []Field{}
	}
	if in.ProviderIDs == nil {
		in.ProviderIDs = []string{}
	}
	if s == nil || s.db == nil || validateDefinition(in) != nil {
		return Definition{}, ErrInvalid
	}
	g, a := guard(authority)
	if g == "0" {
		return Definition{}, ErrUnauthorized
	}
	fields, _ := json.Marshal(in.Fields)
	providers, _ := json.Marshal(in.ProviderIDs)
	gen := randomID()
	if gen == "" {
		return Definition{}, ErrInvalid
	}
	q := append([]any{in.ID, in.Name, in.AuthMethod, boolInt(in.Enabled), int64(1), gen, string(fields), string(providers), in.ID}, a...)
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "auth-collection-definition-create-" + gen, SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json) SELECT ?,?,?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM auth_collection_definitions WHERE id=?) AND (` + g + `)`, Args: q})
	if err != nil {
		return Definition{}, err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return Definition{}, ErrConflict
	}
	return Definition{ID: in.ID, Name: in.Name, AuthMethod: in.AuthMethod, Enabled: in.Enabled, Revision: 1, Fields: in.Fields, ProviderIDs: in.ProviderIDs}, nil
}

func (s *Store) UpdateDefinition(ctx context.Context, id string, revision int64, in DefinitionInput, authority func() (string, []any)) (Definition, error) {
	if in.Fields == nil {
		in.Fields = []Field{}
	}
	if in.ProviderIDs == nil {
		in.ProviderIDs = []string{}
	}
	if s == nil || s.db == nil || revision <= 0 || in.ID != "" && in.ID != id || validateDefinition(DefinitionInput{ID: id, Name: in.Name, AuthMethod: in.AuthMethod, Enabled: in.Enabled, Fields: in.Fields, ProviderIDs: in.ProviderIDs}) != nil {
		return Definition{}, ErrInvalid
	}
	g, a := guard(authority)
	if g == "0" {
		return Definition{}, ErrUnauthorized
	}
	fields, _ := json.Marshal(in.Fields)
	providers, _ := json.Marshal(in.ProviderIDs)
	q := append([]any{in.Name, in.AuthMethod, boolInt(in.Enabled), revision + 1, string(fields), string(providers), id, revision, in.AuthMethod, string(fields)}, a...)
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "auth-collection-definition-update-" + randomID(), SQL: `UPDATE auth_collection_definitions SET name=?,auth_method=?,enabled=?,revision=?,fields_json=?,providers_json=? WHERE id=? AND revision=? AND deleted=0 AND (NOT EXISTS(SELECT 1 FROM auth_collection_connections c WHERE c.collection_id=auth_collection_definitions.id) OR (auth_method=? AND fields_json=?)) AND (` + g + `)`, Args: q})
	if err != nil {
		return Definition{}, err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return Definition{}, ErrConflict
	}
	return Definition{ID: id, Name: in.Name, AuthMethod: in.AuthMethod, Enabled: in.Enabled, Revision: revision + 1, Fields: in.Fields, ProviderIDs: in.ProviderIDs}, nil
}

func (s *Store) DeleteDefinition(ctx context.Context, id string, revision int64, authority func() (string, []any)) error {
	if s == nil || s.db == nil || revision <= 0 {
		return ErrInvalid
	}
	g, a := guard(authority)
	if g == "0" {
		return ErrUnauthorized
	}
	q := append([]any{id, revision}, a...)
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "auth-collection-definition-delete-" + randomID(), SQL: `UPDATE auth_collection_definitions SET deleted=1,enabled=0,revision=revision+1 WHERE id=? AND revision=? AND deleted=0 AND NOT EXISTS(SELECT 1 FROM auth_collection_connections c WHERE c.collection_id=auth_collection_definitions.id) AND (` + g + `)`, Args: q})
	if err != nil {
		return err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return ErrConflict
	}
	return nil
}
func (s *Store) GetDefinition(ctx context.Context, id string, authority func() (string, []any)) (Definition, error) {
	g, a := guard(authority)
	if s == nil || s.db == nil {
		return Definition{}, ErrInvalid
	}
	if g == "0" {
		return Definition{}, ErrUnauthorized
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,name,auth_method,enabled,revision,fields_json,providers_json FROM auth_collection_definitions WHERE id=? AND deleted=0 AND (` + g + `)`, Args: append([]any{id}, a...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Definition{}, err
	}
	if len(r.Rows) != 1 {
		return Definition{}, ErrNotFound
	}
	return decodeDefinition(r.Rows[0])
}
func (s *Store) ListDefinitions(ctx context.Context, authority func() (string, []any)) ([]Definition, error) {
	g, a := guard(authority)
	if s == nil || s.db == nil {
		return nil, ErrInvalid
	}
	if g == "0" {
		return nil, ErrUnauthorized
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,name,auth_method,enabled,revision,fields_json,providers_json FROM auth_collection_definitions WHERE deleted=0 AND (` + g + `) ORDER BY id LIMIT ?`, Args: append(a, int64(maxList+1)), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	if len(r.Rows) > maxList {
		return nil, ErrConflict
	}
	out := make([]Definition, 0, len(r.Rows))
	for _, row := range r.Rows {
		d, e := decodeDefinition(row)
		if e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, nil
}

func (s *Store) CreateConnection(ctx context.Context, owner, collectionID string, definitionRevision int64, metadata json.RawMessage, authority func() (string, []any)) (Connection, error) {
	if s == nil || s.db == nil || !idPattern.MatchString(collectionID) || owner == "" || definitionRevision <= 0 || validateMetadata(metadata, nil) != nil {
		return Connection{}, ErrInvalid
	}
	g, a := guard(authority)
	if g == "0" {
		return Connection{}, ErrUnauthorized
	}
	d, err := s.GetDefinition(ctx, collectionID, authority)
	if err != nil {
		return Connection{}, err
	}
	if validateMetadata(metadata, d.Fields) != nil {
		return Connection{}, ErrInvalid
	}
	if d.Revision != definitionRevision || !d.Enabled {
		return Connection{}, ErrConflict
	}
	id, gen := randomID(), randomID()
	if id == "" || gen == "" {
		return Connection{}, ErrInvalid
	}
	q := append([]any{id, collectionID, owner, definitionRevision, string(metadata), gen, collectionID, definitionRevision, owner, s.now().UnixMilli()}, a...)
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "auth-collection-connection-create-" + gen, SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) SELECT ?,?,?, 'draft',1,?,?,? WHERE EXISTS(SELECT 1 FROM auth_collection_definitions d WHERE d.id=? AND d.enabled=1 AND d.revision=? ) AND EXISTS(SELECT 1 FROM identity_users u WHERE u.subject=? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?)) AND (` + g + `)`, Args: q})
	if err != nil {
		return Connection{}, err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return Connection{}, ErrConflict
	}
	return Connection{id, collectionID, owner, "draft", 1, definitionRevision, append(json.RawMessage(nil), metadata...)}, nil
}
func (s *Store) UpdateConnection(ctx context.Context, owner, collectionID, id string, revision, definitionRevision int64, metadata json.RawMessage, authority func() (string, []any)) (Connection, error) {
	if s == nil || s.db == nil || owner == "" || !idPattern.MatchString(collectionID) || !connectionIDPattern.MatchString(id) || revision <= 0 || definitionRevision <= 0 || validateMetadata(metadata, nil) != nil {
		return Connection{}, ErrInvalid
	}
	g, a := guard(authority)
	if g == "0" {
		return Connection{}, ErrUnauthorized
	}
	d, err := s.GetDefinition(ctx, collectionID, authority)
	if err != nil {
		return Connection{}, err
	}
	if validateMetadata(metadata, d.Fields) != nil {
		return Connection{}, ErrInvalid
	}
	if d.Revision != definitionRevision || !d.Enabled {
		return Connection{}, ErrConflict
	}
	q := append([]any{string(metadata), revision + 1, definitionRevision, id, owner, collectionID, revision, collectionID, definitionRevision, owner, s.now().UnixMilli()}, a...)
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "auth-collection-connection-update-" + randomID(), SQL: `UPDATE auth_collection_connections SET metadata_json=?,revision=?,definition_revision=? WHERE id=? AND owner_subject=? AND collection_id=? AND revision=? AND EXISTS(SELECT 1 FROM auth_collection_definitions d WHERE d.id=? AND d.enabled=1 AND d.revision=?) AND EXISTS(SELECT 1 FROM identity_users u WHERE u.subject=? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?)) AND (` + g + `)`, Args: q})
	if err != nil {
		return Connection{}, err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return Connection{}, ErrConflict
	}
	return Connection{id, collectionID, owner, "draft", revision + 1, definitionRevision, append(json.RawMessage(nil), metadata...)}, nil
}
func (s *Store) DeleteConnection(ctx context.Context, owner, collectionID, id string, revision int64, authority func() (string, []any)) error {
	if s == nil || s.db == nil || owner == "" || revision <= 0 {
		return ErrInvalid
	}
	g, a := guard(authority)
	if g == "0" {
		return ErrUnauthorized
	}
	q := append([]any{id, owner, collectionID, revision, owner, s.now().UnixMilli()}, a...)
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "auth-collection-connection-delete-" + randomID(), SQL: `DELETE FROM auth_collection_connections WHERE id=? AND owner_subject=? AND collection_id=? AND revision=? AND EXISTS(SELECT 1 FROM identity_users u WHERE u.subject=? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?)) AND (` + g + `)`, Args: q})
	if err != nil {
		return err
	}
	if r.Status != "committed" || r.MutationReceipt.RowsAffected != 1 {
		return ErrConflict
	}
	return nil
}
func (s *Store) GetConnection(ctx context.Context, owner, collectionID, id string, authority func() (string, []any)) (Connection, error) {
	return s.getConnection(ctx, owner, collectionID, id, authority)
}
func (s *Store) ListConnections(ctx context.Context, owner, collectionID string, authority func() (string, []any)) ([]Connection, error) {
	g, a := guard(authority)
	if s == nil || s.db == nil {
		return nil, ErrInvalid
	}
	if g == "0" {
		return nil, ErrUnauthorized
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,collection_id,owner_subject,state,revision,definition_revision,metadata_json FROM auth_collection_connections WHERE owner_subject=? AND collection_id=? AND EXISTS(SELECT 1 FROM identity_users u WHERE u.subject=? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?)) AND (` + g + `) ORDER BY id LIMIT ?`, Args: append(append([]any{owner, collectionID, owner, s.now().UnixMilli()}, a...), int64(maxList+1)), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	if len(r.Rows) > maxList {
		return nil, ErrConflict
	}
	out := make([]Connection, 0, len(r.Rows))
	for _, row := range r.Rows {
		c, e := decodeConnection(row)
		if e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *Store) getConnection(ctx context.Context, owner, collectionID, id string, authority func() (string, []any)) (Connection, error) {
	g, a := guard(authority)
	if s == nil || s.db == nil {
		return Connection{}, ErrInvalid
	}
	if g == "0" {
		return Connection{}, ErrUnauthorized
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,collection_id,owner_subject,state,revision,definition_revision,metadata_json FROM auth_collection_connections WHERE id=? AND owner_subject=? AND collection_id=? AND EXISTS(SELECT 1 FROM identity_users u WHERE u.subject=? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?)) AND (` + g + `)`, Args: append([]any{id, owner, collectionID, owner, s.now().UnixMilli()}, a...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Connection{}, err
	}
	if len(r.Rows) != 1 {
		return Connection{}, ErrNotFound
	}
	return decodeConnection(r.Rows[0])
}
func decodeDefinition(row []any) (Definition, error) {
	if len(row) != 7 {
		return Definition{}, ErrInvalid
	}
	id, okID := row[0].(string)
	name, okName := row[1].(string)
	authMethod, okAuthMethod := row[2].(string)
	enabled, okEnabled := row[3].(int64)
	revision, okRevision := row[4].(int64)
	fieldsRaw, okFields := row[5].(string)
	providersRaw, okProviders := row[6].(string)
	if !okID || !okName || !okAuthMethod || !okEnabled || !okRevision || !okFields || !okProviders || (enabled != 0 && enabled != 1) || revision <= 0 {
		return Definition{}, ErrInvalid
	}
	d := Definition{ID: id, Name: name, AuthMethod: authMethod, Enabled: enabled == 1, Revision: revision}
	if json.Unmarshal([]byte(fieldsRaw), &d.Fields) != nil {
		return Definition{}, ErrInvalid
	}
	if d.Fields == nil {
		d.Fields = []Field{}
	}
	if json.Unmarshal([]byte(providersRaw), &d.ProviderIDs) != nil {
		return Definition{}, ErrInvalid
	}
	if d.ProviderIDs == nil {
		d.ProviderIDs = []string{}
	}
	if validateDefinition(DefinitionInput{ID: d.ID, Name: d.Name, AuthMethod: d.AuthMethod, Enabled: d.Enabled, Fields: d.Fields, ProviderIDs: d.ProviderIDs}) != nil {
		return Definition{}, ErrInvalid
	}
	return d, nil
}
func decodeConnection(row []any) (Connection, error) {
	if len(row) != 7 {
		return Connection{}, ErrInvalid
	}
	c := Connection{}
	c.ID, _ = row[0].(string)
	c.CollectionID, _ = row[1].(string)
	c.OwnerSubject, _ = row[2].(string)
	c.State, _ = row[3].(string)
	c.Revision, _ = row[4].(int64)
	c.DefinitionRevision, _ = row[5].(int64)
	m, _ := row[6].(string)
	c.Metadata = json.RawMessage(m)
	return c, nil
}
func boolInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func validateDefinition(in DefinitionInput) error {
	if !idPattern.MatchString(in.ID) || strings.TrimSpace(in.Name) == "" || len(in.Name) > 128 || (in.AuthMethod != "oauth2" && in.AuthMethod != "api_key" && in.AuthMethod != "device_flow") || len(in.Fields) > 32 || len(in.ProviderIDs) > 32 || in.AuthMethod == "oauth2" && len(in.ProviderIDs) > 32 || in.AuthMethod == "api_key" && len(in.ProviderIDs) > 1 || in.AuthMethod == "device_flow" && len(in.ProviderIDs) != 0 {
		return ErrInvalid
	}
	seenProviders := map[string]bool{}
	for _, id := range in.ProviderIDs {
		if !providerIDPattern.MatchString(id) || seenProviders[id] {
			return ErrInvalid
		}
		seenProviders[id] = true
	}
	seen := map[string]bool{}
	for _, f := range in.Fields {
		if !fieldPattern.MatchString(f.Name) || seen[f.Name] || isReserved(f.Name) || (f.Type != "string" && f.Type != "boolean" && f.Type != "integer" && f.Type != "enum") || f.MaxLength < 0 || f.MaxLength > 4096 {
			return ErrInvalid
		}
		seen[f.Name] = true
		if f.Type != "string" && f.MaxLength != 0 {
			return ErrInvalid
		}
		if f.Type != "enum" && len(f.Options) != 0 {
			return ErrInvalid
		}
		if f.Type == "enum" {
			if len(f.Options) == 0 || len(f.Options) > 64 {
				return ErrInvalid
			}
			opts := map[string]bool{}
			for _, o := range f.Options {
				if o == "" || len(o) > 128 || opts[o] {
					return ErrInvalid
				}
				opts[o] = true
			}
		}
	}
	return nil
}
func isReserved(s string) bool {
	switch strings.ToLower(s) {
	case "id", "state", "revision", "owner_subject", "collection_id", "definition_revision", "password", "secret", "token", "client_secret", "access_token", "refresh_token", "credential", "api_key":
		return true
	}
	return false
}
func validateMetadata(raw json.RawMessage, fields []Field) error {
	if len(raw) == 0 || len(raw) > 8192 {
		return ErrInvalid
	}
	if rejectDuplicateJSON(raw) != nil {
		return ErrInvalid
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return ErrInvalid
	}
	if fields == nil {
		return nil
	}
	defs := map[string]Field{}
	for _, f := range fields {
		defs[f.Name] = f
	}
	for name, value := range m {
		f, ok := defs[name]
		if !ok || isReserved(name) {
			return ErrInvalid
		}
		dec := json.NewDecoder(strings.NewReader(string(value)))
		dec.UseNumber()
		var v any
		if dec.Decode(&v) != nil {
			return ErrInvalid
		}
		switch f.Type {
		case "string":
			s, ok := v.(string)
			if !ok || f.MaxLength > 0 && len(s) > f.MaxLength {
				return ErrInvalid
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				return ErrInvalid
			}
		case "integer":
			n, ok := v.(json.Number)
			if !ok {
				return ErrInvalid
			}
			if _, err := n.Int64(); err != nil {
				return ErrInvalid
			}
		case "enum":
			s, ok := v.(string)
			if !ok {
				return ErrInvalid
			}
			found := false
			for _, o := range f.Options {
				found = found || s == o
			}
			if !found {
				return ErrInvalid
			}
		}
	}
	for _, f := range fields {
		if f.Required {
			if _, ok := m[f.Name]; !ok {
				return ErrInvalid
			}
		}
	}
	return nil
}

func rejectDuplicateJSON(raw []byte) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	if err := walkJSON(d); err != nil {
		return err
	}
	if _, err := d.Token(); err == nil {
		return ErrInvalid
	}
	return nil
}
func walkJSON(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := k.(string)
				if !ok || seen[name] {
					return ErrInvalid
				}
				seen[name] = true
				if err := walkJSON(d); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				if err := walkJSON(d); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
	}
	return nil
}
