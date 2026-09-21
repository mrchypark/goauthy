// Package clients stores operator-managed OAuth clients separately from DCR clients.
package clients

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

const TableName = "managed_oauth_clients"

var (
	backchannelURIPattern = regexp.MustCompile(`^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%@]+$`)
	groupPrefixPattern    = regexp.MustCompile(`^[a-zA-Z0-9-_/,:*\s]{2,64}$`)
	ErrInvalid            = errors.New("invalid managed OAuth client")
	ErrConflict           = errors.New("managed OAuth client revision conflict")
	ErrUnauthorized       = errors.New("managed OAuth client unauthorized")
	ErrNotFound           = errors.New("managed OAuth client not found")
	ErrReserved           = errors.New("managed OAuth client ID is reserved")
	idPattern             = regexp.MustCompile(`^[A-Za-z0-9._-]{2,256}$`)
)

type NewRequest struct {
	BackchannelLogoutURI *string  `json:"backchannel_logout_uri"`
	RestrictGroupPrefix  *string  `json:"restrict_group_prefix"`
	ID                   string   `json:"id"`
	Name                 *string  `json:"name"`
	Confidential         bool     `json:"confidential"`
	RedirectURIs         []string `json:"redirect_uris"`
	Scopes               []string `json:"scopes"`
	DefaultScopes        []string `json:"default_scopes"`
	GrantTypes           []string `json:"enabled_flows"`
	Audiences            []string `json:"audience"`
	DefaultAudiences     []string `json:"default_aud"`
	ForceMFA             bool     `json:"force_mfa"`
}
type UpdateRequest struct {
	BackchannelLogoutURI *string  `json:"backchannel_logout_uri"`
	RestrictGroupPrefix  *string  `json:"restrict_group_prefix"`
	Name                 *string  `json:"name"`
	Confidential         bool     `json:"confidential"`
	RedirectURIs         []string `json:"redirect_uris"`
	Enabled              bool     `json:"enabled"`
	Scopes               []string `json:"scopes"`
	DefaultScopes        []string `json:"default_scopes"`
	GrantTypes           []string `json:"enabled_flows"`
	Audiences            []string `json:"audience"`
	DefaultAudiences     []string `json:"default_aud"`
	ForceMFA             bool     `json:"force_mfa"`
}
type Client struct {
	BackchannelLogoutURI *string  `json:"backchannel_logout_uri"`
	RestrictGroupPrefix  *string  `json:"restrict_group_prefix"`
	ID                   string   `json:"id"`
	Name                 *string  `json:"name"`
	Confidential         bool     `json:"confidential"`
	RedirectURIs         []string `json:"redirect_uris"`
	Enabled              bool     `json:"enabled"`
	Scopes               []string `json:"scopes"`
	DefaultScopes        []string `json:"default_scopes"`
	GrantTypes           []string `json:"enabled_flows"`
	Audiences            []string `json:"audience"`
	DefaultAudiences     []string `json:"default_aud"`
	Revision             int64    `json:"revision"`
	Generation           string   `json:"-"`
	SecretHash           []byte   `json:"-"`
	secretEnvelope       []byte
	ForceMFA             bool `json:"force_mfa"`
}
type Store struct {
	db       *rhiza.DB
	keyring  *oidc.Keyring
	reserved map[string]bool
}

// EnsureBootstrap durably reserves the configured bootstrap client ID. Every
// node must present the same ID; an existing managed or DCR owner is rejected.
func (s *Store) EnsureBootstrap(ctx context.Context, id string) error {
	if s == nil || s.db == nil || !idPattern.MatchString(id) {
		return ErrInvalid
	}
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "managed-client-bootstrap-" + randomID(), SQL: `INSERT INTO managed_oauth_client_bootstrap(singleton,id) SELECT 1,? WHERE NOT EXISTS(SELECT 1 FROM managed_oauth_clients WHERE id=?) AND NOT EXISTS(SELECT 1 FROM dynamic_oauth_clients WHERE client_id=?) AND NOT EXISTS(SELECT 1 FROM managed_oauth_client_bootstrap)`, Args: []any{id, id, id}})
	if err != nil {
		return err
	}
	if r.MutationReceipt.RowsAffected == 1 {
		return nil
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id FROM managed_oauth_client_bootstrap WHERE singleton=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(q.Rows) != 1 {
		return ErrConflict
	}
	got, ok := q.Rows[0][0].(string)
	if !ok || got != id {
		return ErrReserved
	}
	return nil
}

func NewStore(db *rhiza.DB, keyring *oidc.Keyring, reservedIDs ...string) *Store {
	r := map[string]bool{}
	for _, id := range reservedIDs {
		r[id] = true
	}
	return &Store{db: db, keyring: keyring, reserved: r}
}

func (c *Client) GetID() string             { return c.ID }
func (c *Client) GetHashedSecret() []byte   { return c.SecretHash }
func (c *Client) GetRedirectURIs() []string { return append([]string(nil), c.RedirectURIs...) }
func (c *Client) GetGrantTypes() fosite.Arguments {
	return append(fosite.Arguments(nil), c.GrantTypes...)
}
func (c *Client) GetResponseTypes() fosite.Arguments {
	if !contains(c.GrantTypes, "authorization_code") {
		return nil
	}
	return fosite.Arguments{"code"}
}
func (c *Client) GetScopes() fosite.Arguments   { return append(fosite.Arguments(nil), c.Scopes...) }
func (c *Client) GetAudience() fosite.Arguments { return append(fosite.Arguments(nil), c.Audiences...) }
func (c *Client) GetDefaultAudience() fosite.Arguments {
	return append(fosite.Arguments(nil), c.DefaultAudiences...)
}
func (c *Client) GetBackchannelLogoutURI() string {
	if c.BackchannelLogoutURI == nil {
		return ""
	}
	return *c.BackchannelLogoutURI
}

func (c *Client) IsPublic() bool { return !c.Confidential }

func (s *Store) CreateWithGuard(ctx context.Context, in NewRequest, authority func() (string, []any)) (Client, error) {
	if s == nil || s.db == nil || s.keyring == nil {
		return Client{}, ErrInvalid
	}
	guard, args := guardArgs(authority)
	if guard == "0" {
		return Client{}, ErrUnauthorized
	}
	if err := validateNew(in, s.reserved); err != nil {
		return Client{}, err
	}
	scopes, defaults, grants := managedDefaults(in)
	c := Client{BackchannelLogoutURI: in.BackchannelLogoutURI, RestrictGroupPrefix: in.RestrictGroupPrefix, ID: in.ID, Name: in.Name, Confidential: in.Confidential, RedirectURIs: append([]string{}, in.RedirectURIs...), Enabled: true, Scopes: scopes, DefaultScopes: defaults, GrantTypes: grants, Audiences: append([]string{}, in.Audiences...), DefaultAudiences: append([]string{}, in.DefaultAudiences...), Revision: 1, Generation: randomGeneration(), ForceMFA: in.ForceMFA}
	if in.Confidential {
		if err := sealSecret(s, &c); err != nil {
			return Client{}, err
		}
	}
	meta, _ := json.Marshal(c.metadata())
	q := append([]any{c.ID, c.Generation, c.Revision, 1, 0, string(meta), c.SecretHash, c.secretEnvelope, boolInt(c.ForceMFA), c.ID}, args...)
	request := rhiza.ExecuteRequest{RequestID: "managed-client-create-" + randomID(), SQL: "INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json,secret_hash,secret_envelope,force_mfa) SELECT ?,?,?,?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM dynamic_oauth_clients WHERE client_id=?) AND (" + guard + ")", Args: q}
	res, err := s.execute(ctx, request, in.Confidential)
	if err != nil {
		return Client{}, err
	}
	if res.Status != "committed" || res.MutationReceipt.RowsAffected != 1 {
		return Client{}, ErrConflict
	}
	return c, nil
}

func (s *Store) UpdateWithGuard(ctx context.Context, id string, rev int64, in UpdateRequest, authority func() (string, []any)) (Client, error) {
	return s.updateWithGuard(ctx, id, rev, in, authority, false)
}

func (s *Store) updateWithGuard(ctx context.Context, id string, rev int64, in UpdateRequest, authority func() (string, []any), forceRotate bool) (Client, error) {
	guard, args := guardArgs(authority)
	if guard == "0" {
		return Client{}, ErrUnauthorized
	}
	if err := validateUpdate(in); err != nil {
		return Client{}, err
	}
	old, err := s.load(ctx, id, true)
	if err != nil {
		return Client{}, err
	}
	if rev < 1 || rev == math.MaxInt64 || old.Revision != rev {
		return Client{}, ErrConflict
	}
	c := old
	c.Name = in.Name
	c.BackchannelLogoutURI = in.BackchannelLogoutURI
	c.RestrictGroupPrefix = in.RestrictGroupPrefix
	c.Confidential = in.Confidential
	c.RedirectURIs = append([]string{}, in.RedirectURIs...)
	c.Enabled = in.Enabled
	c.Scopes = append([]string(nil), in.Scopes...)
	c.DefaultScopes = append([]string(nil), in.DefaultScopes...)
	c.GrantTypes = append([]string(nil), in.GrantTypes...)
	if in.Audiences != nil {
		c.Audiences = append([]string{}, in.Audiences...)
	}
	if in.DefaultAudiences != nil {
		c.DefaultAudiences = append([]string{}, in.DefaultAudiences...)
	}
	c.ForceMFA = in.ForceMFA
	c.Revision = rev + 1
	c.Generation = old.Generation
	if !slices.Equal(c.Audiences, old.Audiences) || !slices.Equal(c.DefaultAudiences, old.DefaultAudiences) || old.Confidential != in.Confidential || old.Enabled && !in.Enabled {
		c.Generation = randomGeneration()
	}
	if forceRotate {
		if err := sealSecret(s, &c); err != nil {
			return Client{}, err
		}
	} else if old.Confidential != in.Confidential {
		if in.Confidential {
			if err := sealSecret(s, &c); err != nil {
				return Client{}, err
			}
		} else {
			c.SecretHash = nil
			c.secretEnvelope = nil
		}
	} else if old.Confidential {
		// A metadata update must not restore an old-key envelope after a
		// concurrent rewrap. Every envelope we write uses the fenced active key.
		if err := resealSecret(s, &c, &old); err != nil {
			return Client{}, err
		}
	} else {
		c.SecretHash = old.SecretHash
		c.secretEnvelope = old.secretEnvelope
	}
	meta, _ := json.Marshal(c.metadata())
	q := append([]any{c.Generation, c.Revision, boolInt(c.Enabled), string(meta), c.SecretHash, c.secretEnvelope, boolInt(c.ForceMFA), id, rev}, args...)
	one := int64(1)
	statements := []rhiza.SQLStatement{{SQL: "UPDATE managed_oauth_clients SET generation=?,revision=?,enabled=?,metadata_json=?,secret_hash=?,secret_envelope=?,force_mfa=? WHERE id=? AND revision=? AND deleted=0 AND (" + guard + ") RETURNING id", Args: q, WantRows: true, ExpectedReturnedRows: &one}}
	for _, table := range []string{"oidc_user_clients", "oidc_session_clients"} {
		statements = append(statements, rhiza.SQLStatement{SQL: "UPDATE " + table + " SET logout_uri=? WHERE client_id=?", Args: []any{c.GetBackchannelLogoutURI(), id}})
	}
	response, err := s.execute(ctx, rhiza.ExecuteRequest{RequestID: "managed-client-update-" + randomID(), Statements: statements}, len(c.secretEnvelope) != 0 || len(old.secretEnvelope) != 0)
	if response.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return Client{}, ErrConflict
	}

	if err != nil {
		return Client{}, err
	}
	if response.Status != "committed" {
		return Client{}, ErrConflict
	}
	return c, nil
}

func (s *Store) DeleteWithGuard(ctx context.Context, id string, rev int64, authority func() (string, []any)) error {
	guard, args := guardArgs(authority)
	if guard == "0" {
		return ErrUnauthorized
	}
	one := int64(1)
	statements := []rhiza.SQLStatement{
		{SQL: "UPDATE managed_oauth_clients SET deleted=1,enabled=0,secret_hash=NULL,secret_envelope=NULL,revision=revision+1 WHERE id=? AND revision=? AND deleted=0 AND (" + guard + ") RETURNING id", Args: append([]any{id, rev}, args...), WantRows: true, ExpectedReturnedRows: &one},
		{SQL: `DELETE FROM oidc_backchannel_deliveries WHERE client_id=?`, Args: []any{id}},
		{SQL: `DELETE FROM oidc_session_clients WHERE client_id=?`, Args: []any{id}},
		{SQL: `DELETE FROM oidc_user_clients WHERE client_id=?`, Args: []any{id}},
		{SQL: `DELETE FROM client_themes WHERE client_id=?`, Args: []any{id}},
		{SQL: `DELETE FROM client_logos WHERE client_id=?`, Args: []any{id}},
		{SQL: `DELETE FROM client_favicons WHERE client_id=?`, Args: []any{id}},
	}
	r, e := s.execute(ctx, rhiza.ExecuteRequest{RequestID: "managed-client-delete-" + randomID(), Statements: statements}, true)
	if r.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return ErrConflict
	}
	if e != nil {
		return e
	}
	if r.Status != "committed" {
		return ErrConflict
	}
	return nil
}

func (s *Store) RotateSecretWithGuard(ctx context.Context, id string, rev int64, authority func() (string, []any)) (Client, error) {
	guard, _ := guardArgs(authority)
	if guard == "0" {
		return Client{}, ErrUnauthorized
	}
	c, e := s.load(ctx, id, true)
	if e != nil {
		return Client{}, e
	}
	return s.updateWithGuard(ctx, id, rev, UpdateRequest{BackchannelLogoutURI: c.BackchannelLogoutURI, RestrictGroupPrefix: c.RestrictGroupPrefix, Name: c.Name, Confidential: true, RedirectURIs: c.RedirectURIs, Enabled: c.Enabled, Scopes: c.Scopes, DefaultScopes: c.DefaultScopes, GrantTypes: c.GrantTypes, Audiences: c.Audiences, DefaultAudiences: c.DefaultAudiences, ForceMFA: c.ForceMFA}, authority, true)
}

func (s *Store) execute(ctx context.Context, request rhiza.ExecuteRequest, envelope bool) (rhiza.ExecuteResponse, error) {
	if !envelope {
		return storage.Execute(ctx, s.db, request)
	}
	keyID, err := s.keyring.ActiveMasterKeyID()
	if err != nil {
		return rhiza.ExecuteResponse{}, err
	}
	return storage.ExecuteEnvelope(ctx, s.db, keyID, request)
}
func (s *Store) ReadSecretWithGuard(ctx context.Context, id string, authority func() (string, []any)) (string, error) {
	return s.readSecretWithGuard(ctx, id, 0, authority)
}

// ReadSecretWithRevisionWithGuard pairs a rotated secret with the exact
// committed revision that produced it; a concurrent rotation fails closed.
func (s *Store) ReadSecretWithRevisionWithGuard(ctx context.Context, id string, rev int64, authority func() (string, []any)) (string, error) {
	if rev < 1 {
		return "", ErrConflict
	}
	return s.readSecretWithGuard(ctx, id, rev, authority)
}

func (s *Store) readSecretWithGuard(ctx context.Context, id string, rev int64, authority func() (string, []any)) (string, error) {
	guard, args := guardArgs(authority)
	if guard == "0" {
		return "", ErrUnauthorized
	}
	where := "id=? AND deleted=0"
	queryArgs := []any{id}
	if rev != 0 {
		where += " AND revision=?"
		queryArgs = append(queryArgs, rev)
	}
	r, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT secret_envelope,metadata_json,generation FROM managed_oauth_clients WHERE " + where + " AND (" + guard + ")", Args: append(queryArgs, args...), Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return "", e
	}
	if len(r.Rows) != 1 {
		if rev != 0 {
			return "", ErrConflict
		}
		return "", ErrNotFound
	}
	var meta struct {
		Confidential bool `json:"confidential"`
	}
	if raw, ok := r.Rows[0][1].(string); !ok || json.Unmarshal([]byte(raw), &meta) != nil || !meta.Confidential {
		return "", ErrNotFound
	}
	env, ok := r.Rows[0][0].([]byte)
	if !ok {
		return "", ErrNotFound
	}
	generation, _ := r.Rows[0][2].(string)
	plain, e := s.keyring.OpenEnvelope(oidc.ManagedClientSecretPurpose(id, generation), env)
	if e != nil {
		return "", e
	}
	return string(plain), nil
}
func (s *Store) ListWithGuard(ctx context.Context, authority func() (string, []any)) ([]Client, error) {
	guard, args := guardArgs(authority)
	if guard == "0" {
		return nil, ErrUnauthorized
	}
	r, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT id,generation,revision,enabled,metadata_json,secret_hash,secret_envelope,force_mfa FROM managed_oauth_clients WHERE deleted=0 AND (" + guard + ") ORDER BY id", Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return nil, e
	}
	out := []Client{}
	for _, row := range r.Rows {
		c, e := decode(row)
		if e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, nil
}
func (s *Store) GetWithGuard(ctx context.Context, id string, authority func() (string, []any)) (Client, error) {
	guard, args := guardArgs(authority)
	if guard == "0" {
		return Client{}, ErrUnauthorized
	}
	r, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT id,generation,revision,enabled,metadata_json,secret_hash,secret_envelope,force_mfa FROM managed_oauth_clients WHERE id=? AND deleted=0 AND (" + guard + ")", Args: append([]any{id}, args...), Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return Client{}, e
	}
	if len(r.Rows) != 1 {
		return Client{}, ErrNotFound
	}
	return decode(r.Rows[0])
}
func (s *Store) Owns(ctx context.Context, id string) (bool, error) {
	r, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 FROM managed_oauth_clients WHERE id=?", Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable})
	return len(r.Rows) == 1, e
}
func (s *Store) load(ctx context.Context, id string, includeDeleted bool) (Client, error) {
	where := "id=?"
	if !includeDeleted {
		where += " AND deleted=0"
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT id,generation,revision,enabled,metadata_json,secret_hash,secret_envelope,force_mfa FROM managed_oauth_clients WHERE " + where, Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Client{}, err
	}
	if len(r.Rows) != 1 {
		return Client{}, ErrNotFound
	}
	return decode(r.Rows[0])
}
func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	c, e := s.GetWithGuard(ctx, id, func() (string, []any) { return "1", nil })
	if errors.Is(e, ErrNotFound) {
		return nil, fosite.ErrNotFound
	}
	if e != nil {
		return nil, e
	}
	if !c.Enabled {
		return nil, fosite.ErrNotFound
	}
	return &c, nil
}

func guardArgs(fn func() (string, []any)) (string, []any) {
	if fn == nil {
		return "0", nil
	}
	g, a := fn()
	if strings.TrimSpace(g) == "" {
		return "0", nil
	}
	return g, a
}
func (c Client) metadata() map[string]any {
	return map[string]any{"backchannel_logout_uri": c.BackchannelLogoutURI, "restrict_group_prefix": c.RestrictGroupPrefix, "name": c.Name, "confidential": c.Confidential, "redirect_uris": c.RedirectURIs, "scopes": c.Scopes, "default_scopes": c.DefaultScopes, "enabled_flows": c.GrantTypes, "audience": c.Audiences, "default_aud": c.DefaultAudiences}
}
func decode(row []any) (Client, error) {
	if len(row) != 8 {
		return Client{}, ErrInvalid
	}
	var c Client
	id, okID := row[0].(string)
	gen, okGen := row[1].(string)
	rev, okRev := row[2].(int64)
	enabled, okEnabled := row[3].(int64)
	meta, okMeta := row[4].(string)
	if !okID || !okGen || !okRev || !okEnabled || !okMeta || rev < 1 || (enabled != 0 && enabled != 1) || json.Unmarshal([]byte(meta), &c) != nil {
		return Client{}, ErrInvalid
	}
	if c.BackchannelLogoutURI != nil && !backchannelURIPattern.MatchString(*c.BackchannelLogoutURI) {
		return Client{}, ErrInvalid
	}
	if c.RestrictGroupPrefix != nil && !groupPrefixPattern.MatchString(*c.RestrictGroupPrefix) {
		return Client{}, ErrInvalid
	}
	c.ID = id
	if c.Audiences == nil {
		c.Audiences = []string{}
	}
	if c.DefaultAudiences == nil {
		c.DefaultAudiences = []string{}
	}
	if validateAudiences(c.Audiences) != nil || validateAudiences(c.DefaultAudiences) != nil {
		return Client{}, ErrInvalid
	}
	c.Generation = gen
	c.Revision = rev
	c.Enabled = enabled == 1
	if row[5] != nil {
		c.SecretHash, _ = row[5].([]byte)
	}
	c.secretEnvelope, _ = row[6].([]byte)
	forceMFA, okForceMFA := row[7].(int64)
	if okForceMFA {
		c.ForceMFA = forceMFA == 1
	}
	return c, nil
}
func sealSecret(s *Store, c *Client) error {
	plain := randomID()
	h, e := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	c.SecretHash = h
	c.secretEnvelope, e = s.keyring.SealEnvelope(oidc.ManagedClientSecretPurpose(c.ID, c.Generation), []byte(plain))
	return e
}

func resealSecret(s *Store, c, old *Client) error {
	plain, err := s.keyring.OpenEnvelope(oidc.ManagedClientSecretPurpose(old.ID, old.Generation), old.secretEnvelope)
	if err != nil {
		return err
	}
	c.SecretHash = append([]byte(nil), old.SecretHash...)
	c.secretEnvelope, err = s.keyring.SealEnvelope(oidc.ManagedClientSecretPurpose(c.ID, c.Generation), plain)
	return err
}
func randomID() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func randomGeneration() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func boolInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func validateNew(in NewRequest, reserved map[string]bool) error {
	if in.BackchannelLogoutURI != nil && !backchannelURIPattern.MatchString(*in.BackchannelLogoutURI) {
		return ErrInvalid
	}
	if in.RestrictGroupPrefix != nil && !groupPrefixPattern.MatchString(*in.RestrictGroupPrefix) {
		return ErrInvalid
	}
	if !idPattern.MatchString(in.ID) {
		return ErrInvalid
	}
	if reserved[in.ID] {
		return ErrReserved
	}
	if in.Name != nil && (len(strings.TrimSpace(*in.Name)) == 0 || len(*in.Name) > 256) {
		return ErrInvalid
	}
	scopes, defaults, grants := managedDefaults(in)
	if err := validatePolicy(in.Confidential, in.RedirectURIs, grants, scopes, defaults); err != nil {
		return err
	}
	// The password grant cannot carry a second factor, so admitting it on a
	// force_mfa client would make the MFA requirement unenforceable (GA-OAUTH-005).
	if in.ForceMFA && contains(grants, "password") {
		return ErrInvalid
	}
	if err := validateAudiences(in.Audiences); err != nil {
		return err
	}
	return validateAudiences(in.DefaultAudiences)
}
func validateUpdate(in UpdateRequest) error {
	if in.BackchannelLogoutURI != nil && !backchannelURIPattern.MatchString(*in.BackchannelLogoutURI) {
		return ErrInvalid
	}
	if in.RestrictGroupPrefix != nil && !groupPrefixPattern.MatchString(*in.RestrictGroupPrefix) {
		return ErrInvalid
	}
	if in.Name != nil && (len(strings.TrimSpace(*in.Name)) == 0 || len(*in.Name) > 256) {
		return ErrInvalid
	}
	if err := validatePolicy(in.Confidential, in.RedirectURIs, in.GrantTypes, in.Scopes, in.DefaultScopes); err != nil {
		return err
	}
	if in.ForceMFA && contains(in.GrantTypes, "password") {
		return ErrInvalid
	}
	if in.Audiences != nil {
		if err := validateAudiences(in.Audiences); err != nil {
			return err
		}
	}
	if in.DefaultAudiences != nil {
		return validateAudiences(in.DefaultAudiences)
	}
	return nil
}
func managedDefaults(in NewRequest) (scopes, defaults, grants []string) {
	scopes = in.Scopes
	if scopes == nil {
		scopes = []string{"openid", "email", "profile", "groups"}
	}
	defaults = in.DefaultScopes
	if defaults == nil {
		defaults = []string{"openid"}
	}
	grants = in.GrantTypes
	if grants == nil {
		grants = []string{"authorization_code"}
	}
	return
}
func validatePolicy(confidential bool, redirects, grants, scopes, defaults []string) error {
	if len(grants) == 0 || len(scopes) == 0 || len(defaults) == 0 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	allowedScopes := map[string]bool{"openid": true, "email": true, "profile": true, "groups": true, "offline_access": true, "goauthy.read": true, "goauthy.connections.read": true, "goauthy.connections.write": true, "goauthy.connections.use": true, "goauthy.providers.read": true, "goauthy.providers.write": true}
	scopeSeen := map[string]bool{}
	for _, scope := range scopes {
		if !allowedScopes[scope] || scopeSeen[scope] {
			return ErrInvalid
		}
		scopeSeen[scope] = true
	}
	for _, grant := range grants {
		if (grant != "password" && grant != "authorization_code" && grant != "refresh_token" && grant != "client_credentials" && grant != "urn:ietf:params:oauth:grant-type:device_code" && grant != "urn:ietf:params:oauth:grant-type:token-exchange") || seen[grant] {
			return ErrInvalid
		}
		seen[grant] = true
	}
	if !confidential && (contains(grants, "client_credentials") || contains(grants, "urn:ietf:params:oauth:grant-type:token-exchange")) {
		return ErrInvalid
	}
	for _, scope := range defaults {
		if !contains(scopes, scope) || seen["scope:"+scope] {
			return ErrInvalid
		}
		seen["scope:"+scope] = true
	}
	if contains(grants, "authorization_code") || len(redirects) != 0 {
		return validateRedirects(redirects)
	}
	return nil
}
func contains(v []string, w string) bool {
	for _, x := range v {
		if x == w {
			return true
		}
	}
	return false
}
func validateAudiences(values []string) error {
	if len(values) > 32 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, raw := range values {
		if len(raw) == 0 || len(raw) > 2048 || strings.TrimSpace(raw) != raw || seen[raw] {
			return ErrInvalid
		}
		seen[raw] = true
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Hostname() == "" || strings.ContainsAny(raw, "# \t\r\n") {
			return ErrInvalid
		}
	}
	return nil
}
func validateRedirects(v []string) error {
	if len(v) == 0 || len(v) > 32 {
		return ErrInvalid
	}
	seen := make(map[string]bool, len(v))
	for _, raw := range v {
		u, e := url.Parse(raw)
		if e != nil || len(raw) > 2048 || seen[raw] || strings.ContainsAny(raw, "*#") || u.User != nil || u.Opaque != "" || u.Hostname() == "" || u.Path == "" {
			return ErrInvalid
		}
		seen[raw] = true
		if u.Scheme != "https" {
			ip := net.ParseIP(u.Hostname())
			if u.Scheme != "http" || !(u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()) {
				return ErrInvalid
			}
		}
	}
	return nil
}

var _ fosite.Client = (*Client)(nil)
