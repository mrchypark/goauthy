package saas

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"golang.org/x/oauth2"
)

var (
	ErrProviderInvalid      = errors.New("invalid SaaS provider")
	ErrProviderNotFound     = errors.New("SaaS provider not found")
	ErrProviderConflict     = errors.New("SaaS provider conflict")
	ErrProviderUnauthorized = errors.New("SaaS provider unauthorized")
	ErrProviderInUse        = errors.New("SaaS provider is in use")
)

type Provider struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Kind             string                 `json:"kind"`
	Enabled          bool                   `json:"enabled"`
	Revision         int64                  `json:"revision"`
	CallbackURI      string                 `json:"callback_uri"`
	ClientID         string                 `json:"client_id,omitempty"`
	AuthorizationURL string                 `json:"auth_endpoint,omitempty"`
	TokenURL         string                 `json:"token_endpoint,omitempty"`
	Scopes           []string               `json:"scopes"`
	AuthStyle        string                 `json:"auth_style,omitempty"`
	IdentityEndpoint string                 `json:"identity_endpoint,omitempty"`
	SubjectField     string                 `json:"subject_field,omitempty"`
	Connector        *APIKeyConnectorConfig `json:"connector,omitempty"`
}

type ProviderInput struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Kind             string                 `json:"kind"`
	Enabled          bool                   `json:"enabled"`
	ClientID         string                 `json:"client_id"`
	ClientSecret     string                 `json:"client_secret"`
	CallbackURI      string                 `json:"callback_uri"`
	AuthorizationURL string                 `json:"auth_endpoint"`
	TokenURL         string                 `json:"token_endpoint"`
	Scopes           []string               `json:"scopes"`
	AuthStyle        string                 `json:"auth_style"`
	IdentityEndpoint string                 `json:"identity_endpoint"`
	SubjectField     string                 `json:"subject_field"`
	Connector        *APIKeyConnectorConfig `json:"connector"`
}

type ProviderStore struct {
	db   *rhiza.DB
	keys *oidc.Keyring
}

func NewProviderStore(db *rhiza.DB, keys *oidc.Keyring) (*ProviderStore, error) {
	if db == nil || keys == nil {
		return nil, ErrProviderInvalid
	}
	if _, err := keys.ActiveMasterKeyID(); err != nil {
		return nil, err
	}
	return &ProviderStore{db: db, keys: keys}, nil
}

func providerGuard(authority func() (string, []any)) (string, []any, error) {
	if authority == nil {
		return "", nil, ErrProviderUnauthorized
	}
	g, a := authority()
	if strings.TrimSpace(g) == "" {
		return "", nil, ErrProviderUnauthorized
	}
	return "(" + g + ")", a, nil
}

func validateProviderInput(in ProviderInput, requireSecret bool) (string, error) {
	if !providerID(in.ID) || len(in.Name) == 0 || len(in.Name) > 256 || strings.TrimSpace(in.Name) != in.Name || in.Kind != "oauth2" && in.Kind != "api_key" || len(in.CallbackURI) > 2048 || strings.ContainsAny(in.CallbackURI, "\x00\r\n") {
		return "", ErrProviderInvalid
	}
	if in.Kind == "oauth2" {
		if in.Connector != nil {
			return "", ErrProviderInvalid
		}
		if requireSecret && !validText(in.ClientSecret) || !validText(in.ClientID) || !validCallback(in.CallbackURI) || !oauthEndpoint(in.AuthorizationURL) || !oauthEndpoint(in.TokenURL) || len(in.Scopes) == 0 || len(in.Scopes) > 64 || (in.AuthStyle != "header" && in.AuthStyle != "params") {
			return "", ErrProviderInvalid
		}
		style := oauth2.AuthStyleInHeader
		if in.AuthStyle == "params" {
			style = oauth2.AuthStyleInParams
		}
		if _, err := NewOAuth2(OAuth2Config{ClientID: in.ClientID, AuthorizationURL: in.AuthorizationURL, TokenURL: in.TokenURL, CallbackURL: in.CallbackURI, Scopes: in.Scopes, AuthStyle: style, IdentityEndpoint: in.IdentityEndpoint, SubjectField: in.SubjectField}, in.ClientSecretOrPlaceholder(requireSecret)); err != nil {
			return "", ErrProviderInvalid
		}
		b, _ := json.Marshal(in.Scopes)
		return string(b), nil
	}
	if in.CallbackURI != "" {
		return "", ErrProviderInvalid
	}
	if in.IdentityEndpoint != "" || in.SubjectField != "" {
		return "", ErrProviderInvalid
	}
	if in.ClientID != "" || in.ClientSecret != "" || in.AuthorizationURL != "" || in.TokenURL != "" || len(in.Scopes) != 0 || in.AuthStyle != "" {
		return "", ErrProviderInvalid
	}
	if in.Connector == nil {
		return "", ErrProviderInvalid
	}
	if _, err := NewAPIKeyConnector(*in.Connector); err != nil {
		return "", ErrProviderInvalid
	}
	if in.Connector.ID != in.ID {
		return "", ErrProviderInvalid
	}
	return "[]", nil
}

func (in ProviderInput) ClientSecretOrPlaceholder(required bool) string {
	if in.ClientSecret != "" {
		return in.ClientSecret
	}
	if !required {
		return "placeholder-secret-16"
	}
	return ""
}

func (s *ProviderStore) Create(ctx context.Context, in ProviderInput, authority func() (string, []any)) (Provider, error) {
	if ctx == nil || s == nil || s.db == nil || s.keys == nil {
		return Provider{}, ErrProviderInvalid
	}
	scopes, err := validateProviderInput(in, true)
	if err != nil {
		return Provider{}, err
	}
	g, ga, err := providerGuard(authority)
	if err != nil {
		return Provider{}, err
	}
	gen := randomCredentialClaim()
	if gen == "" {
		return Provider{}, ErrProviderInvalid
	}
	secret := []byte(nil)
	if in.Kind == "oauth2" {
		secret = []byte(in.ClientSecret)
	}
	envelope, err := s.sealSecret(in.ID, gen, secret)
	if err != nil {
		return Provider{}, err
	}
	var envelopeValue any
	if len(envelope) != 0 {
		envelopeValue = envelope
	}
	args := []any{in.ID, in.Name, in.Kind, boolInt(in.Enabled), int64(1), in.CallbackURI, in.ClientID, in.AuthorizationURL, in.TokenURL, scopes, in.AuthStyle, in.IdentityEndpoint, in.SubjectField, connectorJSON(in), gen, envelopeValue, in.ID}
	args = append(args, ga...)
	active, err := s.keys.ActiveMasterKeyID()
	if err != nil {
		return Provider{}, err
	}
	requestID := randomCredentialClaim()
	if requestID == "" {
		return Provider{}, ErrProviderInvalid
	}
	r, err := storage.ExecuteEnvelope(ctx, s.db, active, rhiza.ExecuteRequest{RequestID: "saas-provider-create-" + requestID, SQL: `INSERT INTO saas_providers(id,name,kind,enabled,revision,callback_uri,client_id,auth_endpoint,token_endpoint,scopes_json,auth_style,identity_endpoint,subject_field,connector_json,generation,secret_envelope) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM saas_providers WHERE id=?) AND (SELECT COUNT(*) FROM saas_providers WHERE deleted=0) < 32 AND (` + g + `)`, Args: args})
	if err != nil {
		return Provider{}, err
	}
	if r.MutationReceipt.RowsAffected != 1 {
		return Provider{}, ErrProviderConflict
	}
	return providerFromInput(in, 1), nil
}

func (s *ProviderStore) Get(ctx context.Context, id string, authority func() (string, []any)) (Provider, error) {
	return s.get(ctx, id, authority)
}
func (s *ProviderStore) List(ctx context.Context, authority func() (string, []any)) ([]Provider, error) {
	if ctx == nil || s == nil || s.db == nil {
		return nil, ErrProviderInvalid
	}
	g, ga, err := providerGuard(authority)
	if err != nil {
		return nil, err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `WITH authorized AS (SELECT 1 WHERE ` + g + `)
		SELECT id,name,kind,enabled,revision,callback_uri,client_id,auth_endpoint,token_endpoint,scopes_json,auth_style,identity_endpoint,subject_field,connector_json FROM saas_providers WHERE deleted=0 AND EXISTS(SELECT 1 FROM authorized)
		UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL WHERE NOT EXISTS(SELECT 1 FROM authorized)
		ORDER BY id LIMIT 33`, Args: ga, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	if len(q.Rows) > 32 {
		return nil, ErrProviderConflict
	}
	out := make([]Provider, 0, len(q.Rows))
	for _, row := range q.Rows {
		if len(row) == 14 && row[0] == nil {
			return nil, ErrProviderUnauthorized
		}
		p, e := decodeProvider(row)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *ProviderStore) get(ctx context.Context, id string, authority func() (string, []any)) (Provider, error) {
	g, ga, err := providerGuard(authority)
	if err != nil {
		return Provider{}, err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,name,kind,enabled,revision,callback_uri,client_id,auth_endpoint,token_endpoint,scopes_json,auth_style,identity_endpoint,subject_field,connector_json FROM saas_providers WHERE id=? AND deleted=0 AND (` + g + `)`, Args: append([]any{id}, ga...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Provider{}, err
	}
	if len(q.Rows) != 1 {
		return Provider{}, ErrProviderNotFound
	}
	return decodeProvider(q.Rows[0])
}

func (s *ProviderStore) Update(ctx context.Context, id string, revision int64, in ProviderInput, authority func() (string, []any)) (Provider, error) {
	if ctx == nil || s == nil || s.db == nil || s.keys == nil || id != in.ID || revision < 1 {
		return Provider{}, ErrProviderInvalid
	}
	old, err := s.get(ctx, id, authority)
	if err != nil {
		return Provider{}, err
	}
	if old.Kind != in.Kind {
		return Provider{}, ErrProviderInvalid
	}
	if old.Revision != revision {
		return Provider{}, ErrProviderConflict
	}
	scopes, err := validateProviderInput(in, in.ClientSecret != "")
	if err != nil {
		return Provider{}, err
	}
	g, ga, err := providerGuard(authority)
	if err != nil {
		return Provider{}, err
	}
	gen := randomCredentialClaim()
	if gen == "" {
		return Provider{}, ErrProviderInvalid
	}
	env, err := s.sealSecret(in.ID, gen, []byte(in.ClientSecret))
	if err != nil {
		return Provider{}, err
	}
	if in.ClientSecret == "" {
		env = nil
	}
	args := []any{in.Name, boolInt(in.Enabled), revision + 1, in.CallbackURI, in.ClientID, in.AuthorizationURL, in.TokenURL, scopes, in.AuthStyle, in.IdentityEndpoint, in.SubjectField, connectorJSON(in)}
	secretSQL := ""
	if in.ClientSecret != "" {
		args = append(args, gen, env)
		secretSQL = ",generation=?,secret_envelope=?"
	}
	args = append(args, id, revision, old.Kind)
	args = append(args, ga...)
	sql := `UPDATE saas_providers SET name=?,enabled=?,revision=?,callback_uri=?,client_id=?,auth_endpoint=?,token_endpoint=?,scopes_json=?,auth_style=?,identity_endpoint=?,subject_field=?,connector_json=?` + secretSQL + ` WHERE id=? AND revision=? AND deleted=0 AND kind=? AND NOT EXISTS(SELECT 1 FROM auth_collection_definitions d WHERE d.deleted=0 AND EXISTS(SELECT 1 FROM json_each(d.providers_json) p WHERE p.type='text' AND p.value=saas_providers.id)) AND (` + g + `)`
	active, err := s.keys.ActiveMasterKeyID()
	if err != nil {
		return Provider{}, err
	}
	requestID := randomCredentialClaim()
	if requestID == "" {
		return Provider{}, ErrProviderInvalid
	}
	r, err := storage.ExecuteEnvelope(ctx, s.db, active, rhiza.ExecuteRequest{RequestID: "saas-provider-update-" + requestID, SQL: sql, Args: args})
	if err != nil {
		return Provider{}, err
	}
	if r.MutationReceipt.RowsAffected != 1 {
		return Provider{}, ErrProviderConflict
	}
	return providerFromInput(in, revision+1), nil
}

func (s *ProviderStore) Delete(ctx context.Context, id string, revision int64, authority func() (string, []any)) error {
	if ctx == nil || s == nil || s.db == nil || revision < 1 {
		return ErrProviderInvalid
	}
	g, ga, err := providerGuard(authority)
	if err != nil {
		return err
	}
	args := append([]any{id, revision}, ga...)
	requestID := randomCredentialClaim()
	if requestID == "" {
		return ErrProviderInvalid
	}
	r, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "saas-provider-delete-" + requestID, SQL: `UPDATE saas_providers SET deleted=1,enabled=0,revision=revision+1 WHERE id=? AND revision=? AND deleted=0 AND NOT EXISTS(SELECT 1 FROM auth_collection_definitions d WHERE d.deleted=0 AND EXISTS(SELECT 1 FROM json_each(d.providers_json) p WHERE p.type='text' AND p.value=saas_providers.id)) AND (` + g + `)`, Args: args})
	if err != nil {
		return err
	}
	if r.MutationReceipt.RowsAffected != 1 {
		return ErrProviderConflict
	}
	return nil
}

func (s *ProviderStore) sealSecret(id, gen string, plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}
	return s.keys.SealEnvelope(providerSecretPurpose(id, gen), plain)
}
func providerID(id string) bool {
	if len(id) == 0 || len(id) > 64 || id[0] == '-' || id[0] == '_' {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func connectorJSON(in ProviderInput) string {
	if in.Connector == nil {
		return ""
	}
	b, _ := json.Marshal(in.Connector)
	return string(b)
}
func boolInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func providerFromInput(in ProviderInput, rev int64) Provider {
	return Provider{ID: in.ID, Name: in.Name, Kind: in.Kind, Enabled: in.Enabled, Revision: rev, CallbackURI: in.CallbackURI, ClientID: in.ClientID, AuthorizationURL: in.AuthorizationURL, TokenURL: in.TokenURL, Scopes: append([]string{}, in.Scopes...), AuthStyle: in.AuthStyle, IdentityEndpoint: in.IdentityEndpoint, SubjectField: in.SubjectField, Connector: in.Connector}
}
func decodeProvider(row []any) (Provider, error) {
	if len(row) != 14 {
		return Provider{}, ErrProviderInvalid
	}
	p := Provider{}
	var ok bool
	p.ID, ok = row[0].(string)
	if !ok {
		return Provider{}, ErrProviderInvalid
	}
	p.Name, _ = row[1].(string)
	p.Kind, _ = row[2].(string)
	e, _ := row[3].(int64)
	p.Enabled = e == 1
	p.Revision, _ = row[4].(int64)
	p.CallbackURI, _ = row[5].(string)
	p.ClientID, _ = row[6].(string)
	p.AuthorizationURL, _ = row[7].(string)
	p.TokenURL, _ = row[8].(string)
	var scopes string
	scopes, _ = row[9].(string)
	if json.Unmarshal([]byte(scopes), &p.Scopes) != nil {
		return Provider{}, ErrProviderInvalid
	}
	p.AuthStyle, _ = row[10].(string)
	p.IdentityEndpoint, _ = row[11].(string)
	p.SubjectField, _ = row[12].(string)
	if raw, _ := row[13].(string); raw != "" {
		p.Connector = &APIKeyConnectorConfig{}
		if json.Unmarshal([]byte(raw), p.Connector) != nil {
			return Provider{}, ErrProviderInvalid
		}
	}
	return p, nil
}
