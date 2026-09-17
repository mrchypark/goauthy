package saas

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrUseGrantInvalid  = errors.New("invalid SaaS use grant")
	ErrUseGrantNotFound = errors.New("SaaS use grant not found")
	ErrUseGrantConflict = errors.New("SaaS use grant conflict")
)

type UseGrantInput struct {
	ConsumerClientID          string  `json:"consumer_client_id"`
	Mode                      string  `json:"mode"`
	Purpose                   string  `json:"purpose"`
	ExpiresAt                 int64   `json:"expires_at_unix_ms"`
	ReviewedConnectorDigest   *string `json:"connector_digest,omitempty"`
	ReviewedCredentialVersion *int64  `json:"credential_version,omitempty"`
	AllowRefresh              bool    `json:"allow_refresh,omitempty"`
}

// UseGrant is consent metadata, not a bearer capability or a credential.
type UseGrant struct {
	ID                 string `json:"id"`
	Owner              string `json:"owner_subject"`
	CollectionID       string `json:"collection_id"`
	ConnectionID       string `json:"connection_id"`
	ConsumerClientID   string `json:"consumer_client_id"`
	Mode               string `json:"mode"`
	Purpose            string `json:"purpose"`
	Resource           string `json:"resource"`
	Generation         string `json:"generation"`
	ConsumerGeneration string `json:"consumer_generation"`
	ProviderID         string `json:"provider_id"`
	ConnectorDigest    string `json:"connector_digest"`
	Revision           int64  `json:"revision"`
	ProviderRevision   int64  `json:"provider_revision"`
	ExpiresAt          int64  `json:"expires_at_unix_ms"`
	Revoked            bool   `json:"revoked"`
	AllowRefresh       bool   `json:"allow_refresh,omitempty"`
}

func validGrantResource(v string) bool {
	u, e := url.Parse(v)
	return e == nil && len(v) <= 2048 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && !strings.Contains(v, "#") && !strings.ContainsFunc(v, unicode.IsSpace)
}
func (s *CredentialStore) validUseTarget(ctx context.Context, o, c, id string) bool {
	return ctx != nil && s != nil && s.db != nil && validText(o) && validText(c) && validText(id)
}

const useGrantColumns = `id,owner_subject,collection_id,connection_id,consumer_client_id,mode,purpose,resource,generation,consumer_generation,provider_id,connector_digest,revision,provider_revision,expires_at_unix_ms,revoked,allow_refresh`
const usePolicyWithoutState = ` FROM auth_collection_connections c
JOIN auth_collection_definitions d ON d.id=c.collection_id
JOIN identity_users u ON u.subject=c.owner_subject
JOIN saas_connection_credentials x ON x.connection_id=c.id AND x.owner_subject=c.owner_subject AND x.collection_id=c.collection_id AND x.generation=c.generation
JOIN managed_oauth_clients m ON m.id=?
LEFT JOIN saas_providers p ON p.id=x.provider_id AND EXISTS(SELECT 1 FROM json_each(d.providers_json) pp WHERE pp.type='text' AND pp.value=x.provider_id)
WHERE c.owner_subject=? AND c.collection_id=? AND c.id=? AND d.enabled=1 AND d.deleted=0
AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?)
AND m.enabled=1 AND m.deleted=0
AND EXISTS(SELECT 1 FROM json_each(m.metadata_json,'$.scopes') s WHERE s.type='text' AND s.value='goauthy.connections.use')
AND EXISTS(SELECT 1 FROM json_each(m.metadata_json,'$.audience') a WHERE a.type='text' AND a.value=?)
AND (?='proxy' OR json_extract(m.metadata_json,'$.confidential')=1)
AND ((d.auth_method='api_key' AND ((x.provider_id='api-key' AND json_array_length(d.providers_json)=0) OR
(json_array_length(d.providers_json)=1 AND p.kind='api_key' AND p.enabled=1 AND p.deleted=0))) OR
(d.auth_method='oauth2' AND p.kind='oauth2' AND p.enabled=1 AND p.deleted=0
AND EXISTS(SELECT 1 FROM json_each(d.providers_json) pp WHERE pp.type='text' AND pp.value=x.provider_id)))`

const usePolicyFrom = usePolicyWithoutState + ` AND x.state='ready'`

func (s *CredentialStore) usePolicyArgs(g UseGrant) []any {
	return []any{g.ConsumerClientID, g.Owner, g.CollectionID, g.ConnectionID, s.now(), g.Resource, g.Mode}
}

func validUseCredential(g UseGrant, v credential, method string, connectorJSON any) bool {
	if method == "oauth2" {
		return g.ConnectorDigest == "" && v.AccessToken != ""
	}
	if method != "api_key" || v.APIKey == "" || !validAuthorizationDigest(g.ConnectorDigest) || g.ConnectorDigest != v.ConnectorDigest {
		return false
	}
	if g.ProviderRevision == 0 {
		return g.ProviderID == apiKeyProviderID
	}
	raw, ok := connectorJSON.(string)
	var cfg APIKeyConnectorConfig
	if !ok || json.Unmarshal([]byte(raw), &cfg) != nil || cfg.ID != g.ProviderID {
		return false
	}
	connector, err := NewAPIKeyConnector(cfg)
	return err == nil && connector.Digest() == g.ConnectorDigest
}
func (s *CredentialStore) usePolicy(g UseGrant, version int64) (string, []any) {
	return s.useStatePolicy(g, version, false)
}

func (s *CredentialStore) useStatePolicy(g UseGrant, version int64, refreshing bool) (string, []any) {
	a := append(s.usePolicyArgs(g), g.Generation, g.ConsumerGeneration, g.ProviderID, g.ProviderRevision)
	from := usePolicyFrom
	if refreshing {
		// Only delegated refresh uses this policy. Load/Claim/CompleteRefresh
		// independently enforce their exact state, version and claim transitions.
		from = usePolicyWithoutState + ` AND x.state IN ('ready','refreshing')`
	}
	q := `EXISTS(SELECT 1` + from + ` AND c.generation=? AND m.generation=? AND x.provider_id=? AND COALESCE(p.revision,0)=?`
	if version > 0 {
		q += ` AND x.token_version=?`
		a = append(a, version)
	}
	return q + `)`, a
}
func decodeUseGrant(r []any) (UseGrant, error) {
	var g UseGrant
	if len(r) != 17 {
		return g, ErrUseGrantInvalid
	}
	for i, p := range []*string{&g.ID, &g.Owner, &g.CollectionID, &g.ConnectionID, &g.ConsumerClientID, &g.Mode, &g.Purpose, &g.Resource, &g.Generation, &g.ConsumerGeneration, &g.ProviderID, &g.ConnectorDigest} {
		v, ok := r[i].(string)
		if !ok {
			return UseGrant{}, ErrUseGrantInvalid
		}
		*p = v
	}
	for i, p := range []*int64{&g.Revision, &g.ProviderRevision, &g.ExpiresAt} {
		v, ok := r[i+12].(int64)
		if !ok {
			return UseGrant{}, ErrUseGrantInvalid
		}
		*p = v
	}
	v, ok := r[15].(int64)
	if !ok || v < 0 || v > 1 {
		return UseGrant{}, ErrUseGrantInvalid
	}
	g.Revoked = v == 1
	v, ok = r[16].(int64)
	if !ok || v < 0 || v > 1 {
		return UseGrant{}, ErrUseGrantInvalid
	}
	g.AllowRefresh = v == 1
	return g, nil
}
func (s *CredentialStore) CreateUseGrant(ctx context.Context, owner, collection, connection, resource string, in UseGrantInput, authority func() (string, []any)) (UseGrant, error) {
	return s.createUseGrant(ctx, owner, collection, connection, resource, in, authority, "")
}

func (s *CredentialStore) createUseGrant(ctx context.Context, owner, collection, connection, resource string, in UseGrantInput, authority func() (string, []any), handoffHash string) (UseGrant, error) {
	if !s.validUseTarget(ctx, owner, collection, connection) || !validText(in.ConsumerClientID) || !validGrantResource(resource) || in.Mode != "proxy" && in.Mode != "credential_delivery" || in.Purpose == "" || strings.TrimSpace(in.Purpose) != in.Purpose || !utf8.ValidString(in.Purpose) || len(in.Purpose) > 256 || strings.ContainsFunc(in.Purpose, unicode.IsControl) {
		return UseGrant{}, ErrUseGrantInvalid
	}
	now := s.now()
	if in.ExpiresAt <= now || in.ExpiresAt-now > int64((30*24*time.Hour)/time.Millisecond) {
		return UseGrant{}, ErrUseGrantInvalid
	}
	auth, aa, e := authorityGuard(authority)
	if e != nil {
		return UseGrant{}, e
	}
	g := UseGrant{Owner: owner, CollectionID: collection, ConnectionID: connection, ConsumerClientID: in.ConsumerClientID, Mode: in.Mode, Purpose: in.Purpose, Resource: resource, Revision: 1, ExpiresAt: in.ExpiresAt, AllowRefresh: in.AllowRefresh}
	q, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT c.generation,m.generation,x.provider_id,COALESCE(p.revision,0),x.token_version,x.credential,d.auth_method,p.connector_json` + usePolicyFrom + ` AND (` + auth + `)`, Args: append(s.usePolicyArgs(g), aa...), Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return UseGrant{}, e
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 8 {
		return UseGrant{}, ErrUseGrantNotFound
	}
	r := q.Rows[0]
	var ok bool
	if g.Generation, ok = r[0].(string); !ok {
		return UseGrant{}, ErrUseGrantInvalid
	}
	if g.ConsumerGeneration, ok = r[1].(string); !ok {
		return UseGrant{}, ErrUseGrantInvalid
	}
	if g.ProviderID, ok = r[2].(string); !ok {
		return UseGrant{}, ErrUseGrantInvalid
	}
	if g.ProviderRevision, ok = r[3].(int64); !ok {
		return UseGrant{}, ErrUseGrantInvalid
	}
	version, ok := r[4].(int64)
	if !ok || version < 1 {
		return UseGrant{}, ErrUseGrantInvalid
	}
	env, ok := r[5].([]byte)
	if !ok {
		return UseGrant{}, ErrUseGrantInvalid
	}
	v, e := openCredential(s.keys, credentialBinding{Owner: owner, CollectionID: collection, ConnectionID: connection, ProviderID: g.ProviderID, Generation: g.Generation, TokenVersion: version}, env)
	if e != nil {
		return UseGrant{}, e
	}
	method, _ := r[6].(string)
	if in.AllowRefresh && (method != "oauth2" || in.Mode != "credential_delivery") {
		return UseGrant{}, ErrUseGrantInvalid
	}
	if method == "api_key" {
		g.ConnectorDigest = v.ConnectorDigest
	}
	if in.ReviewedCredentialVersion != nil {
		if *in.ReviewedCredentialVersion < 1 || method != "oauth2" {
			return UseGrant{}, ErrUseGrantInvalid
		}
		if *in.ReviewedCredentialVersion != version {
			return UseGrant{}, ErrUseGrantConflict
		}
	}
	if in.ReviewedConnectorDigest != nil {
		if !validAuthorizationDigest(*in.ReviewedConnectorDigest) || method != "api_key" {
			return UseGrant{}, ErrUseGrantInvalid
		}
		if *in.ReviewedConnectorDigest != g.ConnectorDigest {
			return UseGrant{}, ErrUseGrantConflict
		}
	}
	if !validUseCredential(g, v, method, r[7]) {
		return UseGrant{}, ErrUseGrantInvalid
	}
	g.ID = randomCredentialClaim()
	if g.ID == "" {
		return UseGrant{}, ErrUseGrantInvalid
	}
	policy, pa := s.usePolicy(g, version)
	auth, aa, e = authorityGuard(authority)
	if e != nil {
		return UseGrant{}, e
	}
	a := []any{g.ID, owner, collection, connection, g.ConsumerClientID, g.Mode, g.Purpose, g.Resource, g.Generation, g.ConsumerGeneration, g.ProviderID, g.ConnectorDigest, g.Revision, g.ProviderRevision, g.ExpiresAt, int64(0), g.AllowRefresh}
	a = append(a, pa...)
	a = append(a, aa...)
	a = append(a, in.ExpiresAt, s.now(), owner, collection, connection, s.now())
	request := rhiza.ExecuteRequest{RequestID: "saas-use-grant-create-" + g.ID, SQL: `INSERT INTO saas_use_grants (` + useGrantColumns + `) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE ` + policy + ` AND (` + auth + `) AND ?>? AND (SELECT COUNT(*) FROM saas_use_grants WHERE owner_subject=? AND collection_id=? AND connection_id=? AND revoked=0 AND expires_at_unix_ms>?)<32`, Args: a}
	if handoffHash != "" {
		// Both statements share one Rhiza transaction. The supplied authority
		// requires this pending handoff; a losing concurrent approval inserts nothing.
		request.Statements = []rhiza.SQLStatement{{SQL: request.SQL, Args: request.Args}, {SQL: `UPDATE saas_use_handoffs SET state='approved',grant_id=? WHERE id_hash=? AND state='pending' AND EXISTS(SELECT 1 FROM saas_use_grants WHERE id=?) RETURNING grant_id`, Args: []any{g.ID, handoffHash, g.ID}, WantRows: true}}
		request.SQL = ""
		request.Args = nil
	}
	res, e := storage.Execute(ctx, s.db, request)
	if e != nil {
		return UseGrant{}, e
	}
	if (handoffHash == "" && res.RowsAffected != 1) || (handoffHash != "" && (len(res.Statements) != 2 || res.Statements[0].RowsAffected != 1 || len(res.Statements[1].Rows) != 1 || len(res.Statements[1].Rows[0]) != 1 || res.Statements[1].Rows[0][0] != g.ID)) {
		return UseGrant{}, ErrUseGrantConflict
	}
	return g, nil
}
func (s *CredentialStore) useOwnerGuard(o, c, id string) (string, []any) {
	return `EXISTS(SELECT 1 FROM auth_collection_connections c JOIN identity_users u ON u.subject=c.owner_subject WHERE c.owner_subject=? AND c.collection_id=? AND c.id=? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?))`, []any{o, c, id, s.now()}
}
func (s *CredentialStore) ListUseGrants(ctx context.Context, o, c, id string, authority func() (string, []any)) ([]UseGrant, error) {
	if !s.validUseTarget(ctx, o, c, id) {
		return nil, ErrUseGrantInvalid
	}
	auth, aa, e := authorityGuard(authority)
	if e != nil {
		return nil, e
	}
	parent, pa := s.useOwnerGuard(o, c, id)
	q, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT ` + useGrantColumns + ` FROM saas_use_grants WHERE owner_subject=? AND collection_id=? AND connection_id=? AND ` + parent + ` AND (` + auth + `) ORDER BY expires_at_unix_ms DESC,id LIMIT 256`, Args: append(append([]any{o, c, id}, pa...), aa...), Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return nil, e
	}
	out := make([]UseGrant, 0, len(q.Rows))
	for _, r := range q.Rows {
		g, e := decodeUseGrant(r)
		if e != nil {
			return nil, e
		}
		out = append(out, g)
	}
	return out, nil
}
func (s *CredentialStore) RevokeUseGrant(ctx context.Context, o, c, connection, id string, revision int64, authority func() (string, []any)) error {
	if !s.validUseTarget(ctx, o, c, connection) || !validText(id) || revision < 1 || revision == 1<<63-1 {
		return ErrUseGrantInvalid
	}
	auth, aa, e := authorityGuard(authority)
	if e != nil {
		return e
	}
	parent, pa := s.useOwnerGuard(o, c, connection)
	entropy := randomCredentialClaim()
	if entropy == "" {
		return ErrUseGrantInvalid
	}
	a := append([]any{id, o, c, connection, revision}, pa...)
	a = append(a, aa...)
	q, e := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "saas-use-grant-revoke-" + entropy, SQL: `UPDATE saas_use_grants SET revoked=1,revision=revision+1 WHERE id=? AND owner_subject=? AND collection_id=? AND connection_id=? AND revision=? AND revoked=0 AND ` + parent + ` AND (` + auth + `)`, Args: a})
	if e != nil {
		return e
	}
	if q.RowsAffected != 1 {
		return ErrUseGrantConflict
	}
	return nil
}

// loadUseGrant checks stored consent only. Callers must also check the current
// connection/provider/client policy at the subsequent credential operation.
func (s *CredentialStore) loadUseGrant(ctx context.Context, o, consumer, id, resource, mode string, authority func() (string, []any)) (UseGrant, string, []any, error) {
	if ctx == nil || s == nil || s.db == nil || !validText(o) || !validText(consumer) || !validText(id) || !validGrantResource(resource) || mode != "proxy" && mode != "credential_delivery" {
		return UseGrant{}, "", nil, ErrUseGrantInvalid
	}
	auth, aa, e := authorityGuard(authority)
	if e != nil {
		return UseGrant{}, "", nil, e
	}
	q, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT ` + useGrantColumns + ` FROM saas_use_grants WHERE id=? AND owner_subject=? AND consumer_client_id=? AND resource=? AND mode=? AND revoked=0 AND expires_at_unix_ms>? AND (` + auth + `)`, Args: append([]any{id, o, consumer, resource, mode, s.now()}, aa...), Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return UseGrant{}, "", nil, e
	}
	if len(q.Rows) != 1 {
		return UseGrant{}, "", nil, ErrUseGrantNotFound
	}
	g, e := decodeUseGrant(q.Rows[0])
	return g, auth, aa, e
}

// AuthorizeUseGrant's guard is required at the subsequent credential read/use.
// Credential version fences that one use, not the lifetime of stored consent.
func (s *CredentialStore) AuthorizeUseGrant(ctx context.Context, o, consumer, id, resource, mode string, authority func() (string, []any)) (UseGrant, func() (string, []any), error) {
	g, auth, aa, e := s.loadUseGrant(ctx, o, consumer, id, resource, mode, authority)
	if e != nil {
		return UseGrant{}, nil, e
	}
	policy, pa := s.usePolicy(g, 0)
	q, e := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT x.token_version,x.credential,d.auth_method,p.connector_json FROM saas_connection_credentials x JOIN auth_collection_definitions d ON d.id=x.collection_id LEFT JOIN saas_providers p ON p.id=x.provider_id WHERE x.connection_id=? AND ` + policy + ` AND (` + auth + `)`, Args: append(append([]any{g.ConnectionID}, pa...), aa...), Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return UseGrant{}, nil, e
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 4 {
		return UseGrant{}, nil, ErrUseGrantNotFound
	}
	version, ok := q.Rows[0][0].(int64)
	if !ok || version < 1 {
		return UseGrant{}, nil, ErrUseGrantInvalid
	}
	env, ok := q.Rows[0][1].([]byte)
	if !ok {
		return UseGrant{}, nil, ErrUseGrantInvalid
	}
	v, e := openCredential(s.keys, credentialBinding{Owner: g.Owner, CollectionID: g.CollectionID, ConnectionID: g.ConnectionID, ProviderID: g.ProviderID, Generation: g.Generation, TokenVersion: version}, env)
	if e != nil {
		return UseGrant{}, nil, e
	}
	method, _ := q.Rows[0][2].(string)
	if !validUseCredential(g, v, method, q.Rows[0][3]) {
		return UseGrant{}, nil, ErrUseGrantNotFound
	}
	guard := func() (string, []any) {
		auth, aa, e := authorityGuard(authority)
		if e != nil {
			return "0", nil
		}
		policy, pa := s.usePolicy(g, version)
		a := append([]any{g.ID, g.Revision, s.now()}, pa...)
		a = append(a, aa...)
		return `EXISTS(SELECT 1 FROM saas_use_grants WHERE id=? AND revision=? AND revoked=0 AND expires_at_unix_ms>?) AND ` + policy + ` AND (` + auth + `)`, a
	}
	check, ca := guard()
	q, e = s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 WHERE ` + check, Args: ca, Consistency: rhiza.ConsistencyLinearizable})
	if e != nil {
		return UseGrant{}, nil, e
	}
	if len(q.Rows) != 1 {
		return UseGrant{}, nil, ErrUseGrantNotFound
	}
	return g, guard, nil
}
