package saas

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type UseHandoffInput struct {
	CollectionID     string `json:"collection_id"`
	ConnectionID     string `json:"connection_id"`
	ConsumerClientID string `json:"consumer_client_id"`
	Mode             string `json:"mode"`
	Purpose          string `json:"purpose"`
	ExpiresAt        int64  `json:"expires_at_unix_ms"`
	ReturnURI        string `json:"return_uri"`
	State            string `json:"state"`
	AllowRefresh     bool   `json:"allow_refresh,omitempty"`
}

// Review is a proposal, not consent. Grant.ID remains empty until approval.
type UseHandoffReview struct {
	RequestClientID string              `json:"request_client_id"`
	ReturnURI       string              `json:"return_uri"`
	ExpiresAt       int64               `json:"expires_at_unix_ms"`
	Grant           UseGrant            `json:"grant"`
	Connector       APIKeyConnectorInfo `json:"connector"`
	OAuth2          *OAuth2Status       `json:"oauth2,omitempty"`
	ReviewDigest    string              `json:"review_digest"`
}

type useHandoff struct {
	Hash, Owner, RequestClient, RequestGeneration, ReturnURI, ReturnState string
	ExpiresAt                                                             int64
	Grant                                                                 UseGrant
	CredentialVersion                                                     int64
}

func (h useHandoff) reviewDigest() string {
	if h.CredentialVersion == 0 {
		return h.Grant.ConnectorDigest
	}
	// The version identifies immutable sealed account/scopes metadata. This is
	// a review commitment, not authorization; every use still checks authority.
	commitment := "oauth2-use-handoff:" + h.Hash + ":" + strconv.FormatInt(h.CredentialVersion, 10)
	if h.Grant.AllowRefresh {
		commitment += ":allow-refresh"
	}
	return authorizationDigest(commitment)
}

func handoffHash(id string) string {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(raw) != 18 || base64.RawURLEncoding.EncodeToString(raw) != id {
		return ""
	}
	hash := sha256.Sum256([]byte(id))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func validHandoffState(state string) bool {
	if len(state) < 32 || len(state) > 128 {
		return false
	}
	for _, c := range state {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *CredentialStore) handoffRequester(h useHandoff) (string, []any) {
	return `EXISTS(SELECT 1 FROM managed_oauth_clients m WHERE m.id=? AND m.generation=? AND m.enabled=1 AND m.deleted=0
		AND EXISTS(SELECT 1 FROM json_each(m.metadata_json,'$.redirect_uris') WHERE type='text' AND value=?)
		AND EXISTS(SELECT 1 FROM json_each(m.metadata_json,'$.scopes') WHERE type='text' AND value='goauthy.connections.write')
		AND EXISTS(SELECT 1 FROM json_each(m.metadata_json,'$.audience') WHERE type='text' AND value=?))`, []any{h.RequestClient, h.RequestGeneration, h.ReturnURI, h.Grant.Resource}
}

// CreateUseHandoff stores a bounded, expiring proposal from the authenticated app.
// The caller must retain its own session-bound state and expected review metadata.
func (s *CredentialStore) CreateUseHandoff(ctx context.Context, owner, requester, resource string, in UseHandoffInput, authority func() (string, []any)) (string, UseHandoffReview, error) {
	if !s.validUseTarget(ctx, owner, in.CollectionID, in.ConnectionID) || !validText(requester) || !validText(in.ConsumerClientID) || !validGrantResource(resource) || !validGrantResource(in.ReturnURI) || !validHandoffState(in.State) || in.Mode != "proxy" && in.Mode != "credential_delivery" || in.Purpose == "" || strings.TrimSpace(in.Purpose) != in.Purpose || len(in.Purpose) > 256 || !utf8.ValidString(in.Purpose) || strings.ContainsFunc(in.Purpose, unicode.IsControl) {
		return "", UseHandoffReview{}, ErrUseGrantInvalid
	}
	now := s.now()
	if in.ExpiresAt <= now || in.ExpiresAt-now > 30*24*60*60*1000 {
		return "", UseHandoffReview{}, ErrUseGrantInvalid
	}
	clientStore := clients.NewStore(s.db, s.keys)
	app, err := clientStore.GetWithGuard(ctx, requester, authority)
	if err != nil {
		return "", UseHandoffReview{}, err
	}
	if !app.Enabled || !slices.Contains(app.RedirectURIs, in.ReturnURI) {
		return "", UseHandoffReview{}, ErrUseGrantNotFound
	}
	auth, aa, err := authorityGuard(authority)
	if err != nil {
		return "", UseHandoffReview{}, err
	}
	g := UseGrant{Owner: owner, CollectionID: in.CollectionID, ConnectionID: in.ConnectionID, ConsumerClientID: in.ConsumerClientID, Mode: in.Mode, Purpose: in.Purpose, Resource: resource, Revision: 1, ExpiresAt: in.ExpiresAt, AllowRefresh: in.AllowRefresh}
	snapshot, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT c.generation,m.generation,x.provider_id,COALESCE(p.revision,0),x.token_version,d.auth_method` + usePolicyFrom + ` AND (` + auth + `)`, Args: append(s.usePolicyArgs(g), aa...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return "", UseHandoffReview{}, err
	}
	if len(snapshot.Rows) != 1 || len(snapshot.Rows[0]) != 6 {
		return "", UseHandoffReview{}, ErrUseGrantNotFound
	}
	row := snapshot.Rows[0]
	for i, target := range []*string{&g.Generation, &g.ConsumerGeneration, &g.ProviderID} {
		value, ok := row[i].(string)
		if !ok || value == "" {
			return "", UseHandoffReview{}, ErrUseGrantInvalid
		}
		*target = value
	}
	var ok bool
	g.ProviderRevision, ok = row[3].(int64)
	if !ok || g.ProviderRevision < 1 {
		return "", UseHandoffReview{}, ErrUseGrantNotFound
	}
	version, ok := row[4].(int64)
	if !ok || version < 1 {
		return "", UseHandoffReview{}, ErrUseGrantInvalid
	}
	method, _ := row[5].(string)
	if in.AllowRefresh && (method != "oauth2" || in.Mode != "credential_delivery") {
		return "", UseHandoffReview{}, ErrUseGrantInvalid
	}
	if method == "oauth2" && in.Mode != "credential_delivery" {
		return "", UseHandoffReview{}, ErrUseGrantInvalid
	}
	if method == "api_key" {
		binding, value, err := s.loadAPIKey(ctx, owner, in.CollectionID, in.ConnectionID, authority)
		if err != nil {
			return "", UseHandoffReview{}, err
		}
		if binding.Generation != g.Generation || binding.ProviderID != g.ProviderID || binding.TokenVersion != version {
			return "", UseHandoffReview{}, ErrUseGrantConflict
		}
		g.ConnectorDigest = value.ConnectorDigest
	} else if method != "oauth2" {
		return "", UseHandoffReview{}, ErrUseGrantInvalid
	}
	id := randomCredentialClaim()
	if id == "" {
		return "", UseHandoffReview{}, ErrUseGrantInvalid
	}
	h := useHandoff{Hash: handoffHash(id), Owner: owner, RequestClient: requester, RequestGeneration: app.Generation, ReturnURI: in.ReturnURI, ReturnState: in.State, ExpiresAt: min(now+5*60*1000, in.ExpiresAt), Grant: g}
	if method == "oauth2" {
		h.CredentialVersion = version
	}
	policy, pa := s.usePolicy(h.Grant, version)
	requestPolicy, ra := s.handoffRequester(h)
	review, err := s.reviewHandoffCredential(ctx, h, func() (string, []any) {
		return policy + ` AND (` + auth + `)`, append(append([]any{}, pa...), aa...)
	})
	if err != nil {
		return "", UseHandoffReview{}, err
	}
	auth, aa, err = authorityGuard(authority)
	if err != nil {
		return "", UseHandoffReview{}, err
	}
	args := []any{h.Hash, h.Owner, h.RequestClient, h.RequestGeneration, g.CollectionID, g.ConnectionID, g.Generation, g.ConsumerClientID, g.ConsumerGeneration, g.ProviderID, g.ProviderRevision, g.ConnectorDigest, g.Resource, g.Mode, g.Purpose, g.ExpiresAt, h.ReturnURI, h.ReturnState, h.ExpiresAt, h.CredentialVersion, g.AllowRefresh}
	args = append(args, pa...)
	args = append(args, ra...)
	args = append(args, aa...)
	args = append(args, h.ExpiresAt, s.now(), owner, s.now())
	res, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "saas-handoff-create-" + h.Hash, Statements: []rhiza.SQLStatement{
		{SQL: `DELETE FROM saas_use_handoffs WHERE owner_subject=? AND expires_at_unix_ms<=? AND (` + auth + `)`, Args: append([]any{owner, now}, aa...)},
		{SQL: `INSERT INTO saas_use_handoffs(id_hash,owner_subject,request_client_id,request_client_generation,collection_id,connection_id,generation,consumer_client_id,consumer_generation,provider_id,provider_revision,connector_digest,resource,mode,purpose,grant_expires_at_unix_ms,return_uri,return_state,expires_at_unix_ms,credential_version,allow_refresh,state) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending' WHERE ` + policy + ` AND ` + requestPolicy + ` AND (` + auth + `) AND ?>? AND (SELECT COUNT(*) FROM saas_use_handoffs WHERE owner_subject=? AND expires_at_unix_ms>?)<16 RETURNING id_hash`, Args: args, WantRows: true},
	}})
	if err != nil {
		return "", UseHandoffReview{}, err
	}
	if len(res.Statements) != 2 || len(res.Statements[1].Rows) != 1 || len(res.Statements[1].Rows[0]) != 1 || res.Statements[1].Rows[0][0] != h.Hash {
		return "", UseHandoffReview{}, ErrUseGrantConflict
	}
	return id, review, nil
}

func (s *CredentialStore) loadUseHandoff(ctx context.Context, owner, id string, authority func() (string, []any)) (useHandoff, error) {
	if ctx == nil || s == nil || s.db == nil || !validText(owner) || handoffHash(id) == "" {
		return useHandoff{}, ErrUseGrantInvalid
	}
	auth, aa, err := authorityGuard(authority)
	if err != nil {
		return useHandoff{}, err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT request_client_id,request_client_generation,collection_id,connection_id,generation,consumer_client_id,consumer_generation,provider_id,connector_digest,resource,mode,purpose,return_uri,return_state,provider_revision,grant_expires_at_unix_ms,expires_at_unix_ms,credential_version,allow_refresh FROM saas_use_handoffs WHERE id_hash=? AND owner_subject=? AND state='pending' AND expires_at_unix_ms>? AND (` + auth + `)`, Args: append([]any{handoffHash(id), owner, s.now()}, aa...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return useHandoff{}, err
	}
	if len(q.Rows) != 1 {
		return useHandoff{}, ErrUseGrantNotFound
	}
	row := q.Rows[0]
	if len(row) != 19 {
		return useHandoff{}, ErrUseGrantInvalid
	}
	h := useHandoff{Hash: handoffHash(id), Owner: owner, Grant: UseGrant{Owner: owner, Revision: 1}}
	g := &h.Grant
	for i, p := range []*string{&h.RequestClient, &h.RequestGeneration, &g.CollectionID, &g.ConnectionID, &g.Generation, &g.ConsumerClientID, &g.ConsumerGeneration, &g.ProviderID, &g.ConnectorDigest, &g.Resource, &g.Mode, &g.Purpose, &h.ReturnURI, &h.ReturnState} {
		v, ok := row[i].(string)
		if !ok {
			return useHandoff{}, ErrUseGrantInvalid
		}
		*p = v
	}
	for i, p := range []*int64{&g.ProviderRevision, &g.ExpiresAt, &h.ExpiresAt, &h.CredentialVersion} {
		v, ok := row[14+i].(int64)
		if !ok {
			return useHandoff{}, ErrUseGrantInvalid
		}
		*p = v
	}
	refresh, ok := row[18].(int64)
	if !ok || refresh < 0 || refresh > 1 {
		return useHandoff{}, ErrUseGrantInvalid
	}
	h.Grant.AllowRefresh = refresh == 1
	return h, nil
}

func (s *CredentialStore) handoffAuthority(h useHandoff, authority func() (string, []any)) func() (string, []any) {
	return func() (string, []any) {
		auth, aa, err := authorityGuard(authority)
		if err != nil {
			return "0", nil
		}
		policy, pa := s.usePolicy(h.Grant, h.CredentialVersion)
		requester, ra := s.handoffRequester(h)
		args := []any{h.Hash, h.Owner, s.now()}
		args = append(args, pa...)
		args = append(args, ra...)
		args = append(args, aa...)
		return `EXISTS(SELECT 1 FROM saas_use_handoffs WHERE id_hash=? AND owner_subject=? AND state='pending' AND expires_at_unix_ms>?) AND ` + policy + ` AND ` + requester + ` AND (` + auth + `)`, args
	}
}

func (s *CredentialStore) ReviewUseHandoff(ctx context.Context, owner, id string, authority func() (string, []any)) (UseHandoffReview, error) {
	h, err := s.loadUseHandoff(ctx, owner, id, authority)
	if err != nil {
		return UseHandoffReview{}, err
	}
	return s.reviewHandoffCredential(ctx, h, s.handoffAuthority(h, authority))
}

func (s *CredentialStore) reviewHandoffCredential(ctx context.Context, h useHandoff, authority func() (string, []any)) (UseHandoffReview, error) {
	review := UseHandoffReview{RequestClientID: h.RequestClient, ReturnURI: h.ReturnURI, ExpiresAt: h.ExpiresAt, Grant: h.Grant, ReviewDigest: h.reviewDigest()}
	if h.CredentialVersion > 0 {
		status, err := s.OAuth2Status(ctx, h.Owner, h.Grant.CollectionID, h.Grant.ConnectionID, authority)
		if err != nil {
			return UseHandoffReview{}, err
		}
		if !status.Connected || status.Version != h.CredentialVersion || status.ProviderID != h.Grant.ProviderID || h.Grant.ConnectorDigest != "" || h.Grant.Mode != "credential_delivery" {
			return UseHandoffReview{}, ErrUseGrantConflict
		}
		review.OAuth2 = &status
		review.Connector.Operations = []APIKeyOperationInfo{}
		return review, nil
	}
	connector, err := s.APIKeyConnector(ctx, h.Owner, h.Grant.CollectionID, h.Grant.ConnectionID, authority)
	if err != nil {
		return UseHandoffReview{}, err
	}
	if connector.Digest() != h.Grant.ConnectorDigest {
		return UseHandoffReview{}, ErrUseGrantConflict
	}
	review.Connector = connector.Info()
	return review, nil
}

func (s *CredentialStore) CompleteUseHandoff(ctx context.Context, owner, id string, approve bool, reviewedDigest string, authority func() (string, []any)) (string, error) {
	h, err := s.loadUseHandoff(ctx, owner, id, authority)
	if err != nil {
		return "", err
	}
	guard := s.handoffAuthority(h, authority)
	u, err := url.Parse(h.ReturnURI)
	if err != nil || !validGrantResource(h.ReturnURI) {
		return "", ErrUseGrantInvalid
	}
	query := url.Values{"state": {h.ReturnState}}
	if approve {
		if !validAuthorizationDigest(reviewedDigest) || reviewedDigest != h.reviewDigest() {
			return "", ErrUseGrantConflict
		}
		g := h.Grant
		in := UseGrantInput{ConsumerClientID: g.ConsumerClientID, Mode: g.Mode, Purpose: g.Purpose, ExpiresAt: g.ExpiresAt, AllowRefresh: g.AllowRefresh}
		if h.CredentialVersion > 0 {
			in.ReviewedCredentialVersion = &h.CredentialVersion
		} else {
			in.ReviewedConnectorDigest = &reviewedDigest
		}
		grant, err := s.createUseGrant(ctx, owner, g.CollectionID, g.ConnectionID, g.Resource, in, guard, h.Hash)
		if err != nil {
			return "", err
		}
		query.Set("grant_id", grant.ID)
	} else {
		q, qa := guard()
		entropy := randomCredentialClaim()
		if entropy == "" {
			return "", ErrUseGrantInvalid
		}
		res, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "saas-handoff-deny-" + entropy, SQL: `UPDATE saas_use_handoffs SET state='denied' WHERE id_hash=? AND (` + q + `)`, Args: append([]any{h.Hash}, qa...)})
		if err != nil {
			return "", err
		}
		if res.RowsAffected != 1 {
			return "", ErrUseGrantConflict
		}
		query.Set("error", "access_denied")
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}
