package saas

import (
	"context"
	"strings"

	"github.com/mrchypark/rhiza"
)

// OAuth2Delivery is the secret-bearing, access-token-only credential contract.
type OAuth2Delivery struct {
	Kind                   string   `json:"kind"`
	AccessToken            string   `json:"access_token"`
	TokenType              string   `json:"token_type"`
	GrantID                string   `json:"grant_id"`
	ProviderID             string   `json:"provider_id"`
	ConnectionGeneration   string   `json:"connection_generation"`
	CredentialVersion      int64    `json:"credential_version"`
	AccountID              string   `json:"account_id"`
	Scopes                 []string `json:"scopes"`
	TokenExpiresAtUnixMS   int64    `json:"token_expires_at_unix_ms"`
	ConsentExpiresAtUnixMS int64    `json:"consent_expires_at_unix_ms"`
}

func (OAuth2Delivery) String() string   { return "[redacted SaaS OAuth2 delivery]" }
func (OAuth2Delivery) GoString() string { return "[redacted SaaS OAuth2 delivery]" }

// DeliverOAuth2 exports only a current OAuth2 access token under explicit,
// confidential credential-delivery consent. It performs no refresh or I/O
// outside the local linearizable credential reads.
func (s *CredentialStore) DeliverOAuth2(ctx context.Context, owner, consumer, grantID, resource string, authority func() (string, []any)) (OAuth2Delivery, error) {
	g, guard, err := s.AuthorizeUseGrant(ctx, owner, consumer, grantID, resource, "credential_delivery", authority)
	if err != nil {
		return OAuth2Delivery{}, err
	}
	if g.ConnectorDigest != "" || g.ProviderRevision < 1 {
		return OAuth2Delivery{}, ErrUseGrantNotFound
	}

	auth, aa, err := authorityGuard(authority)
	if err != nil {
		return OAuth2Delivery{}, err
	}
	policy, pa := s.usePolicy(g, 0)
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT x.token_version,d.auth_method,COALESCE(p.revision,0) FROM saas_connection_credentials x JOIN auth_collection_definitions d ON d.id=x.collection_id LEFT JOIN saas_providers p ON p.id=x.provider_id WHERE x.connection_id=? AND ` + policy + ` AND (` + auth + `)`, Args: append(append([]any{g.ConnectionID}, pa...), aa...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return OAuth2Delivery{}, err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 3 {
		return OAuth2Delivery{}, ErrUseGrantNotFound
	}
	version, versionOK := q.Rows[0][0].(int64)
	method, methodOK := q.Rows[0][1].(string)
	providerRevision, providerRevisionOK := q.Rows[0][2].(int64)
	if !versionOK || version < 1 || !methodOK || method != "oauth2" || !providerRevisionOK || providerRevision < 1 {
		return OAuth2Delivery{}, ErrUseGrantNotFound
	}
	binding := credentialBinding{Owner: g.Owner, CollectionID: g.CollectionID, ConnectionID: g.ConnectionID, ProviderID: g.ProviderID, Generation: g.Generation, TokenVersion: version}
	value, err := s.Load(ctx, binding, guard)
	if err != nil {
		return OAuth2Delivery{}, err
	}
	now := s.now()
	if value.ExpiresAtUnixMS <= 0 || value.ExpiresAtUnixMS <= now || strings.TrimSpace(value.AccessToken) == "" {
		return OAuth2Delivery{}, ErrUseGrantNotFound
	}
	check, args := guard()
	q, err = s.db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + check, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return OAuth2Delivery{}, err
	}
	if len(q.Rows) != 1 {
		return OAuth2Delivery{}, ErrUseGrantNotFound
	}
	now = s.now()
	if value.ExpiresAtUnixMS <= now || g.ExpiresAt <= now {
		return OAuth2Delivery{}, ErrUseGrantNotFound
	}
	return OAuth2Delivery{Kind: "oauth2", AccessToken: value.AccessToken, TokenType: "Bearer", GrantID: g.ID, ProviderID: g.ProviderID, ConnectionGeneration: g.Generation, CredentialVersion: version, AccountID: value.AccountID, Scopes: append([]string{}, value.Scopes...), TokenExpiresAtUnixMS: value.ExpiresAtUnixMS, ConsentExpiresAtUnixMS: g.ExpiresAt}, nil
}
