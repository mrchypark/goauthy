package saas

import (
	"context"

	"github.com/mrchypark/rhiza"
)

// APIKeyDelivery is intentionally secret-bearing and must only be serialized by
// the confidential-consumer delivery boundary, never a collection or status API.
// Consent expiry does not shorten the provider's API-key lifetime.
type APIKeyDelivery struct {
	Kind                 string `json:"kind"`
	APIKey               string `json:"api_key"`
	GrantID              string `json:"grant_id"`
	ProviderID           string `json:"provider_id"`
	ConnectionGeneration string `json:"connection_generation"`
	CredentialVersion    int64  `json:"credential_version"`
	ConnectorDigest      string `json:"connector_digest"`
	Header               string `json:"header"`
	Prefix               string `json:"prefix"`
	ConsentExpiresAt     int64  `json:"consent_expires_at_unix_ms"`
}

func (APIKeyDelivery) String() string   { return "[redacted SaaS credential delivery]" }
func (APIKeyDelivery) GoString() string { return "[redacted SaaS credential delivery]" }

// DeliverAPIKey requires distinct credential_delivery consent. Proxy consent can
// never export a key. The existing policy requires a current confidential client.
func (s *CredentialStore) DeliverAPIKey(ctx context.Context, owner, consumer, grantID, resource string, authority func() (string, []any)) (APIKeyDelivery, error) {
	g, guard, err := s.AuthorizeUseGrant(ctx, owner, consumer, grantID, resource, "credential_delivery", authority)
	if err != nil {
		return APIKeyDelivery{}, err
	}
	if g.ProviderRevision < 1 || g.ConnectorDigest == "" {
		return APIKeyDelivery{}, ErrUseGrantNotFound
	}
	connector, err := s.APIKeyConnector(ctx, owner, g.CollectionID, g.ConnectionID, guard)
	if err != nil {
		return APIKeyDelivery{}, err
	}
	if connector.Digest() != g.ConnectorDigest {
		return APIKeyDelivery{}, ErrUseGrantNotFound
	}
	binding, value, err := s.loadAPIKey(ctx, owner, g.CollectionID, g.ConnectionID, guard)
	if err != nil {
		return APIKeyDelivery{}, err
	}
	if binding.Generation != g.Generation || binding.ProviderID != g.ProviderID || value.ConnectorDigest != g.ConnectorDigest {
		return APIKeyDelivery{}, ErrUseGrantConflict
	}
	// Recheck current consent/authority/credential version after decryption. A
	// successful read cannot recall a key once the caller has received it.
	check, args := guard()
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + check, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return APIKeyDelivery{}, err
	}
	if len(q.Rows) != 1 {
		return APIKeyDelivery{}, ErrUseGrantNotFound
	}
	info := connector.Info()
	return APIKeyDelivery{Kind: "api_key", APIKey: value.APIKey, GrantID: g.ID, ProviderID: g.ProviderID, ConnectionGeneration: g.Generation, CredentialVersion: binding.TokenVersion, ConnectorDigest: g.ConnectorDigest, Header: info.Header, Prefix: info.Prefix, ConsentExpiresAt: g.ExpiresAt}, nil
}
