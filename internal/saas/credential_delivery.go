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
	g, guard, proof, err := s.authorizeUseGrantWithProof(ctx, owner, consumer, grantID, resource, "credential_delivery", authority, true)
	if err != nil {
		return APIKeyDelivery{}, err
	}
	if g.ProviderRevision < 1 || g.ConnectorDigest == "" {
		return APIKeyDelivery{}, ErrUseGrantNotFound
	}
	expected := &providerHTTPBinding{db: s.db, id: g.ProviderID, kind: "api_key", revision: g.ProviderRevision}
	current, err := s.loadAPIKeyForDispatch(ctx, owner, g.CollectionID, g.ConnectionID, guard, expected, &proof)
	if err != nil {
		return APIKeyDelivery{}, err
	}
	if current.binding != proof.binding || current.value.ConnectorDigest != g.ConnectorDigest {
		return APIKeyDelivery{}, ErrUseGrantConflict
	}
	apiKey := current.value.APIKey
	if apiKey == "" {
		// The loader omits plaintext only for an exact proof match. A changed
		// envelope returns its freshly authenticated credential above.
		apiKey = proof.value.APIKey
	}
	if apiKey == "" {
		return APIKeyDelivery{}, ErrUseGrantNotFound
	}
	// Keep the post-load grant/authority check as the last current-state read.
	check, args := guard()
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + check, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return APIKeyDelivery{}, err
	}
	if len(q.Rows) != 1 {
		return APIKeyDelivery{}, ErrUseGrantNotFound
	}
	return APIKeyDelivery{Kind: "api_key", APIKey: apiKey, GrantID: g.ID, ProviderID: g.ProviderID, ConnectionGeneration: g.Generation, CredentialVersion: current.binding.TokenVersion, ConnectorDigest: g.ConnectorDigest, Header: current.connectorHeader, Prefix: current.connectorPrefix, ConsentExpiresAt: g.ExpiresAt}, nil
}
