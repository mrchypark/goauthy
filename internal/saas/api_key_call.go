package saas

import (
	"context"
	"encoding/json"
)

// CallAPIKey executes a configured operation with an explicitly bound key.
// Authorization is checked before dispatch and before releasing the result.
// Revocation cannot retract a request already sent to the external provider.
func (s *CredentialStore) CallAPIKey(ctx context.Context, owner, collection, connection string, connector *APIKeyConnector, operation string, authority func() (string, []any)) (map[string]json.RawMessage, error) {
	if connector == nil || connector.Digest() == "" {
		return nil, ErrAPIKeyConnectorConfig
	}
	binding, value, err := s.loadAPIKey(ctx, owner, collection, connection, authority)
	if err != nil {
		return nil, err
	}
	if value.ConnectorDigest == "" || value.ConnectorDigest != connector.Digest() {
		return nil, ErrCredentialUnauthorized
	}
	result, err := connector.request(ctx, operation, value)
	value = credential{}
	if err != nil {
		return nil, err
	}
	current, value, err := s.loadAPIKey(ctx, owner, collection, connection, authority)
	if err != nil {
		return nil, err
	}
	if current != binding || value.ConnectorDigest != connector.Digest() {
		return nil, ErrCredentialConflict
	}
	return result, nil
}
