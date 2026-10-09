package saas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mrchypark/rhiza"
)

// CallAPIKey executes a configured operation with an explicitly bound key.
// Authorization is checked before dispatch and before releasing the result.
// Revocation cannot retract a request already sent to the external provider.
func (s *CredentialStore) CallAPIKey(ctx context.Context, owner, collection, connection string, connector *APIKeyConnector, operation string, authority func() (string, []any)) (map[string]json.RawMessage, error) {
	if connector == nil || connector.Digest() == "" {
		logAPIKeyCallFailure("connector_validation", ErrAPIKeyConnectorConfig)
		return nil, ErrAPIKeyConnectorConfig
	}
	preflight, err := s.loadAPIKeyForDispatch(ctx, owner, collection, connection, authority, &connector.registered, nil)
	if err != nil {
		logAPIKeyCallFailure("credential_preflight", err)
		return nil, err
	}
	if preflight.value.ConnectorDigest == "" || preflight.value.ConnectorDigest != connector.Digest() {
		logAPIKeyCallFailure("credential_preflight", ErrCredentialUnauthorized)
		return nil, ErrCredentialUnauthorized
	}
	result, err := connector.request(ctx, operation, preflight.value)
	preflight.value = credential{ConnectorDigest: preflight.value.ConnectorDigest}
	if err != nil {
		logAPIKeyCallFailure("provider_request", err)
		return nil, err
	}
	current, err := s.loadAPIKeyForDispatch(ctx, owner, collection, connection, authority, &connector.registered, &preflight)
	if err != nil {
		logAPIKeyCallFailure("credential_postflight", err)
		return nil, err
	}
	postflightDigest := current.value.ConnectorDigest
	current.value = credential{}
	if current.binding != preflight.binding || postflightDigest != connector.Digest() {
		logAPIKeyCallFailure("credential_postflight", ErrCredentialConflict)
		return nil, ErrCredentialConflict
	}
	return result, nil
}

func logAPIKeyCallFailure(stage string, err error) {
	class := "unknown"
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		class = "deadline"
	case errors.Is(err, context.Canceled):
		class = "canceled"
	case errors.Is(err, rhiza.ErrCommitUnknown):
		class = "commit_unknown"
	case errors.Is(err, rhiza.ErrNotReady):
		class = "node_not_ready"
	case errors.Is(err, rhiza.ErrQuorumUnavailable):
		class = "quorum_unavailable"
	case errors.Is(err, rhiza.ErrDurabilityUnavailable):
		class = "durability_unavailable"
	case errors.Is(err, ErrAPIKeyRequest):
		class = "provider_request"
	case errors.Is(err, ErrCredentialNotFound):
		class = "credential_not_found"
	case errors.Is(err, ErrCredentialUnauthorized):
		class = "credential_unauthorized"
	case errors.Is(err, ErrCredentialConflict):
		class = "credential_conflict"
	case errors.Is(err, errCredential):
		class = "credential_invalid"
	case errors.Is(err, ErrAPIKeyConnectorConfig):
		class = "connector_invalid"
	}
	slog.Error("API-key dispatch failed", "stage", stage, "error_class", class, "error_type", fmt.Sprintf("%T", err))
}
