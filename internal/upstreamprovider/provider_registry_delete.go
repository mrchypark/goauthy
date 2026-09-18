package upstreamprovider

import (
	"context"
	"errors"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/rhiza"
)

// DeleteAuthorized atomically removes a provider, its logos, external
// links, and runtime version metadata. Users and user profiles are
// intentionally preserved. Missing providers succeed (no affected-row
// check) matching the pinned rauthy v0.36.2 entity delete behavior.
func (s *RegistryStore) DeleteAuthorized(ctx context.Context, providerID, requestID string, keys *apikey.Store, principal *apikey.Principal) error {
	if s == nil || s.db == nil || keys == nil || providerID == "" || requestID == "" {
		return ErrInvalidConfig
	}

	statements := []rhiza.SQLStatement{
		{
			SQL:  "DELETE FROM auth_provider_logos WHERE auth_provider_id=? AND " + apikey.GuardExistsSQL(),
			Args: []any{providerID, requestID},
		},
		{
			SQL:  "DELETE FROM identity_external_links WHERE provider_id=? AND " + apikey.GuardExistsSQL(),
			Args: []any{providerID, requestID},
		},
		{
			SQL:  "DELETE FROM auth_provider_runtime_versions WHERE provider_id=? AND " + apikey.GuardExistsSQL(),
			Args: []any{providerID, requestID},
		},
		{
			SQL:  "DELETE FROM auth_providers WHERE id=? AND " + apikey.GuardExistsSQL(),
			Args: []any{providerID, requestID},
		},
	}

	_, authorized, err := keys.RunMutation(ctx, principal, authProvidersGroup, apikey.Delete, requestID, statements)
	if err != nil {
		return err
	}
	if !authorized {
		return apikey.ErrForbidden
	}
	return nil
}

// LinkedUsers reads the external links for a provider. Email follows the
// established resetEventEmailSQL fallback: profile email first, then
// recovery email, then empty string. Every linked user is preserved even
// when no profile exists. Independent of DeleteAuthorized for the future
// GET delete_safe endpoint.
func (s *RegistryStore) LinkedUsers(ctx context.Context, providerID string) ([]ProviderLinkedUserResponse, error) {
	if s == nil || s.db == nil || providerID == "" {
		return nil, ErrInvalidConfig
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: "SELECT l.local_subject, " +
			"COALESCE(" +
			"(SELECT NULLIF(email,'') FROM identity_user_profiles WHERE subject=l.local_subject), " +
			"(SELECT email FROM identity_recovery_emails WHERE subject=l.local_subject), " +
			"''" +
			") " +
			"FROM identity_external_links l " +
			"JOIN identity_users u ON u.subject=l.local_subject " +
			"WHERE l.provider_id=?",
		Args:        []any{providerID},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	users := make([]ProviderLinkedUserResponse, 0, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) != 2 {
			return nil, errors.New("invalid linked user row")
		}
		id, ok := row[0].(string)
		if !ok {
			return nil, errors.New("invalid linked user id")
		}
		email := ""
		if row[1] != nil {
			if e, ok := row[1].(string); ok {
				email = e
			}
		}
		users = append(users, ProviderLinkedUserResponse{ID: id, Email: email})
	}
	return users, nil
}
