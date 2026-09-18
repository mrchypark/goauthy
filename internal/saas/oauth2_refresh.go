package saas

import (
	"context"
	"strings"

	"github.com/mrchypark/rhiza"
)

// RefreshOAuth2 performs one registered-provider refresh and returns metadata
// only. The provider and credential bindings remain pinned for the operation.
func (s *CredentialStore) RefreshOAuth2(ctx context.Context, providers *ProviderStore, owner, collection, connection string, expectedVersion int64, authority func() (string, []any)) (OAuth2Status, error) {
	if ctx == nil || s == nil || s.db == nil || providers == nil || !validText(owner) || !validText(collection) || !validText(connection) || expectedVersion < 1 {
		return OAuth2Status{}, ErrCredentialNotFound
	}
	base, ba, err := authorityGuard(authority)
	if err != nil {
		return OAuth2Status{}, err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT c.generation,x.provider_id FROM auth_collection_connections c JOIN auth_collection_definitions d ON d.id=c.collection_id JOIN saas_connection_credentials x ON x.connection_id=c.id WHERE c.owner_subject=? AND c.collection_id=? AND c.id=? AND c.generation=x.generation AND x.token_version=? AND x.state='ready' AND d.auth_method='oauth2' AND (` + base + `)`, Args: append([]any{owner, collection, connection, expectedVersion}, ba...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || len(q.Rows[0]) != 2 {
		if err != nil {
			return OAuth2Status{}, err
		}
		return OAuth2Status{}, ErrCredentialNotFound
	}
	generation, generationOK := q.Rows[0][0].(string)
	providerID, providerOK := q.Rows[0][1].(string)
	if !generationOK || !providerOK || generation == "" || providerID == "" {
		return OAuth2Status{}, ErrCredentialNotFound
	}
	provider, err := providers.Get(ctx, providerID, authority)
	if err != nil {
		return OAuth2Status{}, err
	}
	_, providerGuard, err := oauth2Provider(ctx, providers, provider.ID, provider.CallbackURI, authority)
	if err != nil {
		return OAuth2Status{}, err
	}
	oauthClient, err := providers.LoadOAuth2(ctx, provider.ID, providerGuard)
	if err != nil {
		return OAuth2Status{}, err
	}
	binding := credentialBinding{Owner: owner, CollectionID: collection, ConnectionID: connection, ProviderID: providerID, Generation: generation, TokenVersion: expectedVersion}
	return s.refreshOAuth2(ctx, oauthClient, binding, providerGuard)
}

// The private adapter parameter substitutes only the external HTTP boundary in
// tests. The public entry point always uses the registered restricted client.
func (s *CredentialStore) refreshOAuth2(ctx context.Context, oauthClient *OAuth2, binding credentialBinding, providerGuard func() (string, []any)) (OAuth2Status, error) {
	if ctx == nil || s == nil || oauthClient == nil {
		return OAuth2Status{}, ErrCredentialNotFound
	}
	current, err := s.Load(ctx, binding, providerGuard)
	if err != nil {
		return OAuth2Status{}, err
	}
	if strings.TrimSpace(current.AccountID) == "" || current.RefreshToken == "" {
		return OAuth2Status{}, ErrCredentialNotFound
	}
	_, err = s.refreshCredential(ctx, binding, providerGuard, func(ctx context.Context, old credential) (credential, error) {
		token, err := oauthClient.Refresh(ctx, old.RefreshToken)
		if err != nil || token == nil || strings.TrimSpace(token.AccessToken) == "" {
			return credential{}, ErrOAuth2Exchange
		}
		expires := int64(0)
		if !token.Expiry.IsZero() {
			expires = token.Expiry.UnixMilli()
			if expires <= s.now() {
				return credential{}, ErrOAuth2Exchange
			}
		}
		scopes, err := oauthGrantedScopes(token, old.Scopes)
		if err != nil {
			return credential{}, err
		}
		account, err := oauthClient.Identity(ctx, token.AccessToken)
		if err != nil || account != old.AccountID {
			return credential{}, ErrOAuth2Identity
		}
		if expires != 0 && expires <= s.now() {
			return credential{}, ErrOAuth2Exchange
		}
		updated := credential{AccountID: old.AccountID, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAtUnixMS: expires, Scopes: scopes, RefreshExpiresAtUnixMS: old.RefreshExpiresAtUnixMS}
		if updated.RefreshToken == "" {
			updated.RefreshToken = old.RefreshToken
		}
		return updated, nil
	})
	if err != nil {
		return OAuth2Status{}, err
	}
	status, err := s.OAuth2Status(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, providerGuard)
	if err != nil {
		return OAuth2Status{}, err
	}
	if status.Version != binding.TokenVersion+1 || !status.Connected {
		return OAuth2Status{}, ErrCredentialConflict
	}
	return status, nil
}
