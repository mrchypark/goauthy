package saas

import (
	"context"
	"encoding/json"
	"github.com/mrchypark/rhiza"
)

type OAuth2Start struct {
	AuthorizationURL string `json:"authorization_url"`
}

type OAuth2ConnectionStatus struct {
	Connected bool     `json:"connected"`
	AccountID string   `json:"account_id"`
	Scopes    []string `json:"scopes"`
}

// oauth2Provider pins the administrator's exact provider revision and callback
// to every subsequent database operation. It never accepts a caller destination.
func oauth2Provider(ctx context.Context, providers *ProviderStore, id, callback string, authority func() (string, []any)) (Provider, func() (string, []any), error) {
	if ctx == nil || providers == nil || !providerID(id) || !validCallback(callback) {
		return Provider{}, nil, ErrProviderInvalid
	}
	p, err := providers.Get(ctx, id, authority)
	if err != nil {
		return Provider{}, nil, err
	}
	if !p.Enabled || p.Kind != "oauth2" || p.CallbackURI != callback || p.IdentityEndpoint == "" || p.SubjectField == "" {
		return Provider{}, nil, ErrProviderInvalid
	}
	_, _, err = authorityGuard(authority)
	if err != nil {
		return Provider{}, nil, err
	}
	guard := func() (string, []any) {
		// External exchanges may cross session expiry. Rebuild the caller's time
		// and authority predicate at each read/commit, not only at callback entry.
		g, args, err := authorityGuard(authority)
		if err != nil {
			return "0", nil
		}
		return `EXISTS(SELECT 1 FROM saas_providers WHERE id=? AND revision=? AND enabled=1 AND deleted=0 AND kind='oauth2') AND (` + g + `)`, append([]any{p.ID, p.Revision}, args...)
	}
	return p, guard, nil
}

func oauth2ProviderDigest(p Provider) string {
	raw, _ := json.Marshal(p)
	return authorizationDigest(string(raw))
}

func (s *CredentialStore) BeginOAuth2(ctx context.Context, providers *ProviderStore, owner, collection, connection, provider, sessionDigest, callback string, authority func() (string, []any)) (OAuth2Start, error) {
	if s == nil || !validAuthorizationDigest(sessionDigest) || !validText(owner) || !validText(collection) || !validText(connection) {
		return OAuth2Start{}, errAuthorization
	}
	p, guard, err := oauth2Provider(ctx, providers, provider, callback, authority)
	if err != nil {
		return OAuth2Start{}, err
	}
	g, ga := guard()
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT c.generation,COALESCE(x.token_version,0),COALESCE(x.generation,''),COALESCE(x.state,'') FROM auth_collection_connections c LEFT JOIN saas_connection_credentials x ON x.connection_id=c.id WHERE c.id=? AND c.owner_subject=? AND c.collection_id=? AND (` + g + `)`, Args: append([]any{connection, owner, collection}, ga...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return OAuth2Start{}, err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 4 {
		return OAuth2Start{}, ErrCredentialNotFound
	}
	generation, ok := q.Rows[0][0].(string)
	if !ok {
		return OAuth2Start{}, errAuthorization
	}
	version, ok := q.Rows[0][1].(int64)
	if !ok || version < 0 || version == 1<<63-1 {
		return OAuth2Start{}, ErrCredentialConflict
	}
	if version != 0 && (q.Rows[0][2] == generation || q.Rows[0][3] != "revoked") {
		return OAuth2Start{}, ErrCredentialConflict
	}
	b := credentialBinding{Owner: owner, CollectionID: collection, ConnectionID: connection, ProviderID: provider, Generation: generation, TokenVersion: version + 1}
	o, err := providers.LoadOAuth2(ctx, provider, guard)
	if err != nil {
		return OAuth2Start{}, err
	}
	proof := newAuthorizationProof()
	url, err := o.AuthorizationURL(proof.state, proof.verifier)
	if err != nil {
		return OAuth2Start{}, err
	}
	request := authorizationRequest{Binding: b, StateDigest: authorizationDigest(proof.state), VerifierDigest: authorizationDigest(proof.verifier), SessionDigest: sessionDigest, ProviderDigest: oauth2ProviderDigest(p), ExpiresAtUnixMS: s.now() + maxAuthorizationTTLMS, Verifier: proof.verifier}
	if err := s.CreateAuthorization(ctx, request, guard); err != nil {
		return OAuth2Start{}, err
	}
	return OAuth2Start{AuthorizationURL: url}, nil
}

func (s *CredentialStore) CompleteOAuth2(ctx context.Context, providers *ProviderStore, owner, collection, connection, provider, sessionDigest, callback, state, code string, authority func() (string, []any)) (OAuth2ConnectionStatus, error) {
	p, guard, err := oauth2Provider(ctx, providers, provider, callback, authority)
	if err != nil {
		return OAuth2ConnectionStatus{}, err
	}
	o, err := providers.LoadOAuth2(ctx, provider, guard)
	if err != nil {
		return OAuth2ConnectionStatus{}, err
	}
	return s.completeOAuth2(ctx, o, p, owner, collection, connection, sessionDigest, state, code, guard)
}

// The adapter argument keeps external HTTP at the test boundary. The public
// entry point always loads administrator-registered settings and the restricted client.
func (s *CredentialStore) completeOAuth2(ctx context.Context, o *OAuth2, p Provider, owner, collection, connection, sessionDigest, state, code string, guard func() (string, []any)) (OAuth2ConnectionStatus, error) {
	if s == nil || ctx == nil || !validState(state) || !validText(code) || !validAuthorizationDigest(sessionDigest) {
		return OAuth2ConnectionStatus{}, errAuthorization
	}
	digest, providerDigest := authorizationDigest(state), oauth2ProviderDigest(p)
	b, verifier, err := s.loadAuthorizationVerifier(ctx, digest, sessionDigest, providerDigest, guard)
	if err != nil {
		return OAuth2ConnectionStatus{}, err
	}
	if b.Owner != owner || (collection != "" && b.CollectionID != collection) || (connection != "" && b.ConnectionID != connection) || b.ProviderID != p.ID {
		return OAuth2ConnectionStatus{}, ErrAuthorizationNotFound
	}
	consumed, err := s.ConsumeAuthorization(ctx, digest, authorizationDigest(verifier), sessionDigest, providerDigest, guard)
	if err != nil || consumed != b {
		if err != nil {
			return OAuth2ConnectionStatus{}, err
		}
		return OAuth2ConnectionStatus{}, ErrAuthorizationConflict
	}
	// Consume before the external code exchange: uncertain outcomes cannot be retried.
	token, err := o.Exchange(ctx, code, verifier)
	if err != nil {
		return OAuth2ConnectionStatus{}, ErrOAuth2Exchange
	}
	scopes, err := oauthGrantedScopes(token, p.Scopes)
	if err != nil {
		return OAuth2ConnectionStatus{}, err
	}
	account, err := o.Identity(ctx, token.AccessToken)
	if err != nil {
		return OAuth2ConnectionStatus{}, ErrOAuth2Identity
	}
	expires := int64(0)
	if !token.Expiry.IsZero() {
		expires = token.Expiry.UnixMilli()
		if expires <= s.now() {
			return OAuth2ConnectionStatus{}, ErrOAuth2Exchange
		}
	}
	value := credential{AccountID: account, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAtUnixMS: expires, Scopes: scopes}
	if err := s.CompleteAuthorization(ctx, b, digest, sessionDigest, providerDigest, value, guard); err != nil {
		return OAuth2ConnectionStatus{}, err
	}
	return OAuth2ConnectionStatus{Connected: true, AccountID: account, Scopes: scopes}, nil
}
