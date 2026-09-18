package oauth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/ory/fosite"
)

var ErrResourceAuthorization = errors.New("resource authorization failed")

// AuthorizeUserResource validates a human bearer access token and returns an
// SQL guard suitable for the same Rhiza mutation that changes the resource.
func (s *Server) AuthorizeUserResource(r *http.Request, requiredScope, requiredAudience string) (string, func() (string, []any), error) {
	subject, _, authority, err := s.authorizeResource(r, requiredScope, requiredAudience, false)
	return subject, authority, err
}

// AuthorizeConnectionUse validates a human bearer token for a connection use
// operation and returns the authenticated subject, client, and SQL guard.
func (s *Server) AuthorizeConnectionUse(r *http.Request, requiredAudience string) (string, string, func() (string, []any), error) {
	if r == nil || len(r.Header.Values("Cookie")) != 0 {
		return "", "", nil, ErrResourceAuthorization
	}
	return s.authorizeResource(r, "goauthy.connections.use", requiredAudience, true)
}

// AuthorizeConnectionHandoff validates a human bearer token for a connection
// handoff and returns the owner, requester client, and current SQL guard.
func (s *Server) AuthorizeConnectionHandoff(r *http.Request, requiredAudience string) (string, string, func() (string, []any), error) {
	if r == nil || len(r.Header.Values("Cookie")) != 0 {
		return "", "", nil, ErrResourceAuthorization
	}
	return s.authorizeResource(r, "goauthy.connections.write", requiredAudience, false)
}

func (s *Server) authorizeResource(r *http.Request, requiredScope, requiredAudience string, connectionUse bool) (string, string, func() (string, []any), error) {
	if s == nil || s.store == nil || s.accessTokens == nil || r == nil || requiredAudience == "" || (!connectionUse && !resourceScopeAllowed(requiredScope)) || (connectionUse && requiredScope != "goauthy.connections.use") {
		return "", "", nil, ErrResourceAuthorization
	}
	scheme, raw, ok := authorizationToken(r)
	if !ok || !sameAuthorizationScheme(scheme, "Bearer") {
		return "", "", nil, ErrResourceAuthorization
	}
	signature := s.accessTokens.AccessTokenSignature(r.Context(), raw)
	if signature == "" {
		return "", "", nil, ErrResourceAuthorization
	}
	request, err := s.store.GetAccessTokenSession(r.Context(), signature, &fosite.DefaultSession{})
	if err != nil || s.accessTokens.ValidateAccessToken(r.Context(), request, raw) != nil {
		return "", "", nil, ErrResourceAuthorization
	}
	audiences, audienceErr := accessResourceAudiences(request)
	if audienceErr != nil || request.GetSession() == nil || request.GetSession().GetSubject() == "" || sessionDPoPJKT(request.GetSession()) != "" || request.GetGrantedScopes().Has(requiredScope) == false || !containsAccessAudience(audiences, requiredAudience) {
		return "", "", nil, ErrResourceAuthorization
	}
	grantType := request.GetRequestForm().Get("grant_type")
	if grantType == "client_credentials" || grantType == TokenExchangeGrantType {
		return "", "", nil, ErrResourceAuthorization
	}
	if session, ok := request.GetSession().(*fosite.DefaultSession); !ok || session.Extra != nil && session.Extra["act"] != nil {
		return "", "", nil, ErrResourceAuthorization
	}
	if err := s.store.validateTokenAccounts(r.Context(), request); err != nil {
		return "", "", nil, ErrResourceAuthorization
	}
	clientID, subject := request.GetClient().GetID(), request.GetSession().GetSubject()
	policy, policySet, err := s.clientGroupPolicy(r.Context(), clientID)
	if err != nil {
		return "", "", nil, ErrResourceAuthorization
	}
	if policySet && policy.Prefix != "" {
		principal, principalErr := s.currentPrincipal(r.Context(), subject)
		if principalErr != nil || enforceClientGroupPolicy(principal, policy) != nil {
			return "", "", nil, ErrResourceAuthorization
		}
	}
	managed, managedOK := request.GetClient().(*clients.Client)
	guard := `EXISTS (SELECT 1 FROM oauth_access_tokens at JOIN oauth_token_requests tr ON tr.signature=at.signature
		WHERE at.signature=? AND at.client_id=? AND at.expires_at_unix_ms>? AND
		json_extract(tr.request_json,'$.subject')=? AND EXISTS (SELECT 1 FROM identity_users u WHERE u.subject=? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?)) AND
		EXISTS (SELECT 1 FROM json_each(at.granted_scopes) WHERE value=?) AND
		EXISTS (SELECT 1 FROM json_each(at.granted_audience) WHERE value=?) AND
		((json_extract(tr.request_json,'$.extra.goauthy_oidc_session_id') IS NULL) OR EXISTS (SELECT 1 FROM browser_sessions bs WHERE bs.token_digest=json_extract(tr.request_json,'$.extra.goauthy_oidc_session_id') AND bs.subject=? AND bs.revoked_at_unix_ms IS NULL AND bs.expires_at_unix_ms>?)) AND
		%s
		((json_extract(tr.request_json,'$.managed_client') IS NULL AND NOT EXISTS (SELECT 1 FROM managed_oauth_clients mc0 WHERE mc0.id=at.client_id) AND (EXISTS (SELECT 1 FROM dynamic_oauth_clients dc WHERE dc.client_id=at.client_id) OR at.client_id=?)) OR
		 (json_extract(tr.request_json,'$.managed_client') IS NOT NULL AND EXISTS (SELECT 1 FROM managed_oauth_clients mc WHERE mc.id=at.client_id AND mc.generation=? AND mc.enabled=1 AND mc.deleted=0))) )`
	managedGeneration := ""
	if managedOK {
		managedGeneration = managed.Generation
	}
	policySQL := ""
	policyArgs := []any{}
	if policySet {
		if policy.managedClient {
			policySQL = `EXISTS (SELECT 1 FROM managed_oauth_clients p WHERE p.id=at.client_id AND p.revision=? AND p.enabled=1 AND p.deleted=0)`
			policyArgs = append(policyArgs, policy.Revision)
			if policy.Prefix != "" {
				policySQL += ` AND EXISTS (SELECT 1 FROM rbac_user_groups ug JOIN rbac_groups g ON g.id=ug.group_id WHERE ug.subject=? AND substr(g.name,1,?)=?)`
				policyArgs = append(policyArgs, subject, len(policy.Prefix), policy.Prefix)
			}
		} else if policy.Revision == 0 {
			policySQL = `NOT EXISTS (SELECT 1 FROM bootstrap_client_login_restrictions WHERE client_id=at.client_id)`
		} else {
			policySQL = `EXISTS (SELECT 1 FROM bootstrap_client_login_restrictions p WHERE p.client_id=at.client_id AND p.restrict_group_prefix IS ? AND p.revision=?)`
			var prefix any
			if policy.Prefix != "" {
				prefix = policy.Prefix
			}
			policyArgs = append(policyArgs, prefix, policy.Revision)
			if policy.Prefix != "" {
				policySQL += ` AND EXISTS (SELECT 1 FROM rbac_user_groups ug JOIN rbac_groups g ON g.id=ug.group_id WHERE ug.subject=? AND substr(g.name,1,?)=?)`
				policyArgs = append(policyArgs, subject, len(policy.Prefix), policy.Prefix)
			}
		}
		policySQL += " AND "
	}
	guard = fmt.Sprintf(guard, policySQL)
	return subject, clientID, func() (string, []any) {
		now := s.store.now().UTC().UnixMilli()
		args := []any{signature, clientID, now, subject, subject, now, requiredScope, requiredAudience, subject, now}
		args = append(args, policyArgs...)
		args = append(args, s.store.client.GetID(), managedGeneration)
		return guard, args
	}, nil
}

func resourceScopeAllowed(scope string) bool {
	return scope == "goauthy.connections.read" || scope == "goauthy.connections.write" || scope == "goauthy.providers.read" || scope == "goauthy.providers.write"
}
