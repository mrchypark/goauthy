package oauth

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

const connectionUseScope = "goauthy.connections.use"

// TokenExchangeGrantType is RFC 8693's grant type URI.
const TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

const accessTokenType = "urn:ietf:params:oauth:token-type:access_token"

const (
	exchangeSourceSignatureForm = "goauthy_exchange_source_signature"
	exchangeSourceExpiryForm    = "goauthy_exchange_source_expiry"
	exchangeActorSignatureForm  = "goauthy_exchange_actor_signature"
	exchangeActorExpiryForm     = "goauthy_exchange_actor_expiry"
)

type tokenExchangeHandler struct {
	*oauth2.HandleHelper
	store                 *Store
	strategy              oauth2.AccessTokenStrategy
	config                *fosite.Config
	allowedResources      map[string]struct{}
	defaultAudiences      map[string]string
	connectionUseResource string
	server                *Server
}

var _ fosite.TokenEndpointHandler = (*tokenExchangeHandler)(nil)

func newTokenExchangeHandler(store *Store, strategy oauth2.AccessTokenStrategy, config *fosite.Config, allowedResources map[string]struct{}, defaultAudiences map[string]string, connectionUseResource string) *tokenExchangeHandler {
	return &tokenExchangeHandler{HandleHelper: &oauth2.HandleHelper{AccessTokenStrategy: strategy, AccessTokenStorage: store, Config: config}, store: store, strategy: strategy, config: config, allowedResources: allowedResources, defaultAudiences: defaultAudiences, connectionUseResource: connectionUseResource}
}

func (h *tokenExchangeHandler) CanHandleTokenEndpointRequest(_ context.Context, request fosite.AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(TokenExchangeGrantType)
}
func (*tokenExchangeHandler) CanSkipClientAuth(context.Context, fosite.AccessRequester) bool {
	return false
}

func (h *tokenExchangeHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !h.CanHandleTokenEndpointRequest(ctx, request) || !request.GetClient().GetGrantTypes().Has(TokenExchangeGrantType) {
		return fosite.ErrUnauthorizedClient
	}
	managed, isManaged := request.GetClient().(*clients.Client)
	if request.GetClient().IsPublic() || (isManaged && !managed.Enabled) || (!isManaged && (h.store.client == nil || request.GetClient().GetID() != h.store.client.GetID())) {
		return fosite.ErrUnauthorizedClient
	}
	form := request.GetRequestForm()
	if !onlyExchangeFields(form) {
		return fosite.ErrInvalidRequest
	}
	requestedScopes := splitScopes(form.Get("scope"))
	isConnUse := containsScope(requestedScopes, connectionUseScope) ||
		(h.connectionUseResource != "" && (form.Get("resource") == h.connectionUseResource || form.Get("audience") == h.connectionUseResource))
	if isConnUse {
		if h.connectionUseResource == "" {
			return errServiceUnavailable
		}
		if !isManaged && (h.store.client == nil || request.GetClient().GetID() != h.store.client.GetID()) {
			return fosite.ErrUnauthorizedClient
		}
		if _, hasAudience := form["audience"]; hasAudience {
			return errInvalidTarget
		}
		if !request.GetClient().GetScopes().Has(connectionUseScope) {
			return fosite.ErrInvalidScope
		}
		if scopes, found := form["scope"]; !found || len(scopes) != 1 || len(requestedScopes) != 1 || requestedScopes[0] != connectionUseScope {
			return fosite.ErrInvalidScope
		}
		if resVals, found := form["resource"]; !found || len(resVals) != 1 || resVals[0] != h.connectionUseResource {
			return errInvalidTarget
		}
		if form.Has("actor_token") || form.Has("actor_token_type") {
			return fosite.ErrInvalidGrant
		}
	}
	subjectToken, ok := exactlyOne(form, "subject_token")
	if !ok {
		return fosite.ErrInvalidRequest
	}
	subjectType, ok := exactlyOne(form, "subject_token_type")
	if !ok || subjectType != accessTokenType {
		return fosite.ErrInvalidRequest
	}
	if requested, found := form["requested_token_type"]; found && (len(requested) != 1 || requested[0] != accessTokenType) {
		return fosite.ErrInvalidRequest
	}
	if sessionDPoPJKT(request.GetSession()) != "" {
		return fosite.ErrInvalidRequest
	}
	now := time.Now().UTC()
	source, signature, sourceSession, sourceExpiry, err := h.exchangePrincipal(ctx, subjectToken, now)
	if err != nil {
		return err
	}
	if sourceExpiry, err = h.store.accessTokenExpiry(ctx, signature); err != nil {
		if isUnavailableErr(err) {
			return err
		}
		return fosite.ErrInvalidGrant
	} else if !sourceExpiry.After(now) {
		return fosite.ErrInvalidGrant
	}
	remaining := sourceExpiry.Sub(now)
	if remaining <= 0 {
		return fosite.ErrInvalidGrant
	}
	if isConnUse {
		if source.GetRequestForm().Get("grant_type") == TokenExchangeGrantType || (sourceSession.Extra != nil && sourceSession.Extra["act"] != nil) {
			return fosite.ErrInvalidGrant
		}
		if _, machine, err := machineTokenSubject(source); err != nil || machine {
			return fosite.ErrInvalidGrant
		}
		sourceAudiences, audErr := accessResourceAudiences(source)
		if audErr != nil || !source.GetGrantedScopes().Has(connectionUseScope) || !containsAccessAudience(sourceAudiences, h.connectionUseResource) {
			return fosite.ErrInvalidGrant
		}
		if h.server != nil {
			policy, _, policyErr := h.server.clientGroupPolicy(ctx, request.GetClient().GetID())
			if policyErr != nil {
				return policyErr
			}
			if policy.Prefix != "" {
				principal, principalErr := h.server.currentPrincipal(ctx, sourceSession.Subject)
				if principalErr != nil {
					return principalErr
				}
				if enforceClientGroupPolicy(principal, policy) != nil {
					return fosite.ErrAccessDenied
				}
			}
			if h.store.forceMFA(request.GetClient()) {
				mfaOK, mfaErr := h.server.hasConnectionUseMFA(ctx, source, sourceSession)
				if mfaErr != nil {
					return mfaErr
				}
				if !mfaOK {
					return fosite.ErrAccessDenied
				}
			}
		}
	}
	actorSignature, actorExpiry := "", time.Time{}
	var actorClaims *oidc.ActorClaims
	var actorFlags []bool
	if actorToken, found := form["actor_token"]; found {
		if len(actorToken) != 1 || actorToken[0] == "" {
			return fosite.ErrInvalidRequest
		}
		actorType, ok := exactlyOne(form, "actor_token_type")
		if !ok || actorType != accessTokenType {
			return fosite.ErrInvalidRequest
		}
		actorPrincipal, actorSignatureValue, actorSession, expiry, actorErr := h.exchangePrincipal(ctx, actorToken[0], now)
		if actorErr != nil {
			return actorErr
		}
		actorSignature, actorExpiry = actorSignatureValue, expiry
		priorActor, parseErr := accessSessionActor(actorSession.Extra)
		if parseErr != nil {
			return fosite.ErrInvalidGrant
		}
		actorSubject, machine, subjectErr := machineTokenSubject(actorPrincipal)
		if subjectErr != nil || actorSubject == "" {
			return fosite.ErrInvalidGrant
		}
		priorFlags, flagsErr := actorMachineFlags(actorSession, priorActor)
		if flagsErr != nil {
			return fosite.ErrInvalidGrant
		}
		actorFlags = append([]bool{machine}, priorFlags...)
		value := map[string]any{"sub": actorSubject}
		if nested := actorClaimsExtra(priorActor); nested != nil {
			value["act"] = nested
		}
		actorClaims, parseErr = oidc.ParseActorClaims(value)
		if parseErr != nil {
			return fosite.ErrInvalidGrant
		}
		if actorExpiry, actorErr = h.store.accessTokenExpiry(ctx, actorSignature); actorErr != nil {
			if isUnavailableErr(actorErr) {
				return actorErr
			}
			return fosite.ErrInvalidGrant
		} else if !actorExpiry.After(now) {
			return fosite.ErrInvalidGrant
		}
		if actorExpiry.Sub(now) < remaining {
			remaining = actorExpiry.Sub(now)
		}
	} else if _, found := form["actor_token_type"]; found {
		return fosite.ErrInvalidRequest
	}
	audiences := fosite.Arguments{}
	// Managed defaults are captured by the shared signing strategy, separately
	// from explicit resource grants. Legacy stored exchange grants stay intact.
	if !isConnUse {
		if value := h.defaultAudiences[request.GetClient().GetID()]; !isManaged && value != "" {
			audiences = append(audiences, value)
		}
	}
	_, hasResource := form["resource"]
	_, hasAudience := form["audience"]
	if hasResource && hasAudience {
		return fosite.ErrInvalidRequest
	}
	for _, field := range []string{"resource", "audience"} {
		if values, exists := form[field]; exists {
			if len(values) != 1 {
				return fosite.ErrInvalidRequest
			}
			target := values[0]
			if !validResourceURL(target) || !request.GetClient().GetAudience().Has(target) {
				return errInvalidTarget
			}
			if _, allowed := h.allowedResources[target]; !allowed {
				return errInvalidTarget
			}
			if !audiences.Has(target) {
				audiences = append(audiences, target)
			}
		}
	}
	// Narrow only subject scopes; actor and exchanger scope
	// lists do not constrain this explicitly enabled exchange grant.
	sourceScopes := source.GetGrantedScopes()
	granted := append(fosite.Arguments(nil), sourceScopes...)
	if scopes, found := form["scope"]; found {
		if len(scopes) != 1 || scopes[0] == "" {
			return fosite.ErrInvalidScope
		}
		granted = fosite.Arguments{}
		seen := map[string]struct{}{}
		for _, scope := range splitScopes(scopes[0]) {
			if _, duplicate := seen[scope]; duplicate || !sourceScopes.Has(scope) {
				return fosite.ErrInvalidScope
			}
			seen[scope] = struct{}{}
			granted = append(granted, scope)
		}
		if len(granted) == 0 {
			return fosite.ErrInvalidScope
		}
	}
	request.SetRequestedScopes(granted)
	for _, scope := range granted {
		request.GrantScope(scope)
	}
	request.SetRequestedAudience(audiences)
	for _, audience := range audiences {
		request.GrantAudience(audience)
	}
	targetSession, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return fosite.ErrServerError
	}
	targetSession.Subject, targetSession.Username = sourceSession.Subject, sourceSession.Username
	targetSession.Extra = make(map[string]any)
	if _, machine, err := machineTokenSubject(source); err != nil {
		return fosite.ErrInvalidGrant
	} else if machine {
		targetSession.Extra[machineSubjectExtra] = ""
	} else if sourceSession.Extra != nil {
		for _, key := range []string{oidcSessionIDExtra, oidcAuthMethodExtra, oidcAuthTimeExtra, deviceOIDCExtra, deviceMFAVerifiedExtra} {
			if val, exists := sourceSession.Extra[key]; exists {
				targetSession.Extra[key] = val
			}
		}
	}
	form.Set(exchangeSourceSignatureForm, signature)
	form.Set(exchangeSourceExpiryForm, strconv.FormatInt(sourceExpiry.UnixMilli(), 10))
	if actorSignature != "" {
		form.Set(exchangeActorSignatureForm, actorSignature)
		form.Set(exchangeActorExpiryForm, strconv.FormatInt(actorExpiry.UnixMilli(), 10))
		targetSession.Extra["act"] = actorClaimsExtra(actorClaims)
		targetSession.Extra[actorMachineExtra] = actorFlags
	}
	lifespan := min(fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantType(TokenExchangeGrantType), fosite.AccessToken, h.config.GetAccessTokenLifespan(ctx)), remaining)
	if lifespan <= 0 {
		return fosite.ErrInvalidGrant
	}
	targetSession.SetExpiresAt(fosite.AccessToken, now.Add(lifespan))
	return nil
}

func (h *tokenExchangeHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if !h.CanHandleTokenEndpointRequest(ctx, request) {
		return fosite.ErrUnknownRequest
	}
	form := request.GetRequestForm()
	sourceSignature, expiresRaw := form.Get(exchangeSourceSignatureForm), form.Get(exchangeSourceExpiryForm)
	expiresMS, expiryErr := strconv.ParseInt(expiresRaw, 10, 64)
	if sourceSignature == "" || expiryErr != nil || expiresMS <= 0 {
		return fosite.ErrServerError
	}
	actorSignature, actorExpiry, hasActor := "", time.Time{}, false
	if actorSignature = form.Get(exchangeActorSignatureForm); actorSignature != "" {
		actorExpiryMS, actorErr := strconv.ParseInt(form.Get(exchangeActorExpiryForm), 10, 64)
		if actorErr != nil || actorExpiryMS <= 0 {
			return fosite.ErrServerError
		}
		actorExpiry, hasActor = time.UnixMilli(actorExpiryMS).UTC(), true
	} else if form.Get(exchangeActorExpiryForm) != "" {
		return fosite.ErrServerError
	}
	// Never serialize raw tokens or temporary source/actor signatures into the
	// target request record. `act` is the only actor-related session data kept.
	for _, key := range []string{"subject_token", "subject_token_type", "actor_token", "actor_token_type", "client_secret", exchangeSourceSignatureForm, exchangeSourceExpiryForm, exchangeActorSignatureForm, exchangeActorExpiryForm} {
		form.Del(key)
	}
	sourceExpiry := time.UnixMilli(expiresMS).UTC()
	remaining := time.Until(sourceExpiry)
	if remaining <= 0 {
		return fosite.ErrInvalidGrant
	}
	var txCtx context.Context
	var err error
	if hasActor {
		txCtx, err = h.store.BeginTokenExchangeActorTX(ctx, sourceSignature, sourceExpiry, actorSignature, actorExpiry)
	} else {
		txCtx, err = h.store.BeginTokenExchangeTX(ctx, sourceSignature, sourceExpiry)
	}
	if err != nil {
		if isUnavailableErr(err) {
			return err
		}
		return fosite.ErrServerError
	}
	if hasActor && time.Until(actorExpiry) < remaining {
		remaining = time.Until(actorExpiry)
	}
	lifespan := min(fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantType(TokenExchangeGrantType), fosite.AccessToken, h.config.GetAccessTokenLifespan(txCtx)), remaining)
	if lifespan <= 0 {
		_ = h.store.Rollback(txCtx)
		return fosite.ErrInvalidGrant
	}
	if _, err := h.IssueAccessToken(txCtx, lifespan, request, response); err != nil {
		_ = h.store.Rollback(txCtx)
		if isUnavailableErr(err) {
			return err
		}
		return fosite.ErrServerError
	}
	if err := h.store.Commit(txCtx); err != nil {
		if errors.Is(err, fosite.ErrSerializationFailure) {
			return fosite.ErrInvalidGrant
		}
		if isUnavailableErr(err) {
			return err
		}
		return fosite.ErrServerError
	}
	response.SetExtra("issued_token_type", accessTokenType)
	return nil
}

func onlyExchangeFields(form map[string][]string) bool {
	for key := range form {
		switch key {
		case "grant_type", "client_id", "client_secret", "subject_token", "subject_token_type", "actor_token", "actor_token_type", "requested_token_type", "scope", "resource", "audience":
		default:
			return false
		}
	}
	return true
}
func splitScopes(value string) []string { return strings.Fields(value) }

func (h *tokenExchangeHandler) exchangePrincipal(ctx context.Context, raw string, now time.Time) (fosite.Requester, string, *fosite.DefaultSession, time.Time, error) {
	signature := h.strategy.AccessTokenSignature(ctx, raw)
	principal, err := h.store.GetAccessTokenSession(ctx, signature, &fosite.DefaultSession{})
	if err != nil {
		if isUnavailableErr(err) {
			return nil, "", nil, time.Time{}, err
		}
		return nil, "", nil, time.Time{}, fosite.ErrInvalidGrant
	}
	if h.strategy.ValidateAccessToken(ctx, principal, raw) != nil || sessionDPoPJKT(principal.GetSession()) != "" {
		return nil, "", nil, time.Time{}, fosite.ErrInvalidGrant
	}
	session, ok := principal.GetSession().(*fosite.DefaultSession)
	if !ok {
		return nil, "", nil, time.Time{}, fosite.ErrInvalidGrant
	}
	if err := h.store.validateTokenAccounts(ctx, principal); err != nil {
		if isUnavailableErr(err) {
			return nil, "", nil, time.Time{}, err
		}
		return nil, "", nil, time.Time{}, fosite.ErrInvalidGrant
	}
	expires := session.GetExpiresAt(fosite.AccessToken).UTC()
	if !expires.After(now) {
		return nil, "", nil, time.Time{}, fosite.ErrInvalidGrant
	}
	return principal, signature, session, expires, nil
}
