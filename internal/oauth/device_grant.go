package oauth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

// DeviceGrantType is the RFC 8628 token-endpoint grant value.
const DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

const (
	deviceCodeExtra  = "goauthy_device_code"
	deviceClaimExtra = "goauthy_device_claim"
	deviceOIDCExtra  = "goauthy_device_oidc"
)

type deviceGrantHandler struct {
	*oauth2.HandleHelper
	store            *Store
	device           *device.Store
	refreshTokens    oauth2.RefreshTokenStrategy
	config           *fosite.Config
	customScope      func(context.Context, string) (bool, error)
	oidcEnabled      bool
	validateResource func(context.Context, fosite.Client, string) error
}

var _ fosite.TokenEndpointHandler = (*deviceGrantHandler)(nil)

func newDeviceGrantHandler(store *Store, deviceStore *device.Store, strategy oauth2.CoreStrategy, config *fosite.Config, customScope func(context.Context, string) (bool, error), oidcEnabled bool) *deviceGrantHandler {
	return &deviceGrantHandler{
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: strategy,
			AccessTokenStorage:  store,
			Config:              config,
		},
		store: store, device: deviceStore, refreshTokens: strategy, config: config, customScope: customScope, oidcEnabled: oidcEnabled,
	}
}

func (h *deviceGrantHandler) CanHandleTokenEndpointRequest(_ context.Context, request fosite.AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(DeviceGrantType)
}

func (*deviceGrantHandler) CanSkipClientAuth(context.Context, fosite.AccessRequester) bool {
	return false
}

func (h *deviceGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !h.CanHandleTokenEndpointRequest(ctx, request) {
		return fosite.ErrUnknownRequest
	}
	if !request.GetClient().GetGrantTypes().Has(DeviceGrantType) {
		return fosite.ErrUnauthorizedClient
	}
	form := request.GetRequestForm()
	deviceCode, ok := exactlyOne(form, "device_code")
	if !ok || form.Has("scope") || form.Has("resource") || form.Has("audience") || len(request.GetRequestedScopes()) != 0 {
		return fosite.ErrInvalidRequest
	}
	result, err := h.device.Poll(ctx, deviceCode, request.GetClient().GetID(), time.Now().UTC())
	if err != nil {
		return fosite.ErrServerError
	}
	switch result.Status {
	case device.StatusPending:
		return deviceGrantError("authorization_pending")
	case device.StatusSlowDown:
		return deviceGrantError("slow_down")
	case device.StatusDenied:
		return deviceGrantError("access_denied")
	case device.StatusExpired:
		return deviceGrantError("expired_token")
	case device.StatusClaimed:
		// Continue below.
	default:
		return fosite.ErrServerError
	}
	if result.ClaimToken == "" || result.Subject == "" || len(result.Scopes) == 0 || (!h.oidcEnabled && (containsScope(result.Scopes, openidScope) || containsScope(result.Scopes, groupsScope))) {
		return h.releaseClaimError(ctx, result.ClaimToken, fosite.ErrInvalidScope)
	}
	if h.store.forceMFA(request.GetClient()) && !result.MFAVerified {
		return h.releaseClaimError(ctx, result.ClaimToken, fosite.ErrInvalidGrant)
	}
	if managed, ok := request.GetClient().(*clients.Client); ok && result.ManagedClientGeneration != managed.Generation {
		return h.releaseClaimError(ctx, result.ClaimToken, fosite.ErrInvalidGrant)
	}
	if result.Resource != "" {
		if h.validateResource == nil || h.validateResource(ctx, request.GetClient(), result.Resource) != nil {
			return h.releaseClaimError(ctx, result.ClaimToken, errInvalidTarget)
		}
		request.SetRequestedAudience(fosite.Arguments{result.Resource})
		request.GrantAudience(result.Resource)
	}
	for _, scope := range result.Scopes {
		if h.customScope != nil {
			custom, customErr := h.customScope(ctx, scope)
			if customErr != nil {
				return h.releaseClaimError(ctx, result.ClaimToken, fosite.ErrServerError)
			}
			if custom && !deviceResourcePermissionScope(scope) {
				return h.releaseClaimError(ctx, result.ClaimToken, fosite.ErrInvalidScope)
			}
		}
		if !h.config.GetScopeStrategy(ctx)(request.GetClient().GetScopes(), scope) {
			return h.releaseClaimError(ctx, result.ClaimToken, fosite.ErrInvalidScope)
		}
	}

	request.SetRequestedScopes(append(fosite.Arguments(nil), result.Scopes...))
	for _, scope := range result.Scopes {
		request.GrantScope(scope)
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return h.releaseClaimError(ctx, result.ClaimToken, fosite.ErrServerError)
	}
	session.Subject, session.Username = result.Subject, result.Subject
	session.Extra = map[string]interface{}{deviceCodeExtra: deviceCode, deviceClaimExtra: result.ClaimToken}
	if h.oidcEnabled {
		// Persist origin, not browser authentication claims, for refresh signing.
		session.Extra[deviceOIDCExtra] = true
	}
	now := time.Now().UTC()
	atLifetime := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantType(DeviceGrantType), fosite.AccessToken, h.config.GetAccessTokenLifespan(ctx))
	session.SetExpiresAt(fosite.AccessToken, now.Add(atLifetime).Round(time.Second))
	if h.shouldIssueRefresh(ctx, request) {
		rtLifetime := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantType(DeviceGrantType), fosite.RefreshToken, h.config.GetRefreshTokenLifespan(ctx))
		if rtLifetime > -1 {
			session.SetExpiresAt(fosite.RefreshToken, now.Add(rtLifetime).Round(time.Second))
		}
	}
	return nil
}

func (h *deviceGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) (err error) {
	if !h.CanHandleTokenEndpointRequest(ctx, request) {
		return fosite.ErrUnknownRequest
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok || session.Extra == nil {
		return fosite.ErrServerError
	}
	deviceCode, codeOK := session.Extra[deviceCodeExtra].(string)
	claimToken, claimOK := session.Extra[deviceClaimExtra].(string)
	if !codeOK || !claimOK || deviceCode == "" || claimToken == "" {
		return fosite.ErrServerError
	}
	// These values authorize only this short-lived claim; never retain them in
	// the persisted Fosite session used by introspection or refresh.
	delete(session.Extra, deviceCodeExtra)
	delete(session.Extra, deviceClaimExtra)

	txCtx, err := h.store.BeginDeviceTX(ctx, deviceCode, claimToken)
	if err != nil {
		return h.releaseClaimError(ctx, claimToken, fosite.ErrServerError)
	}
	release := true
	defer func() {
		if release {
			_ = h.store.Rollback(txCtx)
			_ = h.device.Complete(ctx, claimToken, false, time.Now().UTC())
		}
	}()
	if err := h.store.SetDeviceRequestID(txCtx, request.GetID()); err != nil {
		return fosite.ErrServerError
	}

	atLifetime := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantType(DeviceGrantType), fosite.AccessToken, h.config.GetAccessTokenLifespan(txCtx))
	accessSignature, err := h.IssueAccessToken(txCtx, atLifetime, request, response)
	if err != nil {
		return fosite.ErrServerError
	}
	if h.shouldIssueRefresh(txCtx, request) {
		refresh, refreshSignature, err := h.refreshTokens.GenerateRefreshToken(txCtx, request)
		if err != nil {
			return fosite.ErrServerError
		}
		if err := h.store.CreateRefreshTokenSession(txCtx, refreshSignature, accessSignature, request.Sanitize(nil)); err != nil {
			return fosite.ErrServerError
		}
		response.SetExtra("refresh_token", refresh)
	}
	// Once Execute has been attempted, its outcome can be ambiguous to a caller.
	// Leave the claim untouched on an error; releasing it could mint a second
	// pair after a committed-but-unacknowledged transaction.
	release = false
	if err := h.store.Commit(txCtx); err != nil {
		return fosite.ErrServerError
	}
	return nil
}

func (h *deviceGrantHandler) shouldIssueRefresh(ctx context.Context, request fosite.AccessRequester) bool {
	scopes := h.config.GetRefreshTokenScopes(ctx)
	return len(scopes) == 0 || request.GetGrantedScopes().HasOneOf(scopes...)
}

func (h *deviceGrantHandler) releaseClaimError(ctx context.Context, claimToken string, err error) error {
	if claimToken != "" {
		if releaseErr := h.device.Complete(ctx, claimToken, false, time.Now().UTC()); releaseErr != nil {
			return fosite.ErrServerError
		}
	}
	return err
}

func exactlyOne(values map[string][]string, key string) (string, bool) {
	value, ok := values[key]
	returnValue := ""
	if ok && len(value) == 1 {
		returnValue = value[0]
	}
	return returnValue, ok && len(value) == 1 && returnValue != ""
}

func deviceGrantError(code string) error {
	return &fosite.RFC6749Error{ErrorField: code, CodeField: 400}
}

// AuthenticateDeviceClient uses the same Fosite authentication strategy as the
// token endpoint, including each dynamic client's configured authentication method.
func (s *Server) AuthenticateDeviceClient(r *http.Request, clientID string, scopes []string) error {
	if s == nil || r == nil {
		return device.ErrClientAuthentication
	}
	provider, ok := s.provider.(*fosite.Fosite)
	if !ok {
		return device.ErrClientAuthentication
	}
	client, err := provider.AuthenticateClient(r.Context(), r, r.PostForm)
	if err != nil || client == nil || client.GetID() != clientID {
		return device.ErrClientAuthentication
	}
	if client.IsPublic() && (len(r.Header.Values("Authorization")) != 0 || r.PostForm.Has("client_secret")) {
		return device.ErrClientAuthentication
	}
	if managed, ok := client.(*clients.Client); ok {
		device.SetManagedClient(r, managed.ID, managed.Generation, managed.Revision)
	}
	if err := s.authorizeDeviceScopes(r.Context(), client, scopes); err != nil {
		return err
	}
	resource := s.defaultAudiences[clientID]
	if values, present := r.PostForm["resource"]; present {
		if len(values) != 1 || values[0] == "" {
			return device.ErrInvalidTarget
		}
		resource = values[0]
	}
	if resource != "" {
		if err := s.validateDeviceResource(r.Context(), client, resource); err != nil {
			return device.ErrInvalidTarget
		}
		device.SetResource(r, resource)
	}
	return nil
}

// Device grants bypass Fosite's authorization-code handler, so enforce both
// the server resource policy and the client's registered audience here.
func (s *Server) validateDeviceResource(ctx context.Context, client fosite.Client, resource string) error {
	request := fosite.NewRequest()
	request.Client = client
	if err := s.applyResourceAudience(request, []string{resource}); err != nil {
		return err
	}
	return ephemeralAudienceMatchingStrategy(client.GetAudience(), request.GetRequestedAudience())
}

func (s *Server) AuthorizeDeviceClient(ctx context.Context, clientID string, scopes []string) error {
	if s == nil || s.store == nil || clientID == "" || len(scopes) == 0 || len(scopes) > 32 {
		return errors.New("invalid device authorization request")
	}
	client, err := s.store.GetClient(ctx, clientID)
	if err != nil {
		return err
	}
	return s.authorizeDeviceScopes(ctx, client, scopes)
}

func (s *Server) authorizeDeviceScopes(ctx context.Context, client fosite.Client, scopes []string) error {
	if !client.GetGrantTypes().Has(DeviceGrantType) || len(scopes) == 0 || len(scopes) > 32 {
		return errors.New("device client is not authorized")
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		custom, customErr := s.hasCustomUserScope(ctx, []string{scope})
		if customErr != nil || custom && !deviceResourcePermissionScope(scope) || scope == "" || (s.oidc == nil && (scope == openidScope || scope == groupsScope)) || !containsScope(client.GetScopes(), scope) {
			return errors.New("device scope is not authorized")
		}
		if _, duplicate := seen[scope]; duplicate {
			return errors.New("duplicate device scope")
		}
		seen[scope] = struct{}{}
	}
	return nil
}

func containsScope(scopes []string, wanted string) bool {
	for _, scope := range scopes {
		if scope == wanted {
			return true
		}
	}
	return false
}

// These platform permissions may also have catalog entries. They do not turn
// a device grant into permission to request arbitrary custom user scopes.
func deviceResourcePermissionScope(scope string) bool {
	switch scope {
	case "goauthy.connections.read", "goauthy.connections.write", "goauthy.connections.use", "goauthy.providers.read", "goauthy.providers.write":
		return true
	default:
		return false
	}
}
