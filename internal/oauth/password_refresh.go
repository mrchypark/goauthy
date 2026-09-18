package oauth

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
)

type passwordRefreshHandler struct {
	*oauth2.RefreshTokenGrantHandler
	config fosite.Configurator
}

func passwordRefreshFactory(config fosite.Configurator, store interface{}, strategy interface{}) interface{} {
	return &passwordRefreshHandler{RefreshTokenGrantHandler: compose.OAuth2RefreshTokenGrantFactory(config, store, strategy).(*oauth2.RefreshTokenGrantHandler), config: config}
}

func (h *passwordRefreshHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	// Per-request configuration observes the session hydrated by the existing
	// refresh-token lookup; no shared configuration or unverified form marker.
	local := *h.RefreshTokenGrantHandler
	local.Config = passwordRefreshConfig{Configurator: h.config, request: request}
	return local.HandleTokenEndpointRequest(ctx, request)
}

type passwordRefreshConfig struct {
	fosite.Configurator
	request fosite.AccessRequester
}

func (c passwordRefreshConfig) GetRefreshTokenScopes(ctx context.Context) []string {
	if session, ok := c.request.GetSession().(*fosite.DefaultSession); ok {
		if _, passwordOrigin := session.Extra[passwordAuthTimeExtra]; passwordOrigin {
			return nil
		}
	}
	return c.Configurator.GetRefreshTokenScopes(ctx)
}
