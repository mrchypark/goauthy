package oauth

import (
	"context"

	"github.com/mrchypark/goauthy/internal/clients"
)

// PinBootstrapConnections enables the bootstrap client's SaaS policy only when
// the connections resource is configured. It does not change client registration
// or persist authentication secrets. Scope changes retain their existing DB CAS.
func (s *Server) PinBootstrapConnections(ctx context.Context, resource string) error {
	if resource == "" {
		if s == nil || s.store == nil {
			return nil
		}
		return clients.NewStore(s.store.db, nil).CheckBootstrapConnectionsInactive(ctx)
	}
	if s == nil || s.oidc == nil || s.store == nil || s.store.client == nil {
		return clients.ErrInvalid
	}
	c := s.store.client
	p := clients.ConnectionPolicy{
		ID: c.GetID(), Enabled: true, Confidential: !c.IsPublic(),
		RedirectURIs: c.GetRedirectURIs(), Scopes: append([]string(nil), c.GetScopes()...),
		GrantTypes: append([]string(nil), c.GetGrantTypes()...), Audiences: append([]string(nil), c.GetAudience()...),
		ForceMFA: s.store.bootstrapForceMFA,
	}
	if d := s.defaultAudiences[c.GetID()]; d != "" {
		p.DefaultAudiences = []string{d}
	}
	methods := []string{"client_secret_basic", "client_secret_post"}
	if c.IsPublic() {
		methods = []string{"none"}
	}
	return clients.NewStore(s.store.db, nil).PinBootstrapConnections(ctx, clients.BootstrapConnectionConfig{
		Issuer: s.oidc.Issuer, Resource: resource, AuthMethods: methods, Client: p,
	})
}
