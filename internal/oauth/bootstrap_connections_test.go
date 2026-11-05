package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestBootstrapConnectionsRuntimePinAndInactive(t *testing.T) {
	if err := (*Server)(nil).PinBootstrapConnections(t.Context(), ""); err != nil {
		t.Fatalf("inactive feature gated startup: %v", err)
	}
	db := oauthTestDB(t)
	const resource = "https://resource.example.test/connections"
	cs := clients.NewStore(db, nil)
	if err := cs.EnsureBootstrap(t.Context(), testClientID); err != nil {
		t.Fatal(err)
	}
	newServer := func(secret string) *Server {
		s, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, secret, testRedirectURI, []string{resource}, OIDCConfig{Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil }})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := newServer(testClientSecret)
	if err := s.PinBootstrapConnections(t.Context(), ""); err != nil {
		t.Fatalf("inactive never-pinned runtime: %v", err)
	}
	if err := s.PinBootstrapConnections(t.Context(), resource); err != nil {
		t.Fatal(err)
	}
	if err := s.PinBootstrapConnections(t.Context(), ""); !errors.Is(err, clients.ErrConflict) {
		t.Fatalf("unset resource on pinned cluster: %v", err)
	}
	// Secret rotation is not a public policy change and is never fingerprinted.
	restarted := newServer("synthetic-rotated-client-secret")
	if err := restarted.PinBootstrapConnections(t.Context(), resource); err != nil {
		t.Fatalf("secret entered fingerprint: %v", err)
	}
	restarted.oidc.Issuer = "https://different-issuer.example"
	if err := restarted.PinBootstrapConnections(t.Context(), resource); !errors.Is(err, clients.ErrConflict) {
		t.Fatalf("different node config: %v", err)
	}
}
