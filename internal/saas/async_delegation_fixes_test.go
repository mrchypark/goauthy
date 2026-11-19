package saas

import (
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
)

func TestRefreshClaimLeaseExpiryFailClosedAndConflict(t *testing.T) {
	t.Parallel()
	ctx, s, db, b := credentialStoreFixture(t)
	now := int64(1_700_000_000_000)
	s.now = func() int64 { return now }
	providers, err := NewProviderStore(db, s.keys)
	if err != nil {
		t.Fatal(err)
	}
	provider := providerInputForTest("synthetic-provider-secret")
	provider.ID = b.ProviderID
	if _, err := providers.Create(ctx, provider, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if err := s.Install(ctx, b, refreshCredentialFixture(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	consumer, err := clients.NewStore(db, s.keys).CreateWithGuard(ctx, clients.NewRequest{
		ID: "lease-consumer", Confidential: true, RedirectURIs: []string{"https://c.example/cb"},
		Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"},
		GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://c.example/res"},
	}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://c.example/res", UseGrantInput{
		ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "sync",
		AllowRefresh: true, ExpiresAt: now + 300_000,
	}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}

	claim, err := s.ClaimRefresh(ctx, b, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	// Active refreshing -> authorizeUseRefresh returns 409 conflict.
	if _, err := s.RefreshOAuth2UseGrant(ctx, providers, b.Owner, consumer.ID, grant.ID, grant.Resource, 1, credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("concurrent refresh err=%v; want ErrUseGrantConflict", err)
	}

	// Advance past 30s lease.
	now += int64((31 * time.Second) / time.Millisecond)

	// ClaimRefresh MUST NOT recover expired refreshing claims.
	if _, err := s.ClaimRefresh(ctx, b, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("expired re-claim err=%v; want ErrCredentialConflict", err)
	}
	// CompleteRefresh MUST reject late commit after 30s lease.
	if err := s.CompleteRefresh(ctx, b, claim, refreshCredentialFixture(), credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("late CompleteRefresh err=%v; want ErrCredentialConflict", err)
	}
	// OAuth2Status & OAuth2UseGrantStatus project expired refreshing as uncertain.
	st, err := s.OAuth2Status(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || st.State != "uncertain" || st.Connected {
		t.Fatalf("OAuth2Status=%+v err=%v; want uncertain", st, err)
	}
	ust, err := s.OAuth2UseGrantStatus(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority())
	if err != nil || ust.State != "uncertain" || ust.Connected {
		t.Fatalf("OAuth2UseGrantStatus=%+v err=%v; want uncertain", ust, err)
	}
	// Owner RevokeOAuth2 still transitions expired refreshing -> revoked.
	if err := s.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, credentialAuthority()); err != nil {
		t.Fatalf("owner RevokeOAuth2 err=%v", err)
	}
}
