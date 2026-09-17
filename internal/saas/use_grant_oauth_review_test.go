package saas

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
)

func TestUseGrantReviewedCredentialVersionOAuth2(t *testing.T) {
	ctx, s, b, consumer, _ := oauth2DeliveryFixture(t)
	version := int64(1)
	input := UseGrantInput{ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "review", ExpiresAt: s.now() + 60000, ReviewedCredentialVersion: &version}
	if _, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", input, credentialAuthority()); err != nil {
		t.Fatalf("current version: %v", err)
	}
	claim, err := s.ClaimRefresh(ctx, b, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteRefresh(ctx, b, claim, credential{AccountID: "account-1", AccessToken: "access-2", RefreshToken: "refresh-2", ExpiresAtUnixMS: s.now() + 60000}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", input, credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("stale version: %v", err)
	}
	version = 2
	if _, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", input, credentialAuthority()); err != nil {
		t.Fatalf("refreshed version: %v", err)
	}
}

func TestUseGrantReviewedCredentialVersionValidation(t *testing.T) {
	ctx, s, b, consumer, _ := oauth2DeliveryFixture(t)
	for name, version := range map[string]int64{"zero": 0, "negative": -1} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", UseGrantInput{ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "review", ExpiresAt: s.now() + 60000, ReviewedCredentialVersion: &version}, credentialAuthority()); !errors.Is(err, ErrUseGrantInvalid) {
				t.Fatalf("version=%d err=%v", version, err)
			}
		})
	}
	if _, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", UseGrantInput{ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "review", ExpiresAt: s.now() + 60000}, credentialAuthority()); err != nil {
		t.Fatalf("omitted version: %v", err)
	}

	ctx, s, db, b, connector := registeredAPIKeyFixture(t, "review-version-api-key")
	if _, err := s.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "bound", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	apiConsumer, err := clients.NewStore(db, s.keys).CreateWithGuard(ctx, clients.NewRequest{ID: "review-version-api-key-consumer", RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	version := int64(1)
	if _, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", UseGrantInput{ConsumerClientID: apiConsumer.ID, Mode: "proxy", Purpose: "review", ExpiresAt: s.now() + 60000, ReviewedCredentialVersion: &version}, credentialAuthority()); !errors.Is(err, ErrUseGrantInvalid) {
		t.Fatalf("api key version misuse: %v", err)
	}
}
