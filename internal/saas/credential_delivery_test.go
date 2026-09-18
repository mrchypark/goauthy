package saas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func deliveryFixture(t *testing.T) (context.Context, *CredentialStore, *rhiza.DB, credentialBinding, *APIKeyConnector, clients.Client, UseGrant) {
	t.Helper()
	ctx, s, db, b, connector := registeredAPIKeyFixture(t, "delivery-provider")
	if _, err := s.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	consumer, err := clients.NewStore(db, s.keys).CreateWithGuard(ctx, clients.NewRequest{ID: "delivery-consumer", Confidential: true, RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", UseGrantInput{ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "export", ExpiresAt: s.now() + 60000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	return ctx, s, db, b, connector, consumer, grant
}

func TestDeliverAPIKeyExactDTOAndRedaction(t *testing.T) {
	ctx, s, _, b, connector, consumer, grant := deliveryFixture(t)
	got, err := s.DeliverAPIKey(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "api_key" || got.APIKey != "synthetic-key" || got.GrantID != grant.ID || got.ProviderID != grant.ProviderID || got.ConnectionGeneration != grant.Generation || got.CredentialVersion != 1 || got.ConnectorDigest != connector.Digest() {
		t.Fatalf("delivery=%+v", got)
	}
	if fmt.Sprint(got) != "[redacted SaaS credential delivery]" || fmt.Sprintf("%#v", got) != "[redacted SaaS credential delivery]" {
		t.Fatalf("redaction=%q/%q", fmt.Sprint(got), fmt.Sprintf("%#v", got))
	}
	raw, _ := json.Marshal(got)
	text := string(raw)
	for _, bad := range []string{"refresh", "client_secret"} {
		if strings.Contains(text, bad) {
			t.Fatalf("leak %q in %s", bad, text)
		}
	}
}

func TestDeliverAPIKeyRejectsInvalidConsentAndConsumers(t *testing.T) {
	ctx, s, _, b, _, consumer, grant := deliveryFixture(t)
	for _, tc := range []struct{ name, owner, cid, resource string }{{"owner", "wrong-owner", consumer.ID, grant.Resource}, {"consumer", b.Owner, "other", grant.Resource}, {"resource", b.Owner, consumer.ID, "https://wrong.example"}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.DeliverAPIKey(ctx, tc.owner, tc.cid, grant.ID, tc.resource, credentialAuthority())
			if err == nil || got.APIKey != "" {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
	if err := s.RevokeUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, grant.ID, grant.Revision, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if got, err := s.DeliverAPIKey(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority()); err == nil || got.APIKey != "" {
		t.Fatalf("revoked=%+v/%v", got, err)
	}
}

// Trigger real store mutations at the authorization callbacks, without sleeps
// or scheduler races. Callback six is the final check after key decryption.
func TestDeliverAPIKeyRechecksBeforeReturningSecret(t *testing.T) {
	for _, phase := range []int{2, 6} {
		for _, change := range []string{"revoke", "rotate"} {
			t.Run(fmt.Sprintf("%s/check-%d", change, phase), func(t *testing.T) {
				ctx, s, _, b, connector, consumer, grant := deliveryFixture(t)
				calls := 0
				authority := func() (string, []any) {
					calls++
					if calls == phase {
						var err error
						if change == "revoke" {
							err = s.RevokeUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, grant.ID, grant.Revision, credentialAuthority())
						} else {
							_, err = s.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, "rotated-synthetic-key", connector, connector.Digest(), credentialAuthority())
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					return "1", nil
				}
				got, err := s.DeliverAPIKey(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, authority)
				if calls != phase || err == nil || got != (APIKeyDelivery{}) {
					t.Fatalf("check=%d calls=%d error=%v nonzero response=%t", phase, calls, err, got != (APIKeyDelivery{}))
				}
			})
		}
	}
}

func TestDeliverAPIKeyProxyConsentCannotExport(t *testing.T) {
	ctx, s, _, b, _, consumer, _ := deliveryFixture(t)
	grant, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", UseGrantInput{ConsumerClientID: consumer.ID, Mode: "proxy", Purpose: "proxy only", ExpiresAt: s.now() + 60000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.DeliverAPIKey(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority())
	if !errors.Is(err, ErrUseGrantNotFound) || got != (APIKeyDelivery{}) {
		t.Fatalf("proxy export error=%v nonzero response=%t", err, got != (APIKeyDelivery{}))
	}
}

func TestDeliverAPIKeyProviderAndGenerationFences(t *testing.T) {
	ctx, s, db, b, _, consumer, grant := deliveryFixture(t)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "delivery-provider-disable", SQL: `UPDATE saas_providers SET enabled=0 WHERE id=?`, Args: []any{grant.ProviderID}}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.DeliverAPIKey(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority()); err == nil || got.APIKey != "" {
		t.Fatalf("disabled=%+v/%v", got, err)
	}
	ctx, s, db, b, _, consumer, grant = deliveryFixture(t)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "delivery-provider-rotate", SQL: `UPDATE saas_providers SET revision=revision+1 WHERE id=?`, Args: []any{grant.ProviderID}}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.DeliverAPIKey(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority()); err == nil || got.APIKey != "" {
		t.Fatalf("rotated=%+v/%v", got, err)
	}
}

func TestDeliverAPIKeyExpiryAndPublicConsumer(t *testing.T) {
	ctx, s, db, b, _, consumer, grant := deliveryFixture(t)
	s.now = func() int64 { return grant.ExpiresAt }
	if got, err := s.DeliverAPIKey(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority()); err == nil || got.APIKey != "" {
		t.Fatalf("expired=%+v/%v", got, err)
	}
	_ = db
	ctx, s, db, b, _, _, _ = deliveryFixture(t)
	public, err := clients.NewStore(db, s.keys).CreateWithGuard(ctx, clients.NewRequest{ID: "delivery-public", Confidential: false, RedirectURIs: []string{"https://public.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", UseGrantInput{ConsumerClientID: public.ID, Mode: "credential_delivery", Purpose: "x", ExpiresAt: s.now() + 60000}, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("public grant=%v", err)
	}
}
