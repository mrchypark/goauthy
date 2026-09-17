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

func oauth2DeliveryFixture(t *testing.T) (ctx context.Context, s *CredentialStore, b credentialBinding, consumer clients.Client, grant UseGrant) {
	t.Helper()
	ctx, s, _, b = credentialStoreFixture(t)
	providers, err := NewProviderStore(s.db, s.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := providers.Create(ctx, ProviderInput{ID: "provider", Name: "Provider", Kind: "oauth2", Enabled: true, ClientID: "client", ClientSecret: "provider-secret", CallbackURI: "https://auth.example/callback", AuthorizationURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token", Scopes: []string{"openid", "profile"}, AuthStyle: "header", IdentityEndpoint: "https://provider.example/identity", SubjectField: "sub"}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if err := s.Install(ctx, b, credential{AccountID: "account-1", AccessToken: "access-token", RefreshToken: "refresh-secret", ExpiresAtUnixMS: s.now() + 60000, Scopes: []string{"openid"}}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	consumer, err = clients.NewStore(s.db, s.keys).CreateWithGuard(ctx, clients.NewRequest{ID: "oauth2-delivery-consumer", Confidential: true, RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	grant, err = s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", UseGrantInput{ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "oauth2 export", ExpiresAt: s.now() + 120000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestDeliverOAuth2DTOAndRedaction(t *testing.T) {
	ctx, s, b, consumer, grant := oauth2DeliveryFixture(t)
	got, err := s.DeliverOAuth2(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority())
	if err != nil || got.Kind != "oauth2" || got.AccessToken != "access-token" || got.TokenType != "Bearer" || got.GrantID != grant.ID || got.ProviderID != "provider" || got.ConnectionGeneration != b.Generation || got.CredentialVersion != 1 || got.AccountID != "account-1" || len(got.Scopes) != 1 || got.TokenExpiresAtUnixMS <= s.now() || got.ConsentExpiresAtUnixMS != grant.ExpiresAt {
		t.Fatalf("delivery=%+v err=%v", got, err)
	}
	if fmt.Sprint(got) != "[redacted SaaS OAuth2 delivery]" || fmt.Sprintf("%#v", got) != "[redacted SaaS OAuth2 delivery]" {
		t.Fatal("delivery was not redacted")
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "refresh") || strings.Contains(string(raw), "provider-secret") {
		t.Fatalf("secret leaked: %s", raw)
	}
}

func TestDeliverOAuth2RejectsInvalidConsentAndExpiry(t *testing.T) {
	ctx, s, b, consumer, grant := oauth2DeliveryFixture(t)
	for _, tc := range []struct {
		name, owner, client string
	}{
		{"owner", "other", consumer.ID}, {"client", b.Owner, "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := s.DeliverOAuth2(ctx, tc.owner, tc.client, grant.ID, grant.Resource, credentialAuthority()); err == nil || got.AccessToken != "" {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
	if err := s.RevokeUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, grant.ID, grant.Revision, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if got, err := s.DeliverOAuth2(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority()); err == nil || got.AccessToken != "" {
		t.Fatalf("revoked got=%+v err=%v", got, err)
	}
}

func TestDeliverOAuth2RequiresKnownFutureTokenExpiry(t *testing.T) {
	ctx, s, b, consumer, grant := oauth2DeliveryFixture(t)
	base := int64(1_800_000_000_000)
	for _, tc := range []struct {
		name string
		now  int64
		want bool
	}{{"immediately before", base + 59999, true}, {"exact expiry", base + 60000, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s.now = func() int64 { return tc.now }
			got, err := s.DeliverOAuth2(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority())
			if tc.want && (err != nil || got.AccessToken == "") || !tc.want && (!errors.Is(err, ErrUseGrantNotFound) || got.AccessToken != "") {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
	envelope, err := sealCredential(s.keys, b, credential{AccessToken: "access-unknown", ExpiresAtUnixMS: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "oauth2-delivery-unknown-expiry", SQL: `UPDATE saas_connection_credentials SET credential=? WHERE connection_id=?`, Args: []any{envelope, b.ConnectionID}}); err != nil {
		t.Fatal(err)
	}
	s.now = func() int64 { return base }
	if got, err := s.DeliverOAuth2(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) || got.AccessToken != "" {
		t.Fatalf("unknown expiry got=%+v err=%v", got, err)
	}
}

func TestDeliverOAuth2ProxyAndReconnectAreDenied(t *testing.T) {
	ctx, s, b, consumer, grant := oauth2DeliveryFixture(t)
	proxy, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, "https://consumer.example/resource", UseGrantInput{ConsumerClientID: consumer.ID, Mode: "proxy", Purpose: "proxy", ExpiresAt: s.now() + 120000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.DeliverOAuth2(ctx, b.Owner, consumer.ID, proxy.ID, proxy.Resource, credentialAuthority()); err == nil || got.AccessToken != "" {
		t.Fatalf("proxy got=%+v err=%v", got, err)
	}
	if err := s.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareOAuth2Reconnect(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if got, err := s.DeliverOAuth2(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority()); err == nil || got.AccessToken != "" {
		t.Fatalf("reconnected got=%+v err=%v", got, err)
	}
}

func TestDeliverOAuth2RefreshVersionAndPostDecryptRecheck(t *testing.T) {
	ctx, s, b, consumer, grant := oauth2DeliveryFixture(t)
	claim, err := s.ClaimRefresh(ctx, b, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteRefresh(ctx, b, claim, credential{AccountID: "account-1", AccessToken: "access-2", RefreshToken: "refresh-2", ExpiresAtUnixMS: s.now() + 60000}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	got, err := s.DeliverOAuth2(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, credentialAuthority())
	if err != nil || got.AccessToken != "access-2" || got.CredentialVersion != 2 || got.ConsentExpiresAtUnixMS != grant.ExpiresAt {
		t.Fatalf("refreshed=%+v err=%v", got, err)
	}
	raw, err := json.Marshal(got)
	if err != nil || !strings.Contains(string(raw), `"scopes":[]`) {
		t.Fatal("empty scopes must be a JSON array")
	}
	calls := 0
	authority := func() (string, []any) {
		calls++
		if calls == 5 {
			if err := s.RevokeUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, grant.ID, grant.Revision, credentialAuthority()); err != nil {
				t.Fatal(err)
			}
		}
		return "1", nil
	}
	got, err = s.DeliverOAuth2(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, authority)
	if calls != 5 || err == nil || got.AccessToken != "" {
		t.Fatalf("postdecrypt mutation got=%+v err=%v calls=%d", got, err, calls)
	}
}

func TestDeliverOAuth2FinalTokenExpiryAndVersionFence(t *testing.T) {
	for _, mutation := range []string{"expiry", "refresh", "public consumer"} {
		t.Run(mutation, func(t *testing.T) {
			ctx, s, b, consumer, grant := oauth2DeliveryFixture(t)
			calls := 0
			authority := func() (string, []any) {
				calls++
				// Calls 1/2 authorize consent, 3 reads binding, 4 loads ciphertext;
				// call 5 is the final guard, after access-token decryption.
				if calls == 5 {
					switch mutation {
					case "expiry":
						now := s.now() + 60000
						s.now = func() int64 { return now }
					case "refresh":
						claim, err := s.ClaimRefresh(ctx, b, credentialAuthority())
						if err != nil {
							t.Fatal(err)
						}
						if err := s.CompleteRefresh(ctx, b, claim, credential{AccountID: "account-1", AccessToken: "replacement", ExpiresAtUnixMS: s.now() + 60000}, credentialAuthority()); err != nil {
							t.Fatal(err)
						}
					case "public consumer":
						if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "delivery-public-consumer", SQL: `UPDATE managed_oauth_clients SET metadata_json=json_set(metadata_json,'$.confidential',json('false')) WHERE id=?`, Args: []any{consumer.ID}}); err != nil {
							t.Fatal(err)
						}
					}
				}
				return "1", nil
			}
			got, err := s.DeliverOAuth2(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, authority)
			if calls != 5 || err == nil || got.AccessToken != "" {
				t.Fatalf("final mutation not fenced: calls=%d err=%v", calls, err)
			}
		})
	}
}
