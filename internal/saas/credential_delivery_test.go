package saas

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
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
	t.Parallel()
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

func TestDeliverAPIKeyReusesAuthenticatedSnapshot(t *testing.T) {
	t.Parallel()
	ctx, s, _, b, _, consumer, grant := deliveryFixture(t)
	keyringDir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(255 - i)
	}
	if err := os.WriteFile(filepath.Join(keyringDir, "other"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	otherKeys, err := oidc.LoadKeyring(keyringDir, "other")
	if err != nil {
		t.Fatal(err)
	}

	// The first callback after AuthorizeUseGrant returns is the boundary before
	// delivery's final current-state read. An old duplicate-decrypt path fails
	// here because this keyring cannot open the already-authenticated envelope.
	calls := 0
	swapped := false
	authority := func() (string, []any) {
		calls++
		if calls == 3 {
			s.keys = otherKeys
			swapped = true
		}
		return "1", nil
	}
	got, err := s.DeliverAPIKey(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, authority)
	if !swapped || err != nil || got.APIKey != "synthetic-key" || got.CredentialVersion != 1 {
		t.Fatalf("snapshot delivery failed: swapped=%t callbacks=%d err=%v", swapped, calls, err)
	}
}

func TestDeliverAPIKeyUsesFinalCredentialForChangedEnvelope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, finalKey string
		tamper         bool
		wantErr        bool
	}{
		{name: "valid-rewrap", finalKey: "synthetic-key"},
		{name: "changed-current-key", finalKey: "current-synthetic-key"},
		{name: "tampered", finalKey: "synthetic-key", tamper: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, s, db, b, connector, consumer, grant := deliveryFixture(t)
			calls := 0
			mutated := false
			authority := func() (string, []any) {
				calls++
				if calls == 3 {
					binding := credentialBinding{Owner: grant.Owner, CollectionID: grant.CollectionID, ConnectionID: grant.ConnectionID, ProviderID: grant.ProviderID, Generation: grant.Generation, TokenVersion: 1}
					prior, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials WHERE connection_id=? AND token_version=1`, Args: []any{grant.ConnectionID}})
					if err != nil || len(prior.Rows) != 1 || len(prior.Rows[0]) != 1 {
						t.Fatalf("read prior credential envelope: rows=%d err=%v", len(prior.Rows), err)
					}
					priorEnvelope, ok := prior.Rows[0][0].([]byte)
					if !ok {
						t.Fatal("prior credential envelope has unexpected type")
					}
					envelope, err := sealCredential(s.keys, binding, credential{APIKey: tc.finalKey, ConnectorDigest: connector.Digest()})
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Equal(priorEnvelope, envelope) {
						t.Fatal("replacement envelope did not change ciphertext")
					}
					if tc.tamper {
						envelope[len(envelope)-1] ^= 1
					}
					result, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "delivery-envelope-" + tc.name, SQL: `UPDATE saas_connection_credentials SET credential=? WHERE connection_id=? AND token_version=1`, Args: []any{envelope, grant.ConnectionID}})
					if err != nil || result.RowsAffected != 1 {
						t.Fatalf("replace current envelope: rows=%d err=%v", result.RowsAffected, err)
					}
					mutated = true
				}
				return "1", nil
			}
			got, err := s.DeliverAPIKey(ctx, b.Owner, consumer.ID, grant.ID, grant.Resource, authority)
			wantCalls := 4
			if tc.wantErr {
				wantCalls = 3
			}
			if !mutated || calls != wantCalls {
				t.Fatalf("mutation boundary not reached: mutated=%t callbacks=%d", mutated, calls)
			}
			if tc.wantErr {
				if err == nil || got != (APIKeyDelivery{}) {
					t.Fatal("tampered current envelope was delivered")
				}
				return
			}
			if err != nil || got.APIKey != tc.finalKey {
				t.Fatalf("delivery did not use final authenticated credential: err=%v", err)
			}
		})
	}
}

func TestDeliverAPIKeyRejectsInvalidConsentAndConsumers(t *testing.T) {
	t.Parallel()
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
// or scheduler races. Callback two is AuthorizeUseGrant's own check; callback
// three is the loader read and callback four is the preserved last guard.
func TestDeliverAPIKeyRechecksBeforeReturningSecret(t *testing.T) {
	t.Parallel()
	for _, phase := range []int{2, 3, 4} {
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
