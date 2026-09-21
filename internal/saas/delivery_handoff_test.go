package saas

import (
	"errors"
	"net/url"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/rhiza"
)

func TestCredentialDeliveryHandoffApproveAndDeliver(t *testing.T) {
	t.Parallel()
	ctx, s, db, b, connector := registeredAPIKeyFixture(t, "delivery-handoff-provider")
	if _, err := s.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	cs := clients.NewStore(db, s.keys)
	requester, err := cs.CreateWithGuard(ctx, clients.NewRequest{ID: "delivery-handoff-requester", RedirectURIs: []string{"https://requester.example/callback"}, Scopes: []string{"goauthy.connections.write"}, DefaultScopes: []string{"goauthy.connections.write"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := cs.CreateWithGuard(ctx, clients.NewRequest{ID: "delivery-handoff-consumer", Confidential: true, RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	in := UseHandoffInput{CollectionID: b.CollectionID, ConnectionID: b.ConnectionID, ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "export", ExpiresAt: s.now() + 60000, ReturnURI: "https://requester.example/callback", State: "delivery-handoff-state-012345678901234567890123"}
	id, review, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", in, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if review.Grant.ID != "" {
		t.Fatal("proposal issued grant")
	}
	if _, err = s.ReviewUseHandoff(ctx, b.Owner, id, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	redirect, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, connector.Digest(), credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := s.ListUseGrants(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || len(grant) != 1 || grant[0].Mode != "credential_delivery" {
		t.Fatalf("grants=%+v err=%v", grant, err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil || parsed.Query().Get("grant_id") != grant[0].ID {
		t.Fatalf("redirect=%q grant=%s err=%v", redirect, grant[0].ID, err)
	}
	if _, err = s.CompleteUseHandoff(ctx, b.Owner, id, true, connector.Digest(), credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("replay=%v", err)
	}
	delivery, err := s.DeliverAPIKey(ctx, b.Owner, consumer.ID, grant[0].ID, grant[0].Resource, credentialAuthority())
	if err != nil || delivery.APIKey != "synthetic-key" {
		t.Fatalf("delivery=%+v err=%v", delivery, err)
	}
	deniedID, _, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", in, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	deniedURI, err := s.CompleteUseHandoff(ctx, b.Owner, deniedID, false, "", credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	denied, err := url.Parse(deniedURI)
	if err != nil || denied.Query().Get("error") != "access_denied" || denied.Query().Get("grant_id") != "" {
		t.Fatal("denial returned invalid result")
	}
	if _, err = s.CompleteUseHandoff(ctx, b.Owner, deniedID, true, connector.Digest(), credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("denied ticket replay=%v", err)
	}
	remaining, err := s.ListUseGrants(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || len(remaining) != 1 || remaining[0].ID != grant[0].ID {
		t.Fatal("denial created or changed consent")
	}
}

func TestCredentialDeliveryHandoffRejectsPublicConsumer(t *testing.T) {
	t.Parallel()
	ctx, s, db, b, connector := registeredAPIKeyFixture(t, "delivery-public-handoff")
	cs := clients.NewStore(db, s.keys)
	if _, err := s.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	requester, err := cs.CreateWithGuard(ctx, clients.NewRequest{ID: "delivery-public-requester", RedirectURIs: []string{"https://requester.example/callback"}, Scopes: []string{"goauthy.connections.write"}, DefaultScopes: []string{"goauthy.connections.write"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	public, err := cs.CreateWithGuard(ctx, clients.NewRequest{ID: "delivery-public-consumer", RedirectURIs: []string{"https://public.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	in := UseHandoffInput{CollectionID: b.CollectionID, ConnectionID: b.ConnectionID, ConsumerClientID: public.ID, Mode: "credential_delivery", Purpose: "export", ExpiresAt: s.now() + 60000, ReturnURI: requester.RedirectURIs[0], State: "delivery-public-handoff-state-0123456789"}
	if _, _, err = s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", in, credentialAuthority()); err == nil {
		t.Fatal("public consumer accepted")
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_use_handoffs`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || q.Rows[0][0] != int64(0) {
		t.Fatalf("public ticket=%v err=%v", q.Rows, err)
	}
}

func TestCredentialDeliveryHandoffConfidentialityFence(t *testing.T) {
	t.Parallel()
	ctx, s, db, b, connector := registeredAPIKeyFixture(t, "delivery-handoff-fence")
	if _, err := s.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	cs := clients.NewStore(db, s.keys)
	requester, err := cs.CreateWithGuard(ctx, clients.NewRequest{ID: "delivery-fence-requester", RedirectURIs: []string{"https://requester.example/callback"}, Scopes: []string{"goauthy.connections.write"}, DefaultScopes: []string{"goauthy.connections.write"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := cs.CreateWithGuard(ctx, clients.NewRequest{ID: "delivery-fence-consumer", Confidential: true, RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	in := UseHandoffInput{CollectionID: b.CollectionID, ConnectionID: b.ConnectionID, ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "export", ExpiresAt: s.now() + 60000, ReturnURI: "https://requester.example/callback", State: "delivery-handoff-state-012345678901234567890123"}
	id, _, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", in, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	updated, err := cs.UpdateWithGuard(ctx, consumer.ID, consumer.Revision, clients.UpdateRequest{Confidential: false, RedirectURIs: consumer.RedirectURIs, Scopes: consumer.Scopes, DefaultScopes: consumer.DefaultScopes, GrantTypes: consumer.GrantTypes, Audiences: consumer.Audiences}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	_ = updated
	if _, err = s.CompleteUseHandoff(ctx, b.Owner, id, true, connector.Digest(), credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) && !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("confidentiality fence=%v", err)
	}
	grants, err := s.ListUseGrants(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || len(grants) != 0 {
		t.Fatalf("grants=%+v err=%v", grants, err)
	}
}
