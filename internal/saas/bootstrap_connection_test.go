package saas

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestBootstrapConnectionHandoffDeliveryAndScopeFence(t *testing.T) {
	ctx, s, db, b, connector := registeredAPIKeyFixture(t, "bootstrap-key-provider")
	if _, err := s.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-bootstrap-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	cs := clients.NewStore(db, s.keys)
	const id = "bootstrap-delivery"
	if err := cs.EnsureBootstrap(ctx, id); err != nil {
		t.Fatal(err)
	}
	cfg := clients.BootstrapConnectionConfig{Issuer: "https://issuer.example", Resource: handoffResource, AuthMethods: []string{"client_secret_basic", "client_secret_post"}, Client: clients.ConnectionPolicy{ID: id, Enabled: true, Confidential: true, RedirectURIs: []string{"https://requester.example/callback"}, Scopes: []string{"openid"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{handoffResource}}}
	if err := cs.PinBootstrapConnections(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "bootstrap-scopes-initial", SQL: `INSERT INTO bootstrap_client_claim_scopes(client_id,allowed_scopes_json,default_scopes_json,revision) VALUES(?,?,'[]',1)`, Args: []any{id, `["goauthy.connections.use","goauthy.connections.write"]`}}); err != nil {
		t.Fatal(err)
	}
	in := newHandoff(s, b, id, id)
	in.Mode = "credential_delivery"
	ticket, _, err := s.CreateUseHandoff(ctx, b.Owner, id, handoffResource, in, credentialAuthority())
	if err != nil {
		t.Fatalf("bootstrap requester/consumer handoff: %v", err)
	}
	if _, err = s.CompleteUseHandoff(ctx, b.Owner, ticket, true, "wrong-digest", credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("digest fence: %v", err)
	}
	redirect, err := s.CompleteUseHandoff(ctx, b.Owner, ticket, true, connector.Digest(), credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	grantID := u.Query().Get("grant_id")
	if grantID == "" {
		t.Fatal("missing consent grant")
	}
	if _, err = s.DeliverAPIKey(ctx, b.Owner, id, grantID, handoffResource, credentialAuthority()); err != nil {
		t.Fatalf("bootstrap delivery: %v", err)
	}
	if _, err = s.DeliverAPIKey(ctx, "other-owner", id, grantID, handoffResource, credentialAuthority()); err == nil {
		t.Fatal("wrong owner accepted")
	}
	if _, err = s.DeliverAPIKey(ctx, b.Owner, "other-consumer", grantID, handoffResource, credentialAuthority()); err == nil {
		t.Fatal("wrong consumer accepted")
	}
	if _, err = s.DeliverAPIKey(ctx, b.Owner, id, grantID, "https://wrong.example/api", credentialAuthority()); err == nil {
		t.Fatal("wrong resource accepted")
	}
	_, guard, err := s.AuthorizeUseGrant(ctx, b.Owner, id, grantID, handoffResource, "credential_delivery", credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	staleTicket, _, err := s.CreateUseHandoff(ctx, b.Owner, id, handoffResource, in, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	for n, scopes := range []string{`[]`, `["goauthy.connections.use","goauthy.connections.write"]`} {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "bootstrap-scope-transition-" + strings.Repeat("x", n+1), SQL: `UPDATE bootstrap_client_claim_scopes SET allowed_scopes_json=?,revision=revision+1 WHERE client_id=?`, Args: []any{scopes, id}}); err != nil {
			t.Fatal(err)
		}
		if _, err = s.DeliverAPIKey(ctx, b.Owner, id, grantID, handoffResource, credentialAuthority()); err == nil {
			t.Fatal("old consent survived scope revision")
		}
		if _, err = s.ReviewUseHandoff(ctx, b.Owner, staleTicket, credentialAuthority()); err == nil {
			t.Fatal("old requester ticket survived scope revision")
		}
		sql, args := guard()
		q, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(q.Rows) != 0 {
			t.Fatalf("captured guard survived: %v %v", q.Rows, err)
		}
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM managed_oauth_clients WHERE id=?`, Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || q.Rows[0][0] != int64(0) {
		t.Fatal("bootstrap became managed")
	}
	freshTicket, _, err := s.CreateUseHandoff(ctx, b.Owner, id, handoffResource, in, credentialAuthority())
	if err != nil {
		t.Fatalf("fresh consent after revision: %v", err)
	}
	freshReturn, err := s.CompleteUseHandoff(ctx, b.Owner, freshTicket, true, connector.Digest(), credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	freshURL, err := url.Parse(freshReturn)
	if err != nil {
		t.Fatal(err)
	}
	freshGrant := freshURL.Query().Get("grant_id")
	if _, err = s.DeliverAPIKey(ctx, b.Owner, id, freshGrant, handoffResource, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	s.now = func() int64 { return in.ExpiresAt }
	if _, err = s.DeliverAPIKey(ctx, b.Owner, id, freshGrant, handoffResource, credentialAuthority()); err == nil {
		t.Fatal("expired consent accepted")
	}
}

func TestPublicBootstrapConnectionProxyOnly(t *testing.T) {
	ctx, s, db, b, connector := registeredAPIKeyFixture(t, "public-bootstrap-provider")
	if _, err := s.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-public-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	cs := clients.NewStore(db, nil)
	const id = "public-bootstrap"
	if err := cs.EnsureBootstrap(ctx, id); err != nil {
		t.Fatal(err)
	}
	cfg := clients.BootstrapConnectionConfig{Issuer: "https://issuer.example", Resource: handoffResource, AuthMethods: []string{"none"}, Client: clients.ConnectionPolicy{ID: id, Enabled: true, Confidential: false, RedirectURIs: []string{"https://requester.example/callback"}, Scopes: []string{"goauthy.connections.use", "goauthy.connections.write"}, Audiences: []string{handoffResource}}}
	if err := cs.PinBootstrapConnections(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	in := newHandoff(s, b, id, id)
	if _, _, err := s.CreateUseHandoff(ctx, b.Owner, id, handoffResource, in, credentialAuthority()); err != nil {
		t.Fatalf("public proxy rejected: %v", err)
	}
	in.Mode = "credential_delivery"
	if _, _, err := s.CreateUseHandoff(ctx, b.Owner, id, handoffResource, in, credentialAuthority()); err == nil {
		t.Fatal("public delivery handoff accepted")
	}
	if _, err := s.CreateUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, handoffResource, UseGrantInput{ConsumerClientID: id, Mode: "credential_delivery", Purpose: "delivery", ExpiresAt: in.ExpiresAt}, credentialAuthority()); err == nil {
		t.Fatal("public delivery grant accepted")
	}
}

func TestBootstrapConnectionDenyReadGrantAndRevoke(t *testing.T) {
	ctx, s, db, b, connector := registeredAPIKeyFixture(t, "bootstrap-lifecycle-provider")
	if _, err := s.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-lifecycle-key", connector, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	const id = "bootstrap-lifecycle"
	cs := clients.NewStore(db, nil)
	if err := cs.EnsureBootstrap(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := cs.PinBootstrapConnections(ctx, clients.BootstrapConnectionConfig{
		Issuer: "https://issuer.example", Resource: handoffResource,
		AuthMethods: []string{"client_secret_basic", "client_secret_post"},
		Client: clients.ConnectionPolicy{ID: id, Enabled: true, Confidential: true,
			RedirectURIs: []string{"https://requester.example/callback"},
			Scopes:       []string{"goauthy.connections.use", "goauthy.connections.write"},
			Audiences:    []string{handoffResource}},
	}); err != nil {
		t.Fatal(err)
	}
	in := newHandoff(s, b, id, id)
	in.Mode = "credential_delivery"
	denied, _, err := s.CreateUseHandoff(ctx, b.Owner, id, handoffResource, in, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	returnURI, err := s.CompleteUseHandoff(ctx, b.Owner, denied, false, "", credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	denial, err := url.Parse(returnURI)
	if err != nil || denial.Query().Get("error") != "access_denied" || denial.Query().Get("grant_id") != "" {
		t.Fatal("denial did not return access_denied without a grant")
	}
	items, err := s.ListUseGrants(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || len(items) != 0 {
		t.Fatal("denial created consent")
	}
	if _, err := s.CompleteUseHandoff(ctx, b.Owner, denied, true, connector.Digest(), credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("denied ticket replay: %v", err)
	}
	ticket, _, err := s.CreateUseHandoff(ctx, b.Owner, id, handoffResource, in, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	returnURI, err = s.CompleteUseHandoff(ctx, b.Owner, ticket, true, connector.Digest(), credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	approved, err := url.Parse(returnURI)
	if err != nil {
		t.Fatal(err)
	}
	grantID := approved.Query().Get("grant_id")
	status, err := s.GetUseGrantStatus(ctx, b.Owner, b.CollectionID, b.ConnectionID, grantID, handoffResource, credentialAuthority())
	if err != nil || status.Grant.ConsumerClientID != id || status.Grant.Mode != "credential_delivery" || status.Grant.ConnectorDigest != connector.Digest() || status.Grant.Revoked || status.ConnectionGeneration != b.Generation {
		t.Fatalf("bootstrap grant read: %v", err)
	}
	items, err = s.ListUseGrants(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || len(items) != 1 || items[0].ID != grantID {
		t.Fatal("bootstrap grant list did not retain exactly one approved consent")
	}
	if _, err := s.GetUseGrantStatus(ctx, "other-owner", b.CollectionID, b.ConnectionID, grantID, handoffResource, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("cross-owner grant read: %v", err)
	}
	if _, err := s.DeliverAPIKey(ctx, b.Owner, id, grantID, handoffResource, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	_, beforeRevoke, err := s.AuthorizeUseGrant(ctx, b.Owner, id, grantID, handoffResource, "credential_delivery", credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, grantID, status.Grant.Revision+1, credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("stale revoke revision: %v", err)
	}
	if err := s.RevokeUseGrant(ctx, b.Owner, b.CollectionID, b.ConnectionID, grantID, status.Grant.Revision, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	status, err = s.GetUseGrantStatus(ctx, b.Owner, b.CollectionID, b.ConnectionID, grantID, handoffResource, credentialAuthority())
	if err != nil || !status.Grant.Revoked {
		t.Fatal("revoked consent metadata unavailable or not marked revoked")
	}
	if _, err := s.DeliverAPIKey(ctx, b.Owner, id, grantID, handoffResource, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("revoked delivery accepted: %v", err)
	}
	guard, args := beforeRevoke()
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 0 {
		t.Fatal("captured pre-revocation SQL authority remained valid")
	}
}
