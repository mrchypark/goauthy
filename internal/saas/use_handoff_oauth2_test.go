package saas

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func oauth2HandoffFixture(t *testing.T) (context.Context, *CredentialStore, *rhiza.DB, credentialBinding, clients.Client, clients.Client) {
	t.Helper()
	ctx, s, b, consumer, _ := oauth2DeliveryFixture(t)
	cs := clients.NewStore(s.db, s.keys)
	requester, err := cs.CreateWithGuard(ctx, clients.NewRequest{ID: "oauth2-handoff-requester", RedirectURIs: []string{"https://requester.example/callback"}, Scopes: []string{"goauthy.connections.write"}, DefaultScopes: []string{"goauthy.connections.write"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{"https://consumer.example/resource"}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	return ctx, s, s.db, b, requester, consumer
}

func oauth2HandoffInput(s *CredentialStore, b credentialBinding, consumer clients.Client) UseHandoffInput {
	return UseHandoffInput{CollectionID: b.CollectionID, ConnectionID: b.ConnectionID, ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "oauth2 export", ExpiresAt: s.now() + 60000, ReturnURI: "https://requester.example/callback", State: strings.Repeat("s", 32)}
}

func TestOAuth2UseHandoffApproveAndDeliver(t *testing.T) {
	ctx, s, _, b, requester, consumer := oauth2HandoffFixture(t)
	id, review, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", oauth2HandoffInput(s, b, consumer), credentialAuthority())
	if err != nil || review.OAuth2 == nil || review.OAuth2.Version != 1 || review.OAuth2.AccountID != "account-1" || review.ReviewDigest == "" || review.Grant.ID != "" {
		t.Fatalf("create review=%+v err=%v", review, err)
	}
	raw, err := json.Marshal(review)
	if err != nil || strings.Contains(string(raw), "access-token") || strings.Contains(string(raw), "refresh-secret") {
		t.Fatal("review leaked a credential secret")
	}
	reviewed, err := s.ReviewUseHandoff(ctx, b.Owner, id, credentialAuthority())
	if err != nil || reviewed.OAuth2 == nil || reviewed.OAuth2.Version != review.OAuth2.Version || reviewed.OAuth2.AccountID != review.OAuth2.AccountID || len(reviewed.OAuth2.Scopes) != len(review.OAuth2.Scopes) || reviewed.ReviewDigest != review.ReviewDigest {
		t.Fatalf("review changed=%+v err=%v", reviewed, err)
	}
	redirect, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, review.ReviewDigest, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil || parsed.Query().Get("grant_id") == "" || parsed.Query().Get("state") != strings.Repeat("s", 32) || strings.Contains(redirect, "access-token") {
		t.Fatalf("redirect=%q err=%v", redirect, err)
	}
	grants, err := s.ListUseGrants(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || len(grants) != 2 { // fixture creates one baseline grant
		t.Fatalf("grants=%+v err=%v", grants, err)
	}
	got, err := s.DeliverOAuth2(ctx, b.Owner, consumer.ID, parsed.Query().Get("grant_id"), "https://consumer.example/resource", credentialAuthority())
	if err != nil || got.AccessToken != "access-token" || got.CredentialVersion != 1 {
		t.Fatalf("delivery=%+v err=%v", got, err)
	}
	if _, err = s.CompleteUseHandoff(ctx, b.Owner, id, true, review.ReviewDigest, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("replay=%v", err)
	}
}

func TestOAuth2UseHandoffDenialAndProxyRejected(t *testing.T) {
	ctx, s, _, b, requester, consumer := oauth2HandoffFixture(t)
	in := oauth2HandoffInput(s, b, consumer)
	in.Mode = "proxy"
	if _, _, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", in, credentialAuthority()); !errors.Is(err, ErrUseGrantInvalid) {
		t.Fatalf("proxy err=%v", err)
	}
	in.Mode = "credential_delivery"
	id, review, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", in, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := s.CompleteUseHandoff(ctx, b.Owner, id, false, "", credentialAuthority())
	if err != nil || !strings.Contains(redirect, "error=access_denied") {
		t.Fatalf("deny redirect=%q err=%v", redirect, err)
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_use_grants`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || q.Rows[0][0] != int64(1) {
		t.Fatalf("denial changed grant count=%v err=%v", q.Rows, err)
	}
	if _, err = s.CompleteUseHandoff(ctx, b.Owner, id, true, review.ReviewDigest, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("denied replay=%v", err)
	}
}

func TestOAuth2UseHandoffTicketAndExpiryFence(t *testing.T) {
	ctx, s, db, b, requester, consumer := oauth2HandoffFixture(t)
	in := oauth2HandoffInput(s, b, consumer)
	id, review, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", in, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", in, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if other.ReviewDigest == review.ReviewDigest {
		t.Fatal("different tickets share a review commitment")
	}
	if _, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, other.ReviewDigest, credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("other ticket commitment: %v", err)
	}
	s.now = func() int64 { return review.ExpiresAt - 1 }
	if _, err := s.ReviewUseHandoff(ctx, b.Owner, id, credentialAuthority()); err != nil {
		t.Fatalf("one millisecond before expiry: %v", err)
	}
	s.now = func() int64 { return review.ExpiresAt }
	if _, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, review.ReviewDigest, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("exact expiry: %v", err)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_use_grants`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(1) {
		t.Fatal("rejected approvals changed the baseline grant count")
	}
}

func TestOAuth2UseHandoffReviewDigestAndVersionFence(t *testing.T) {
	ctx, s, _, b, requester, consumer := oauth2HandoffFixture(t)
	id, review, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", oauth2HandoffInput(s, b, consumer), credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CompleteUseHandoff(ctx, b.Owner, id, true, "bad", credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("wrong digest=%v", err)
	}
	claim, err := s.ClaimRefresh(ctx, b, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteRefresh(ctx, b, claim, credential{AccountID: "account-1", AccessToken: "access-2", RefreshToken: "refresh-2", ExpiresAtUnixMS: s.now() + 60000}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReviewUseHandoff(ctx, b.Owner, id, credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) && !errors.Is(err, ErrUseGrantNotFound) && !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("version fence=%v", err)
	}
	if _, err = s.CompleteUseHandoff(ctx, b.Owner, id, true, review.ReviewDigest, credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) && !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("stale approval=%v", err)
	}
}

func TestOAuth2UseHandoffReconnectProviderAndClientFences(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(context.Context, *CredentialStore, credentialBinding, clients.Client, clients.Client) error
	}{
		{"requester", func(ctx context.Context, s *CredentialStore, _ credentialBinding, requester, _ clients.Client) error {
			_, err := clients.NewStore(s.db, s.keys).UpdateWithGuard(ctx, requester.ID, requester.Revision, clients.UpdateRequest{Enabled: false, RedirectURIs: requester.RedirectURIs, Scopes: requester.Scopes, DefaultScopes: requester.DefaultScopes, GrantTypes: requester.GrantTypes, Audiences: requester.Audiences}, credentialAuthority())
			return err
		}},
		{"consumer", func(ctx context.Context, s *CredentialStore, _ credentialBinding, _, consumer clients.Client) error {
			_, err := clients.NewStore(s.db, s.keys).UpdateWithGuard(ctx, consumer.ID, consumer.Revision, clients.UpdateRequest{Enabled: false, RedirectURIs: consumer.RedirectURIs, Scopes: consumer.Scopes, DefaultScopes: consumer.DefaultScopes, GrantTypes: consumer.GrantTypes, Audiences: consumer.Audiences}, credentialAuthority())
			return err
		}},
		{"provider", func(ctx context.Context, s *CredentialStore, b credentialBinding, _, _ clients.Client) error {
			_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "oauth2-handoff-provider-fence", SQL: `UPDATE saas_providers SET revision=revision+1 WHERE id=?`, Args: []any{"provider"}})
			return err
		}},
		{"reconnect", func(ctx context.Context, s *CredentialStore, b credentialBinding, _, _ clients.Client) error {
			if err := s.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, credentialAuthority()); err != nil {
				return err
			}
			_, err := s.PrepareOAuth2Reconnect(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, credentialAuthority())
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, s, _, b, requester, consumer := oauth2HandoffFixture(t)
			id, review, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", oauth2HandoffInput(s, b, consumer), credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			if err = tc.mutate(ctx, s, b, requester, consumer); err != nil {
				t.Fatal(err)
			}
			if _, err = s.ReviewUseHandoff(ctx, b.Owner, id, credentialAuthority()); err == nil {
				t.Fatal("stale handoff reviewed")
			}
			if _, err = s.CompleteUseHandoff(ctx, b.Owner, id, true, review.ReviewDigest, credentialAuthority()); err == nil {
				t.Fatal("stale handoff approved")
			}
			q, qerr := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_use_grants`, Consistency: rhiza.ConsistencyLinearizable})
			if qerr != nil || q.Rows[0][0] != int64(1) {
				t.Fatalf("stale approval changed grant count=%v err=%v", q.Rows, qerr)
			}
			state, qerr := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state FROM saas_use_handoffs WHERE id_hash=?`, Args: []any{handoffHash(id)}, Consistency: rhiza.ConsistencyLinearizable})
			if qerr != nil || len(state.Rows) != 1 || state.Rows[0][0] != "pending" {
				t.Fatalf("stale approval changed ticket=%v err=%v", state.Rows, qerr)
			}
		})
	}
}
