package saas

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const handoffResource = "https://resource.example/api"

func handoffFixture(t *testing.T) (ctx context.Context, s *CredentialStore, db *rhiza.DB, b credentialBinding, c *APIKeyConnector, requester, consumer string) {
	t.Helper()
	ctx, s, db, b, c = registeredAPIKeyFixture(t, "handoff-provider")
	if _, err := s.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "bound", c, c.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	cs := clients.NewStore(db, s.keys)
	request, err := cs.CreateWithGuard(ctx, clients.NewRequest{ID: "handoff-requester", RedirectURIs: []string{"https://requester.example/callback"}, Scopes: []string{"goauthy.connections.write"}, DefaultScopes: []string{"goauthy.connections.write"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{handoffResource}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	use, err := cs.CreateWithGuard(ctx, clients.NewRequest{ID: "handoff-consumer", RedirectURIs: []string{"https://consumer.example/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{handoffResource}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	return ctx, s, db, b, c, request.ID, use.ID
}

func newHandoff(s *CredentialStore, b credentialBinding, requester, consumer string) UseHandoffInput {
	return UseHandoffInput{CollectionID: b.CollectionID, ConnectionID: b.ConnectionID, ConsumerClientID: consumer, Mode: "proxy", Purpose: "sync", ExpiresAt: s.now() + 60_000, ReturnURI: "https://requester.example/callback", State: strings.Repeat("s", 32)}
}

func handoffCreate(t *testing.T) (context.Context, *CredentialStore, *rhiza.DB, credentialBinding, *APIKeyConnector, string, string, string) {
	t.Helper()
	ctx, s, db, b, c, requester, consumer := handoffFixture(t)
	id, review, err := s.CreateUseHandoff(ctx, b.Owner, requester, handoffResource, newHandoff(s, b, requester, consumer), credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if review.Grant.ID != "" || review.RequestClientID != requester || review.ReturnURI != "https://requester.example/callback" {
		t.Fatalf("review=%+v", review)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_use_grants`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || q.Rows[0][0] != int64(0) {
		t.Fatalf("grants=%v err=%v", q.Rows, err)
	}
	h, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id_hash FROM saas_use_handoffs WHERE owner_subject=?`, Args: []any{b.Owner}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(h.Rows) != 1 || h.Rows[0][0] == id || h.Rows[0][0] != handoffHash(id) {
		t.Fatalf("handoff hash=%v err=%v", h.Rows, err)
	}
	return ctx, s, db, b, c, requester, consumer, id
}

func TestUseHandoffCreateReviewComplete(t *testing.T) {
	ctx, s, db, b, c, _, _, id := handoffCreate(t)
	review, err := s.ReviewUseHandoff(ctx, b.Owner, id, credentialAuthority())
	if err != nil || review.Grant.ConnectorDigest != c.Digest() || review.Grant.Resource != handoffResource {
		t.Fatalf("review=%+v err=%v", review, err)
	}
	redirect, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, c.Digest(), credentialAuthority())
	if err != nil || !strings.Contains(redirect, "grant_id=") || !strings.Contains(redirect, "state=ssssssssssssssssssssssssssssssss") {
		t.Fatalf("redirect=%q err=%v", redirect, err)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state,grant_id FROM saas_use_handoffs`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != "approved" || q.Rows[0][1] == "" {
		t.Fatalf("handoff=%v err=%v", q.Rows, err)
	}
}

func TestUseHandoffRejectsBadInputsAndReplay(t *testing.T) {
	ctx, s, _, b, c, requester, consumer, id := handoffCreate(t)
	for name, mutate := range map[string]func(*UseHandoffInput){"uri": func(in *UseHandoffInput) { in.ReturnURI = "http://bad" }, "state": func(in *UseHandoffInput) { in.State = "short" }, "mode": func(in *UseHandoffInput) { in.Mode = "invalid" }} {
		t.Run(name, func(t *testing.T) {
			in := newHandoff(s, b, requester, consumer)
			mutate(&in)
			if _, _, err := s.CreateUseHandoff(ctx, b.Owner, requester, handoffResource, in, credentialAuthority()); !errors.Is(err, ErrUseGrantInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if _, err := s.ReviewUseHandoff(ctx, "other-owner", id, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("owner=%v", err)
	}
	if _, err := s.ReviewUseHandoff(ctx, b.Owner, "bad", credentialAuthority()); !errors.Is(err, ErrUseGrantInvalid) {
		t.Fatalf("id=%v", err)
	}
	if _, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, "bad", credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("digest=%v", err)
	}
	if _, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, c.Digest(), credentialAuthority()); err != nil {
		t.Fatalf("approve=%v", err)
	}
	if _, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, c.Digest(), credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("replay=%v", err)
	}
}

func TestUseHandoffDenyAndReplay(t *testing.T) {
	ctx, s, db, b, _, _, _, id := handoffCreate(t)
	redirect, err := s.CompleteUseHandoff(ctx, b.Owner, id, false, "", credentialAuthority())
	if err != nil || !strings.Contains(redirect, "error=access_denied") {
		t.Fatalf("redirect=%q err=%v", redirect, err)
	}
	if _, err = s.CompleteUseHandoff(ctx, b.Owner, id, false, "", credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("replay=%v", err)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_use_grants`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || q.Rows[0][0] != int64(0) {
		t.Fatalf("denied grants=%v err=%v", q.Rows, err)
	}
}

func TestUseHandoffConcurrentApprovalCreatesOneGrant(t *testing.T) {
	ctx, s, db, b, c, _, _, id := handoffCreate(t)
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, c.Digest(), credentialAuthority())
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	var ok int
	for err := range errs {
		if err == nil {
			ok++
		} else if !errors.Is(err, ErrUseGrantNotFound) && !errors.Is(err, ErrUseGrantConflict) {
			t.Fatalf("err=%v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("successes=%d", ok)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_use_grants`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || q.Rows[0][0] != int64(1) {
		t.Fatalf("grants=%v err=%v", q.Rows, err)
	}
}

func TestUseHandoffExpiryAndProviderFence(t *testing.T) {
	ctx, s, db, b, _, requester, consumer, id := handoffCreate(t)
	now := s.now()
	s.now = func() int64 { return now + 301_000 }
	if _, err := s.ReviewUseHandoff(ctx, b.Owner, id, credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
		t.Fatalf("expiry=%v", err)
	}
	s.now = func() int64 { return now }
	id = mustCreateHandoff(t, ctx, s, b, requester, consumer)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "handoff-provider-fence", SQL: `UPDATE saas_providers SET revision=revision+1 WHERE id=?`, Args: []any{"handoff-provider"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReviewUseHandoff(ctx, b.Owner, id, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("provider fence=%v", err)
	}
}

func TestUseHandoffClientAndAuthorityFences(t *testing.T) {
	for _, tc := range []struct {
		name    string
		uri     string
		enabled bool
	}{
		{"redirect removal", "https://requester.example/changed", true}, {"requester disable", "https://requester.example/callback", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, s, db, b, connector, requester, _, id := handoffCreate(t)
			cs := clients.NewStore(db, s.keys)
			r, err := cs.GetWithGuard(ctx, requester, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			_, err = cs.UpdateWithGuard(ctx, requester, r.Revision, clients.UpdateRequest{Enabled: tc.enabled, RedirectURIs: []string{tc.uri}, Scopes: []string{"goauthy.connections.write"}, DefaultScopes: []string{"goauthy.connections.write"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{handoffResource}}, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.ReviewUseHandoff(ctx, b.Owner, id, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
				t.Fatalf("fence=%v", err)
			}
			if _, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, connector.Digest(), credentialAuthority()); !errors.Is(err, ErrUseGrantNotFound) {
				t.Fatalf("fenced approval=%v", err)
			}
			q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_use_grants`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(0) {
				t.Fatalf("fenced grants=%v err=%v", q.Rows, err)
			}
		})
	}
	ctx, s, _, b, _, requester, consumer, _ := handoffCreate(t)
	if _, _, err := s.CreateUseHandoff(ctx, b.Owner, requester, handoffResource, newHandoff(s, b, requester, consumer), func() (string, []any) { return "0", nil }); !errors.Is(err, clients.ErrUnauthorized) {
		t.Fatalf("authority=%v", err)
	}
	ctx, s, db, b, _, _, consumer, id := handoffCreate(t)
	cs := clients.NewStore(db, s.keys)
	c, err := cs.GetWithGuard(ctx, consumer, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	_, err = cs.UpdateWithGuard(ctx, consumer, c.Revision, clients.UpdateRequest{Enabled: false, RedirectURIs: c.RedirectURIs, Scopes: c.Scopes, DefaultScopes: c.DefaultScopes, GrantTypes: c.GrantTypes, Audiences: c.Audiences}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReviewUseHandoff(ctx, b.Owner, id, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("consumer disable=%v", err)
	}
}

func TestUseHandoffQuotaCleansExpired(t *testing.T) {
	ctx, s, _, b, _, requester, consumer := handoffFixture(t)
	now := s.now()
	s.now = func() int64 { return now }
	for i := 0; i < 16; i++ {
		if _, _, err := s.CreateUseHandoff(ctx, b.Owner, requester, handoffResource, newHandoff(s, b, requester, consumer), credentialAuthority()); err != nil {
			t.Fatalf("handoff %d: %v", i, err)
		}
	}
	if _, _, err := s.CreateUseHandoff(ctx, b.Owner, requester, handoffResource, newHandoff(s, b, requester, consumer), credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("quota=%v", err)
	}
	s.now = func() int64 { return now + 301_000 }
	if _, _, err := s.CreateUseHandoff(ctx, b.Owner, requester, handoffResource, newHandoff(s, b, requester, consumer), credentialAuthority()); err != nil {
		t.Fatalf("expiry cleanup=%v", err)
	}
}

func mustCreateHandoff(t *testing.T, ctx context.Context, s *CredentialStore, b credentialBinding, requester, consumer string) string {
	id, _, err := s.CreateUseHandoff(ctx, b.Owner, requester, handoffResource, newHandoff(s, b, requester, consumer), credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	return id
}
