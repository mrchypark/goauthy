package saas

import (
	"errors"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestUseHandoffRefreshOptInPersistsThroughApproval(t *testing.T) {
	ctx, s, db, b, requester, consumer := oauth2HandoffFixture(t)
	in := oauth2HandoffInput(s, b, consumer)
	in.AllowRefresh = true
	id, review, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", in, credentialAuthority())
	if err != nil || !review.Grant.AllowRefresh || review.ReviewDigest == "" {
		t.Fatalf("review=%+v err=%v", review, err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT allow_refresh FROM saas_use_handoffs WHERE id_hash=?`, Args: []any{handoffHash(id)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(1) {
		t.Fatalf("handoff allow_refresh=%v err=%v", row.Rows, err)
	}
	if _, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, review.ReviewDigest, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	grant, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_use_grants WHERE allow_refresh=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(grant.Rows) != 1 || grant.Rows[0][0] != int64(1) {
		t.Fatalf("approved grants=%v err=%v", grant.Rows, err)
	}
}

func TestUseHandoffRefreshDigestAndLegacyAPIKeyBoundaries(t *testing.T) {
	// Use the same ticket hash: two different tickets already have different
	// digests even without a refresh opt-in, so that alone proves nothing.
	h := useHandoff{Hash: "same-ticket", CredentialVersion: 1}
	legacy := authorizationDigest("oauth2-use-handoff:same-ticket:1")
	if h.reviewDigest() != legacy {
		t.Fatal("default-false OAuth digest changed")
	}
	h.Grant.AllowRefresh = true
	if h.reviewDigest() == legacy {
		t.Fatal("refresh opt-in is not committed into the review digest")
	}
	ctx, s, _, b, requester, consumer := oauth2HandoffFixture(t)
	without := oauth2HandoffInput(s, b, consumer)
	_, oldReview, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", without, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	with := without
	with.AllowRefresh = true
	id, newReview, err := s.CreateUseHandoff(ctx, b.Owner, requester.ID, "https://consumer.example/resource", with, credentialAuthority())
	if err != nil || oldReview.ReviewDigest == newReview.ReviewDigest {
		t.Fatalf("refresh opt-in digest old=%q new=%q err=%v", oldReview.ReviewDigest, newReview.ReviewDigest, err)
	}
	if _, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, oldReview.ReviewDigest, credentialAuthority()); !errors.Is(err, ErrUseGrantConflict) {
		t.Fatalf("cross-mode digest err=%v", err)
	}

	apiCtx, apiStore, _, apiBinding, connector, apiRequester, apiConsumer, _ := handoffCreate(t)
	apiInput := newHandoff(apiStore, apiBinding, apiRequester, apiConsumer)
	apiInput.AllowRefresh = true
	if _, _, err := apiStore.CreateUseHandoff(apiCtx, apiBinding.Owner, apiRequester, handoffResource, apiInput, credentialAuthority()); !errors.Is(err, ErrUseGrantInvalid) {
		t.Fatalf("API-key refresh opt-in err=%v", err)
	}
	if connector.Digest() == "" {
		t.Fatal("fixture connector digest missing")
	}
}

func TestUseHandoffLegacyFalseDigestUnchanged(t *testing.T) {
	ctx, s, db, b, connector, _, consumer, id := handoffCreate(t)
	review, err := s.ReviewUseHandoff(ctx, b.Owner, id, credentialAuthority())
	if err != nil || review.Grant.AllowRefresh || review.ReviewDigest != connector.Digest() {
		t.Fatalf("legacy review=%+v err=%v", review, err)
	}
	if _, err := s.CompleteUseHandoff(ctx, b.Owner, id, true, connector.Digest(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT allow_refresh,connector_digest FROM saas_use_grants WHERE consumer_client_id=? AND connector_digest=?`, Args: []any{consumer, connector.Digest()}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) == 0 || row.Rows[0][0] != int64(0) || row.Rows[0][1] != connector.Digest() {
		t.Fatalf("legacy grant=%v err=%v", row.Rows, err)
	}
}
