package browser

import (
	"context"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"testing"
	"time"
)

func TestReauthenticationConsumeRequiresActiveSameSubjectParent(t *testing.T) {
	for _, mode := range []string{"valid", "wrong subject", "wrong peer", "revoked", "revoked after preparation", "expired", "init parent"} {
		t.Run(mode, func(t *testing.T) {
			store := testStore(t)
			ctx := context.Background()
			now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
			store.now = func() time.Time { return now }
			parent, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Minute), "203.0.113.8")
			if err != nil {
				t.Fatal(err)
			}
			if mode == "init parent" {
				parent, err = store.CreateInitSession(ctx, now.Add(time.Minute), "203.0.113.8")
				if err != nil {
					t.Fatal(err)
				}
			}
			child, err := store.CreateInitSession(ctx, now.Add(5*time.Minute), "203.0.113.8")
			if err != nil {
				t.Fatal(err)
			}
			interaction, err := store.CreateAuthorizationInteraction(ctx, child.Token, "reauth-test", []byte("target"), now.Add(5*time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			digest, err := CanonicalTokenDigest(interaction.Token)
			if err != nil {
				t.Fatal(err)
			}
			subject, peer := "user-1", "203.0.113.8"
			guard, args := store.SessionAuthorizationGuard(parent.Session, peer)
			switch mode {
			case "wrong subject":
				subject = "other"
			case "wrong peer":
				peer = "203.0.113.9"
			case "revoked", "revoked after preparation":
				if err := store.RevokeSessionID(ctx, parent.ID); err != nil {
					t.Fatal(err)
				}
			case "expired":
				now = now.Add(time.Minute)
			}
			if mode == "revoked after preparation" {
				_, err = store.consumeAuthorizationInteractionGuarded(ctx, child.ID, digest, true, guard, args)
			} else {
				_, err = store.ConsumeReauthenticationInteractionByDigest(ctx, child.Token, digest, parent.ID, subject, peer)
			}
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err = store.ConsumeReauthenticationInteractionByDigest(ctx, child.Token, digest, parent.ID, subject, peer); err == nil {
					t.Fatal("replay accepted")
				}
			} else {
				if err == nil {
					t.Fatal("invalid parent accepted")
				}
				if _, err := store.LoadAuthorizationInteractionReadOnly(ctx, child.Token, interaction.Token); err != nil {
					t.Fatalf("rejected parent consumed interaction: %v", err)
				}
			}
		})
	}
}

func TestReauthenticationReplacementRollsBackOnBindingFailure(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	parent, err := store.CreateUpstreamSession(ctx, "user-1", UpstreamSessionBinding{Issuer: "https://upstream.example.test", ClientID: "client", Subject: "external-user", SessionID: "sid"}, "external", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	// A real constraint failure on the inherited binding must roll back the new
	// session and leave the parent eligible; no cookie may escape this failure.
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "binding-copy-failure", SQL: "CREATE UNIQUE INDEX one_test_binding_per_issuer ON browser_upstream_session_bindings(issuer)"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateReauthenticatedSession(ctx, "user-1", "mfa", now.Add(time.Hour), "203.0.113.8", parent.ID, nil); err == nil {
		t.Fatal("binding failure accepted")
	}
	if _, err := store.LoadSession(ctx, parent.Token); err != nil {
		t.Fatalf("parent retired on rollback: %v", err)
	}
	assertUpstreamBindingAndSessionCount(t, store, 1, 1)
}

func TestReauthenticationReplacementRejectsParentRevokedAfterRead(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	parent, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeSessionID(ctx, parent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.createSessionWithParent(ctx, "user-1", "mfa", now.Add(time.Hour), "203.0.113.8", nil, &parent.Session); err == nil {
		t.Fatal("stale parent snapshot created replacement")
	}
	assertUpstreamBindingAndSessionCount(t, store, 0, 1)
}
