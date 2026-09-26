package device

import (
	"errors"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"testing"
	"time"
)

func TestReviewPendingGrant(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	grant, err := store.CreateWithBinding(ctx, "client", []string{"openid", "goauthy.read"}, ClientBinding{Resource: "https://resource.example.test/api"}, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Review(ctx, " "+stringsLower(grant.UserCode)+" ", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != "client" || got.Resource != "https://resource.example.test/api" || len(got.Scopes) != 2 || got.Scopes[0] != "openid" || got.Scopes[1] != "goauthy.read" {
		t.Fatalf("review=%#v", got)
	}
}

func TestReviewRejectsUnavailableCodes(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	grant, err := store.Create(ctx, "client", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Review(ctx, grant.UserCode, now); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	cases := []struct {
		name string
		code string
		at   time.Time
		act  func() error
	}{
		{"expired", grant.UserCode, grant.ExpiresAt, nil},
		{"denied", grant.UserCode, now, func() error { return store.Deny(ctx, grant.UserCode, now) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.act != nil && tc.act() != nil {
				t.Fatal("decision failed")
			}
			if _, err := store.Review(ctx, tc.code, tc.at); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	approved, err := store.Create(ctx, "client", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(ctx, approved.UserCode, "subject", now); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"missing", "bad code!", approved.UserCode} {
		if _, err := store.Review(ctx, code, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("code=%q error=%v", code, err)
		}
	}
}

func TestReviewUsesCurrentMFAAndOriginalClientGeneration(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	seedManagedBinding(t, ctx, store, "review-client", "gen-a", 1, 1)
	grant, err := store.CreateWithBinding(ctx, "review-client", nil, ClientBinding{ID: "review-client", Generation: "gen-a", Revision: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := store.Review(ctx, grant.UserCode, now)
	if err != nil || initial.ForceMFA {
		t.Fatalf("initial=%+v err=%v", initial, err)
	}
	for _, tc := range []struct {
		name, update   string
		available, mfa bool
	}{
		{"tighten", "force_mfa=1,revision=2", true, true},
		{"relax", "force_mfa=0,revision=3", true, false},
		{"disable", "enabled=0", false, false},
		{"enable", "enabled=1", true, false},
		{"delete", "deleted=1", false, false},
		{"replace", "deleted=0,generation='gen-b'", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "review-policy-" + tc.name, SQL: "UPDATE managed_oauth_clients SET " + tc.update + " WHERE id='review-client'"}); err != nil {
				t.Fatal(err)
			}
			review, err := store.Review(ctx, grant.UserCode, now)
			if tc.available {
				if err != nil || review.ForceMFA != tc.mfa {
					t.Fatalf("review=%+v err=%v", review, err)
				}
			} else if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unavailable review err=%v", err)
			}
		})
	}
}
