package device

import (
	"errors"
	"testing"
	"time"
)

func TestReviewPendingGrant(t *testing.T) {
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
