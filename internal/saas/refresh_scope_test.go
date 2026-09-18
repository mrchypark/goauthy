package saas

import (
	"bytes"
	"testing"
)

func TestCompleteRefreshNeverExpandsScopes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		old, next []string
		allow     bool
	}{
		{"same", []string{"read", "write"}, []string{"write", "read"}, true},
		{"narrow", []string{"read", "write"}, []string{"read"}, true},
		{"empty", []string{"read"}, nil, true},
		{"expand", []string{"read"}, []string{"read", "write"}, false},
		{"unknown", nil, []string{"read"}, false},
		{"duplicate", []string{"read"}, []string{"read", "read"}, false},
		{"invalid", []string{"read"}, []string{"read\n"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, s, _, b := credentialStoreFixture(t)
			if err := s.Install(ctx, b, credential{AccountID: "account", AccessToken: "old", RefreshToken: "refresh", Scopes: tc.old}, credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			claim, err := s.ClaimRefresh(ctx, b, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			version, _, before := credentialSnapshot(t, ctx, s, b)
			err = s.CompleteRefresh(ctx, b, claim, credential{AccountID: "account", AccessToken: "next", Scopes: tc.next}, credentialAuthority())
			gotVersion, state, after := credentialSnapshot(t, ctx, s, b)
			if tc.allow {
				if err != nil || gotVersion != version+1 || state != "ready" {
					t.Fatalf("valid scope rotation failed: %v", err)
				}
			} else if err == nil || gotVersion != version || state != "refreshing" || !bytes.Equal(before, after) {
				t.Fatal("scope mutation replaced credential")
			}
		})
	}
}
