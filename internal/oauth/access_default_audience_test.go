package oauth

import (
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/ory/fosite"
)

func TestAccessDefaultAudienceSnapshotCompatibility(t *testing.T) {
	t.Parallel()
	const resource = "https://api.example.test/resource"
	const defaultAudience = "https://api.example.test/default"
	now := time.Unix(1_800_000_000, 0).UTC()
	strategy := &signedAccessTokenStrategy{issuer: "https://issuer.example.test", now: func() time.Time { return now }}
	request := fosite.NewRequest()
	request.Client = &clients.Client{ID: testClientID, DefaultAudiences: []string{"https://current.example.test/not-retroactive"}}
	request.Form = url.Values{"grant_type": {"authorization_code"}}
	request.GrantAudience(resource)
	session := &fosite.DefaultSession{Subject: "user-1"}
	session.SetExpiresAt(fosite.AccessToken, now.Add(time.Hour))
	request.Session = session
	for _, tc := range []struct {
		name  string
		extra map[string]any
		want  []string
	}{
		{"legacy", nil, []string{testClientID, resource}},
		{"explicit empty", map[string]any{accessDefaultAudiencesExtra: []string{}}, []string{testClientID, resource}},
		{"JSON empty", map[string]any{accessDefaultAudiencesExtra: []any{}}, []string{testClientID, resource}},
		{"snapshot", map[string]any{accessDefaultAudiencesExtra: []string{defaultAudience, resource}}, []string{testClientID, defaultAudience, resource}},
		{"JSON roundtrip", map[string]any{accessDefaultAudiencesExtra: []any{defaultAudience, resource}}, []string{testClientID, defaultAudience, resource}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session.Extra = tc.extra
			claims, err := strategy.claims(request, "jti")
			if err != nil || !slices.Equal(claims.Audience, tc.want) || !strategy.matchesRequest(request, claims) {
				t.Fatal("access audience snapshot changed signed-token semantics")
			}
			claims.Audience = append(claims.Audience, "https://ungranted.example.test")
			if strategy.matchesRequest(request, claims) {
				t.Fatal("accepted audience outside persisted snapshot")
			}
			if !slices.Equal([]string(request.GetGrantedAudience()), []string{resource}) {
				t.Fatal("defaults changed Fosite explicit resource grants")
			}
		})
	}
	for _, invalid := range []any{nil, "string", []any{true}, []string{""}, []string{"http://insecure.example.test"}, []string{defaultAudience, defaultAudience}} {
		session.Extra = map[string]any{accessDefaultAudiencesExtra: invalid}
		if _, err := strategy.claims(request, "jti"); err == nil {
			t.Fatal("accepted malformed default audience snapshot")
		}
	}
	session.Extra = map[string]any{accessDefaultAudiencesExtra: []string{defaultAudience}, "goauthy_custom_root": []string{accessDefaultAudiencesExtra}}
	if _, err := strategy.claims(request, "jti"); err == nil {
		t.Fatal("interpreted legacy custom claim as audience authority")
	}
}
