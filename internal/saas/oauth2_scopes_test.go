package saas

import (
	"errors"
	"reflect"
	"testing"

	"golang.org/x/oauth2"
)

func TestOAuthGrantedScopes(t *testing.T) {
	t.Parallel()
	requested := []string{"openid", "profile", "email"}
	for _, test := range []struct {
		name   string
		extra  any
		want   []string
		failed bool
	}{
		{name: "omitted", want: requested},
		{name: "narrower", extra: "openid email", want: []string{"openid", "email"}},
		{name: "reorder", extra: "email openid", want: []string{"email", "openid"}},
		{name: "duplicate", extra: "openid openid", failed: true},
		{name: "invalid tab", extra: "openid\tprofile", failed: true},
		{name: "invalid empty", extra: "openid  profile", failed: true},
		{name: "invalid character", extra: "openid\"", failed: true},
		{name: "escalation", extra: "openid admin", failed: true},
		{name: "array", extra: []string{"openid"}, failed: true},
		{name: "numeric", extra: int64(1), failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := &oauth2.Token{}
			if test.name != "omitted" {
				token = token.WithExtra(map[string]any{"scope": test.extra})
			}
			got, err := oauthGrantedScopes(token, requested)
			if test.failed {
				if !errors.Is(err, ErrOAuth2Exchange) {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got=%v err=%v", got, err)
			}
		})
	}
}

func TestOAuthGrantedScopesNilAndDefensiveCopy(t *testing.T) {
	t.Parallel()
	if _, err := oauthGrantedScopes(nil, []string{"openid"}); !errors.Is(err, ErrOAuth2Exchange) {
		t.Fatalf("nil token err=%v", err)
	}
	requested := []string{"openid"}
	got, err := oauthGrantedScopes(&oauth2.Token{}, requested)
	if err != nil || len(got) != 1 {
		t.Fatalf("got=%v err=%v", got, err)
	}
	got[0] = "mutated"
	if requested[0] != "openid" {
		t.Fatal("requested scopes aliased")
	}
	requested[0] = "changed"
	if got[0] != "mutated" {
		t.Fatal("result unexpectedly aliased")
	}
}
