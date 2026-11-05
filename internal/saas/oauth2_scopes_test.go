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
			got, err := oauthGrantedScopes(token, requested, false)
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
	if _, err := oauthGrantedScopes(nil, []string{"openid"}, false); !errors.Is(err, ErrOAuth2Exchange) {
		t.Fatalf("nil token err=%v", err)
	}
	requested := []string{"openid"}
	got, err := oauthGrantedScopes(&oauth2.Token{}, requested, false)
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

func TestOAuthGrantedScopesGoogleAliases(t *testing.T) {
	t.Parallel()
	requested := []string{"openid", "email", "profile"}
	for _, scope := range []string{
		"openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
		"openid email https://www.googleapis.com/auth/userinfo.email profile https://www.googleapis.com/auth/userinfo.profile",
	} {
		token := (&oauth2.Token{}).WithExtra(map[string]any{"scope": scope})
		got, err := oauthGrantedScopes(token, requested, true)
		if err != nil || !reflect.DeepEqual(got, requested) {
			t.Fatalf("got=%v err=%v", got, err)
		}
	}
}

func TestOAuthGrantedScopesGoogleControls(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		requested []string
		scope     string
		google    bool
		want      []string
	}{
		{"reduced", []string{"openid", "email", "profile"}, "https://www.googleapis.com/auth/userinfo.email", true, []string{"email"}},
		{"reverse aliases", []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}, "email profile", true, []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}},
		{"exact duplicate", []string{"email"}, "email email", true, nil},
		{"alias exact duplicate", []string{"email"}, "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.email", true, nil},
		{"unrequested alias", []string{"openid"}, "openid https://www.googleapis.com/auth/userinfo.email", true, nil},
		{"drive escalation", []string{"openid", "email"}, "openid https://www.googleapis.com/auth/drive", true, nil},
		{"gmail escalation", []string{"openid", "email"}, "openid https://www.googleapis.com/auth/gmail.readonly", true, nil},
		{"non Google alias", []string{"email"}, "https://www.googleapis.com/auth/userinfo.email", false, nil},
		{"non Google distinct", []string{"email", "https://www.googleapis.com/auth/userinfo.email"}, "email https://www.googleapis.com/auth/userinfo.email", false, []string{"email", "https://www.googleapis.com/auth/userinfo.email"}},
		{"malformed Google scope", []string{"email"}, "email\tprofile", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := oauthGrantedScopes((&oauth2.Token{}).WithExtra(map[string]any{"scope": tc.scope}), tc.requested, tc.google)
			if tc.want == nil {
				if !errors.Is(err, ErrOAuth2Exchange) {
					t.Fatalf("err=%v", err)
				}
			} else if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%v err=%v", got, err)
			}
		})
	}
}

func TestGoogleOAuth2ProfileExactEndpoints(t *testing.T) {
	t.Parallel()
	auth, token, identity := "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "https://openidconnect.googleapis.com/v1/userinfo"
	if !googleOAuth2Profile(auth, token, identity) {
		t.Fatal("Google profile not recognized")
	}
	for _, endpoints := range [][3]string{
		{auth + "/", token, identity}, {auth, token + "?tenant=other", identity}, {auth, token, identity + "/"},
		{"https://accounts.google.com.evil.example/o/oauth2/v2/auth", token, identity},
		{auth, "https://oauth2.googleapis.com:443/token", identity}, {auth, token, "https://issuer.example/userinfo"},
	} {
		if googleOAuth2Profile(endpoints[0], endpoints[1], endpoints[2]) {
			t.Fatal("non-exact Google profile accepted")
		}
	}
}
