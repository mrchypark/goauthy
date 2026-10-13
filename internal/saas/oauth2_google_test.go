package saas

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

func googleOAuth2TestHTTP(t *testing.T, scope string) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	tokens, identities := new(atomic.Int32), new(atomic.Int32)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			tokens.Add(1)
			if r.Method != http.MethodPost || r.ParseForm() != nil {
				t.Error("invalid synthetic token request")
			}
			if r.Form.Get("grant_type") == "authorization_code" && !validVerifier(r.Form.Get("code_verifier")) {
				t.Error("missing PKCE verifier")
			}
			_, _ = io.WriteString(w, `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","scope":"`+scope+`"}`)
		case "/v1/userinfo":
			identities.Add(1)
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer synthetic-access" {
				t.Error("invalid synthetic identity request")
			}
			_, _ = io.WriteString(w, `{"sub":"account-1"}`)
		default:
			t.Error("unexpected synthetic endpoint")
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, tokens, identities
}

func TestOAuth2GoogleIssuerAndDenialDoNotConsume(t *testing.T) {
	ctx, credentials, db, binding := credentialStoreFixture(t)
	providers, err := NewProviderStore(db, credentials.keys)
	if err != nil {
		t.Fatal(err)
	}
	const callback = "https://auth.example/callback"
	const issuer = "https://accounts.google.com"
	input := ProviderInput{ID: binding.ProviderID, Name: "Synthetic Google", Kind: "oauth2", Enabled: true,
		ClientID: "synthetic-client", ClientSecret: "synthetic-secret", CallbackURI: callback,
		AuthorizationURL: issuer + "/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token",
		IdentityEndpoint: "https://openidconnect.googleapis.com/v1/userinfo", SubjectField: "sub", AuthStyle: "params",
		Scopes: []string{"openid", "email", "profile"}}
	if _, err := providers.Create(ctx, input, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	session := authorizationTestDigest("synthetic-session")
	start, err := credentials.BeginOAuth2(ctx, providers, binding.Owner, binding.CollectionID, binding.ConnectionID, binding.ProviderID, session, callback, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	authorizationURL, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal("invalid synthetic authorization URL")
	}
	state := authorizationURL.Query().Get("state")
	p, guard, err := oauth2Provider(ctx, providers, binding.ProviderID, callback, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	o, err := providers.LoadOAuth2(ctx, binding.ProviderID, guard)
	if err != nil {
		t.Fatal(err)
	}
	server, tokens, identities := googleOAuth2TestHTTP(t, "openid email https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile")
	o.client.Transport = rewriteTransport{target: server.URL, base: server.Client().Transport}
	assertPending := func() {
		t.Helper()
		if _, _, err := credentials.loadAuthorizationVerifier(ctx, authorizationDigest(state), session, oauth2ProviderDigest(p), guard); err != nil {
			t.Fatalf("authorization no longer pending: %v", err)
		}
		if tokens.Load() != 0 || identities.Load() != 0 {
			t.Fatal("rejected callback made an external call")
		}
		status, err := credentials.OAuth2Status(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, guard)
		if err != nil || status.Connected || status.Version != 0 {
			t.Fatal("rejected callback installed a credential")
		}
	}
	for _, issuers := range [][]string{nil, {""}, {"https://evil.example"}, {"accounts.google.com"}, {issuer + "/"}, {issuer, issuer}} {
		// The public API must enforce the issuer even for callers using the old signature.
		if _, err := credentials.CompleteOAuth2(ctx, providers, binding.Owner, binding.CollectionID, binding.ConnectionID, binding.ProviderID, session, callback, state, "synthetic-code", credentialAuthority(), issuers...); !errors.Is(err, ErrOAuth2Exchange) {
			t.Fatalf("public issuer rejection: %v", err)
		}
		if _, err := credentials.completeOAuth2(ctx, o, p, binding.Owner, binding.CollectionID, binding.ConnectionID, session, state, "synthetic-code", guard, issuers...); !errors.Is(err, ErrOAuth2Exchange) {
			t.Fatalf("shared issuer rejection: %v", err)
		}
		assertPending()
	}
	for _, tc := range []struct {
		owner, session, issuer string
		want                   error
	}{
		{binding.Owner, session, issuer, nil},
		{binding.Owner, authorizationTestDigest("wrong-session"), issuer, ErrAuthorizationNotFound},
		{"wrong-owner", session, issuer, ErrAuthorizationNotFound},
		{binding.Owner, session, "https://evil.example", ErrOAuth2Exchange},
	} {
		if err := credentials.RejectOAuth2(ctx, providers, tc.owner, binding.ProviderID, tc.session, callback, state, tc.issuer, credentialAuthority()); !errors.Is(err, tc.want) {
			t.Fatalf("denial binding: %v", err)
		}
		assertPending()
	}
	if _, err := credentials.completeOAuth2(ctx, o, p, binding.Owner, binding.CollectionID, binding.ConnectionID, authorizationTestDigest("wrong-session"), state, "synthetic-code", guard, issuer); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("wrong session: %v", err)
	}
	assertPending()
	status, err := credentials.completeOAuth2(ctx, o, p, binding.Owner, binding.CollectionID, binding.ConnectionID, session, state, "synthetic-code", guard, issuer)
	if err != nil || !status.Connected || status.AccountID != "account-1" || !reflect.DeepEqual(status.Scopes, input.Scopes) {
		t.Fatalf("completion scopes=%v err=%v", status.Scopes, err)
	}
	loaded, err := credentials.Load(ctx, binding, credentialAuthority())
	if err != nil || !reflect.DeepEqual(loaded.Scopes, input.Scopes) {
		t.Fatalf("persisted scopes=%v err=%v", loaded.Scopes, err)
	}
	if _, err := credentials.completeOAuth2(ctx, o, p, binding.Owner, binding.CollectionID, binding.ConnectionID, session, state, "synthetic-code", guard, issuer); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("replay: %v", err)
	}
	if tokens.Load() != 1 || identities.Load() != 1 {
		t.Fatal("completion or replay call count changed")
	}
}

func TestRefreshOAuth2GoogleScopeParity(t *testing.T) {
	for _, tc := range []struct {
		name, scope string
		google      bool
		want        []string
	}{
		{"aliases", "openid https://www.googleapis.com/auth/userinfo.profile", true, []string{"openid", "profile"}},
		{"reduced", "openid", true, []string{"openid"}},
		{"alias deduplication", "profile https://www.googleapis.com/auth/userinfo.profile", true, []string{"profile"}},
		{"unrequested email", "openid https://www.googleapis.com/auth/userinfo.email", true, nil},
		{"Drive escalation", "openid https://www.googleapis.com/auth/drive", true, nil},
		{"exact duplicate", "profile profile", true, nil},
		{"non Google", "openid https://www.googleapis.com/auth/userinfo.profile", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshFixture(t, "account-1")
			server, tokens, identities := googleOAuth2TestHTTP(t, tc.scope)
			f.o.config.Endpoint = oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token", AuthStyle: oauth2.AuthStyleInHeader}
			f.o.identityEndpoint = "https://openidconnect.googleapis.com/v1/userinfo"
			if !tc.google {
				f.o.config.Endpoint.AuthURL = "https://issuer.example/authorize"
			}
			f.o.client.Transport = rewriteTransport{target: server.URL, base: server.Client().Transport}
			status, err := f.s.refreshOAuth2(f.ctx, f.o, f.b, f.guard)
			if tc.want == nil {
				if !errors.Is(err, errRefreshUncertain) || identities.Load() != 0 {
					t.Fatalf("scope rejection: %v", err)
				}
			} else if err != nil || !status.Connected || !reflect.DeepEqual(status.Scopes, tc.want) || identities.Load() != 1 {
				t.Fatalf("refresh scopes=%v err=%v", status.Scopes, err)
			}
			if tokens.Load() != 1 {
				t.Fatal("refresh made more than one exchange")
			}
		})
	}
}
