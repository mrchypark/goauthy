package saas

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func githubPublicTestConfig() OAuth2Config {
	return OAuth2Config{ClientID: "synthetic-client", CallbackURL: "http://localhost:18080/callback",
		AuthorizationURL: githubAuthorizeURL, TokenURL: githubTokenURL,
		IdentityEndpoint: githubAPIURL + "/user", SubjectField: "id", AuthStyle: oauth2.AuthStyleInParams}
}

func TestGitHubPublicOAuth2Configuration(t *testing.T) {
	for _, scopes := range [][]string{nil, {}} {
		cfg := githubPublicTestConfig()
		cfg.Scopes = scopes
		o, err := NewOAuth2(cfg, "synthetic-secret")
		if err != nil {
			t.Fatalf("public-ID profile rejected: %v", err)
		}
		authorize, err := o.AuthorizationURL("synthetic-state", strings.Repeat("v", 43))
		u, parseErr := url.Parse(authorize)
		if err != nil || parseErr != nil || u.Query().Has("scope") || u.Query().Get("code_challenge_method") != "S256" {
			t.Fatal("invalid no-scope authorization request")
		}
	}
	for name, mutate := range map[string]func(*OAuth2Config){
		"generic auth":    func(c *OAuth2Config) { c.AuthorizationURL = "https://provider.example/authorize" },
		"auth suffix":     func(c *OAuth2Config) { c.AuthorizationURL += "/" },
		"token suffix":    func(c *OAuth2Config) { c.TokenURL += "/" },
		"token port":      func(c *OAuth2Config) { c.TokenURL = "https://github.com:443/login/oauth/access_token" },
		"identity suffix": func(c *OAuth2Config) { c.IdentityEndpoint += "/" },
		"identity query":  func(c *OAuth2Config) { c.IdentityEndpoint += "?id=1" },
		"wrong subject":   func(c *OAuth2Config) { c.SubjectField = "login" },
		"missing subject": func(c *OAuth2Config) { c.SubjectField = "" },
		"Google": func(c *OAuth2Config) {
			c.AuthorizationURL, c.TokenURL = "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token"
			c.IdentityEndpoint, c.SubjectField = "https://openidconnect.googleapis.com/v1/userinfo", "sub"
		},
		"empty scope token": func(c *OAuth2Config) { c.Scopes = []string{""} },
		"auto auth":         func(c *OAuth2Config) { c.AuthStyle = oauth2.AuthStyleAutoDetect },
		"nonlocal callback": func(c *OAuth2Config) { c.CallbackURL = "http://example.com/callback" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := githubPublicTestConfig()
			mutate(&cfg)
			if _, err := NewOAuth2(cfg, "synthetic-secret"); !errors.Is(err, ErrOAuth2Config) {
				t.Fatalf("invalid empty-scope configuration accepted: %v", err)
			}
		})
	}
}

func TestGitHubPublicGrantedScopes(t *testing.T) {
	cfg := githubPublicTestConfig()
	o, err := NewOAuth2(cfg, "synthetic-secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []*oauth2.Token{
		{},
		(&oauth2.Token{}).WithExtra(map[string]any{"scope": ""}),
		(&oauth2.Token{}).WithExtra(url.Values{}),
		(&oauth2.Token{}).WithExtra(url.Values{"scope": {""}}),
	} {
		got, err := o.grantedScopes(token, nil)
		if err != nil || got == nil || len(got) != 0 {
			t.Fatalf("absent/empty scope must resolve to []: %v", err)
		}
	}
	for _, raw := range []any{"read:user", "repo", "read:user,repo", " ", "\t", "\n", 1, false, []string{}, map[string]any{}} {
		token := (&oauth2.Token{}).WithExtra(map[string]any{"scope": raw})
		if _, err := o.grantedScopes(token, nil); !errors.Is(err, ErrOAuth2Exchange) {
			t.Fatal("nonempty/malformed scope accepted")
		}
	}
	if _, err := o.grantedScopes(nil, nil); !errors.Is(err, ErrOAuth2Exchange) {
		t.Fatal("nil token accepted")
	}
	empty := (&oauth2.Token{}).WithExtra(map[string]any{"scope": ""})
	if _, err := o.grantedScopes(empty, []string{"read:user"}); !errors.Is(err, ErrOAuth2Exchange) {
		t.Fatal("previous scope authority accepted with unscoped configuration")
	}
	for _, mutate := range []func(*OAuth2){
		func(c *OAuth2) { c.config.Scopes = []string{"read:user"} },
		func(c *OAuth2) { c.config.Endpoint.AuthURL += "/" },
		func(c *OAuth2) { c.config.Endpoint.TokenURL += "/" },
		func(c *OAuth2) { c.identityEndpoint += "/" },
		func(c *OAuth2) { c.subjectField = "login" },
		func(c *OAuth2) {
			c.config.Endpoint.AuthURL, c.config.Endpoint.TokenURL = "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token"
			c.identityEndpoint, c.subjectField = "https://openidconnect.googleapis.com/v1/userinfo", "sub"
		},
	} {
		other := *o
		mutate(&other)
		if _, err := other.grantedScopes(empty, nil); !errors.Is(err, ErrOAuth2Exchange) {
			t.Fatal("explicit empty accepted outside configured public-ID profile")
		}
	}
}

func TestGitHubPublicOAuth2Lifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, scopeJSON string
		allow           bool
	}{
		{"absent", "", true}, {"empty", `,"scope":""`, true},
		{"unexpected", `,"scope":"read:user"`, false}, {"comma", `,"scope":"read:user,repo"`, false},
		{"whitespace", `,"scope":" "`, false}, {"number", `,"scope":1`, false},
		{"array", `,"scope":[]`, false}, {"object", `,"scope":{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, s, db, b := credentialStoreFixture(t)
			providers, err := NewProviderStore(db, s.keys)
			if err != nil {
				t.Fatal(err)
			}
			cfg := githubPublicTestConfig()
			input := ProviderInput{ID: b.ProviderID, Name: "Synthetic GitHub", Kind: "oauth2", Enabled: true,
				ClientID: cfg.ClientID, ClientSecret: "synthetic-secret", CallbackURI: cfg.CallbackURL,
				AuthorizationURL: cfg.AuthorizationURL, TokenURL: cfg.TokenURL, IdentityEndpoint: cfg.IdentityEndpoint,
				SubjectField: cfg.SubjectField, AuthStyle: "params"}
			p, err := providers.Create(ctx, input, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			p, err = providers.Get(ctx, p.ID, credentialAuthority())
			if err != nil || p.Scopes == nil {
				t.Fatalf("provider scopes must be []: %v", err)
			}
			session := authorizationTestDigest("synthetic-session")
			start, err := s.BeginOAuth2(ctx, providers, b.Owner, b.CollectionID, b.ConnectionID, b.ProviderID, session, cfg.CallbackURL, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(start.AuthorizationURL)
			if err != nil || u.Query().Has("scope") {
				t.Fatal("Start requested scopes")
			}
			state := u.Query().Get("state")
			p, guard, err := oauth2Provider(ctx, providers, b.ProviderID, cfg.CallbackURL, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			o, err := providers.LoadOAuth2(ctx, p.ID, guard)
			if err != nil {
				t.Fatal(err)
			}
			var tokens, identities atomic.Int32
			var responseScope atomic.Value
			responseScope.Store(tc.scopeJSON)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/login/oauth/access_token":
					tokens.Add(1)
					if r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("client_id") != cfg.ClientID || r.Form.Get("client_secret") != "synthetic-secret" || r.Form.Has("scope") {
						t.Error("invalid synthetic token request")
					}
					if r.Form.Get("grant_type") == "authorization_code" && !validVerifier(r.Form.Get("code_verifier")) {
						t.Error("missing PKCE verifier")
					}
					_, _ = io.WriteString(w, `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer"`+responseScope.Load().(string)+`}`)
				case "/user":
					identities.Add(1)
					if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer synthetic-access" {
						t.Error("invalid synthetic identity request")
					}
					_, _ = io.WriteString(w, `{"id":12345}`)
				default:
					t.Error("unexpected endpoint")
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)
			o.client.Transport = rewriteTransport{target: server.URL, base: server.Client().Transport}
			status, err := s.completeOAuth2(ctx, o, p, b.Owner, b.CollectionID, b.ConnectionID, session, state, "synthetic-code", guard, "https://github.com/login/oauth")
			if !tc.allow {
				if !errors.Is(err, ErrOAuth2Exchange) || identities.Load() != 0 {
					t.Fatalf("scope rejection before identity: %v", err)
				}
				current, err := s.OAuth2Status(ctx, b.Owner, b.CollectionID, b.ConnectionID, guard)
				if err != nil || current.Connected || current.Version != 0 {
					t.Fatal("rejected scope installed credentials")
				}
			} else {
				if err != nil || !status.Connected || status.AccountID != "12345" || status.Scopes == nil || len(status.Scopes) != 0 {
					t.Fatalf("completion: %v", err)
				}
				loaded, err := s.Load(ctx, b, guard)
				if err != nil || loaded.AccountID != "12345" || loaded.Scopes == nil || len(loaded.Scopes) != 0 {
					t.Fatalf("credential empty-array roundtrip: %v", err)
				}
				current, err := s.OAuth2Status(ctx, b.Owner, b.CollectionID, b.ConnectionID, guard)
				encoded, marshalErr := json.Marshal(current)
				if err != nil || marshalErr != nil || !current.Connected || !strings.Contains(string(encoded), `"scopes":[]`) {
					t.Fatal("status scopes must be []")
				}
				refreshed, err := s.refreshOAuth2(ctx, o, b, guard)
				if err != nil || !refreshed.Connected || refreshed.Version != 2 || refreshed.Scopes == nil || len(refreshed.Scopes) != 0 {
					t.Fatalf("empty-scope refresh CAS: %v", err)
				}
				if _, err := s.refreshOAuth2(ctx, o, b, guard); err == nil || tokens.Load() != 2 {
					t.Fatal("stale refresh replay exchanged token")
				}
				b.TokenVersion++
				responseScope.Store(`,"scope":"repo"`)
				if _, err := s.refreshOAuth2(ctx, o, b, guard); !errors.Is(err, errRefreshUncertain) || identities.Load() != 2 {
					t.Fatal("refresh scope escalation reached identity")
				}
				if err := s.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, b.TokenVersion, guard); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Load(ctx, b, guard); !errors.Is(err, ErrCredentialNotFound) {
					t.Fatal("revoked credential usable")
				}
			}
			calls := tokens.Load()
			if _, err := s.completeOAuth2(ctx, o, p, b.Owner, b.CollectionID, b.ConnectionID, session, state, "synthetic-code", guard, "https://github.com/login/oauth"); !errors.Is(err, ErrAuthorizationNotFound) || tokens.Load() != calls {
				t.Fatal("callback replay exchanged token")
			}
		})
	}
}

func TestGitHubOAuth2IssuerAndDenialDoNotConsume(t *testing.T) {
	ctx, s, db, b := credentialStoreFixture(t)
	// Match the protocol parser's clock for GitHub's eight-hour token expiry.
	now := time.Now().UnixMilli()
	s.now = func() int64 { return now }
	providers, err := NewProviderStore(db, s.keys)
	if err != nil {
		t.Fatal(err)
	}
	cfg := githubPublicTestConfig()
	input := ProviderInput{ID: b.ProviderID, Name: "Synthetic GitHub", Kind: "oauth2", Enabled: true,
		ClientID: cfg.ClientID, ClientSecret: "synthetic-secret", CallbackURI: cfg.CallbackURL,
		AuthorizationURL: cfg.AuthorizationURL, TokenURL: cfg.TokenURL, IdentityEndpoint: cfg.IdentityEndpoint,
		SubjectField: cfg.SubjectField, AuthStyle: "params"}
	if _, err := providers.Create(ctx, input, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	session := authorizationTestDigest("synthetic-session")
	start, err := s.BeginOAuth2(ctx, providers, b.Owner, b.CollectionID, b.ConnectionID, b.ProviderID, session, cfg.CallbackURL, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal("invalid synthetic authorization URL")
	}
	state := u.Query().Get("state")
	p, guard, err := oauth2Provider(ctx, providers, b.ProviderID, cfg.CallbackURL, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	o, err := providers.LoadOAuth2(ctx, p.ID, guard)
	if err != nil {
		t.Fatal(err)
	}
	var tokens, identities atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			tokens.Add(1)
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = io.WriteString(w, "access_token=synthetic-access&scope=&token_type=bearer&expires_in=28800&refresh_token=synthetic-refresh&refresh_token_expires_in=15897600")
		case "/user":
			identities.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":12345,"login":"synthetic-public","node_id":"synthetic-node","name":null,"email":null,"public_repos":2,"site_admin":false}`)
		default:
			t.Error("unexpected synthetic endpoint")
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	o.client.Transport = rewriteTransport{target: server.URL, base: server.Client().Transport}
	const issuer = "https://github.com/login/oauth"
	// The actual GitHub-shaped issuer must pass the shared check before any I/O.
	if _, _, err := s.callbackAuthorization(ctx, p, b.Owner, b.CollectionID, b.ConnectionID, session, state, guard, []string{issuer}); err != nil {
		t.Fatalf("actual GitHub-shaped issuer rejected: %v", err)
	}
	assertPending := func() {
		t.Helper()
		if _, _, err := s.loadAuthorizationVerifier(ctx, authorizationDigest(state), session, oauth2ProviderDigest(p), guard); err != nil {
			t.Fatal("rejected callback consumed or invalidated authorization")
		}
		if tokens.Load() != 0 || identities.Load() != 0 {
			t.Fatal("rejected callback made an external call")
		}
		status, err := s.OAuth2Status(ctx, b.Owner, b.CollectionID, b.ConnectionID, guard)
		if err != nil || status.Connected || status.Version != 0 {
			t.Fatal("rejected callback installed credentials")
		}
	}
	for _, issuers := range [][]string{nil, {""}, {"https://github.com"}, {"https://accounts.google.com"}, {issuer + "/"}, {issuer + "?x=1"}, {issuer, issuer}} {
		if _, err := s.CompleteOAuth2(ctx, providers, b.Owner, b.CollectionID, b.ConnectionID, b.ProviderID, session, cfg.CallbackURL, state, "synthetic-code", credentialAuthority(), issuers...); !errors.Is(err, ErrOAuth2Exchange) {
			t.Fatalf("public issuer rejection: %v", err)
		}
		if _, err := s.completeOAuth2(ctx, o, p, b.Owner, b.CollectionID, b.ConnectionID, session, state, "synthetic-code", guard, issuers...); !errors.Is(err, ErrOAuth2Exchange) {
			t.Fatalf("shared issuer rejection: %v", err)
		}
		assertPending()
	}
	for _, tc := range []struct {
		owner, session, issuer string
		want                   error
	}{
		{b.Owner, session, issuer, nil},
		{b.Owner, session, "", ErrOAuth2Exchange},
		{b.Owner, session, "https://github.com", ErrOAuth2Exchange},
		{b.Owner, authorizationTestDigest("wrong-session"), issuer, ErrAuthorizationNotFound},
		{"wrong-owner", session, issuer, ErrAuthorizationNotFound},
	} {
		if err := s.RejectOAuth2(ctx, providers, tc.owner, b.ProviderID, tc.session, cfg.CallbackURL, state, tc.issuer, credentialAuthority()); !errors.Is(err, tc.want) {
			t.Fatalf("denial binding: %v", err)
		}
		assertPending()
	}
	if _, err := s.completeOAuth2(ctx, o, p, b.Owner, b.CollectionID, b.ConnectionID, authorizationTestDigest("wrong-session"), state, "synthetic-code", guard, issuer); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("wrong session: %v", err)
	}
	assertPending()
	status, err := s.completeOAuth2(ctx, o, p, b.Owner, b.CollectionID, b.ConnectionID, session, state, "synthetic-code", guard, issuer)
	if err != nil || !status.Connected || status.AccountID != "12345" || status.Scopes == nil || len(status.Scopes) != 0 {
		t.Fatalf("GitHub-shaped completion: %v; token calls=%d identity calls=%d", err, tokens.Load(), identities.Load())
	}
	if _, err := s.completeOAuth2(ctx, o, p, b.Owner, b.CollectionID, b.ConnectionID, session, state, "synthetic-code", guard, issuer); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("replay: %v", err)
	}
	if tokens.Load() != 1 || identities.Load() != 1 {
		t.Fatal("completion or replay call count changed")
	}
}

func TestOAuth2CallbackIssuerExactGitHubProfileBoundary(t *testing.T) {
	for name, mutate := range map[string]func(*ProviderInput){
		"authorization": func(p *ProviderInput) { p.AuthorizationURL += "/" },
		"token":         func(p *ProviderInput) { p.TokenURL += "/" },
		"identity":      func(p *ProviderInput) { p.IdentityEndpoint += "/" },
		"subject":       func(p *ProviderInput) { p.SubjectField = "login" },
	} {
		t.Run(name, func(t *testing.T) {
			ctx, s, db, b := credentialStoreFixture(t)
			providers, err := NewProviderStore(db, s.keys)
			if err != nil {
				t.Fatal(err)
			}
			cfg := githubPublicTestConfig()
			input := ProviderInput{ID: b.ProviderID, Name: "Synthetic generic", Kind: "oauth2", Enabled: true,
				ClientID: cfg.ClientID, ClientSecret: "synthetic-secret", CallbackURI: cfg.CallbackURL,
				AuthorizationURL: cfg.AuthorizationURL, TokenURL: cfg.TokenURL, IdentityEndpoint: cfg.IdentityEndpoint,
				SubjectField: cfg.SubjectField, Scopes: []string{"read"}, AuthStyle: "params"}
			mutate(&input)
			if _, err := providers.Create(ctx, input, credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			session := authorizationTestDigest("synthetic-session")
			start, err := s.BeginOAuth2(ctx, providers, b.Owner, b.CollectionID, b.ConnectionID, b.ProviderID, session, cfg.CallbackURL, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(start.AuthorizationURL)
			if err != nil {
				t.Fatal("invalid synthetic authorization URL")
			}
			state := u.Query().Get("state")
			p, guard, err := oauth2Provider(ctx, providers, b.ProviderID, cfg.CallbackURL, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			for _, issuers := range [][]string{nil, {""}} {
				got, _, err := s.callbackAuthorization(ctx, p, b.Owner, b.CollectionID, b.ConnectionID, session, state, guard, issuers)
				if err != nil || got != b {
					t.Fatalf("generic omitted issuer rejected: %v", err)
				}
			}
			for _, issuers := range [][]string{{"https://github.com/login/oauth"}, {"https://accounts.google.com"}, {"https://provider.example"}, {"", ""}} {
				if _, _, err := s.callbackAuthorization(ctx, p, b.Owner, b.CollectionID, b.ConnectionID, session, state, guard, issuers); !errors.Is(err, ErrOAuth2Exchange) {
					t.Fatalf("generic nonempty/duplicate issuer accepted: %v", err)
				}
			}
			if _, _, err := s.loadAuthorizationVerifier(ctx, authorizationDigest(state), session, oauth2ProviderDigest(p), guard); err != nil {
				t.Fatal("issuer checks consumed authorization")
			}
		})
	}
}
