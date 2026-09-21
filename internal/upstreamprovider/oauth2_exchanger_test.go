package upstreamprovider

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type rewriteTransport struct{ target *url.URL }

func (t rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme, r.URL.Host = t.target.Scheme, t.target.Host
	return http.DefaultTransport.RoundTrip(r)
}

func testOAuth2Exchanger(t *testing.T, handler http.Handler) (*OAuth2TokenExchanger, map[string]Config, map[string]string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	configs := map[string]Config{"provider": {
		Issuer: "https://issuer.example.test", AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint: "https://issuer.example.test/token", ClientID: "client",
	}}
	secrets := map[string]string{"provider": "secret"}
	exchanger, err := NewOAuth2TokenExchanger(configs, secrets, &http.Client{Transport: rewriteTransport{target: target}})
	if err != nil {
		t.Fatal(err)
	}
	return exchanger, configs, secrets
}

func TestOAuth2TokenExchangerExchangeCode(t *testing.T) {
	t.Parallel()
	exchanger, _, _ := testOAuth2Exchanger(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPost; got != want {
			t.Errorf("method = %q, want %q", got, want)
		}
		if got, want := r.FormValue("grant_type"), "authorization_code"; got != want {
			t.Errorf("grant_type = %q, want %q", got, want)
		}
		if got, want := r.FormValue("code"), "code"; got != want {
			t.Errorf("code = %q, want %q", got, want)
		}
		if got, want := r.FormValue("code_verifier"), "verifier"; got != want {
			t.Errorf("code_verifier = %q, want %q", got, want)
		}
		if got, want := r.FormValue("redirect_uri"), "https://app.example.test/callback"; got != want {
			t.Errorf("redirect_uri = %q, want %q", got, want)
		}
		if user, pass, ok := r.BasicAuth(); !ok || user != "client" || pass != "secret" {
			t.Errorf("client authentication = %q:%q ok=%t", user, pass, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","id_token":"identity"}`))
	}))

	result, err := exchanger.ExchangeCode(context.Background(), "provider", "https://app.example.test/callback", "code", "verifier")
	if err != nil || result == nil || result.IDToken != "identity" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
}

func TestOAuth2TokenExchangerRejectsInvalidInputAndCopiesMaps(t *testing.T) {
	t.Parallel()
	exchanger, configs, secrets := testOAuth2Exchanger(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","id_token":"identity"}`))
	}))
	configs["provider"] = Config{}
	secrets["provider"] = "changed"
	if _, err := exchanger.ExchangeCode(context.Background(), "other", "https://app.example.test/callback", "code", "verifier"); !errors.Is(err, errTokenExchange) {
		t.Fatalf("unknown provider error = %v", err)
	}
	result, err := exchanger.ExchangeCode(context.Background(), "provider", "https://app.example.test/callback", "code", "verifier")
	if err != nil || result.IDToken != "identity" {
		t.Fatalf("copied config exchange = %#v, %v", result, err)
	}
	if _, err := NewOAuth2TokenExchanger(map[string]Config{"provider": {}}, map[string]string{"provider": "secret"}, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("malformed config error = %v", err)
	}
	if _, err := NewOAuth2TokenExchanger(map[string]Config{"provider": {
		Issuer: "https://issuer.example.test", AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint: "https://issuer.example.test/token", ClientID: "client",
	}}, map[string]string{"provider": "secret", "extra": "secret"}, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("extra secret error = %v", err)
	}
	for _, id := range []string{"Provider", " provider", "íêµ­ì´"} { //-provider in Korean
		if _, err := NewOAuth2TokenExchanger(map[string]Config{id: {
			Issuer: "https://issuer.example.test", AuthorizationEndpoint: "https://issuer.example.test/auth",
			TokenEndpoint: "https://issuer.example.test/token", ClientID: "client",
		}}, map[string]string{id: "secret"}, nil); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("provider key %q error = %v, want invalid config", id, err)
		}
	}
}

func TestOAuth2TokenExchangerRejectsMalformedCallbackWithoutNetwork(t *testing.T) {
	t.Parallel()
	called := make(chan struct{}, 1)
	exchanger, _, _ := testOAuth2Exchanger(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called <- struct{}{}
	}))
	_, err := exchanger.ExchangeCode(context.Background(), "provider", "http://app.example.test/callback", "code", "verifier")
	if !errors.Is(err, errTokenExchange) {
		t.Fatalf("ExchangeCode() error = %v", err)
	}
	select {
	case <-called:
		t.Fatal("malformed callback made a network request")
	default:
	}
}

func TestOAuth2TokenExchangerClientPolicy(t *testing.T) {
	t.Parallel()
	configs := map[string]Config{"provider": {
		Issuer: "https://issuer.example.test", AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint: "https://issuer.example.test/token", ClientID: "client",
	}}
	secrets := map[string]string{"provider": "secret"}
	defaultClient, err := NewOAuth2TokenExchanger(configs, secrets, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := defaultClient.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableCompression || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("default transport = %#v", defaultClient.client.Transport)
	}
	if defaultClient.client.Timeout != upstreamTokenExchangeTimeout || defaultClient.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("default client does not enforce exchange policy")
	}

	callerRedirect := func(*http.Request, []*http.Request) error { return errors.New("caller redirect") }
	caller := &http.Client{Timeout: 20 * upstreamTokenExchangeTimeout, Transport: http.DefaultTransport, CheckRedirect: callerRedirect}
	injected, err := NewOAuth2TokenExchanger(configs, secrets, caller)
	if err != nil {
		t.Fatal(err)
	}
	if injected.client == caller || injected.client.Transport != caller.Transport || injected.client.Timeout != upstreamTokenExchangeTimeout || injected.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("injected client was not safely cloned")
	}
	if caller.Timeout != 20*upstreamTokenExchangeTimeout || caller.CheckRedirect(nil, nil).Error() != "caller redirect" {
		t.Fatal("caller client was mutated")
	}
}

func TestOAuth2TokenExchangerDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	followed := make(chan struct{}, 1)
	exchanger, _, _ := testOAuth2Exchanger(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Location", "/follow")
			w.WriteHeader(http.StatusFound)
		case "/follow":
			followed <- struct{}{}
		}
	}))
	_, err := exchanger.ExchangeCode(context.Background(), "provider", "https://app.example.test/callback", "code", "verifier")
	if !errors.Is(err, errTokenExchange) {
		t.Fatalf("ExchangeCode() error = %v", err)
	}
	select {
	case <-followed:
		t.Fatal("token exchange followed redirect")
	default:
	}
}

func TestOAuth2TokenExchangerRejectsBadTokenResponses(t *testing.T) {
	t.Parallel()
	for name, response := range map[string]string{
		"non-2xx":          "status",
		"error field":      `{"access_token":"x","error":"invalid_grant"}`,
		"empty access":     `{"id_token":"id"}`,
		"missing id_token": `{"access_token":"access"}`,
	} {
		t.Run(name, func(t *testing.T) {
			exchanger, _, _ := testOAuth2Exchanger(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if response == "status" {
					http.Error(w, "upstream failure", http.StatusBadGateway)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(response))
			}))
			_, err := exchanger.ExchangeCode(context.Background(), "provider", "https://app.example.test/callback", "sensitive-code", "verifier")
			if !errors.Is(err, errTokenExchange) || strings.Contains(err.Error(), "sensitive-code") {
				t.Fatalf("ExchangeCode() error = %v", err)
			}
		})
	}
}

func TestOAuth2TokenExchangerCancellation(t *testing.T) {
	t.Parallel()
	exchanger, _, _ := testOAuth2Exchanger(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := exchanger.ExchangeCode(ctx, "provider", "https://app.example.test/callback", "code", "verifier")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ExchangeCode() error = %v, want context cancellation", err)
	}
}

func TestOAuth2TokenExchangerCancelsInFlightRequest(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	exchanger, _, _ := testOAuth2Exchanger(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","id_token":"identity"}`))
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := exchanger.ExchangeCode(ctx, "provider", "https://app.example.test/callback", "code", "verifier")
		result <- err
	}()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("ExchangeCode() error = %v, want context cancellation", err)
	}
}

func boolPtr(b bool) *bool { return &b }

func testExchangerWithProtocol(t *testing.T, handler http.Handler, proto ProviderProtocol, secrets map[string]string) (*OAuth2TokenExchanger, string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	configs := map[string]Config{"provider": {
		Issuer:                "https://issuer.example.test",
		AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint:         "https://issuer.example.test/token",
		ClientID:              "client",
		Protocol:              proto,
	}}
	if secrets == nil {
		secrets = map[string]string{}
	}
	exchanger, err := NewOAuth2TokenExchanger(configs, secrets, &http.Client{Transport: rewriteTransport{target: target}})
	if err != nil {
		t.Fatal(err)
	}
	return exchanger, "https://app.example.test/callback"
}

func TestExplicitBasicOnly(t *testing.T) {
	t.Parallel()
	var gotBasic, gotPost, gotVerifier bool
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, ok := r.BasicAuth()
		gotBasic = ok && user == "client"
		gotPost = r.FormValue("client_secret") != ""
		gotVerifier = r.FormValue("code_verifier") != ""
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","id_token":"identity"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(true), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
	}, map[string]string{"provider": "secret"})
	result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "verifier")
	if err != nil || result == nil || result.IDToken != "identity" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
	if !gotBasic {
		t.Error("expected Basic Auth header")
	}
	if gotPost {
		t.Error("unexpected client_secret in form body")
	}
	if !gotVerifier {
		t.Error("expected code_verifier in form body")
	}
}

func TestExplicitPostOnly(t *testing.T) {
	t.Parallel()
	var gotBasic, gotPost, gotVerifier bool
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, ok := r.BasicAuth()
		gotBasic = ok
		gotPost = r.FormValue("client_secret") == "secret"
		gotVerifier = r.FormValue("code_verifier") != ""
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","id_token":"identity"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(true), ClientSecretBasic: boolPtr(false), ClientSecretPost: boolPtr(true),
	}, map[string]string{"provider": "secret"})
	result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "verifier")
	if err != nil || result == nil || result.IDToken != "identity" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
	if gotBasic {
		t.Error("unexpected Basic Auth header")
	}
	if !gotPost {
		t.Error("expected client_secret in form body")
	}
	if !gotVerifier {
		t.Error("expected code_verifier in form body")
	}
}

func TestExplicitBasicAndPost(t *testing.T) {
	t.Parallel()
	var gotBasic, gotPost bool
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		gotBasic = ok && user == "client" && pass == "secret"
		gotPost = r.FormValue("client_secret") == "secret"
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","id_token":"identity"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(true), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(true),
	}, map[string]string{"provider": "secret"})
	result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "verifier")
	if err != nil || result == nil || result.IDToken != "identity" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
	if !gotBasic {
		t.Error("expected Basic Auth header")
	}
	if !gotPost {
		t.Error("expected client_secret in form body")
	}
}

func TestExplicitPKCEOff(t *testing.T) {
	t.Parallel()
	var gotVerifier bool
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVerifier = r.FormValue("code_verifier") != ""
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","id_token":"identity"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
	}, map[string]string{"provider": "secret"})
	// Empty verifier should succeed when PKCE is off.
	result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if err != nil || result == nil || result.IDToken != "identity" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
	if gotVerifier {
		t.Error("unexpected code_verifier in form body")
	}
}

func TestExplicitPublicClient(t *testing.T) {
	t.Parallel()
	// Public client: PKCE on, no secret auth.
	var gotBasic, gotPost, gotVerifier bool
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, ok := r.BasicAuth()
		gotBasic = ok
		gotPost = r.FormValue("client_secret") != ""
		gotVerifier = r.FormValue("code_verifier") == "pub-verifier"
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","id_token":"identity"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(true), ClientSecretBasic: boolPtr(false), ClientSecretPost: boolPtr(false),
	}, nil) // no secrets
	result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "pub-verifier")
	if err != nil || result == nil || result.IDToken != "identity" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
	if gotBasic {
		t.Error("unexpected Basic Auth for public client")
	}
	if gotPost {
		t.Error("unexpected client_secret for public client")
	}
	if !gotVerifier {
		t.Error("expected code_verifier for public client")
	}
}

func TestExplicitRejectsMissingVerifierWhenPKCE(t *testing.T) {
	t.Parallel()
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","id_token":"identity"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(true), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
	}, map[string]string{"provider": "secret"})
	_, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if !errors.Is(err, errTokenExchange) {
		t.Fatalf("missing verifier with PKCE: err = %v", err)
	}
}

func TestExplicitAllowsEmptyVerifierWhenPKCEOff(t *testing.T) {
	t.Parallel()
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","id_token":"identity"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
	}, map[string]string{"provider": "secret"})
	result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if err != nil || result == nil || result.IDToken != "identity" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
}

func TestExplicitRejectsTokenErrors(t *testing.T) {
	t.Parallel()
	for name, response := range map[string]string{
		"non-2xx":     "status",
		"error field": `{"access_token":"x","error":"invalid_grant"}`,
	} {
		t.Run(name, func(t *testing.T) {
			exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if response == "status" {
					http.Error(w, "upstream failure", http.StatusBadGateway)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(response))
			}), ProviderProtocol{
				UsePKCE: boolPtr(true), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
			}, map[string]string{"provider": "secret"})
			_, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "verifier")
			if !errors.Is(err, errTokenExchange) {
				t.Fatalf("ExchangeCode() error = %v", err)
			}
		})
	}
}

func TestExplicitConstructorAllowsNoSecretWhenBasic(t *testing.T) {
	t.Parallel()
	_, err := NewOAuth2TokenExchanger(map[string]Config{"p": {
		Issuer:                "https://issuer.example.test",
		AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint:         "https://issuer.example.test/token",
		ClientID:              "c",
		Protocol:              ProviderProtocol{ClientSecretBasic: boolPtr(true)},
	}}, map[string]string{}, nil)
	if err != nil {
		t.Fatalf("absent secret with basic (Rauthy-aligned): err = %v", err)
	}
}

func TestExplicitConstructorAllowsNoSecretForPublicClient(t *testing.T) {
	t.Parallel()
	_, err := NewOAuth2TokenExchanger(map[string]Config{"p": {
		Issuer:                "https://issuer.example.test",
		AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint:         "https://issuer.example.test/token",
		ClientID:              "c",
		Protocol:              ProviderProtocol{UsePKCE: boolPtr(true), ClientSecretBasic: boolPtr(false), ClientSecretPost: boolPtr(false)},
	}}, map[string]string{}, nil)
	if err != nil {
		t.Fatalf("public client no secret: err = %v", err)
	}
}

func TestExplicitConstructorClonesProtocolPointers(t *testing.T) {
	t.Parallel()
	trueVal := true
	cfg := Config{
		Issuer:                "https://issuer.example.test",
		AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint:         "https://issuer.example.test/token",
		ClientID:              "c",
		Protocol: ProviderProtocol{
			UsePKCE:           &trueVal,
			ClientSecretBasic: &trueVal,
			ClientSecretPost:  &trueVal,
		},
	}
	secrets := map[string]string{"p": "s"}
	configs := map[string]Config{"p": cfg}
	exchanger, err := NewOAuth2TokenExchanger(configs, secrets, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the original Protocol pointers — exchanger must not see this.
	falseVal := false
	cfg.Protocol.UsePKCE = &falseVal
	cfg.Protocol.ClientSecretBasic = &falseVal
	cfg.Protocol.ClientSecretPost = &falseVal
	got := exchanger.configs["p"].EffectiveProtocol()
	if !got.UsePKCE || !got.ClientSecretBasic || !got.ClientSecretPost {
		t.Fatalf("Protocol pointers leaked mutation: pkce=%v basic=%v post=%v", got.UsePKCE, got.ClientSecretBasic, got.ClientSecretPost)
	}
}

func TestExplicitPublicClientNoSecret2xxAccepted(t *testing.T) {
	t.Parallel()
	// Public client with no secret, server returns 201.
	var gotBasic, gotPost bool
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, ok := r.BasicAuth()
		gotBasic = ok
		gotPost = r.FormValue("client_secret") != ""
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"id"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(true), ClientSecretBasic: boolPtr(false), ClientSecretPost: boolPtr(false),
	}, nil)
	result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "ver")
	if err != nil || result == nil || result.IDToken != "id" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
	if gotBasic {
		t.Error("unexpected Basic Auth")
	}
	if gotPost {
		t.Error("unexpected client_secret in form")
	}
}

func TestExplicitRejectsMissingIDToken(t *testing.T) {
	t.Parallel()
	// OIDC providers must return a non-empty id_token.
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
	}, map[string]string{"provider": "secret"})
	_, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if !errors.Is(err, errTokenExchange) {
		t.Fatalf("ExchangeCode() error = %v, want errTokenExchange for missing id_token", err)
	}
}

func TestExplicitBasicAuthSendsUsernameColonWithAbsentSecret(t *testing.T) {
	t.Parallel()
	// Rauthy-aligned: Basic flag => Authorization header even with absent secret.
	var gotBasic bool
	var gotUser, gotPass string
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotBasic = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"id"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
	}, nil) // no secrets at all
	result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if err != nil || result == nil || result.IDToken != "id" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
	if !gotBasic {
		t.Fatal("expected Basic Auth header with absent secret")
	}
	if gotUser != "client" || gotPass != "" {
		t.Errorf("Basic auth = %q:%q, want client:", gotUser, gotPass)
	}
}

func TestExplicitPostIncludesEmptySecretWhenKeyPresent(t *testing.T) {
	t.Parallel()
	// Post flag => form field when map key is present, even with empty value.
	var gotPostVal string
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPostVal = r.FormValue("client_secret")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"id"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(false), ClientSecretPost: boolPtr(true),
	}, map[string]string{"provider": ""}) // key present, empty value
	result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if err != nil || result == nil || result.IDToken != "id" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
	if gotPostVal != "" {
		t.Errorf("client_secret = %q, want empty string (present but empty)", gotPostVal)
	}
}

func TestExplicitPostOmitsSecretWhenKeyAbsent(t *testing.T) {
	t.Parallel()
	// Post flag => no form field when map key is absent.
	var gotPost bool
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPost = r.FormValue("client_secret") != ""
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"id"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(false), ClientSecretPost: boolPtr(true),
	}, nil) // no secrets map key
	result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if err != nil || result == nil || result.IDToken != "id" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
	if gotPost {
		t.Error("unexpected client_secret in form body with absent map key")
	}
}

func TestLegacyConstructorRejectsMissingSecret(t *testing.T) {
	t.Parallel()
	// Legacy protocol (isZero) must reject missing/empty secret.
	_, err := NewOAuth2TokenExchanger(map[string]Config{"p": {
		Issuer: "https://issuer.example.test", AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint: "https://issuer.example.test/token", ClientID: "c",
	}}, map[string]string{}, nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("legacy empty secret: err = %v, want ErrInvalidConfig", err)
	}
}

func TestLegacyConstructorRejectsEmptySecret(t *testing.T) {
	t.Parallel()
	// Legacy protocol (isZero) must reject key-present-but-empty secret.
	_, err := NewOAuth2TokenExchanger(map[string]Config{"p": {
		Issuer: "https://issuer.example.test", AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint: "https://issuer.example.test/token", ClientID: "c",
	}}, map[string]string{"p": ""}, nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("legacy empty secret value: err = %v, want ErrInvalidConfig", err)
	}
}

func TestExplicitConstructorPreservesSecretMembership(t *testing.T) {
	t.Parallel()
	// Basic flag always sends header; Post flag distinguishes absent vs present.
	t.Run("basic_sends_with_both_absent_and_present", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			secrets map[string]string
		}{
			{"absent", nil},
			{"present_empty", map[string]string{"provider": ""}},
			{"present_value", map[string]string{"provider": "s"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var gotBasic bool
				var gotUser string
				exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					gotUser, _, gotBasic = r.BasicAuth()
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"id_token":"id"}`))
				}), ProviderProtocol{
					UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
				}, tc.secrets)
				result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
				if err != nil || result == nil || result.IDToken != "id" {
					t.Fatalf("ExchangeCode() = %#v, %v", result, err)
				}
				if !gotBasic {
					t.Error("expected Basic Auth header")
				}
				if gotUser != "client" {
					t.Errorf("user = %q, want client", gotUser)
				}
			})
		}
	})
	t.Run("post_absent_omits_present_includes", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			secrets  map[string]string
			wantPost bool
		}{
			{"absent", nil, false},
			{"present_empty", map[string]string{"provider": ""}, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var gotPost bool
				exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_ = r.ParseForm()
					gotPost = r.PostForm.Has("client_secret")
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"id_token":"id"}`))
				}), ProviderProtocol{
					UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(false), ClientSecretPost: boolPtr(true),
				}, tc.secrets)
				result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
				if err != nil || result == nil || result.IDToken != "id" {
					t.Fatalf("ExchangeCode() = %#v, %v", result, err)
				}
				if gotPost != tc.wantPost {
					t.Errorf("client_secret in form = %v, want %v", gotPost, tc.wantPost)
				}
			})
		}
	})
}

func TestExplicitRejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"id"}{"extra":true}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
	}, map[string]string{"provider": "secret"})
	_, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if !errors.Is(err, errTokenExchange) {
		t.Fatalf("trailing JSON: err = %v, want errTokenExchange", err)
	}
}

func TestExplicitRejectsOversizeBody(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("x", tokenMaxBytes+100)
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(big))
	}), ProviderProtocol{
		UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
	}, map[string]string{"provider": "secret"})
	_, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if !errors.Is(err, errTokenExchange) {
		t.Fatalf("oversize body: err = %v, want errTokenExchange", err)
	}
}

func TestExplicitRejectsTrailingNonWhitespace(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"trailing space", `{"id_token":"id"} `, false},
		{"trailing tab", `{"id_token":"id"}` + "	", false},
		{"trailing object", `{"id_token":"id"}{"extra":1}`, true},
		{"trailing text", `{"id_token":"id"} garbage`, true},
		{"whitespace then second JSON", `{"id_token":"id"}` + strings.Repeat(" ", 8192) + `{"extra":1}`, true},
		{"whitespace only 8192", `{"id_token":"id"}` + strings.Repeat(" ", 8192), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}), ProviderProtocol{
				UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
			}, map[string]string{"provider": "secret"})
			_, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
			if tc.wantErr && !errors.Is(err, errTokenExchange) {
				t.Errorf("err = %v, want errTokenExchange", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("err = %v, want nil", err)
			}
		})
	}
}

func TestExplicitOIDCRequiresIDToken(t *testing.T) {
	t.Parallel()
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
	}, map[string]string{"provider": "secret"})
	_, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if !errors.Is(err, errTokenExchange) {
		t.Fatalf("OIDC missing id_token: err = %v, want errTokenExchange", err)
	}
}

func TestExplicitOIDCAcceptsIDTokenOnly(t *testing.T) {
	t.Parallel()
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"myid"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
	}, map[string]string{"provider": "secret"})
	result, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if err != nil || result == nil || result.IDToken != "myid" {
		t.Fatalf("ExchangeCode() = %#v, %v", result, err)
	}
}

func TestOIDCProviderRejectsMissingIDTokenEvenWithUserInfo(t *testing.T) {
	t.Parallel()
	// OIDC providers must reject access-token-only responses even when a
	// UserInfo endpoint is configured. Falling back to UserInfo bypasses
	// id_token signature, issuer, audience, nonce, and time validation.
	var userinfoHits int
	exchanger, cb := testExchangerWithProtocol(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}), ProviderProtocol{
		UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
	}, map[string]string{"provider": "secret"})
	// Inject UserInfoEndpoint into the cloned config so the old fallback path is reachable.
	cfg := exchanger.configs["provider"]
	cfg.UserInfoEndpoint = "https://issuer.example.test/userinfo"
	exchanger.configs["provider"] = cfg
	_ = userinfoHits // UserInfo must never be called
	_, err := exchanger.ExchangeCode(context.Background(), "provider", cb, "code", "")
	if !errors.Is(err, errTokenExchange) {
		t.Fatalf("OIDC with UserInfo missing id_token: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoProviderAcceptsMissingIDToken(t *testing.T) {
	t.Parallel()
	// Control: ProviderKindOAuthUserInfo legitimately uses UserInfo and does
	// not require an id_token.
	var userinfoHits int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	t.Cleanup(server.Close)
	userinfoServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userinfoHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"ctrl-user"}`))
	}))
	t.Cleanup(userinfoServer.Close)
	configs := map[string]Config{testPID: {
		Kind:                  ProviderKindOAuthUserInfo,
		Issuer:                "https://issuer.example.test",
		AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint:         server.URL,
		UserInfoEndpoint:      userinfoServer.URL,
		ClientID:              "client",
		Protocol: ProviderProtocol{
			UsePKCE:           boolPtr(true),
			ClientSecretBasic: boolPtr(true),
			ClientSecretPost:  boolPtr(false),
		},
		ProviderSource: "registry",
		RuntimeVersion: "v1",
	}}
	exchanger, err := NewOAuth2TokenExchanger(configs, map[string]string{testPID: ""}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := exchanger.ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "verifier")
	if err != nil {
		t.Fatalf("OAuthUserInfo missing id_token: err = %v", err)
	}
	if result == nil || result.Subject == nil || result.Subject.Subject != "ctrl-user" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if userinfoHits != 1 {
		t.Errorf("userinfo hits = %d, want 1", userinfoHits)
	}
}

func TestExplicitBasicAuthFormEncodesCredentialComponents(t *testing.T) {
	t.Parallel()
	// RFC 6749 section 2.3.1: client_id and client_secret are
	// application/x-www-form-urlencoded encoded before Basic construction.
	const reservedID = "client:id/@"
	const reservedSecret = "secret+/=&%:@ "

	exchange := func(t *testing.T, clientID, secret string) (string, string, bool) {
		t.Helper()
		var user, pass string
		var ok bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok = r.BasicAuth()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id_token":"id"}`))
		}))
		t.Cleanup(server.Close)
		target, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		configs := map[string]Config{"provider": {
			Issuer:                "https://issuer.example.test",
			AuthorizationEndpoint: "https://issuer.example.test/auth",
			TokenEndpoint:         "https://issuer.example.test/token",
			ClientID:              clientID,
			Protocol: ProviderProtocol{
				UsePKCE: boolPtr(false), ClientSecretBasic: boolPtr(true), ClientSecretPost: boolPtr(false),
			},
		}}
		exchanger, err := NewOAuth2TokenExchanger(configs, map[string]string{"provider": secret}, &http.Client{Transport: rewriteTransport{target: target}})
		if err != nil {
			t.Fatal(err)
		}
		result, err := exchanger.ExchangeCode(context.Background(), "provider", "https://app.example.test/callback", "code", "")
		if err != nil || result == nil || result.IDToken != "id" {
			t.Fatalf("ExchangeCode() = %#v, %v", result, err)
		}
		return user, pass, ok
	}

	t.Run("reserved characters round-trip through the endpoint", func(t *testing.T) {
		user, pass, ok := exchange(t, reservedID, reservedSecret)
		if !ok {
			t.Fatal("expected Basic Auth header")
		}
		if user != url.QueryEscape(reservedID) || pass != url.QueryEscape(reservedSecret) {
			t.Errorf("Basic auth = %q:%q, want %q:%q", user, pass, url.QueryEscape(reservedID), url.QueryEscape(reservedSecret))
		}
		// A conforming endpoint form-decodes each component and recovers the originals.
		decodedUser, err := url.QueryUnescape(user)
		if err != nil {
			t.Fatalf("query-unescape username: %v", err)
		}
		decodedPass, err := url.QueryUnescape(pass)
		if err != nil {
			t.Fatalf("query-unescape password: %v", err)
		}
		if decodedUser != reservedID || decodedPass != reservedSecret {
			t.Errorf("decoded Basic auth = %q:%q, want %q:%q", decodedUser, decodedPass, reservedID, reservedSecret)
		}
	})

	t.Run("unreserved ascii is unchanged", func(t *testing.T) {
		user, pass, ok := exchange(t, "client", "secret")
		if !ok || user != "client" || pass != "secret" {
			t.Errorf("Basic auth = %q:%q (present=%t), want \"client\":\"secret\"", user, pass, ok)
		}
	})
}
