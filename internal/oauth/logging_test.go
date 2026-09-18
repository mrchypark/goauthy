package oauth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
)

type tokenLoggingTestProvider struct {
	fosite.OAuth2Provider
	request fosite.AccessRequester
	err     error
}

func (p tokenLoggingTestProvider) NewAccessRequest(context.Context, *http.Request, fosite.Session) (fosite.AccessRequester, error) {
	return p.request, nil
}

func (p tokenLoggingTestProvider) NewAccessResponse(context.Context, fosite.AccessRequester) (fosite.AccessResponder, error) {
	return nil, p.err
}

func (tokenLoggingTestProvider) WriteAccessError(context.Context, http.ResponseWriter, fosite.AccessRequester, error) {
}

func TestTokenIssuanceLogRedactsErrorDetails(t *testing.T) {
	const (
		bearerToken  = "sentinel-bearer-token"
		code         = "sentinel-authorization-code"
		clientSecret = "sentinel-client-secret"
	)

	request := fosite.NewAccessRequest(&fosite.DefaultSession{})
	request.GrantTypes = fosite.Arguments{"client_credentials"}
	request.Form = url.Values{"grant_type": {"client_credentials"}}
	request.SetRequestedScopes(fosite.Arguments{"goauthy.read"})
	request.Client = &fosite.DefaultClient{ID: "other-client", GrantTypes: []string{"client_credentials"}}
	provider := tokenLoggingTestProvider{
		request: request,
		err:     errors.New("token issuance failed: bearer=" + bearerToken + " code=" + code + " client_secret=" + clientSecret),
	}
	server := &Server{
		provider: provider,
		store:    &Store{client: &fosite.DefaultClient{ID: "bootstrap-client"}, now: time.Now},
	}

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.TokenHandler().ServeHTTP(httptest.NewRecorder(), req)

	output := logs.String()
	for _, secret := range []string{bearerToken, code, clientSecret} {
		if strings.Contains(output, secret) {
			t.Fatalf("token issuance log contains sentinel %q: %s", secret, output)
		}
	}
	if strings.Contains(output, "debug=") || strings.Contains(output, "error=") {
		t.Fatalf("token issuance log contains an unredacted error attribute: %s", output)
	}
	if !strings.Contains(output, "class=error") {
		t.Fatalf("token issuance log omitted the stable OAuth error class: %s", output)
	}
}
