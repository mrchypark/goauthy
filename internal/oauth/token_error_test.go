package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/claims"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

type tokenErrorProvider struct {
	tokenLoggingTestProvider
	requestError error
}

func (p tokenErrorProvider) NewAccessRequest(context.Context, *http.Request, fosite.Session) (fosite.AccessRequester, error) {
	return p.request, p.requestError
}

func (tokenErrorProvider) WriteAccessError(ctx context.Context, w http.ResponseWriter, request fosite.AccessRequester, err error) {
	provider := &fosite.Fosite{Config: &fosite.Config{SendDebugMessagesToClients: false}}
	provider.WriteAccessError(ctx, w, request, err)
}

func TestTokenEndpointInternalErrorResponse(t *testing.T) {
	t.Parallel()
	const secret = "private-storage-error-sentinel"
	for _, tc := range []struct {
		name         string
		err          error
		requestStage bool
		status       int
		code         string
	}{
		{"request storage failure", fmt.Errorf("%s: %w", secret, rhiza.ErrCommitUnknown), true, 500, "server_error"},
		{"response storage failure", fmt.Errorf("%s: %w", secret, rhiza.ErrCommitUnknown), false, 500, "server_error"},
		{"request cancellation", context.DeadlineExceeded, true, 500, "server_error"},
		{"wrapped client quorum failure", fosite.ErrInvalidClient.WithWrap(fmt.Errorf("%s: %w", secret, rhiza.ErrQuorumUnavailable)), true, 500, "server_error"},
		{"wrapped client not ready", fosite.ErrInvalidClient.WithWrap(fmt.Errorf("%s: %w", secret, rhiza.ErrNotReady)), true, 500, "server_error"},
		{"wrapped client durability failure", fosite.ErrInvalidClient.WithWrap(fmt.Errorf("%s: %w", secret, rhiza.ErrDurabilityUnavailable)), true, 500, "server_error"},
		{"wrapped client commit unknown", fosite.ErrInvalidClient.WithWrap(fmt.Errorf("%s: %w", secret, rhiza.ErrCommitUnknown)), true, 500, "server_error"},
		{"wrapped client deadline", fosite.ErrInvalidClient.WithWrap(fmt.Errorf("%s: %w", secret, context.DeadlineExceeded)), true, 500, "server_error"},
		{"client authentication rejection", fosite.ErrInvalidClient.WithDebug(secret), true, 401, "invalid_client"},
		{"protocol rejection", fosite.ErrInvalidGrant.WithDebug(secret), false, 400, "invalid_grant"},
		{"typed serialization conflict", fosite.ErrSerializationFailure.WithDebug(secret), false, 409, "error"},
		{"temporary failure", fosite.ErrTemporarilyUnavailable.WithDebug(secret), false, 503, "temporarily_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := fosite.NewAccessRequest(&fosite.DefaultSession{})
			request.GrantTypes = fosite.Arguments{"client_credentials"}
			request.Form = url.Values{"grant_type": {"client_credentials"}}
			request.SetRequestedScopes(fosite.Arguments{"goauthy.read"})
			request.Client = &fosite.DefaultClient{ID: "other-client", GrantTypes: []string{"client_credentials"}}
			provider := tokenErrorProvider{tokenLoggingTestProvider: tokenLoggingTestProvider{request: request}}
			if tc.requestStage {
				provider.requestError = tc.err
			} else {
				provider.err = tc.err
			}
			server := &Server{provider: provider, store: &Store{client: &fosite.DefaultClient{ID: "bootstrap-client"}, now: time.Now}}
			r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("grant_type=client_credentials"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			server.TokenHandler().ServeHTTP(w, r)
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal("token error response is not JSON")
			}
			if w.Code != tc.status || body["error"] != tc.code {
				t.Fatalf("unexpected token error classification: status=%d", w.Code)
			}
			if _, exists := body["access_token"]; exists || strings.Contains(w.Body.String(), secret) {
				t.Fatal("token error response exposes token or internal detail")
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("token error response permits caching")
			}
		})
	}
}

func TestTokenEndpointBootstrapScopeAvailabilityUsesServerError(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	var scopeReads atomic.Int32
	scopeStore := claims.NewStore(db)
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer,
		LoadSigningKey: func(context.Context) (oidc.SigningKey, error) {
			return oidcTestKey(t), nil
		},
		BootstrapClientScopes: func(ctx context.Context, clientID string) (claims.ClientScopes, error) {
			scopeReads.Add(1)
			return scopeStore.BootstrapClientScopes(ctx, clientID)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(ctx context.Context, clientID, clientSecret string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{
			"grant_type": {"client_credentials"}, "scope": {"goauthy.read"},
		}.Encode())).WithContext(ctx)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(clientID, clientSecret)
		w := httptest.NewRecorder()
		server.TokenHandler().ServeHTTP(w, r)
		return w
	}
	assertInvalidClient := func(response *httptest.ResponseRecorder) {
		t.Helper()
		if response.Code != http.StatusUnauthorized || tokenError(t, response) != "invalid_client" {
			t.Fatalf("invalid client status=%d body=%q", response.Code, response.Body.String())
		}
	}
	assertInvalidClient(request(context.Background(), testClientID, "wrong-bootstrap-secret"))
	assertInvalidClient(request(context.Background(), "unknown-bootstrap-client", testClientSecret))

	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	response := request(deadline, testClientID, testClientSecret)
	if scopeReads.Load() < 2 {
		t.Fatal("bootstrap scope lookup did not reach the real claims store")
	}
	if response.Code != http.StatusInternalServerError || tokenError(t, response) != "server_error" {
		t.Fatalf("availability status=%d body=%q", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), testClientSecret) || strings.Contains(response.Body.String(), "access_token") {
		t.Fatal("availability response exposed a credential or token")
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("availability response cache headers=%#v", response.Header())
	}
}
