package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/claims"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/rhiza"
)

func TestUserInfoResolverBackendErrorsFailUnavailable(t *testing.T) {
	for name, backendErr := range r9UnverifiableBackendErrors() {
		t.Run(name, func(t *testing.T) {
			server := userInfoTestServer(t, oauthTestDB(t), nil)
			token := issueUserInfoToken(t, server)
			server.oidc.ResolvePrincipal = func(context.Context, string) (PrincipalClaims, error) {
				return PrincipalClaims{}, backendErr
			}
			response := userInfoResponse(server, token)
			if response.Code != http.StatusServiceUnavailable || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
			}
		})
	}
}

func TestForwardAuthResolverBackendErrorsFailUnavailable(t *testing.T) {
	for name, backendErr := range r9UnverifiableBackendErrors() {
		t.Run(name, func(t *testing.T) {
			server := userInfoTestServer(t, oauthTestDB(t), nil)
			token := issueUserInfoToken(t, server)
			server.oidc.ForwardAuthEnabled = true
			server.oidc.ResolvePrincipal = func(context.Context, string) (PrincipalClaims, error) {
				return PrincipalClaims{}, backendErr
			}
			server.oidc.ResolveForwardAuthProfile = func(context.Context, string) (ForwardAuthProfile, error) {
				return ForwardAuthProfile{}, nil
			}
			server.oidc.ResolveForwardAuthPasskeyEnrollment = func(context.Context, string) (bool, error) {
				return false, nil
			}
			response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, token, nil))
			if response.Code != http.StatusServiceUnavailable || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get(ForwardAuthUserHeader) != "" {
				t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
			}
		})
	}
}

func TestIntrospectionResolverBackendErrorsFailUnavailable(t *testing.T) {
	for name, backendErr := range r9UnverifiableBackendErrors() {
		t.Run(name, func(t *testing.T) {
			server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) {
				return PrincipalClaims{Roles: []string{"reader"}, Revision: 1}, nil
			})
			token := issueRBACAccessToken(t, server, strings.Repeat("r", 43), "openid goauthy.read offline_access")
			server.oidc.ResolvePrincipal = func(context.Context, string) (PrincipalClaims, error) {
				return PrincipalClaims{}, backendErr
			}
			response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token}}, testClientID, testClientSecret)
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), `"active":false`) {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

func TestResourceEndpointsTreatClosedTokenStoreAsUnavailable(t *testing.T) {
	for name, endpoint := range map[string]string{
		"userinfo":      "userinfo",
		"forward_auth":  "forward_auth",
		"introspection": "introspection",
	} {
		t.Run(name, func(t *testing.T) {
			db := oauthTestDB(t)
			server := userInfoTestServer(t, db, nil)
			token := issueUserInfoToken(t, server)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			var status int
			switch endpoint {
			case "userinfo":
				status = userInfoResponse(server, token).Code
			case "forward_auth":
				status = forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, token, nil)).Code
			case "introspection":
				status = postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token}}, testClientID, testClientSecret).Code
			}
			if status != http.StatusServiceUnavailable {
				t.Fatalf("status=%d, want service unavailable for closed token store", status)
			}
		})
	}
}

func TestIntrospectionClientLookupStorageErrorReturnsServiceUnavailable(t *testing.T) {
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	token := issueUserInfoToken(t, server)
	server.store.bootstrapClientScopes = func(context.Context, string) (claims.ClientScopes, error) {
		return claims.ClientScopes{}, fmt.Errorf("%w: %v", rhiza.ErrInvalidRequest, errors.New("scope policy SQL read failed"))
	}
	response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token}}, testClientID, testClientSecret)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), `"active":false`) {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestKnownInactiveSubjectRemainsInvalidAcrossResourceEndpoints(t *testing.T) {
	t.Run("userinfo", func(t *testing.T) {
		server := userInfoTestServer(t, oauthTestDB(t), nil)
		token := issueUserInfoToken(t, server)
		server.oidc.ValidateSubject = func(context.Context, string) error { return identity.ErrInactiveSubject }
		response := userInfoResponse(server, token)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
		}
	})

	t.Run("forward_auth", func(t *testing.T) {
		server := userInfoTestServer(t, oauthTestDB(t), nil)
		token := issueUserInfoToken(t, server)
		server.oidc.ValidateSubject = func(context.Context, string) error { return identity.ErrInactiveSubject }
		response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, token, nil))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
		}
	})

	t.Run("introspection", func(t *testing.T) {
		server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) {
			return PrincipalClaims{Roles: []string{"reader"}, Revision: 1}, nil
		})
		token := issueRBACAccessToken(t, server, strings.Repeat("s", 43), "openid goauthy.read offline_access")
		server.oidc.ResolvePrincipal = func(context.Context, string) (PrincipalClaims, error) {
			return PrincipalClaims{}, identity.ErrInactiveSubject
		}
		response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token}}, testClientID, testClientSecret)
		assertInactive(t, response)
	})
}

func TestRevokedTokenControlsRemainInvalid(t *testing.T) {
	t.Run("userinfo", func(t *testing.T) {
		server := userInfoTestServer(t, oauthTestDB(t), nil)
		token := issueUserInfoToken(t, server)
		if err := server.store.DeleteAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), token)); err != nil {
			t.Fatal(err)
		}
		response := userInfoResponse(server, token)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
		}
	})

	t.Run("forward_auth", func(t *testing.T) {
		server := userInfoTestServer(t, oauthTestDB(t), nil)
		token := issueUserInfoToken(t, server)
		if err := server.store.DeleteAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), token)); err != nil {
			t.Fatal(err)
		}
		response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, token, nil))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
		}
	})

	t.Run("introspection", func(t *testing.T) {
		server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) {
			return PrincipalClaims{Roles: []string{"reader"}, Revision: 1}, nil
		})
		token := issueRBACAccessToken(t, server, strings.Repeat("t", 43), "openid goauthy.read offline_access")
		if err := server.store.DeleteAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), token)); err != nil {
			t.Fatal(err)
		}
		response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token}}, testClientID, testClientSecret)
		assertInactive(t, response)
	})
}

func r9UnverifiableBackendErrors() map[string]error {
	return map[string]error{
		"generic_storage_error":         errors.New("profile storage read failed"),
		"wrapped_rhiza_invalid_request": fmt.Errorf("%w: %v", rhiza.ErrInvalidRequest, errors.New("profile SQL read failed")),
	}
}

func userInfoResponse(server *Server, token string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	server.UserInfoHandler().ServeHTTP(response, userInfoRequest(http.MethodGet, token, nil))
	return response
}
