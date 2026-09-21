package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/claims"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestClientCredentialsClaimSigningUsesFixedClock(t *testing.T) {
	t.Parallel()
	fixed := time.Date(2042, time.March, 4, 5, 6, 7, 0, time.UTC)
	for _, test := range []struct {
		name   string
		custom oidc.CustomClaims
		want   string
	}{
		{name: "nested", custom: oidc.CustomClaims{Values: map[string]json.RawMessage{"department": json.RawMessage(`"ops"`)}}, want: "custom"},
		{name: "root", custom: oidc.CustomClaims{Values: map[string]json.RawMessage{"tenant": json.RawMessage(`"acme"`)}, AtRoot: true}, want: "tenant"},
		{name: "clear", custom: oidc.CustomClaims{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _ := clientCredentialsClaimsServer(t, "", false)
			server.accessTokens.(*signedAccessTokenStrategy).now = func() time.Time { return fixed }
			session := &fosite.DefaultSession{}
			session.SetExpiresAt(fosite.AccessToken, fixed.Add(time.Hour))
			request := fosite.NewRequest()
			request.Client, request.ID, request.RequestedAt, request.Session = server.store.client, "fixed-client-claims", fixed, session
			request.Form = url.Values{"grant_type": {"client_credentials"}}
			request.SetRequestedScopes(fosite.Arguments{"goauthy.read"})
			request.GrantScope("goauthy.read")
			if err := setClientCredentialsAccessClaims(request, test.custom); err != nil {
				t.Fatal(err)
			}
			token, _, err := server.accessTokens.GenerateAccessToken(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			payload := jwtPayload(t, token)
			if payload["iat"] != float64(fixed.Unix()) || (test.want != "" && payload[test.want] == nil) || (test.want == "" && payload["custom"] != nil) {
				t.Fatalf("fixed-clock payload=%#v", payload)
			}
		})
	}
}

func TestBootstrapClientCredentialsClaimsSignedOnly(t *testing.T) {
	t.Parallel()
	server, _ := clientCredentialsClaimsServer(t, `{"department":"ops"}`, false)
	issued := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}))
	payload := jwtPayload(t, issued.AccessToken)
	if custom, ok := payload["custom"].(map[string]any); !ok || custom["department"] != "ops" {
		t.Fatalf("nested client claims=%#v", payload)
	}
	response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret)
	got := map[string]any{}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || response.Code != http.StatusOK || got["custom"] != nil || got["department"] != nil || got[clientCredentialsClaimsExtra] != nil {
		t.Fatalf("client claims leaked through introspection: status=%d claims=%#v err=%v", response.Code, got, err)
	}
	userInfo := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	userInfo.Header.Set("Authorization", "Bearer "+issued.AccessToken)
	userInfoResponse := httptest.NewRecorder()
	server.UserInfoHandler().ServeHTTP(userInfoResponse, userInfo)
	if userInfoResponse.Code != http.StatusUnauthorized {
		t.Fatalf("client credentials UserInfo status=%d", userInfoResponse.Code)
	}
}

func TestBootstrapClientCredentialsClaimsRootClearAndCollision(t *testing.T) {
	t.Parallel()
	t.Run("root", func(t *testing.T) {
		server, _ := clientCredentialsClaimsServer(t, `{"tenant":{"id":7}}`, true)
		issued := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}}))
		if got := jwtPayload(t, issued.AccessToken); got["tenant"].(map[string]any)["id"].(float64) != 7 || got["custom"] != nil {
			t.Fatalf("root client claims=%#v", got)
		}
	})
	t.Run("clear", func(t *testing.T) {
		server, _ := clientCredentialsClaimsServer(t, "", false)
		issued := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}}))
		if got := jwtPayload(t, issued.AccessToken); got["custom"] != nil {
			t.Fatalf("cleared client claims=%#v", got)
		}
	})
	t.Run("reserved root fails before artifacts", func(t *testing.T) {
		server, db := clientCredentialsClaimsServer(t, `{"sub":"collision"}`, true)
		if response := postToken(server, url.Values{"grant_type": {"client_credentials"}}); response.Code == http.StatusOK {
			t.Fatal("reserved root claim issued a token")
		}
		assertClientCredentialsTokenRows(t, db, 0)
	})
}

func TestClientCredentialsClaimsExcludeDynamicClients(t *testing.T) {
	t.Parallel()
	server, _ := clientCredentialsClaimsServer(t, `{"department":"ops"}`, false)
	called := 0
	server.oidc.ResolveClientCredentialsClaims = func(context.Context, string) (claims.ClientCredentialsClaims, error) {
		called++
		return claims.ClientCredentialsClaims{ClientID: testClientID, Values: map[string]json.RawMessage{"department": json.RawMessage(`"ops"`)}, Revision: 1}, nil
	}
	dynamic, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{ClientID: "dynamic-machine-claims", GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "dynamic"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(dynamic.ClientID, dynamic.ClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || called != 0 {
		t.Fatalf("dynamic status=%d resolver calls=%d body=%s", response.Code, called, response.Body.String())
	}
	issued := decodeToken(t, response)
	if got := jwtPayload(t, issued.AccessToken); got["custom"] != nil || got["department"] != nil {
		t.Fatalf("dynamic client claims=%#v", got)
	}
}

func TestClientCredentialsClaimRevisionRaceLeavesNoArtifact(t *testing.T) {
	t.Parallel()
	server, db := clientCredentialsClaimsServer(t, `{"department":"ops"}`, false)
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "client-claims-race", SQL: `UPDATE bootstrap_client_credentials_claims SET revision=revision+1 WHERE client_id=?`, Args: []any{testClientID}}); err != nil {
			t.Fatal(err)
		}
	}
	if response := postToken(server, url.Values{"grant_type": {"client_credentials"}}); response.Code == http.StatusOK {
		t.Fatalf("stale client claims issued token: %s", response.Body.String())
	}
	assertClientCredentialsTokenRows(t, db, 0)
}

func clientCredentialsClaimsServer(t *testing.T, policy string, atRoot bool) (*Server, *rhiza.DB) {
	t.Helper()
	db := oauthTestDB(t)
	if policy != "" {
		root := int64(0)
		if atRoot {
			root = 1
		}
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "client-credentials-claims-policy", SQL: `INSERT INTO bootstrap_client_credentials_claims(client_id,claims_json,claims_at_root,revision,updated_at_unix_ms) VALUES(?,?,?,?,0)`, Args: []any{testClientID, policy, root, int64(1)}}); err != nil {
			t.Fatal(err)
		}
	}
	store := claims.NewStore(db)
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		ResolveClientCredentialsClaims: store.BootstrapClientCredentialsClaims,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, db
}

func assertClientCredentialsTokenRows(t *testing.T, db *rhiza.DB, want int64) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != want {
		t.Fatalf("access rows=%#v err=%v want=%d", result.Rows, err, want)
	}
	result, err = db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_token_requests`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != want {
		t.Fatalf("request rows=%#v err=%v want=%d", result.Rows, err, want)
	}
}
