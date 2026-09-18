package dcr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistrationHTTPConfidentialGrantAdmissionAndDPoPUpdate(t *testing.T) {
	h := testHandler(t, testGlobalToken)
	created := registerHTTPGrantClient(t, h, `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic","client_name":"Code Refresh","dpop_bound_access_tokens":false}`, "grant-code-refresh")
	if created.DPoPBoundAccessTokens || len(created.GrantTypes) != 2 {
		t.Fatalf("initial code-refresh metadata policy=%t grants=%v", created.DPoPBoundAccessTokens, created.GrantTypes)
	}

	updatedBody := `{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code","client_credentials"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic","client_name":"Code Credentials","dpop_bound_access_tokens":true}`
	updated := httptest.NewRecorder()
	h.ServeHTTP(updated, request(http.MethodPut, registrationPath+"/"+created.ClientID, updatedBody, created.RegistrationAccessToken))
	if updated.Code != http.StatusOK {
		t.Fatalf("mixed grant DPoP update status=%d", updated.Code)
	}
	var replacement registrationResponse
	if err := json.Unmarshal(updated.Body.Bytes(), &replacement); err != nil || replacement.ClientID != created.ClientID || !replacement.DPoPBoundAccessTokens || len(replacement.GrantTypes) != 2 || !contains(replacement.GrantTypes, "authorization_code") || !contains(replacement.GrantTypes, "client_credentials") || replacement.RegistrationAccessToken == "" || replacement.RegistrationAccessToken == created.RegistrationAccessToken {
		t.Fatalf("mixed grant DPoP update decoded=%t policy=%t grants=%v credentials_rotated=%t", err == nil, replacement.DPoPBoundAccessTokens, replacement.GrantTypes, replacement.RegistrationAccessToken != "" && replacement.RegistrationAccessToken != created.RegistrationAccessToken)
	}

	metadata := httptest.NewRecorder()
	h.ServeHTTP(metadata, request(http.MethodGet, registrationPath+"/"+created.ClientID, "", replacement.RegistrationAccessToken))
	var read registrationResponse
	if metadata.Code != http.StatusOK || json.Unmarshal(metadata.Body.Bytes(), &read) != nil || !read.DPoPBoundAccessTokens || len(read.GrantTypes) != 2 || !contains(read.GrantTypes, "client_credentials") || read.ClientSecret != "" || read.RegistrationAccessToken != "" {
		t.Fatalf("mixed grant DPoP metadata status=%d policy=%t grants=%v credentials_exposed=%t", metadata.Code, read.DPoPBoundAccessTokens, read.GrantTypes, read.ClientSecret != "" || read.RegistrationAccessToken != "")
	}
}

func TestRegistrationHTTPClientCredentialsGrantMetadata(t *testing.T) {
	h := testHandler(t, testGlobalToken)
	created := registerHTTPGrantClient(t, h, `{"redirect_uris":[],"grant_types":["client_credentials"],"response_types":[],"token_endpoint_auth_method":"client_secret_post","client_name":"Credentials Only","dpop_bound_access_tokens":true}`, "grant-client-credentials")
	if !created.DPoPBoundAccessTokens || len(created.RedirectURIs) != 0 || len(created.ResponseTypes) != 0 || len(created.GrantTypes) != 1 || created.GrantTypes[0] != "client_credentials" || created.TokenEndpointAuthMethod != "client_secret_post" {
		t.Fatalf("client-credentials metadata policy=%t redirects=%v responses=%v grants=%v method=%q", created.DPoPBoundAccessTokens, created.RedirectURIs, created.ResponseTypes, created.GrantTypes, created.TokenEndpointAuthMethod)
	}

	metadata := httptest.NewRecorder()
	h.ServeHTTP(metadata, request(http.MethodGet, registrationPath+"/"+created.ClientID, "", created.RegistrationAccessToken))
	var read registrationResponse
	if metadata.Code != http.StatusOK || json.Unmarshal(metadata.Body.Bytes(), &read) != nil || !read.DPoPBoundAccessTokens || len(read.RedirectURIs) != 0 || len(read.ResponseTypes) != 0 || len(read.GrantTypes) != 1 || read.GrantTypes[0] != "client_credentials" || read.ClientSecret != "" || read.RegistrationAccessToken != "" {
		t.Fatalf("client-credentials read status=%d policy=%t grants=%v credentials_exposed=%t", metadata.Code, read.DPoPBoundAccessTokens, read.GrantTypes, read.ClientSecret != "" || read.RegistrationAccessToken != "")
	}
}

func TestRegistrationHTTPPublicAuthorizationCodeRefreshGrantMetadata(t *testing.T) {
	h := testHandler(t, testGlobalToken)
	response := httptest.NewRecorder()
	body := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Public Code Refresh"}`
	h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, body, testGlobalToken, "public-code-refresh"))
	var registration registrationResponse
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &registration) != nil || registration.ClientID == "" || registration.ClientSecret != "" || registration.RegistrationAccessToken == "" || len(registration.RedirectURIs) != 1 || len(registration.ResponseTypes) != 1 || len(registration.GrantTypes) != 2 || !contains(registration.GrantTypes, "authorization_code") || !contains(registration.GrantTypes, "refresh_token") {
		t.Fatalf("public code-refresh metadata status=%d client_set=%t public=%t grants=%v", response.Code, registration.ClientID != "", registration.ClientSecret == "", registration.GrantTypes)
	}
}

func TestRegistrationHTTPRejectsInvalidClientCredentialsGrantCombinations(t *testing.T) {
	h := testHandler(t, testGlobalToken)
	for index, tc := range []struct {
		name, body string
	}{
		{name: "public client credentials", body: `{"redirect_uris":[],"grant_types":["client_credentials"],"response_types":[],"token_endpoint_auth_method":"none","client_name":"Public Credentials"}`},
		{name: "refresh only", body: `{"redirect_uris":[],"grant_types":["refresh_token"],"response_types":[],"token_endpoint_auth_method":"client_secret_basic","client_name":"Refresh Only"}`},
		{name: "unknown grant", body: `{"redirect_uris":[],"grant_types":["unknown_grant"],"response_types":[],"token_endpoint_auth_method":"client_secret_basic","client_name":"Unknown Grant"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, tc.body, testGlobalToken, "invalid-grant-"+string(rune('a'+index))))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d", response.Code)
			}
		})
	}
}

func TestStoreEnforcesClientCredentialsAndRefreshGrantRelationships(t *testing.T) {
	ctx, store, _ := testStore(t)
	for index, tc := range []struct {
		name string
		edit func(*CreateRequest)
		want bool
	}{
		{name: "code refresh", want: true, edit: func(request *CreateRequest) {}},
		{name: "confidential credentials", want: true, edit: func(request *CreateRequest) {
			request.RedirectURIs, request.ResponseTypes = nil, nil
			request.GrantTypes = []string{"client_credentials"}
		}},
		{name: "public credentials", edit: func(request *CreateRequest) {
			request.RedirectURIs, request.ResponseTypes = nil, nil
			request.GrantTypes = []string{"client_credentials"}
			request.TokenEndpointAuthMethod = TokenEndpointAuthNone
		}},
		{name: "refresh only", edit: func(request *CreateRequest) {
			request.RedirectURIs, request.ResponseTypes = nil, nil
			request.GrantTypes = []string{"refresh_token"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := validRequest("grant-store-"+string(rune('a'+index)), TokenEndpointAuthClientBasic)
			tc.edit(&request)
			_, err := store.Create(ctx, request)
			if (err == nil) != tc.want {
				t.Fatalf("accepted=%t want=%t", err == nil, tc.want)
			}
		})
	}
}

func registerHTTPGrantClient(t *testing.T, h http.Handler, body, key string) registrationResponse {
	t.Helper()
	response := httptest.NewRecorder()
	h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, body, testGlobalToken, key))
	if response.Code != http.StatusCreated {
		t.Fatalf("grant registration status=%d", response.Code)
	}
	var registration registrationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &registration); err != nil {
		t.Fatal(err)
	}
	if registration.ClientID == "" || registration.ClientSecret == "" || registration.RegistrationAccessToken == "" {
		t.Fatal("grant registration omitted confidential credentials")
	}
	return registration
}

func TestRegistrationHTTPPasswordGrantMetadata(t *testing.T) {
	for _, method := range []string{"none", "client_secret_basic", "client_secret_post"} {
		t.Run(method, func(t *testing.T) {
			h := testHandler(t, testGlobalToken)
			body := `{"redirect_uris":[],"grant_types":["password","refresh_token"],"response_types":[],"token_endpoint_auth_method":"` + method + `","client_name":"Password Client"}`
			response := httptest.NewRecorder()
			h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, body, testGlobalToken, "password-"+method))
			var got registrationResponse
			if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &got) != nil || !contains(got.GrantTypes, "password") || !contains(got.GrantTypes, "refresh_token") || got.TokenEndpointAuthMethod != method || (got.ClientSecret == "") != (method == "none") {
				t.Fatalf("password registration status=%d", response.Code)
			}
		})
	}
}
