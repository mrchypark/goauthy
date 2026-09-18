package apidocs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mrchypark/goauthy/internal/fedcm"
)

func TestAddFedCMOperationsContract(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addFedCMOperations(doc, Features{FedCM: true, FedCMLanding: "/fedcm/login"}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []struct{ path, method string }{{"/.well-known/web-identity", "GET"}, {"/auth/v1/fed_cm/config", "GET"}, {"/auth/v1/fed_cm/accounts", "GET"}, {"/auth/v1/fed_cm/client_meta", "GET"}, {"/auth/v1/fed_cm/token", "POST"}, {"/auth/v1/fed_cm/status", "GET"}, {"/fedcm/login", "GET"}, {"/fedcm/login", "POST"}} {
		if op := doc.Paths.Find(route.path).GetOperation(route.method); op == nil || op.Responses.Status(200) == nil {
			t.Fatalf("missing %s %s", route.method, route.path)
		}
	}
	token := doc.Paths.Find("/auth/v1/fed_cm/token").Post
	if token.RequestBody == nil || token.RequestBody.Value.Content.Get("application/x-www-form-urlencoded") == nil {
		t.Fatal("token must accept a form body")
	}
	if token.RequestBody.Value.Content.Get("application/x-www-form-urlencoded").Schema.Value.Properties["account_id"] == nil {
		t.Fatal("token schema missing account_id")
	}
	landing := doc.Paths.Find("/fedcm/login").Post
	if landing.RequestBody.Value.Content.Get("application/x-www-form-urlencoded").Schema.Value.Properties["csrf_token"] == nil {
		t.Fatal("landing schema missing csrf_token")
	}
}

func TestAddFedCMOperationsDisabledAndAuthLoginOwnership(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addFedCMOperations(doc, Features{FedCMLanding: "/auth/login"}); err != nil {
		t.Fatal(err)
	}
	if doc.Paths.Find("/auth/v1/fed_cm/config") != nil || doc.Paths.Find("/auth/login") != nil {
		t.Fatal("disabled FedCM catalog leaked routes")
	}
	data, err := Document("https://id.example.test", Features{FedCM: true, FedCMLanding: "/auth/login"})
	if err != nil {
		t.Fatal(err)
	}
	doc, err = openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	p := doc.Paths.Value("/auth/login")
	if p == nil || p.Get == nil || p.Post == nil {
		t.Fatal("/auth/login must retain OAuth POST and add FedCM GET")
	}
	schema := p.Post.RequestBody.Value.Content["application/x-www-form-urlencoded"].Schema.Value
	for _, body := range []any{
		map[string]any{"interaction": "one-use", "username": "alice", "password": "password"},
		map[string]any{"fedcm": "1", "interaction": "one-use", "username": "alice", "password": "password", "csrf_token": "session-token"},
	} {
		if err := schema.VisitJSON(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := schema.VisitJSON(map[string]any{"fedcm": "1", "interaction": "one-use", "username": "alice", "password": "password"}); err == nil {
		t.Fatal("marked FedCM form without CSRF must not match the legacy form")
	}
}

func TestFedCMContractAcceptsRealHandlerResponses(t *testing.T) {
	const issuer = "https://id.example.test"
	data, err := Document(issuer, Features{FedCM: true, FedCMLanding: "/auth/v1/account"})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	h, err := fedcm.NewHandler(fedcm.Config{Issuer: issuer, Enabled: true, ClientID: "client", ClientOrigin: "https://rp.example.test",
		PrivacyPolicyURL: "https://rp.example.test/privacy", TermsOfServiceURL: "https://rp.example.test/terms",
		ResolveCurrent: func(context.Context, *http.Request) (fedcm.Account, error) {
			return fedcm.Account{ID: "alice", Name: "Alice", Email: "alice@example.test", ApprovedClients: []string{"client"}, LoginHints: []string{"alice"}, DomainHints: []string{"example.test"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fedcm.ManifestPath, fedcm.ConfigPath, fedcm.AccountsPath, fedcm.ClientMetadataPath, fedcm.StatusPath} {
		t.Run(path, func(t *testing.T) {
			u := issuer + path
			if path == fedcm.ClientMetadataPath {
				u += "?client_id=client"
			}
			r := httptest.NewRequest("GET", u, nil)
			r.Header.Set("Sec-Fetch-Dest", "webidentity")
			if path == fedcm.ClientMetadataPath {
				r.Header.Set("Origin", "https://rp.example.test")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			response := doc.Paths.Value(path).Get.Responses.Status(200).Value
			if path == fedcm.StatusPath {
				if w.Body.Len() != 0 || len(response.Content) != 0 || w.Header().Get("Set-Login") != "logged-in" {
					t.Fatal("status must be empty with Set-Login header")
				}
				return
			}
			var body any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if err := response.Content["application/json"].Schema.Value.VisitJSON(body); err != nil {
				t.Fatal(err)
			}
		})
	}
	form := doc.Paths.Value(fedcm.AssertionPath).Post.RequestBody.Value.Content["application/x-www-form-urlencoded"].Schema.Value
	if err := form.VisitJSON(map[string]any{"account_id": "alice", "client_id": "client", "disclosure_text_shown": "true"}); err != nil {
		t.Fatal(err)
	}
	if err := form.VisitJSON(map[string]any{"account_id": "alice", "client_id": "client"}); err == nil {
		t.Fatal("missing disclosure accepted")
	}
	if got := doc.Components.SecuritySchemes["fedcmSession"].Value.Name; got != "__Host-goauthy_fedcm_session" {
		t.Fatalf("wrong FedCM cookie %q", got)
	}
	if doc.Paths.Value(fedcm.AssertionPath).Post.Security == nil || (*doc.Paths.Value(fedcm.AssertionPath).Post.Security)[0]["fedcmSession"] == nil {
		t.Fatal("assertion must require the dedicated FedCM session")
	}
}
