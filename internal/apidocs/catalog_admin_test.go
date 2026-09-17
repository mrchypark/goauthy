package apidocs

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestAddAdminOperationsCatalog(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Paths: openapi3.NewPaths(), Components: &components}
	if err := addAdminOperations(doc, Features{Blacklist: true}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/auth/v1/admin", "/auth/v1/roles", "/auth/v1/users/{subject}", "/auth/v1/api_keys", "/auth/v1/blacklist/{ip}"} {
		if doc.Paths.Value(p) == nil {
			t.Errorf("missing path %s", p)
		}
	}
	if got := doc.Paths.Value("/auth/v1/users/{subject}").GetOperation("PATCH"); got == nil || got.Parameters.GetByInAndName("path", "subject") == nil {
		t.Error("PATCH user membership lacks required subject parameter")
	}
	if _, err := Document("https://id.example.test", Features{Blacklist: true}); err != nil {
		t.Fatal(err)
	}
}

func TestAddAdminOperationsBlacklistFeatureGate(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Paths: openapi3.NewPaths(), Components: &components}
	if err := addAdminOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	if doc.Paths.Value("/auth/v1/blacklist") != nil {
		t.Fatal("blacklist routes must be omitted when feature is disabled")
	}
}

func TestAdminClientRequestAndResponseContractsDiffer(t *testing.T) {
	data, err := Document("https://id.example.test", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		route    string
		response map[string]any
	}{
		{"scopes", map[string]any{"client_id": "client", "allowed_scopes": []any{"openid"}, "default_scopes": []any{"openid"}}},
		{"login-restriction", map[string]any{"client_id": "client", "restrict_group_prefix": nil, "revision": float64(0)}},
	} {
		op := doc.Paths.Value("/auth/v1/clients/{id}/" + fixture.route).Put
		if err := op.Responses.Status(200).Value.Content["application/json"].Schema.Value.VisitJSON(fixture.response); err != nil {
			t.Fatal(err)
		}
		body := op.RequestBody.Value.Content["application/json"].Schema.Value
		if err := body.VisitJSON(fixture.response); err == nil {
			t.Fatal("client_id must not be accepted in update body")
		}
		delete(fixture.response, "client_id")
		if err := body.VisitJSON(fixture.response); err != nil {
			t.Fatal(err)
		}
	}
	claims := doc.Paths.Value("/auth/v1/clients/{id}/claims").Put.RequestBody.Value.Content["application/json"].Schema.Value
	if err := claims.VisitJSON(map[string]any{"claims": nil, "claims_at_root": false, "revision": float64(0)}); err != nil {
		t.Fatal(err)
	}
}


func TestAdminPasskeyRoutesBrowserOnly(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Paths: openapi3.NewPaths(), Components: &components}
	if err := addAdminOperations(doc, Features{Recovery: true}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/auth/v1/users/{subject}/webauthn/admin_register", "/auth/v1/users/{subject}/convert_password"} {
		op := doc.Paths.Value(route).Post
		if op == nil {
			t.Fatalf("missing %s", route)
		}
		sec := *op.Security
		if len(sec) != 1 {
			t.Fatalf("%s must have exactly one security alternative (browser+CSRF only, no API key)", route)
		}
		if _, has := sec[0]["browserSession"]; !has {
			t.Fatalf("%s must require browserSession", route)
		}
		if _, has := sec[0]["csrfToken"]; !has {
			t.Fatalf("%s must require csrfToken", route)
		}
	}
}

func TestConvertPasswordResponseSchema(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Paths: openapi3.NewPaths(), Components: &components}
	if err := addAdminOperations(doc, Features{Recovery: true}); err != nil {
		t.Fatal(err)
	}
	op := doc.Paths.Value("/auth/v1/users/{subject}/convert_password").Post
	if op.Responses.Status(409) == nil {
		t.Fatal("convert_password missing 409 conflict response")
	}
	if op.Responses.Status(204) == nil {
		t.Fatal("convert_password missing 204 success response")
	}
	body := op.RequestBody.Value.Content["application/json"].Schema.Value
	if body.Properties["password_new"] == nil {
		t.Fatal("convert_password missing password_new in request body")
	}
}
