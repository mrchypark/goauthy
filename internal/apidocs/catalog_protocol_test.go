package apidocs

import (
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestProtocolCatalogFeatureGatesAndSecurity(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3"}
	if err := addProtocolOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	if doc.Paths.Value("/oidc/register") != nil {
		t.Fatal("DCR operation present when disabled")
	}
	if doc.Paths.Value("/auth/{subject}/profile") != nil {
		t.Fatal("WebID operation present when disabled")
	}
	if doc.Paths.Value("/oidc/token").Post.RequestBody.Value.Content["application/x-www-form-urlencoded"] == nil {
		t.Fatal("token form schema missing")
	}
	if doc.Components.Schemas["DeviceAuthorizationRequest"].Value.Properties["resource"] == nil {
		t.Fatal("device resource parameter missing")
	}
	if _, err := Document("https://id.example.test", Features{}); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolCatalogIncludesEnabledOptionalOperations(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3"}
	if err := addProtocolOperations(doc, Features{DCR: true, WebID: true, FedCM: true, FedCMLanding: "/fedcm/login"}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/oidc/register", "/oidc/register/{id}", "/.well-known/openid-configuration"} {
		if doc.Paths.Value(path) == nil {
			t.Fatalf("missing enabled path %q", path)
		}
	}
	grantTypes := doc.Components.Schemas["ClientRegistration"].Value.Properties["grant_types"].Value.Items.Value.Enum
	password := false
	for _, grantType := range grantTypes {
		if grantType == "password" {
			password = true
		}
	}
	if !password || !strings.Contains(doc.Components.Schemas["ClientRegistration"].Value.Description, "password") {
		t.Fatal("DCR password grant missing from metadata")
	}
	if _, err := Document("https://id.example.test", Features{DCR: true}); err != nil {
		t.Fatal(err)
	}
}

func TestDCRAudienceMetadataIsAuthenticatedOnly(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		doc := &openapi3.T{OpenAPI: "3.0.3"}
		if err := addProtocolOperations(doc, Features{DCR: true, DCRAnonymous: anonymous}); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ClientRegistration", "ClientRegistrationUpdate"} {
			flag := doc.Components.Schemas[name].Value.Properties["dpop_bound_access_tokens"]
			if flag == nil || !flag.Value.Type.Is("boolean") || flag.Value.Default != false || flag.Value.Nullable {
				t.Fatalf("%s DPoP metadata must be a non-nullable boolean defaulting false", name)
			}
			_, present := doc.Components.Schemas[name].Value.Properties["audience"]
			if present == anonymous {
				t.Fatalf("%s audience present=%t anonymous=%t", name, present, anonymous)
			}
		}
	}
}

func TestDCRBackchannelMetadataSchema(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3"}
	if err := addProtocolOperations(doc, Features{DCR: true}); err != nil {
		t.Fatal(err)
	}
	schemas := []*openapi3.Schema{
		doc.Components.Schemas["ClientRegistration"].Value,
		doc.Components.Schemas["ClientRegistrationUpdate"].Value,
		doc.Paths.Value("/oidc/register").Post.Responses.Status(201).Value.Content["application/json"].Schema.Value,
		doc.Paths.Value("/oidc/register/{id}").Get.Responses.Status(200).Value.Content["application/json"].Schema.Value,
		doc.Paths.Value("/oidc/register/{id}").Put.Responses.Status(200).Value.Content["application/json"].Schema.Value,
	}
	for _, schema := range schemas {
		uri := schema.Properties["backchannel_logout_uri"]
		if uri == nil {
			t.Fatal("DCR schema lacks backchannel URI")
		}
		if !uri.Value.Nullable {
			t.Fatal("DCR backchannel URI must accept null")
		}
		for _, value := range []any{nil, "http://localhost:8080/logout", "https://rp.example.test/logout?tenant=a"} {
			if err := uri.Value.VisitJSON(value); err != nil {
				t.Fatalf("DCR schema rejects supported metadata: %v", err)
			}
		}
		for _, value := range []any{"", "https://rp.example.test/bad path", false} {
			if err := uri.Value.VisitJSON(value); err == nil {
				t.Fatal("DCR schema accepts invalid metadata")
			}
		}
	}
}
