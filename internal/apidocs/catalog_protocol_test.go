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

func TestProfileRoutesPresence(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3"}
	if err := addProtocolOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	get := doc.Paths.Value("/auth/profile").Get
	post := doc.Paths.Value("/auth/profile").Post
	if get == nil || post == nil {
		t.Fatal("GET or POST /auth/profile missing")
	}
	if get.OperationID != "profileGet" {
		t.Fatalf("unexpected GET operation ID %q", get.OperationID)
	}
	if post.OperationID != "profilePost" {
		t.Fatalf("unexpected POST operation ID %q", post.OperationID)
	}
}

func TestProfileGETSecurityAndParameters(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3"}
	if err := addProtocolOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	get := doc.Paths.Value("/auth/profile").Get
	if get.Security == nil || len(*get.Security) != 1 || (*get.Security)[0]["browserSession"] == nil {
		t.Fatal("GET /auth/profile must require browserSession")
	}
	found := false
	for _, p := range get.Parameters {
		if p.Value.Name == "interaction" && p.Value.In == "query" && p.Value.Required {
			found = true
		}
	}
	if !found {
		t.Fatal("GET /auth/profile missing required query parameter interaction")
	}
	if get.Responses.Status(200) == nil {
		t.Fatal("GET /auth/profile missing 200 response")
	}
	if get.Responses.Status(403) == nil {
		t.Fatal("GET /auth/profile missing 403 response")
	}
	if get.Responses.Status(503) == nil {
		t.Fatal("GET /auth/profile missing 503 response")
	}
	if get.Responses.Status(400) == nil {
		t.Fatal("GET /auth/profile missing 400 response")
	}
	ct := get.Responses.Status(200).Value.Content
	if ct["text/html"] == nil {
		t.Fatal("GET /auth/profile 200 must be text/html")
	}
}

func TestProfilePOSTSecurityAndFormFields(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3"}
	if err := addProtocolOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	post := doc.Paths.Value("/auth/profile").Post
	if post.Security == nil || len(*post.Security) != 1 || (*post.Security)[0]["browserSession"] == nil {
		t.Fatal("POST /auth/profile must require browserSession")
	}
	foundInteraction := false
	for _, p := range post.Parameters {
		if p.Value.Name == "interaction" && p.Value.In == "query" && p.Value.Required {
			foundInteraction = true
		}
	}
	if !foundInteraction {
		t.Fatal("POST /auth/profile missing required query parameter interaction")
	}
	if post.RequestBody == nil {
		t.Fatal("POST /auth/profile missing request body")
	}
	ct := post.RequestBody.Value.Content["application/x-www-form-urlencoded"]
	if ct == nil {
		t.Fatal("POST /auth/profile must accept form-urlencoded")
	}
	schema := doc.Components.Schemas["ProfileRequest"].Value
	if schema == nil {
		t.Fatal("ProfileRequest schema missing from components")
	}
	requiredSet := map[string]bool{}
	for _, r := range schema.Required {
		requiredSet[r] = true
	}
	if !requiredSet["interaction"] || !requiredSet["csrf_token"] {
		t.Fatal("POST /auth/profile form must require interaction and csrf_token")
	}
	optionalFields := []string{"given_name", "family_name", "preferred_username", "birthdate", "phone", "street", "zip", "city", "country", "tz"}
	for _, field := range optionalFields {
		if schema.Properties[field] == nil {
			t.Fatalf("POST /auth/profile form missing optional field %q", field)
		}
		if requiredSet[field] {
			t.Fatalf("POST /auth/profile optional field %q must not be required", field)
		}
	}
	protected := []string{"email", "roles"}
	for _, field := range protected {
		if schema.Properties[field] != nil {
			t.Fatalf("POST /auth/profile must not expose protected field %q", field)
		}
	}
	for _, status := range []int{200, 303, 400, 403, 409, 503} {
		if post.Responses.Status(status) == nil {
			t.Fatalf("POST /auth/profile missing %d response", status)
		}
	}
}

func TestProfilePOSTForbiddenFieldsRejected(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3"}
	if err := addProtocolOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	schema := doc.Components.Schemas["ProfileRequest"].Value
	if schema.AdditionalProperties.Has != nil && *schema.AdditionalProperties.Has {
		t.Fatal("ProfileRequest must reject additional properties")
	}
}

func TestProfileDescriptionMentionsRevalidateFlag(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3"}
	if err := addProtocolOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	getDesc := doc.Paths.Value("/auth/profile").Get.Description
	postDesc := doc.Paths.Value("/auth/profile").Post.Description
	if !strings.Contains(getDesc, "GOAUTHY_USER_VALUES_REVALIDATE_DURING_LOGIN") {
		t.Fatal("GET /auth/profile description must mention the feature flag")
	}
	if !strings.Contains(postDesc, "GOAUTHY_USER_VALUES_REVALIDATE_DURING_LOGIN") {
		t.Fatal("POST /auth/profile description must mention the feature flag")
	}
	if !strings.Contains(postDesc, "409") {
		t.Fatal("POST /auth/profile description must mention 409 CAS conflict")
	}
}

func TestProtocolNoFallbackBrowserSessionScheme(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3"}
	if err := addProtocolOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	scheme := doc.Components.SecuritySchemes["browserSession"]
	if scheme != nil && scheme.Value.Name == "session" {
		t.Fatal("browserSession must not invent fallback cookie name 'session'; reuse the global definition")
	}
}
