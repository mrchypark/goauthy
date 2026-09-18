package apidocs

import (
	"net/http"
	"slices"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestSaaSProvidersCatalog(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Paths: openapi3.NewPaths(), Components: &components}
	if err := addSaaSProviderOperations(doc); err != nil {
		t.Fatal(err)
	}
	op := doc.Paths.Value("/auth/v1/saas/providers").Get
	if op == nil || op.Security == nil || len(*op.Security) != 2 || (*op.Security)[0]["browserSession"] == nil || (*op.Security)[1]["bearerToken"] == nil {
		t.Fatalf("security=%v", op.Security)
	}
	if (*op.Security)[0]["apiKey"] != nil || (*op.Security)[1]["apiKey"] != nil || op.Description == "" {
		t.Fatalf("unexpected machine security=%v", *op.Security)
	}
	for _, status := range []int{http.StatusUnauthorized, http.StatusMethodNotAllowed, http.StatusServiceUnavailable} {
		if op.Responses.Status(status) == nil {
			t.Fatalf("missing response %d", status)
		}
	}
	body := op.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	if err := body.VisitJSON([]any{map[string]any{
		"id":           "github",
		"kind":         "github",
		"callback_uri": "https://id.example.test/auth/v1/saas/callback/github",
		"scopes":       []any{"read:user", "user:email"},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"client_secret", "credential"} {
		value := map[string]any{
			"id":           "github",
			"kind":         "github",
			"callback_uri": "https://id.example.test/auth/v1/saas/callback/github",
			"scopes":       []any{"read:user"},
		}
		value[field] = "secret"
		if err := body.VisitJSON([]any{value}); err == nil {
			t.Fatalf("secret field %q accepted", field)
		}
	}
	managed := map[string]any{"id": "custom", "name": "Custom", "kind": "oauth2", "enabled": true, "revision": 1, "callback_uri": "https://id.example.test/callback", "client_id": "client", "auth_endpoint": "https://id.example.test/authorize", "token_endpoint": "https://id.example.test/token", "scopes": []any{"read"}, "auth_style": "header"}
	managed["identity_endpoint"] = "https://provider.example/user"
	managed["subject_field"] = "account_id"
	if err := body.VisitJSON([]any{managed}); err != nil {
		t.Fatal(err)
	}
	post := doc.Paths.Value("/auth/v1/saas/providers").Post
	if post == nil || post.Security == nil || (*post.Security)[0]["csrfToken"] == nil || post.RequestBody == nil {
		t.Fatal("provider POST must require browser CSRF and a body")
	}
	if len(*post.Security) != 2 || (*post.Security)[1]["bearerToken"] == nil || post.Description == "" {
		t.Fatal("provider POST must document bearer alternative")
	}
	if !post.RequestBody.Value.Content["application/json"].Schema.Value.Properties["client_secret"].Value.WriteOnly {
		t.Fatal("client_secret must be write-only")
	}
	if post.RequestBody.Value.Content["application/json"].Schema.Value.Properties["id"].Value.WriteOnly || !slices.Contains(post.RequestBody.Value.Content["application/json"].Schema.Value.Required, "id") {
		t.Fatal("provider POST id must be readable and required")
	}
	put := doc.Paths.Value("/auth/v1/saas/providers/{provider_id}").Put
	for _, schema := range []*openapi3.Schema{body.Items.Value, post.RequestBody.Value.Content["application/json"].Schema.Value, put.RequestBody.Value.Content["application/json"].Schema.Value} {
		if schema.Properties["identity_endpoint"] == nil || schema.Properties["subject_field"] == nil || schema.Properties["identity_endpoint"].Value.WriteOnly {
			t.Fatal("identity configuration must be exposed in input and metadata")
		}
		if err := schema.Properties["subject_field"].Value.VisitJSON("nested.subject"); err == nil {
			t.Fatal("subject field must be a simple top-level name")
		}
	}
	del := doc.Paths.Value("/auth/v1/saas/providers/{provider_id}").Delete
	if put == nil || del == nil || put.Parameters.GetByInAndName("header", "If-Match") == nil || del.Parameters.GetByInAndName("header", "If-Match") == nil || put.Responses.Status(428) == nil || del.Responses.Status(428) == nil {
		t.Fatal("provider PUT/DELETE must require If-Match and document 428")
	}
}
