package apidocs

import (
	"context"
	"github.com/getkin/kin-openapi/openapi3"
	"strings"
	"testing"
)

func TestConnectionAPIKeyCatalogContract(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3", Info: &openapi3.Info{Title: "test", Version: "test"}, Paths: openapi3.NewPaths(), Components: &openapi3.Components{Schemas: openapi3.Schemas{}}}
	if err := addConnectionAPIKeyOperations(doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Paths.Value("/auth/v1/account/connections/{collection_id}/{connection_id}/api-key")
	if p == nil || p.Get == nil || p.Put == nil || p.Delete == nil {
		t.Fatal("missing operations")
	}
	connectorPath := doc.Paths.Value("/auth/v1/account/connections/{collection_id}/{connection_id}/api-key/connector")
	if connectorPath == nil || connectorPath.Get == nil || connectorPath.Get.Security == nil || (*connectorPath.Get.Security)[0]["browserSession"] == nil {
		t.Fatal("missing owner connector GET")
	}
	if connectorPath.Get.RequestBody != nil || connectorPath.Get.Parameters.GetByInAndName("query", "anything") != nil || connectorPath.Get.Parameters.GetByInAndName("header", "If-Match") != nil {
		t.Fatal("connector GET must not accept body, query, or If-Match")
	}
	if (*p.Put.Security)[0]["csrfToken"] == nil || (*p.Put.Security)[0]["bearerToken"] != nil {
		t.Fatal("invalid security")
	}
	putBody := p.Put.RequestBody.Value.Content.Get("application/json").Schema.Value
	if p.Put.RequestBody.Value.Required != true || putBody.Properties["api_key"].Value.WriteOnly != true {
		t.Fatal("write-only API key missing")
	}
	requiredDigest := false
	for _, name := range putBody.Required {
		requiredDigest = requiredDigest || name == "connector_digest"
	}
	if _, ok := putBody.Properties["connector_digest"]; !ok || requiredDigest {
		t.Fatal("connector_digest must be optional")
	}
	if err := putBody.VisitJSON(map[string]any{"api_key": "secret", "version": float64(0)}); err != nil {
		t.Fatal("legacy PUT rejected: ", err)
	}
	if putBody.Properties["connector_digest"].Value.WriteOnly || p.Get.Parameters[0].Value.Schema.Value.WriteOnly {
		t.Fatal("write-only API-key flag leaked into public metadata schema")
	}
	if err := putBody.VisitJSON(map[string]any{"api_key": "secret", "version": float64(0), "connector_digest": strings.Repeat("A", 43)}); err != nil {
		t.Fatal("bound PUT rejected: ", err)
	}
	if err := putBody.VisitJSON(map[string]any{"api_key": "secret", "version": float64(0), "connector_digest": nil}); err == nil {
		t.Fatal("connector_digest must reject null")
	}
	connector := connectorPath.Get.Responses.Status(200).Value.Content.Get("application/json").Schema.Value
	if err := connector.VisitJSON(map[string]any{
		"id": "billing", "digest": "digest", "header": "Authorization", "prefix": "Bearer ",
		"operations": []any{map[string]any{"id": "account", "method": "GET", "url": "https://api.example/account", "response_fields": map[string]any{"id": "string"}}},
	}); err != nil {
		t.Fatal("connector response rejected: ", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
}
