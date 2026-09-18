package apidocs

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestEventsStreamContract(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Paths: openapi3.NewPaths(), Components: &components}
	if err := addAdminOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	path := doc.Paths.Value("/auth/v1/events/stream")
	if path == nil || path.Get == nil {
		t.Fatal("missing lifecycle event SSE endpoint")
	}
	op := path.Get
	if op.RequestBody != nil {
		t.Fatal("SSE endpoint must not have a request body")
	}
	if op.Security == nil || len(*op.Security) != 2 || (*op.Security)[0]["browserSession"] == nil || (*op.Security)[1]["apiKey"] == nil {
		t.Fatalf("unexpected Events:read security: %#v", op.Security)
	}
	latest := op.Parameters.GetByInAndName("query", "latest")
	if latest == nil || latest.Schema == nil || latest.Schema.Value.Min == nil || *latest.Schema.Value.Min != 0 || latest.Schema.Value.Max == nil || *latest.Schema.Value.Max != 1000 || latest.Schema.Value.Default != 0 {
		t.Fatalf("latest query contract mismatch: %#v", latest)
	}
	level := op.Parameters.GetByInAndName("query", "level")
	if level == nil || level.Schema == nil || level.Schema.Value.Default != "info" {
		t.Fatalf("level query contract mismatch: %#v", level)
	}
	if err := level.Schema.Value.VisitJSON("warning"); err != nil {
		t.Fatalf("valid level rejected: %v", err)
	}
	if err := level.Schema.Value.VisitJSON("debug"); err == nil {
		t.Fatal("invalid level accepted")
	}
	response := op.Responses.Status(200).Value.Content
	if len(response) != 1 || response["text/event-stream"] == nil {
		t.Fatalf("SSE response content mismatch: %#v", response)
	}
	if !response["text/event-stream"].Schema.Value.Type.Is("string") {
		t.Fatal("SSE response must be represented as a string stream")
	}
	if op.Responses.Status(200).Value.Content["application/json"] != nil {
		t.Fatal("SSE endpoint must not advertise JSON response content")
	}
	if path.Get.Description == "" {
		t.Fatal("SSE replay/authorization behavior must be documented")
	}
	eventsPath := doc.Paths.Value("/auth/v1/events")
	if eventsPath == nil || eventsPath.Get == nil || eventsPath.Post == nil {
		t.Fatal("stream addition must preserve event GET and POST operations")
	}
}
