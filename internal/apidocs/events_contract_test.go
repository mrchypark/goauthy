package apidocs

import (
	"math"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestEventsQueryContract(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Paths: openapi3.NewPaths(), Components: &components}
	if err := addAdminOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	path := doc.Paths.Value("/auth/v1/events")
	if path == nil || path.Post == nil {
		t.Fatal("missing lifecycle event POST")
	}
	post := path.Post
	if post.Security == nil || len(*post.Security) != 2 || (*post.Security)[0]["browserSession"] == nil || (*post.Security)[1]["apiKey"] == nil {
		t.Fatalf("unexpected Events:read security: %#v", post.Security)
	}
	body := post.RequestBody.Value.Content["application/json"].Schema.Value
	valid := map[string]any{"from": float64(1719784800), "level": "info"}
	if err := body.VisitJSON(valid); err != nil {
		t.Fatalf("minimum valid query rejected: %v", err)
	}
	if err := body.VisitJSON(map[string]any{"from": float64(math.MaxInt64 / 1000), "until": nil, "level": "critical", "typ": "TokenIssued"}); err != nil {
		t.Fatalf("full valid query rejected: %v", err)
	}
	for _, invalid := range []map[string]any{
		{"level": "info"},
		{"from": float64(1719784799), "level": "info"},
		{"from": float64(1719784800), "level": "INFO"},
		{"from": float64(1719784800), "level": "info", "typ": "not-an-event"},
		{"from": float64(1719784800), "level": "info", "typ": "1234567890123456789012345"},
	} {
		if err := body.VisitJSON(invalid); err == nil {
			t.Errorf("invalid query accepted: %#v", invalid)
		}
	}
	response := post.Responses.Status(200).Value.Content["application/json"].Schema.Value
	if err := response.VisitJSON([]any{map[string]any{
		"id": "event-id", "timestamp": float64(1719784800000), "level": "notice", "typ": "NewUserRegistered",
		"ip": nil, "data": nil, "text": nil,
	}}); err != nil {
		t.Fatalf("valid event response rejected: %v", err)
	}
	if err := response.VisitJSON([]any{map[string]any{"id": "event-id", "timestamp": float64(1719784800000), "level": "notice", "typ": "NewUserRegistered"}}); err == nil {
		t.Fatal("response accepted missing nullable wire fields")
	}
}

func TestEventsQueryDoesNotReplaceLegacyAuditGET(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Paths: openapi3.NewPaths(), Components: &components}
	if err := addAdminOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	path := doc.Paths.Value("/auth/v1/events")
	if path.Get == nil || path.Post == nil {
		t.Fatal("legacy GET and lifecycle POST must coexist")
	}
	if path.Get.RequestBody != nil {
		t.Fatal("legacy audit GET unexpectedly gained a request body")
	}
	if got := path.Get.Responses.Status(200).Value.Content["application/json"].Schema.Value.Properties["events"]; got == nil {
		t.Fatal("legacy audit response was replaced")
	}
}
