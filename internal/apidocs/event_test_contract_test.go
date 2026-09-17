package apidocs

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestEventTestContract(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Paths: openapi3.NewPaths(), Components: &components}
	if err := addAdminOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	op := doc.Paths.Value("/auth/v1/events/test").Post
	if op == nil {
		t.Fatal("missing event test endpoint")
	}
	if op.RequestBody != nil {
		t.Fatal("event test must not accept a request body")
	}
	if op.Security == nil || len(*op.Security) != 2 || (*op.Security)[0]["browserSession"] == nil || (*op.Security)[0]["csrfToken"] == nil || (*op.Security)[1]["apiKey"] == nil {
		t.Fatalf("event test security must be browser+CSRF or API key: %#v", op.Security)
	}
	response := op.Responses.Status(200).Value
	if response == nil || len(response.Content) != 0 {
		t.Fatal("event test success must be an empty 200 response")
	}
	if op.Description == "" {
		t.Fatal("event test authorization and server-assigned payload must be documented")
	}
	events := doc.Paths.Value("/auth/v1/events")
	if events == nil || events.Get == nil || events.Post == nil {
		t.Fatal("event test addition must preserve legacy GET and query POST")
	}
	stream := doc.Paths.Value("/auth/v1/events/stream")
	if stream == nil || stream.Get == nil {
		t.Fatal("event test addition must preserve SSE stream")
	}
}
