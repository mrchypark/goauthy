package apidocs

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestForcedLogoutContract(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Paths: openapi3.NewPaths(), Components: &components}
	if err := addAdminOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	path := doc.Paths.Value("/auth/v1/sessions/{subject}")
	if path == nil || path.Delete == nil {
		t.Fatal("missing user-wide forced logout")
	}
	op := path.Delete
	if op.RequestBody != nil || len(op.Parameters) != 1 || op.Parameters[0].Value.Name != "subject" || op.Parameters[0].Value.In != "path" || !op.Parameters[0].Value.Required {
		t.Fatal("forced logout requires only its target path parameter")
	}
	if op.Security == nil || len(*op.Security) != 2 {
		t.Fatal("missing browser/CSRF and API key alternatives")
	}
	if _, ok := (*op.Security)[0]["csrfToken"]; !ok {
		t.Fatal("browser mutation must require CSRF")
	}
	if _, ok := (*op.Security)[1]["apiKey"]; !ok {
		t.Fatal("missing API key authorization")
	}
	if len(op.Responses.Status(200).Value.Content) != 0 {
		t.Fatal("success must have an empty body")
	}
}

func TestSingleSessionDeleteContract(t *testing.T) {
	data, err := Document("https://issuer.example", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	path := doc.Paths.Value("/auth/v1/sessions/id/{session_id}")
	if path == nil || path.Delete == nil {
		t.Fatal("missing single-session delete route")
	}
	op := path.Delete
	if op.RequestBody != nil || len(op.Parameters) != 1 || op.Parameters[0].Value.Name != "session_id" || !op.Parameters[0].Value.Required {
		t.Fatal("single-session delete requires only a path SID")
	}
	if op.Security == nil || len(*op.Security) != 2 || len(op.Responses.Status(200).Value.Content) != 0 {
		t.Fatal("invalid session-delete authorization/response contract")
	}
	if _, ok := (*op.Security)[0]["csrfToken"]; !ok {
		t.Fatal("missing browser CSRF")
	}
	if _, ok := (*op.Security)[1]["apiKey"]; !ok {
		t.Fatal("missing API-key alternative")
	}
}

func TestGlobalSessionLogoutContract(t *testing.T) {
	data, err := Document("https://issuer.example", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	path := doc.Paths.Value("/auth/v1/sessions")
	if path == nil || path.Get == nil || path.Delete == nil {
		t.Fatal("missing session list or global logout route")
	}
	op := path.Delete
	if op.RequestBody != nil || len(op.Parameters) != 0 {
		t.Fatal("global logout does not accept parameters or a request body")
	}
	if op.Security == nil || len(*op.Security) != 2 || op.Responses.Status(200) == nil || len(op.Responses.Status(200).Value.Content) != 0 {
		t.Fatal("invalid global logout authorization/response contract")
	}
	if _, ok := (*op.Security)[0]["csrfToken"]; !ok {
		t.Fatal("missing browser CSRF")
	}
	if _, ok := (*op.Security)[1]["apiKey"]; !ok {
		t.Fatal("missing API-key alternative")
	}
}
