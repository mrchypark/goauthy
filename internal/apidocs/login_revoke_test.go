package apidocs

import (
	"github.com/getkin/kin-openapi/openapi3"
	"testing"
)

func TestLoginRevokeCatalogWithoutPasswordRecovery(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	path := doc.Paths.Find("/auth/v1/users/{subject}/revoke/{code}")
	if path == nil || path.Get == nil {
		t.Fatal("missing public revoke route")
	}
	op := path.Get
	if op.Security != nil && len(*op.Security) != 0 {
		t.Fatal("revoke requires unrelated authentication")
	}
	if op.Responses.Status(200).Value.Content["text/html"] == nil {
		t.Fatal("missing HTML response")
	}
	found := false
	for _, p := range op.Parameters {
		if p.Value.Name == "ip" && p.Value.In == "query" {
			found = p.Value.Required
		}
	}
	if !found {
		t.Fatal("IP query must be required")
	}
}
