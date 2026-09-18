package apidocs

import (
	"context"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestConnectionResourceCatalogContract(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3", Info: &openapi3.Info{Title: "test", Version: "test"}, Paths: openapi3.NewPaths(), Components: &openapi3.Components{Schemas: openapi3.Schemas{}}}
	if err := addConnectionResourceOperations(doc); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/auth/v1/connection-collections", "/auth/v1/connections/{collection_id}", "/auth/v1/connections/{collection_id}/{connection_id}"} {
		if doc.Paths.Value(path) == nil {
			t.Fatalf("missing %s", path)
		}
	}
	put := doc.Paths.Value("/auth/v1/connections/{collection_id}/{connection_id}").Put
	if put == nil || put.Parameters.GetByInAndName("header", "If-Match") == nil || !strings.Contains(put.Description, "goauthy.connections.write") {
		t.Fatal("PUT contract incomplete")
	}
	for _, path := range doc.Paths.Map() {
		for method, op := range path.Operations() {
			scopes, ok := (*op.Security)[0]["bearerToken"]
			if !ok || len(scopes) != 0 {
				t.Fatal("HTTP bearer security must use an empty scope array")
			}
			want := "goauthy.connections.write"
			if method == "GET" {
				want = "goauthy.connections.read"
			}
			if !strings.Contains(op.Description, want) {
				t.Fatalf("missing scope contract for %s", op.OperationID)
			}
			for _, p := range op.Parameters {
				if p.Value.In == "path" && p.Value.Schema.Value.VisitJSON("_real-connection-id") != nil {
					t.Fatal("path constrained by unrelated enum")
				}
			}
		}
	}
	response := put.Responses.Status(200).Value.Content["application/json"].Schema.Value
	value := map[string]any{"id": "_real-connection-id", "collection_id": "accounts", "owner_subject": "user-1", "state": "draft", "revision": float64(2), "definition_revision": float64(1), "metadata": map[string]any{}}
	if err := response.VisitJSON(value); err != nil {
		t.Fatalf("realistic connection response rejected: %v", err)
	}
	value["state"] = "unknown"
	if err := response.VisitJSON(value); err == nil {
		t.Fatal("unknown connection state accepted")
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
}
