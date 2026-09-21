package apidocs

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestKVOperationsCatalogMatchesAllRoutes(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addKVOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"/auth/v1/kv/ns":                         {"GET", "POST"},
		"/auth/v1/kv/ns/{ns}":                    {"PUT", "DELETE"},
		"/auth/v1/kv/ns/{ns}/access":             {"GET", "POST"},
		"/auth/v1/kv/ns/{ns}/access/{id}":        {"PUT", "DELETE"},
		"/auth/v1/kv/ns/{ns}/access/{id}/secret": {"POST"},
		"/auth/v1/kv/ns/{ns}/values":             {"GET", "POST", "PUT"},
		"/auth/v1/kv/ns/{ns}/values/{key}":       {"DELETE"},
		"/auth/v1/kv/pub/{ns}/{key}":             {"GET"},
		"/auth/v1/kv/keys":                       {"GET", "PUT"},
		"/auth/v1/kv/keys/{key}":                 {"GET", "DELETE"},
		"/auth/v1/kv/values":                     {"GET"},
		"/auth/v1/kv/test":                       {"GET"},
	}
	for path, methods := range want {
		item := doc.Paths.Value(path)
		if item == nil {
			t.Fatalf("missing path %s", path)
		}
		for _, method := range methods {
			if item.GetOperation(method) == nil {
				t.Fatalf("missing %s %s", method, path)
			}
		}
	}
	if got := len(doc.Paths.Map()); got != len(want) {
		t.Fatalf("paths=%d want=%d", got, len(want))
	}
	if op := doc.Paths.Value("/auth/v1/kv/ns").GetOperation("GET"); len(*op.Security) != 1 || (*op.Security)[0]["browserSession"] == nil {
		t.Fatal("namespace GET must require browser session")
	}
	if op := doc.Paths.Value("/auth/v1/kv/ns").GetOperation("POST"); len(*op.Security) != 1 || (*op.Security)[0]["browserSession"] == nil || (*op.Security)[0]["csrfToken"] == nil {
		t.Fatal("namespace POST must require browser session and CSRF")
	}
	if op := doc.Paths.Value("/auth/v1/kv/keys").GetOperation("GET"); (*op.Security)[0]["kvBearer"] == nil {
		t.Fatal("external KV must require KV bearer")
	}
	if op := doc.Paths.Value("/auth/v1/kv/pub/{ns}/{key}").GetOperation("GET"); op.Security != nil {
		t.Fatal("public KV must be unauthenticated")
	}
	if op := doc.Paths.Value("/auth/v1/kv/ns/{ns}/access").GetOperation("POST"); op.Responses.Value("201") == nil {
		t.Fatal("access creation must document 201")
	}
	if schema := doc.Paths.Value("/auth/v1/kv/ns").GetOperation("GET").Responses.Value("200").Value.Content["application/json"].Schema.Value; schema.VisitJSON([]any{}) != nil {
		t.Fatal("namespace list schema rejected empty array")
	}
	if schema := doc.Paths.Value("/auth/v1/kv/ns/{ns}/access").GetOperation("POST").Responses.Value("201").Value.Content["application/json"].Schema.Value; schema.VisitJSON(map[string]any{"id": "abcdefghijklmnop", "ns": "test-ns", "secret": "secret", "enabled": true}) != nil {
		t.Fatal("access response schema rejected valid access")
	}
	accessUpdate := doc.Paths.Value("/auth/v1/kv/ns/{ns}/access/{id}").GetOperation("PUT")
	var id string
	for _, p := range accessUpdate.Parameters {
		if p.Value.Name == "id" {
			id = p.Value.Schema.Value.Pattern
		}
	}
	if id != `^[A-Za-z0-9]{16}$` {
		t.Fatalf("access id pattern=%q", id)
	}
	if op := doc.Paths.Value("/auth/v1/kv/ns").GetOperation("POST"); len(*op.Security) != 1 || (*op.Security)[0]["apiKey"] != nil {
		t.Fatal("admin KV must not allow API-key fallback")
	}
	body := doc.Paths.Value("/auth/v1/kv/keys").GetOperation("PUT").RequestBody.Value.Content["application/json"].Schema.Value
	if body.AdditionalProperties.Has == nil || *body.AdditionalProperties.Has || body.Properties["value"] == nil || body.Properties["value"].Value.Type != nil {
		t.Fatal("KV value body must be strict while allowing any JSON value")
	}
	responseSchema := doc.Paths.Value("/auth/v1/kv/ns/{ns}/values").GetOperation("GET").Responses.Value("200").Value.Content["application/json"].Schema.Value
	for _, raw := range []any{nil, "text", float64(1), true, []any{"x"}, map[string]any{"x": 1}} {
		if err := responseSchema.VisitJSON([]any{map[string]any{"key": "x", "encrypted": true, "value": raw}}); err != nil {
			t.Fatalf("value %T rejected: %v", raw, err)
		}
	}
	// Every listing is a keyset page: it accepts a cursor and answers a
	// continuing page with 206 plus the token that resumes it.
	for path, operationID := range map[string]string{
		"/auth/v1/kv/ns":             "GET",
		"/auth/v1/kv/ns/{ns}/access": "GET",
		"/auth/v1/kv/ns/{ns}/values": "GET",
		"/auth/v1/kv/keys":           "GET",
		"/auth/v1/kv/values":         "GET",
	} {
		op := doc.Paths.Value(path).GetOperation(operationID)
		var cursor bool
		for _, p := range op.Parameters {
			cursor = cursor || p.Value.Name == "cursor"
		}
		if !cursor {
			t.Fatalf("%s must accept a cursor", path)
		}
		partial := op.Responses.Value("206")
		if partial == nil || partial.Value.Headers["x-continuation-token"] == nil {
			t.Fatalf("%s must document 206 with a continuation token", path)
		}
	}
}
