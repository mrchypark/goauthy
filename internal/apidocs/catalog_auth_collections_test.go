package apidocs

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestAuthCollectionCatalogOperations(t *testing.T) {
	data, err := Document("https://id.example.test", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/auth/v1/auth-collections", "/auth/v1/auth-collections/{collection_id}",
		"/auth/v1/account/auth-collections", "/auth/v1/account/connections/{collection_id}",
		"/auth/v1/account/connections/{collection_id}/{connection_id}",
	} {
		if doc.Paths.Value(path) == nil {
			t.Fatalf("missing auth collection path %s", path)
		}
	}
	put := doc.Paths.Value("/auth/v1/auth-collections/{collection_id}").Put
	if put == nil || put.Parameters.GetByInAndName("header", "If-Match") == nil || put.Responses.Status(428) == nil {
		t.Fatal("definition PUT must require If-Match and document 428")
	}
	del := doc.Paths.Value("/auth/v1/account/connections/{collection_id}/{connection_id}").Delete
	if del == nil || del.Parameters.GetByInAndName("header", "If-Match") == nil || del.Responses.Status(428) == nil {
		t.Fatal("connection DELETE must require If-Match and document 428")
	}
	if got := put.Parameters.GetByInAndName("header", "If-Match").Schema.Value.Pattern; got != `^"[1-9][0-9]*"$` {
		t.Fatalf("If-Match pattern=%q", got)
	}
	if doc.Paths.Value("/auth/v1/auth-collections").Get.Responses.Status(200).Value.Headers != nil {
		t.Fatal("definition list must not claim an ETag")
	}
	updateBody := put.RequestBody.Value.Content.Get("application/json").Schema.Value
	if err := updateBody.VisitJSON(map[string]any{"name": "Login", "auth_method": "oauth2", "enabled": true, "fields": []any{}}); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{"id", "revision"} {
		fixture := map[string]any{"name": "Login", "auth_method": "oauth2", "enabled": true, "fields": []any{}, extra: "unexpected"}
		if extra == "revision" {
			fixture[extra] = float64(1)
		}
		if err := updateBody.VisitJSON(fixture); err == nil {
			t.Fatalf("definition update must reject %s", extra)
		}
	}
	definition := doc.Paths.Value("/auth/v1/auth-collections").Post.RequestBody.Value.Content.Get("application/json").Schema.Value
	if err := definition.VisitJSON(map[string]any{
		"id": "login", "name": "Login", "auth_method": "oauth2", "enabled": true,
		"fields": []any{map[string]any{"name": "tenant", "type": "string", "required": true, "max_length": float64(64)}},
	}); err != nil {
		t.Fatal(err)
	}
	connection := doc.Paths.Value("/auth/v1/account/connections/{collection_id}").Post.RequestBody.Value.Content.Get("application/json").Schema.Value
	if err := connection.VisitJSON(map[string]any{"definition_revision": float64(1), "metadata": map[string]any{"tenant": "acme"}}); err != nil {
		t.Fatal(err)
	}
	if err := connection.VisitJSON(map[string]any{"definition_revision": float64(1), "metadata": map[string]any{}, "owner_subject": "alice"}); err == nil {
		t.Fatal("connection input must reject caller-supplied owner")
	}
	response := doc.Paths.Value("/auth/v1/account/connections/{collection_id}/{connection_id}").Get.Responses.Status(200).Value.Content.Get("application/json").Schema.Value
	if err := response.VisitJSON(map[string]any{"id": "conn", "collection_id": "login", "owner_subject": "alice", "state": "draft", "revision": float64(1), "definition_revision": float64(1), "metadata": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
}
