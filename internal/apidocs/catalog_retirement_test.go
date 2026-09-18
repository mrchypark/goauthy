package apidocs

import (
	"context"
	"github.com/getkin/kin-openapi/openapi3"
	"testing"
)

func TestRetirementCatalog(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3", Info: &openapi3.Info{Title: "test", Version: "test"}, Paths: openapi3.NewPaths()}
	if err := addRetirementOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	p := doc.Paths.Value("/auth/v1/master_key_retirement/{action}")
	if p == nil || p.Post == nil || p.Post.RequestBody == nil {
		t.Fatal("missing action contract")
	}
	if got := p.Parameters.GetByInAndName("path", "action"); got == nil || !got.Required {
		t.Fatal("action enum missing")
	}
	if got := p.Post.RequestBody.Value.Content.Get("application/json").Schema.Value; got == nil || len(got.OneOf) != 2 {
		t.Fatal("action body must expose prepare and epoch-only oneOf schemas")
	}
	for _, want := range []string{"prepare", "fence", "ready", "abort"} {
		found := false
		for _, value := range p.Parameters.GetByInAndName("path", "action").Schema.Value.Enum {
			if value == want {
				found = true
			}
		}
		if !found {
			t.Errorf("action enum missing %q", want)
		}
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	body := p.Post.RequestBody.Value.Content.Get("application/json").Schema.Value
	for _, valid := range []any{map[string]any{"epoch": float64(1)}, map[string]any{"epoch": float64(1), "old_key_id": "old", "replacement_key_id": "new"}} {
		if err := body.VisitJSON(valid); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []any{map[string]any{}, map[string]any{"epoch": float64(0)}, map[string]any{"epoch": float64(1), "old_key_id": "old"}, map[string]any{"epoch": float64(1), "membership": []any{"attacker"}}} {
		if err := body.VisitJSON(invalid); err == nil {
			t.Fatalf("invalid request accepted: %v", invalid)
		}
	}
}
