package apidocs

import (
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestManagedClientInitialPolicyCatalog(t *testing.T) {
	data, err := Document("https://id.example.test", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	create := doc.Paths.Value("/auth/v1/clients").Post.RequestBody.Value.Content.Get("application/json").Schema.Value
	input := map[string]any{"id": "public-device", "name": nil, "confidential": false, "redirect_uris": []any{}, "scopes": []any{"goauthy.read", "offline_access"}, "default_scopes": []any{"goauthy.read"}, "enabled_flows": []any{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}}
	if err := create.VisitJSON(input); err != nil {
		t.Fatal(err)
	}
	if create.Properties["audience"] == nil || doc.Paths.Value("/auth/v1/clients/{id}").Put.RequestBody.Value.Content.Get("application/json").Schema.Value.Properties["audience"] == nil {
		t.Fatal("audience must be accepted on managed client create/update")
	}
	response := doc.Paths.Value("/auth/v1/clients/{id}").Get.Responses.Status(200).Value.Content.Get("application/json").Schema.Value
	if response.Properties["audience"] == nil || !slices.Contains(response.Required, "audience") {
		t.Fatal("managed client response must require audience")
	}
	if !strings.Contains(doc.Paths.Value("/auth/v1/clients/{id}").Put.Description, "[]") || !strings.Contains(doc.Paths.Value("/auth/v1/clients/{id}").Put.Description, "generation") {
		t.Fatal("audience PUT preserve/clear and generation semantics missing")
	}
	input["generation"] = "caller-cannot-control"
	if err := create.VisitJSON(input); err == nil {
		t.Fatal("create schema accepts caller-supplied generation")
	}
	for _, key := range []string{"generation", "scopes", "default_scopes", "enabled_flows"} {
		delete(input, key)
	}
	if err := create.VisitJSON(input); err != nil {
		t.Fatalf("optional policy rejected: %v", err)
	}
	rotate := doc.Paths.Value("/auth/v1/clients/{id}/secret").Put
	if rotate.Parameters.GetByInAndName("header", "If-Match") == nil || rotate.Responses.Status(200).Value.Headers["ETag"] == nil {
		t.Fatal("rotation must expose request/response revision contract")
	}
}

func TestManagedGroupPrefixCatalog(t *testing.T) {
	data, err := Document("https://id.example.test", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	schemas := []*openapi3.Schema{
		doc.Paths.Value("/auth/v1/clients").Post.RequestBody.Value.Content.Get("application/json").Schema.Value,
		doc.Paths.Value("/auth/v1/clients/{id}").Put.RequestBody.Value.Content.Get("application/json").Schema.Value,
		doc.Paths.Value("/auth/v1/clients/{id}").Get.Responses.Status(200).Value.Content.Get("application/json").Schema.Value,
	}
	for _, schema := range schemas {
		p := schema.Properties["restrict_group_prefix"]
		if p == nil {
			t.Fatal("group prefix missing")
		}
		for _, value := range []any{nil, "team/", " team"} {
			if err := p.Value.VisitJSON(value); err != nil {
				t.Fatal(err)
			}
		}
		for _, value := range []any{"", "a", "team\\a"} {
			if err := p.Value.VisitJSON(value); err == nil {
				t.Fatal("invalid prefix accepted")
			}
		}
	}
}

func TestManagedBackchannelURICatalog(t *testing.T) {
	data, err := Document("https://id.example.test", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	schemas := []*openapi3.Schema{
		doc.Paths.Value("/auth/v1/clients").Post.RequestBody.Value.Content.Get("application/json").Schema.Value,
		doc.Paths.Value("/auth/v1/clients/{id}").Put.RequestBody.Value.Content.Get("application/json").Schema.Value,
		doc.Paths.Value("/auth/v1/clients/{id}").Get.Responses.Status(200).Value.Content.Get("application/json").Schema.Value,
	}
	for _, schema := range schemas {
		p := schema.Properties["backchannel_logout_uri"]
		if p == nil {
			t.Fatal("backchannel URI missing")
		}
		for _, value := range []any{nil, "https://rp.example.test/logout", "http://localhost/logout"} {
			if err := p.Value.VisitJSON(value); err != nil {
				t.Fatal(err)
			}
		}
		for _, value := range []any{"", "https://rp.example.test/ bad", "https://rp.example.test/\\bad"} {
			if err := p.Value.VisitJSON(value); err == nil {
				t.Fatal("invalid URI accepted")
			}
		}
	}
}
