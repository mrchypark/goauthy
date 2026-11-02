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
	input := map[string]any{"id": "public-device", "name": nil, "confidential": false, "redirect_uris": []any{}, "scopes": []any{"goauthy.read", "offline_access"}, "default_scopes": []any{"goauthy.read"}, "enabled_flows": []any{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}, "force_mfa": true}
	if err := create.VisitJSON(input); err != nil {
		t.Fatal(err)
	}
	update := doc.Paths.Value("/auth/v1/clients/{id}").Put.RequestBody.Value.Content.Get("application/json").Schema.Value
	response := doc.Paths.Value("/auth/v1/clients/{id}").Get.Responses.Status(200).Value.Content.Get("application/json").Schema.Value
	for name, schema := range map[string]*openapi3.Schema{"create": create, "update": update, "response": response} {
		field := schema.Properties["force_mfa"]
		if field == nil {
			t.Fatalf("%s schema is missing force_mfa", name)
		}
		for _, value := range []any{true, false} {
			if err := field.Value.VisitJSON(value); err != nil {
				t.Fatalf("%s force_mfa rejected %v: %v", name, value, err)
			}
		}
		for _, value := range []any{"true", nil} {
			if err := field.Value.VisitJSON(value); err == nil {
				t.Fatalf("%s force_mfa accepted invalid %v", name, value)
			}
		}
	}
	if !slices.Contains(response.Required, "force_mfa") {
		t.Fatal("managed client response must require force_mfa")
	}
	updateInput := map[string]any{"confidential": false, "redirect_uris": []any{}, "enabled": true, "scopes": []any{}, "default_scopes": []any{}, "enabled_flows": []any{}, "force_mfa": false}
	if err := update.VisitJSON(updateInput); err != nil {
		t.Fatalf("update rejected force_mfa: %v", err)
	}
	responseInput := map[string]any{"id": "public-device", "revision": int64(1), "name": nil, "confidential": false, "redirect_uris": []any{}, "enabled": true, "scopes": []any{}, "default_scopes": []any{}, "enabled_flows": []any{}, "audience": []any{}, "default_aud": []any{}, "force_mfa": false}
	if err := response.VisitJSON(responseInput); err != nil {
		t.Fatalf("response rejected force_mfa: %v", err)
	}
	responseInput["unexpected"] = true
	if err := response.VisitJSON(responseInput); err == nil {
		t.Fatal("managed client response accepted an undocumented field")
	}
	if create.Properties["audience"] == nil || doc.Paths.Value("/auth/v1/clients/{id}").Put.RequestBody.Value.Content.Get("application/json").Schema.Value.Properties["audience"] == nil {
		t.Fatal("audience must be accepted on managed client create/update")
	}
	if create.Properties["client_uri"] == nil || update.Properties["client_uri"] == nil || update.Properties["client_uri"].Value.Nullable == false {
		t.Fatal("client_uri must be documented on create and nullable update")
	}
	if err := update.Properties["client_uri"].Value.VisitJSON(nil); err != nil {
		t.Fatalf("null client_uri clear rejected: %v", err)
	}
	clientResponse := doc.Paths.Value("/auth/v1/clients/{id}").Get.Responses.Status(200).Value.Content.Get("application/json").Schema.Value
	if clientResponse.Properties["client_uri"] == nil || !clientResponse.Properties["client_uri"].Value.Nullable {
		t.Fatal("client_uri response must allow a missing stored value")
	}
	if !strings.Contains(doc.Paths.Value("/auth/v1/clients/{id}").Put.Description, "Omit client_uri to preserve it") {
		t.Fatal("client_uri omission/clear semantics missing")
	}
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
