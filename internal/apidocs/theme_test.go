package apidocs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mrchypark/goauthy/internal/branding"
)

func TestThemeContractAcceptsPinnedActionAndRejectsMissingTuple(t *testing.T) {
	data, err := Document("https://id.example.test", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	theme := branding.DefaultTheme("client-a")
	theme.BrandName = strings.Repeat("가", 120)
	theme.Light.Action = []uint16{65535, 65535, 65535}
	raw, err := json.Marshal(theme)
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	path := doc.Paths.Value("/auth/v1/theme/{client_id}")
	for _, schema := range []*openapi3.Schema{
		path.Post.Responses.Status(200).Value.Content.Get("application/json").Schema.Value,
		path.Put.RequestBody.Value.Content.Get("application/json").Schema.Value,
	} {
		if err := schema.VisitJSON(input); err != nil {
			t.Fatalf("pinned valid theme rejected: %v", err)
		}
		input["brand_name"] = strings.Repeat("가", 121)
		if err := schema.VisitJSON(input); err == nil {
			t.Fatal("overlong brand name accepted")
		}
		input["brand_name"] = theme.BrandName
	}
	schema := path.Put.RequestBody.Value.Content.Get("application/json").Schema.Value
	input["light"].(map[string]any)["text"] = []any{float64(1), float64(2)}
	if err := schema.VisitJSON(input); err == nil {
		t.Fatal("incomplete HSL tuple accepted")
	}
	public := doc.Paths.Value("/auth/v1/theme/{client_id}/{timestamp}").Get
	if public.Security != nil && len(*public.Security) != 0 {
		t.Fatal("public theme unexpectedly requires authentication")
	}
	if public.Responses.Status(200).Value.Content.Get("text/css") == nil {
		t.Fatal("missing CSS content type")
	}
	if !strings.Contains(public.Description, "global GoAuthy theme") || strings.Contains(strings.ToLower(public.Description), "rauthy") {
		t.Fatalf("unexpected public theme description: %q", public.Description)
	}
}
