package apidocs

import (
	"encoding/json"
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
	schema := doc.Paths.Value("/auth/v1/theme/{client_id}").Put.RequestBody.Value.Content.Get("application/json").Schema.Value
	theme := branding.DefaultTheme("client-a")
	theme.Light.Action = []uint16{65535, 65535, 65535}
	raw, err := json.Marshal(theme)
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	if err := schema.VisitJSON(input); err != nil {
		t.Fatalf("pinned valid theme rejected: %v", err)
	}
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
}
