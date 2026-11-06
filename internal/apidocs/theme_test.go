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

func TestElysduiStylesheetIsPublicCSS(t *testing.T) {
	data, err := Document("https://id.example.test", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	path := doc.Paths.Value("/auth/v1/elysdui.css")
	if path == nil || path.Get == nil {
		t.Fatal("missing elysdui stylesheet operation")
	}
	op := path.Get
	if (op.Security != nil && len(*op.Security) != 0) || (op.Security == nil && len(doc.Security) != 0) {
		t.Fatal("elysdui stylesheet unexpectedly requires authentication")
	}
	if response := op.Responses.Status(200); response == nil || response.Value.Content.Get("text/css") == nil {
		t.Fatal("missing CSS response")
	}
}

func TestCommonBrandingAndLegacyContracts(t *testing.T) {
	data, err := Document("https://id.example.test", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []struct {
		method, path string
		public       bool
		status       int
	}{
		{"GET", "/auth/v1/branding/theme/{timestamp}", true, 200},
		{"POST", "/auth/v1/branding/theme", false, 200},
		{"PUT", "/auth/v1/branding/theme", false, 200},
		{"DELETE", "/auth/v1/branding/theme", false, 200},
		{"GET", "/auth/v1/branding/logo", true, 200},
		{"PUT", "/auth/v1/branding/logo", false, 200},
		{"DELETE", "/auth/v1/branding/logo", false, 200},
		{"GET", "/auth/v1/branding/legacy", false, 200},
		{"GET", "/auth/v1/branding/legacy/theme", false, 200},
		{"GET", "/auth/v1/branding/legacy/logo", false, 200},
		{"POST", "/auth/v1/branding/legacy/resolve", false, 204},
	} {
		item := doc.Paths.Value(route.path)
		if item == nil {
			t.Fatalf("missing %s", route.path)
		}
		op := item.GetOperation(route.method)
		if op == nil || op.Responses.Status(route.status) == nil {
			t.Fatalf("missing operation/status: %+v", route)
		}
		secured := op.Security != nil && len(*op.Security) > 0
		if secured == route.public {
			t.Fatalf("wrong security: %+v", route)
		}
	}
	resolve := doc.Paths.Value("/auth/v1/branding/legacy/resolve").Post
	if resolve.Responses.Status(200) != nil || resolve.Responses.Status(503) == nil {
		t.Fatal("resolution must have empty 204 and atomic-failure 503")
	}
	schema := resolve.RequestBody.Value.Content.Get("application/json").Schema.Value
	valid := map[string]any{"confirm_client_ownership": true, "copy_theme": false, "copy_logo": false}
	if err := schema.VisitJSON(valid); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"confirm_client_ownership", "copy_theme", "copy_logo"} {
		missing := map[string]any{"confirm_client_ownership": true, "copy_theme": false, "copy_logo": false}
		delete(missing, field)
		if schema.VisitJSON(missing) == nil {
			t.Fatalf("missing %s accepted", field)
		}
		missing[field] = nil
		if schema.VisitJSON(missing) == nil {
			t.Fatalf("null %s accepted", field)
		}
	}
	valid["confirm_client_ownership"] = false
	if schema.VisitJSON(valid) == nil {
		t.Fatal("unconfirmed ownership accepted")
	}
	theme := branding.DefaultTheme(branding.GlobalBrandID)
	theme.Login = &branding.LoginAppearance{Copy: map[string]branding.LoginCopy{"en": {Title: "Synthetic title"}}, LogoAlignment: "center", CardWidth: 400}
	raw, err := json.Marshal(theme)
	if err != nil {
		t.Fatal(err)
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	themeSchema := doc.Paths.Value("/auth/v1/branding/theme").Put.RequestBody.Value.Content.Get("application/json").Schema.Value
	if err := themeSchema.VisitJSON(payload); err != nil {
		t.Fatalf("actual theme DTO rejected: %v", err)
	}
	payload.(map[string]any)["client_id"] = "another-client"
	if themeSchema.VisitJSON(payload) == nil {
		t.Fatal("common theme accepted another client ID")
	}
	for _, path := range []string{"/auth/v1/branding/legacy", "/auth/v1/branding/legacy/theme", "/auth/v1/branding/legacy/logo"} {
		if doc.Paths.Value(path).Get.Responses.Status(200).Value.Headers["Cache-Control"] == nil {
			t.Fatalf("missing no-store header: %s", path)
		}
	}
	legacyLogo := doc.Paths.Value("/auth/v1/branding/legacy/logo").Get
	browserCSRF, key := false, false
	for _, requirement := range *legacyLogo.Security {
		_, browser := requirement["browserSession"]
		_, csrf := requirement["csrfToken"]
		_, apiKey := requirement["apiKey"]
		browserCSRF = browserCSRF || browser && csrf
		key = key || apiKey
	}
	if !browserCSRF || !key {
		t.Fatal("legacy logo inspection needs CSRF for browser or API key")
	}
	if doc.Paths.Value("/auth/v1/branding/logo").Put.RequestBody.Value.Content.Get("multipart/form-data") == nil {
		t.Fatal("common logo upload missing multipart schema")
	}
}
