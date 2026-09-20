package apidocs

import (
	"fmt"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3gen"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/fedcm"
)

func addFedCMOperations(doc *openapi3.T, features Features) error {
	if doc == nil || doc.Paths == nil {
		return fmt.Errorf("uninitialized FedCM API document")
	}
	if !features.FedCM {
		return nil
	}
	if doc.Components == nil {
		components := openapi3.NewComponents()
		doc.Components = &components
	}
	if doc.Components.SecuritySchemes == nil {
		doc.Components.SecuritySchemes = openapi3.SecuritySchemes{}
	}
	doc.Components.SecuritySchemes["fedcmSession"] = &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{Type: "apiKey", In: "cookie", Name: browser.FedCMSessionCookieName, Description: "Dedicated Secure SameSite=None cookie with an authenticated, peer-bound session. An ordinary browser cookie is not a substitute."}}
	session := &openapi3.SecurityRequirements{{"fedcmSession": {}}}
	add := func(path, method, id string, codes ...int) *openapi3.Operation {
		op := &openapi3.Operation{OperationID: id, Tags: []string{"FedCM"}, Responses: openapi3.NewResponses()}
		for _, code := range codes {
			op.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
		}
		doc.AddOperation(path, method, op)
		return op
	}
	for _, route := range []struct {
		path, method, id string
		response         any
		required         []string
		origin           bool
	}{
		{fedcm.ManifestPath, "GET", "fedcmManifest", fedcm.ManifestDocument{}, []string{"provider_urls"}, false},
		{fedcm.ConfigPath, "GET", "fedcmConfig", fedcm.ProviderConfig{}, []string{"accounts_endpoint", "client_metadata_endpoint", "id_assertion_endpoint", "login_url"}, false},
		{fedcm.AccountsPath, "GET", "fedcmAccounts", fedcm.AccountsResponse{}, []string{"accounts"}, false},
		{fedcm.ClientMetadataPath, "GET", "fedcmClientMetadata", fedcm.ClientMetadata{}, []string{"privacy_policy_url", "terms_of_service_url"}, true},
		{fedcm.AssertionPath, "POST", "fedcmToken", fedcm.AssertionResponse{}, []string{"token"}, true},
		{fedcm.StatusPath, "GET", "fedcmStatus", nil, nil, false},
	} {
		op := add(route.path, route.method, route.id, 200, 400, 403)
		op.AddParameter(openapi3.NewHeaderParameter("Sec-Fetch-Dest").WithRequired(true).WithSchema(openapi3.NewStringSchema().WithEnum("webidentity")))
		op.Description = "Exactly one Sec-Fetch-Dest: webidentity header is required. Query parameters and an Origin header are forbidden."
		if route.origin {
			op.AddParameter(openapi3.NewHeaderParameter("Origin").WithRequired(true).WithSchema(openapi3.NewStringSchema()))
			op.Description = "Exactly one Sec-Fetch-Dest: webidentity and one Origin matching the requested client's registered origin are required. Duplicate or unknown fields are rejected."
		}
		if route.response != nil {
			schema, err := openapi3gen.NewSchemaRefForValue(route.response, nil)
			if err != nil {
				return err
			}
			schema.Value.WithRequired(route.required)
			if route.path == fedcm.AccountsPath {
				schema.Value.Properties["accounts"].Value.Items.Value.WithRequired([]string{"id", "name", "email"})
				op.AddResponse(401, openapi3.NewResponse().WithDescription("No authenticated account; accounts is an empty array").WithJSONSchema(schema.Value))
			}
			op.Responses.Status(200).Value.WithJSONSchema(schema.Value)
		}
		if route.path == fedcm.AccountsPath || route.path == fedcm.StatusPath || route.path == fedcm.AssertionPath {
			op.Security = session
			if op.Responses.Status(401) == nil {
				op.AddResponse(401, openapi3.NewResponse().WithDescription("No authenticated account"))
			}
		}
		if route.path == fedcm.AccountsPath || route.path == fedcm.StatusPath {
			for _, status := range []int{200, 401} {
				op.Responses.Status(status).Value.Headers = openapi3.Headers{"Set-Login": {Value: &openapi3.Header{Parameter: openapi3.Parameter{Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithEnum("logged-in", "logged-out")}}}}}
			}
		}
	}
	text := openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(256)
	doc.Paths.Value(fedcm.ClientMetadataPath).Get.AddParameter(openapi3.NewQueryParameter("client_id").WithRequired(true).WithSchema(openapi3.NewStringSchema().WithMinLength(2).WithMaxLength(256)))
	token := doc.Paths.Value(fedcm.AssertionPath).Post
	token.AddResponse(503, openapi3.NewResponse().WithDescription("Signing key unavailable"))
	form := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithRequired([]string{"account_id", "client_id", "disclosure_text_shown"})
	for _, field := range []string{"account_id", "client_id", "nonce", "is_auto_selected", "mode", "fields", "disclosure_shown_for"} {
		form.WithProperty(field, text)
	}
	// Accounts are projected with native base64url subjects, so the accepted
	// contract is the bounded opaque-subject rule the handler enforces.
	form.WithProperty("account_id", openapi3.NewStringSchema().WithPattern("^[A-Za-z0-9_-]{1,256}$"))
	form.WithProperty("client_id", openapi3.NewStringSchema().WithMinLength(2).WithMaxLength(256))
	form.WithProperty("disclosure_text_shown", openapi3.NewStringSchema().WithEnum("1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False"))
	form.Description = "URL-encoded form, at most 8 KiB; each field occurs once with a non-empty, trimmed value. nonce is optional. disclosure_text_shown uses Go strconv.ParseBool text forms. No query parameters."
	token.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithSchema(form, []string{"application/x-www-form-urlencoded"})}
	if landing := features.FedCMLanding; landing != "" {
		get := add(landing, "GET", "fedcmLoginLanding", 200, 400, 403, 500, 503)
		html := openapi3.Content{"text/html": {Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}}
		get.Responses.Status(200).Value.Content = html
		get.Description = "Creates the Init session, one-use interaction and form CSRF token, or displays the authenticated account. No query parameters."
		body := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithRequired([]string{"fedcm", "interaction", "username", "password", "csrf_token"})
		body.WithProperty("fedcm", openapi3.NewStringSchema().WithEnum("1"))
		for _, name := range []string{"interaction", "username", "password", "csrf_token"} {
			body.WithProperty(name, openapi3.NewStringSchema().WithMinLength(1))
		}
		body.WithProperty("password", openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(256))
		if landing == "/auth/login" && doc.Paths.Value(landing).Post != nil {
			// The runtime dispatches marked forms to FedCM and leaves ordinary
			// OAuth forms with the legacy login handler on this shared path.
			post := doc.Paths.Value(landing).Post
			legacy := post.RequestBody.Value.Content["application/x-www-form-urlencoded"].Schema
			post.RequestBody.Value.Content["application/x-www-form-urlencoded"].Schema = &openapi3.SchemaRef{Value: &openapi3.Schema{OneOf: openapi3.SchemaRefs{legacy, {Value: body}}}}
			post.Description += " When fedcm=1, the FedCM landing form instead requires its Init session, interaction and form CSRF token."
			post.AddResponse(413, openapi3.NewResponse().WithDescription("Login body exceeds 8 KiB"))
		} else {
			post := add(landing, "POST", "fedcmLoginLandingSubmit", 200, 400, 401, 403, 406, 503)
			post.Description = "Requires the Init-session cookie and one-use interaction plus form csrf_token from GET, same-issuer Origin when present, and safe Sec-Fetch-Site. No query parameters. Explicit forced MFA is never downgraded to password login."
			post.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithSchema(body, []string{"application/x-www-form-urlencoded"})}
			post.Responses.Status(200).Value.Content = html
		}
	}
	return nil
}
