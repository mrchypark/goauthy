package apidocs

import (
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
)

func addSaaSProviderOperations(doc *openapi3.T) error {
	str := openapi3.NewStringSchema()
	identityEndpoint := openapi3.NewStringSchema().WithMaxLength(2048)
	identityEndpoint.Description = "Optional trusted HTTPS account identity endpoint; configure together with subject_field. OAuth2 providers only."
	subjectField := openapi3.NewStringSchema().WithPattern(`^[A-Za-z0-9_-]{1,64}$`)
	subjectField.Description = "Top-level stable account ID field in the identity endpoint JSON response; string or canonical int64."
	provider := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"id": str, "name": str, "kind": openapi3.NewStringSchema().WithEnum("oauth2", "github", "api_key"),
		"enabled": openapi3.NewBoolSchema(), "revision": openapi3.NewInt64Schema().WithMin(1), "callback_uri": str,
		"client_id": str, "auth_endpoint": str, "token_endpoint": str, "scopes": openapi3.NewArraySchema().WithItems(str),
		"identity_endpoint": identityEndpoint, "subject_field": subjectField,
		"auth_style": openapi3.NewStringSchema().WithEnum("header", "params"), "connector": connectorSchema(),
	}).WithRequired([]string{"id", "kind", "callback_uri", "scopes"})
	secret := openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(2048)
	secret.WriteOnly = true
	input := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"id": str, "name": str, "kind": openapi3.NewStringSchema().WithEnum("oauth2", "api_key"), "enabled": openapi3.NewBoolSchema(),
		"client_id": str, "client_secret": secret, "callback_uri": str, "auth_endpoint": str, "token_endpoint": str,
		"identity_endpoint": identityEndpoint, "subject_field": subjectField,
		"scopes": openapi3.NewArraySchema().WithItems(str), "auth_style": openapi3.NewStringSchema().WithEnum("header", "params"), "connector": connectorSchema(),
	}).WithRequired([]string{"id", "name", "kind", "enabled"})
	update := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"name": str, "kind": openapi3.NewStringSchema().WithEnum("oauth2", "api_key"), "enabled": openapi3.NewBoolSchema(),
		"client_id": str, "client_secret": secret, "callback_uri": str, "auth_endpoint": str, "token_endpoint": str,
		"identity_endpoint": identityEndpoint, "subject_field": subjectField,
		"scopes": openapi3.NewArraySchema().WithItems(str), "auth_style": openapi3.NewStringSchema().WithEnum("header", "params"), "connector": connectorSchema(),
	}).WithRequired([]string{"name", "kind", "enabled"})
	read := &openapi3.SecurityRequirements{{"browserSession": {}}, {"bearerToken": {}}}
	write := &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}, {"bearerToken": {}}}
	add := func(method, path, id string, body, response *openapi3.Schema, status int, cas bool) {
		op := &openapi3.Operation{OperationID: id, Summary: id, Tags: []string{"Administration"}, Security: read, Responses: openapi3.NewResponses()}
		op.Description = "Browser administrators use a session (and CSRF token for writes), or an access token from the exact GOAUTHY_PROVIDERS_RESOURCE with the required provider scope and current administrator role. Bearer requests cannot include cookies."
		if method != http.MethodGet {
			op.Security = write
			op.Description += " Bearer scope: goauthy.providers.write."
		} else {
			op.Description += " Bearer scope: goauthy.providers.read."
		}
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body)}
		}
		if path != "/auth/v1/saas/providers" {
			op.AddParameter(openapi3.NewPathParameter("provider_id").WithSchema(str))
		}
		for _, code := range []int{400, 401, 403, 404, 405, 409, 503} {
			op.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
		}
		if cas {
			op.AddParameter(openapi3.NewHeaderParameter("If-Match").WithRequired(true).WithSchema(openapi3.NewStringSchema().WithPattern(`^"[1-9][0-9]*"$`)))
			op.AddResponse(428, openapi3.NewResponse().WithDescription("Strong quoted If-Match revision required"))
		}
		out := openapi3.NewResponse().WithDescription(http.StatusText(status))
		if response != nil && status != http.StatusNoContent {
			out.WithJSONSchema(response)
		}
		if status != http.StatusNoContent {
			out.Headers = openapi3.Headers{"ETag": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: str}, Description: "Strong quoted revision when managed"}}}
		}
		op.AddResponse(status, out)
		doc.AddOperation(path, method, op)
	}
	add(http.MethodGet, "/auth/v1/saas/providers", "listSaaSProviders", nil, openapi3.NewArraySchema().WithItems(provider), http.StatusOK, false)
	add(http.MethodPost, "/auth/v1/saas/providers", "createSaaSProvider", input, provider, http.StatusCreated, false)
	add(http.MethodGet, "/auth/v1/saas/providers/{provider_id}", "getSaaSProvider", nil, provider, http.StatusOK, false)
	add(http.MethodPut, "/auth/v1/saas/providers/{provider_id}", "updateSaaSProvider", update, provider, http.StatusOK, true)
	add(http.MethodDelete, "/auth/v1/saas/providers/{provider_id}", "deleteSaaSProvider", nil, nil, http.StatusNoContent, true)
	return addSaaSConnectionOperations(doc)
}

func connectorSchema() *openapi3.Schema {
	str := openapi3.NewStringSchema()
	responseFields := openapi3.NewObjectSchema()
	responseFields.AdditionalProperties = openapi3.BoolSchema{Schema: &openapi3.SchemaRef{Value: str}}
	field := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"id": str, "url": str, "response_fields": responseFields}).WithRequired([]string{"id", "url", "response_fields"})
	return openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"id": str, "header": str, "prefix": str, "operations": openapi3.NewArraySchema().WithItems(field)}).WithRequired([]string{"id", "header", "prefix", "operations"})
}
