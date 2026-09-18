package apidocs

import (
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
)

// addAuthCollectionOperations documents the administrator-owned definitions
// and browser-session-owned draft connections. These are metadata only; no
// credentials or caller-supplied owner fields are part of this contract.
func addAuthCollectionOperations(doc *openapi3.T) error {
	str := openapi3.NewStringSchema()
	field := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"name": str, "type": openapi3.NewStringSchema().WithEnum("string", "boolean", "integer", "enum"),
		"required": openapi3.NewBoolSchema(), "max_length": openapi3.NewIntegerSchema().WithMin(0).WithMax(4096),
		"options": openapi3.NewArraySchema().WithItems(str),
	}).WithRequired([]string{"name", "type"})
	fields := openapi3.NewArraySchema().WithMaxItems(32).WithItems(field)
	providers := openapi3.NewArraySchema().WithMaxItems(32).WithItems(openapi3.NewStringSchema().WithMaxLength(64).WithPattern(`^[a-z0-9][a-z0-9_-]*$`))
	providers.UniqueItems = true
	providers.Description = "Configured SaaS provider IDs allowed for OAuth2 connections. Empty denies credential use. For API-key collections, use an empty list for legacy connectors or one registered, enabled api_key provider. Removing a provider permanently revokes its stored credentials."
	definition := func(includeID, includeRevision bool, required ...string) *openapi3.Schema {
		properties := map[string]*openapi3.Schema{
			"name": str, "auth_method": openapi3.NewStringSchema().WithEnum("oauth2", "api_key", "device_flow"),
			"enabled": openapi3.NewBoolSchema(), "fields": fields, "provider_ids": providers,
		}
		if includeID {
			properties["id"] = str
		}
		if includeRevision {
			properties["revision"] = openapi3.NewInt64Schema().WithMin(1)
		}
		return openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(properties).WithRequired(required)
	}
	metadata := openapi3.NewObjectSchema()
	connection := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"id": str, "collection_id": str, "owner_subject": str, "state": openapi3.NewStringSchema().WithEnum("draft"), "revision": openapi3.NewInt64Schema().WithMin(1),
		"definition_revision": openapi3.NewInt64Schema().WithMin(1), "metadata": metadata,
	}).WithRequired([]string{"id", "collection_id", "owner_subject", "state", "revision", "definition_revision", "metadata"})
	connectionInput := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"definition_revision": openapi3.NewInt64Schema().WithMin(1), "metadata": metadata,
	}).WithRequired([]string{"definition_revision", "metadata"})
	read := &openapi3.SecurityRequirements{{"browserSession": {}}}
	write := &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}}
	add := func(method, path, id, summary string, body, response *openapi3.Schema, security *openapi3.SecurityRequirements, cas, etag bool, code int) {
		op := &openapi3.Operation{OperationID: id, Summary: summary, Tags: []string{"Authentication collections"}, Security: security, Responses: openapi3.NewResponses()}
		if path == "/auth/v1/auth-collections" || path == "/auth/v1/auth-collections/{collection_id}" {
			op.Description = "Requires an authenticated browser session with the rauthy_admin role. API keys and caller-supplied owners are not accepted."
		}
		if path == "/auth/v1/auth-collections/{collection_id}" || path == "/auth/v1/account/connections/{collection_id}" {
			op.AddParameter(openapi3.NewPathParameter("collection_id").WithSchema(str))
		}
		if path == "/auth/v1/account/connections/{collection_id}/{connection_id}" {
			op.AddParameter(openapi3.NewPathParameter("collection_id").WithSchema(str))
			op.AddParameter(openapi3.NewPathParameter("connection_id").WithSchema(str))
		}
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body)}
		}
		for _, status := range []int{400, 401, 404, 409, 503} {
			op.AddResponse(status, openapi3.NewResponse().WithDescription(http.StatusText(status)))
		}
		if cas {
			op.AddParameter(openapi3.NewHeaderParameter("If-Match").WithRequired(true).WithSchema(openapi3.NewStringSchema().WithPattern(`^"[1-9][0-9]*"$`)))
			op.AddResponse(428, openapi3.NewResponse().WithDescription("Strong quoted If-Match revision required"))
		}
		resp := openapi3.NewResponse().WithDescription(http.StatusText(code))
		if response != nil && code != http.StatusNoContent {
			resp.WithJSONSchema(response)
		}
		if etag && code != http.StatusNoContent {
			resp.Headers = openapi3.Headers{"ETag": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: str}, Description: "Strong quoted revision"}}}
		}
		op.AddResponse(code, resp)
		doc.AddOperation(path, method, op)
	}
	resp := definition(true, true, "id", "name", "auth_method", "enabled", "revision", "fields")
	add("GET", "/auth/v1/auth-collections", "listAuthCollections", "List authentication collection definitions", nil, openapi3.NewArraySchema().WithItems(resp), read, false, false, 200)
	add("POST", "/auth/v1/auth-collections", "createAuthCollection", "Create an authentication collection definition", definition(true, false, "id", "name", "auth_method", "enabled", "fields"), resp, write, false, true, 201)
	add("GET", "/auth/v1/auth-collections/{collection_id}", "getAuthCollection", "Read an authentication collection definition", nil, resp, read, false, true, 200)
	add("PUT", "/auth/v1/auth-collections/{collection_id}", "updateAuthCollection", "Replace an authentication collection definition", definition(false, false, "name", "auth_method", "enabled", "fields"), resp, write, true, true, 200)
	add("DELETE", "/auth/v1/auth-collections/{collection_id}", "deleteAuthCollection", "Delete an authentication collection definition", nil, nil, write, true, false, 204)
	add("GET", "/auth/v1/account/auth-collections", "listAccountAuthCollections", "List authentication collection definitions for draft connections", nil, openapi3.NewArraySchema().WithItems(resp), read, false, false, 200)
	add("GET", "/auth/v1/account/connections/{collection_id}", "listAccountConnections", "List draft authentication connections", nil, openapi3.NewArraySchema().WithItems(connection), read, false, false, 200)
	add("POST", "/auth/v1/account/connections/{collection_id}", "createAccountConnection", "Create a draft authentication connection", connectionInput, connection, write, false, true, 201)
	add("GET", "/auth/v1/account/connections/{collection_id}/{connection_id}", "getAccountConnection", "Read a draft authentication connection", nil, connection, read, false, true, 200)
	add("PUT", "/auth/v1/account/connections/{collection_id}/{connection_id}", "updateAccountConnection", "Replace a draft authentication connection", connectionInput, connection, write, true, true, 200)
	add("DELETE", "/auth/v1/account/connections/{collection_id}/{connection_id}", "deleteAccountConnection", "Delete a draft authentication connection", nil, nil, write, true, false, 204)
	return nil
}
