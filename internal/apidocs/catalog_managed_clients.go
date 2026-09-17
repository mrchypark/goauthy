package apidocs

import (
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

func addManagedClientOperations(doc *openapi3.T) {
	str := openapi3.NewStringSchema()
	prefix := openapi3.NewStringSchema().WithNullable().WithPattern(`^[a-zA-Z0-9-_/,:*\s]{2,64}$`)
	prefix.Description = "Raw case-sensitive group-name prefix required for user admission. Null or omission on PUT clears the restriction."
	backchannel := openapi3.NewStringSchema().WithNullable().WithPattern(`^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%@]+$`)
	backchannel.Description = "Registered backchannel logout URI metadata. Null or omission on PUT clears it. Updates synchronize existing login associations; logout queues delivery to the registered URI with separate outbound network security checks."
	list := openapi3.NewArraySchema().WithItems(str)
	object := func(fields map[string]*openapi3.Schema, required ...string) *openapi3.Schema {
		s := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithRequired(required)
		for key, value := range fields {
			s.WithProperty(key, value)
		}
		return s
	}
	fields := func() map[string]*openapi3.Schema {
		return map[string]*openapi3.Schema{
			"backchannel_logout_uri": backchannel, "restrict_group_prefix": prefix, "name": openapi3.NewStringSchema().WithNullable(), "confidential": openapi3.NewBoolSchema(),
			"redirect_uris": list, "enabled": openapi3.NewBoolSchema(), "scopes": list,
			"default_scopes": list, "enabled_flows": list, "audience": openapi3.NewArraySchema().WithItems(str), "default_aud": openapi3.NewArraySchema().WithItems(str),
		}
	}
	update := object(fields(), "confidential", "redirect_uris", "enabled", "scopes", "default_scopes", "enabled_flows")
	responseFields := fields()
	responseFields["id"], responseFields["revision"] = str, openapi3.NewInt64Schema().WithMin(1)
	client := object(responseFields, "id", "revision", "name", "confidential", "redirect_uris", "enabled", "scopes", "default_scopes", "enabled_flows", "audience", "default_aud")
	create := object(map[string]*openapi3.Schema{"id": str, "backchannel_logout_uri": backchannel, "restrict_group_prefix": prefix, "name": openapi3.NewStringSchema().WithNullable(), "confidential": openapi3.NewBoolSchema(), "redirect_uris": list, "audience": openapi3.NewArraySchema().WithItems(str), "default_aud": openapi3.NewArraySchema().WithItems(str)}, "id", "confidential", "redirect_uris")
	create.WithProperty("scopes", list).WithProperty("default_scopes", list).WithProperty("enabled_flows", list)
	create.Description = "default_aud configures independent default access-token audiences across grants, included alongside any explicitly granted resource. Defaults do not expand the resource request allow-list. Token exchange is admitted only for confidential clients with the explicit token-exchange enabled_flow. Optional initial scopes, default_scopes, enabled_flows and audience configure the client atomically. Omitted or empty audience allows no explicitly requested resource audience. Entries must be unique absolute HTTPS URLs without userinfo, query or fragment, at most 32 entries of 2048 bytes each. Token requests also require the resource in the server allow-list. Empty redirect_uris are valid only when authorization_code is not enabled. Device-only public clients require no client secret or synthetic callback URL."
	update.Description = "Omit audience or default_aud to preserve that policy; send [] to clear it. A changed audience policy invalidates the previous client generation and its tokens."
	secret := object(map[string]*openapi3.Schema{"secret": str}, "secret")
	read := &openapi3.SecurityRequirements{{"browserSession": {}}, {"apiKey": {}}}
	write := &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}, {"apiKey": {}}}
	add := func(method, path, summary, rights string, code int, body, result *openapi3.Schema, auth *openapi3.SecurityRequirements, cas bool) {
		op := &openapi3.Operation{OperationID: method + path, Summary: summary, Tags: []string{"Administration"}, Security: auth, Responses: openapi3.NewResponses()}
		op.Description = "Requires direct administrator authority or API-key " + rights + ". Only managed clients are exposed; bootstrap and DCR ownership cannot be changed here. Unsupported policies are rejected."
		if strings.Contains(path, "{id}") {
			op.AddParameter(openapi3.NewPathParameter("id").WithSchema(str))
		}
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body)}
		}
		for _, status := range []int{400, 401, 403, 404, 409, 503} {
			op.AddResponse(status, openapi3.NewResponse().WithDescription(http.StatusText(status)))
		}
		response := openapi3.NewResponse().WithDescription(http.StatusText(code))
		if result != nil {
			response.WithJSONSchema(result)
		}
		if code != 204 && strings.Contains(path, "{id}") && !strings.HasSuffix(path, "/secret") || code == 201 || method == "PUT" && strings.HasSuffix(path, "/secret") {
			response.Headers = openapi3.Headers{"ETag": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: str}, Description: "Strong quoted revision"}}}
		}
		if strings.HasSuffix(path, "/secret") {
			op.Description += " Response is no-store. Request body must be empty; old-secret grace periods are not supported."
		}
		op.AddResponse(code, response)
		if cas {
			op.AddParameter(openapi3.NewHeaderParameter("If-Match").WithRequired(true).WithSchema(openapi3.NewStringSchema().WithPattern(`^"[1-9][0-9]*"$`)))
			op.AddResponse(428, openapi3.NewResponse().WithDescription("Strong quoted If-Match revision required"))
		}
		doc.AddOperation(path, method, op)
	}
	add("GET", "/auth/v1/clients", "List managed clients", "Clients.Read", 200, nil, openapi3.NewArraySchema().WithItems(client), read, false)
	add("POST", "/auth/v1/clients", "Create managed client", "Clients.Create", 201, create, client, write, false)
	add("GET", "/auth/v1/clients/{id}", "Read managed client", "Clients.Read", 200, nil, client, read, false)
	add("PUT", "/auth/v1/clients/{id}", "Replace managed client configuration", "Clients.Update", 200, update, client, write, true)
	doc.Paths.Value("/auth/v1/clients/{id}").Put.Description += " Omit audience or default_aud to preserve that policy; send [] to clear it. A changed audience policy invalidates the previous client generation and its tokens."
	add("DELETE", "/auth/v1/clients/{id}", "Delete managed client", "Clients.Delete", 204, nil, nil, write, true)
	add("POST", "/auth/v1/clients/{id}/secret", "Read client secret", "Secrets.Read", 200, nil, secret, write, false)
	add("PUT", "/auth/v1/clients/{id}/secret", "Rotate client secret", "Secrets.Update", 200, nil, secret, write, true)
}
