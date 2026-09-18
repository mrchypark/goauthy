package apidocs

import (
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
)

func addAccountDeviceOperations(doc *openapi3.T) error {
	str := openapi3.NewStringSchema()
	device := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"id": str, "client_id": str, "scopes": openapi3.NewArraySchema().WithItems(str),
		"created_at_unix_ms": openapi3.NewInt64Schema().WithMin(0), "revoked_at_unix_ms": openapi3.NewInt64Schema().WithMin(0).WithNullable(),
	}).WithRequired([]string{"id", "client_id", "scopes", "created_at_unix_ms"})
	browserRead := &openapi3.SecurityRequirements{{"browserSession": {}}}
	browserWrite := &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}}
	add := func(method, path, id string, security *openapi3.SecurityRequirements, body *openapi3.Schema, response *openapi3.Schema, code int) {
		op := &openapi3.Operation{OperationID: id, Summary: id, Tags: []string{"Account devices"}, Security: security, Responses: openapi3.NewResponses()}
		if path == "/auth/v1/account/devices/{id}" {
			op.AddParameter(openapi3.NewPathParameter("id").WithSchema(str))
		}
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body)}
		}
		for _, status := range []int{400, 401, 404, 409, 503} {
			op.AddResponse(status, openapi3.NewResponse().WithDescription(http.StatusText(status)))
		}
		resp := openapi3.NewResponse().WithDescription(http.StatusText(code))
		if response != nil {
			resp.WithJSONSchema(response)
		}
		op.AddResponse(code, resp)
		doc.AddOperation(path, method, op)
	}
	add("GET", "/auth/v1/account/devices", "listAccountDevices", browserRead, nil, openapi3.NewArraySchema().WithItems(device), 200)
	add("DELETE", "/auth/v1/account/devices/{id}", "deleteAccountDevice", browserWrite, nil, nil, 204)
	return nil
}
