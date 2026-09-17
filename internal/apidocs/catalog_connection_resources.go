package apidocs

import (
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

func addConnectionResourceOperations(doc *openapi3.T) error {
	str := openapi3.NewStringSchema()
	connection := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"id": str, "collection_id": str, "owner_subject": str, "state": openapi3.NewStringSchema().WithEnum("draft"), "revision": openapi3.NewInt64Schema().WithMin(1), "definition_revision": openapi3.NewInt64Schema().WithMin(1), "metadata": openapi3.NewObjectSchema(),
	}).WithRequired([]string{"id", "collection_id", "owner_subject", "state", "revision", "definition_revision", "metadata"})
	input := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"definition_revision": openapi3.NewInt64Schema().WithMin(1), "metadata": openapi3.NewObjectSchema()}).WithRequired([]string{"definition_revision", "metadata"})
	read, write := "goauthy.connections.read", "goauthy.connections.write"
	add := func(method, path, operationID string, body, response *openapi3.Schema, scope string, cas bool, status int) {
		op := &openapi3.Operation{OperationID: operationID, Summary: operationID, Description: "Requires a user Bearer access token with scope " + scope + ". Session cookies and machine tokens are not accepted.", Tags: []string{"Connections"}, Security: &openapi3.SecurityRequirements{{"bearerToken": {}}}, Responses: openapi3.NewResponses()}
		for _, name := range []string{"collection_id", "connection_id"} {
			if strings.Contains(path, "{"+name+"}") {
				op.AddParameter(openapi3.NewPathParameter(name).WithSchema(str))
			}
		}
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body)}
		}
		for _, code := range []int{400, 401, 404, 409, 503} {
			op.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
		}
		if cas {
			op.AddParameter(openapi3.NewHeaderParameter("If-Match").WithRequired(true).WithSchema(openapi3.NewStringSchema().WithPattern(`^"[1-9][0-9]*"$`)))
			op.AddResponse(428, openapi3.NewResponse().WithDescription("Strong quoted If-Match revision required"))
		}
		out := openapi3.NewResponse().WithDescription(http.StatusText(status))
		if response != nil && status != 204 {
			out.WithJSONSchema(response)
		}
		op.AddResponse(status, out)
		doc.AddOperation(path, method, op)
	}
	add("GET", "/auth/v1/connection-collections", "listConnectionCollections", nil, openapi3.NewArraySchema().WithItems(openapi3.NewObjectSchema()), read, false, 200)
	add("GET", "/auth/v1/connections/{collection_id}", "listResourceConnections", nil, openapi3.NewArraySchema().WithItems(connection), read, false, 200)
	add("POST", "/auth/v1/connections/{collection_id}", "createResourceConnection", input, connection, write, false, 201)
	add("GET", "/auth/v1/connections/{collection_id}/{connection_id}", "getResourceConnection", nil, connection, read, false, 200)
	add("PUT", "/auth/v1/connections/{collection_id}/{connection_id}", "updateResourceConnection", input, connection, write, true, 200)
	add("DELETE", "/auth/v1/connections/{collection_id}/{connection_id}", "deleteResourceConnection", nil, nil, write, true, 204)
	return nil
}
