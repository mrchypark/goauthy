package apidocs

import (
	"github.com/getkin/kin-openapi/openapi3"
	"net/http"
)

func addConnectionAPIKeyOperations(doc *openapi3.T) error {
	str := openapi3.NewStringSchema()
	path := "/auth/v1/account/connections/{collection_id}/{connection_id}/api-key"
	status := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"registered": openapi3.NewBoolSchema(), "version": openapi3.NewInt64Schema().WithMin(0)}).WithRequired([]string{"registered", "version"})
	apiKey := openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(2048)
	apiKey.WriteOnly = true
	connectorDigest := openapi3.NewStringSchema().WithMinLength(43).WithMaxLength(43)
	connectorDigest.Description = "Optional registered API-key connector digest. Owners must first fetch and review the connector metadata; a supplied digest must match the currently registered provider connector. Omit for legacy API-key collections."
	put := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"api_key": apiKey, "version": openapi3.NewInt64Schema().WithMin(0), "connector_digest": connectorDigest}).WithRequired([]string{"api_key", "version"})
	remove := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"version": openapi3.NewInt64Schema().WithMin(1)}).WithRequired([]string{"version"})
	read := &openapi3.SecurityRequirements{{"browserSession": {}}}
	write := &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}}
	add := func(method string, body, response *openapi3.Schema, security *openapi3.SecurityRequirements, code int) {
		op := &openapi3.Operation{OperationID: method + "ConnectionAPIKey", Summary: "Manage connection API key", Tags: []string{"Connections"}, Security: security, Responses: openapi3.NewResponses()}
		op.AddParameter(openapi3.NewPathParameter("collection_id").WithSchema(str))
		op.AddParameter(openapi3.NewPathParameter("connection_id").WithSchema(str))
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body)}
		}
		for _, c := range []int{400, 401, 404, 409, 503} {
			op.AddResponse(c, openapi3.NewResponse().WithDescription(http.StatusText(c)))
		}
		out := openapi3.NewResponse().WithDescription(http.StatusText(code))
		if response != nil {
			out.WithJSONSchema(response)
		}
		op.AddResponse(code, out)
		doc.AddOperation(path, method, op)
	}
	add("GET", nil, status, read, 200)
	add("PUT", put, status, write, 200)
	add("DELETE", remove, nil, write, 204)
	connector := &openapi3.Operation{OperationID: "getAccountConnectionAPIKeyConnector", Summary: "Review connection API key connector", Tags: []string{"Connections"}, Security: read, Responses: openapi3.NewResponses()}
	connector.Description = "Owner-only browser-session metadata for the registered API-key connector. No request body, query parameters, or If-Match header are accepted. Fetch and review the digest before binding an API key with PUT. Legacy API-key collections have no registered connector."
	connector.AddParameter(openapi3.NewPathParameter("collection_id").WithSchema(str))
	connector.AddParameter(openapi3.NewPathParameter("connection_id").WithSchema(str))
	for _, code := range []int{400, 401, 404, 409, 503} {
		connector.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
	}
	connector.AddResponse(200, openapi3.NewResponse().WithDescription(http.StatusText(200)).WithJSONSchema(apiKeyConnectorInfoSchema()))
	doc.AddOperation(path+"/connector", "GET", connector)
	return nil
}

func apiKeyConnectorInfoSchema() *openapi3.Schema {
	str := openapi3.NewStringSchema()
	responseFields := openapi3.NewObjectSchema()
	responseFields.AdditionalProperties = openapi3.BoolSchema{Schema: &openapi3.SchemaRef{Value: str}}
	operation := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"id": str, "method": str, "url": str, "response_fields": responseFields,
	}).WithRequired([]string{"id", "method", "url", "response_fields"})
	return openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"id": str, "digest": str, "header": str, "prefix": str,
		"operations": openapi3.NewArraySchema().WithItems(operation),
	}).WithRequired([]string{"id", "digest", "header", "prefix", "operations"})
}
