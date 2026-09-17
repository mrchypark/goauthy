package apidocs

import (
	"fmt"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3gen"
	"github.com/mrchypark/goauthy/internal/kv"
)

// addKVOperations documents the namespace-admin and bearer-authenticated KV
// routes mounted by internal/kv/http.go.
func addKVOperations(doc *openapi3.T, features Features) error {
	_ = features
	if doc == nil || doc.Paths == nil {
		return fmt.Errorf("openapi document has no paths")
	}
	strict := func(props map[string]*openapi3.SchemaRef, required ...string) *openapi3.SchemaRef {
		s := openapi3.NewObjectSchema().WithoutAdditionalProperties()
		for name, schema := range props {
			s = s.WithPropertyRef(name, schema)
		}
		s = s.WithRequired(required)
		return &openapi3.SchemaRef{Value: s}
	}
	str := func() *openapi3.SchemaRef {
		return &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithPattern(`^[A-Za-z0-9-_/,:*\s]{2,64}$`)}
	}
	nsBody := strict(map[string]*openapi3.SchemaRef{"name": str(), "public": {Value: openapi3.NewBoolSchema()}}, "name")
	accessBody := strict(map[string]*openapi3.SchemaRef{"enabled": {Value: openapi3.NewBoolSchema()}, "name": {Value: str().Value.WithNullable()}}, "enabled")
	valueBody := strict(map[string]*openapi3.SchemaRef{
		"key":       {Value: openapi3.NewStringSchema().WithPattern(`^[A-Za-z0-9-_/,:*\s]{2,64}$`)},
		"encrypted": {Value: openapi3.NewBoolSchema()},
		"value":     {Value: openapi3.NewSchema().WithNullable()},
	}, "key", "value")
	if doc.Components == nil {
		components := openapi3.NewComponents()
		doc.Components = &components
	}
	nsResponse, err := openapi3gen.NewSchemaRefForValue([]kv.Namespace{}, doc.Components.Schemas)
	if err != nil {
		return err
	}
	accessResponse, err := openapi3gen.NewSchemaRefForValue([]kv.Access{}, doc.Components.Schemas)
	if err != nil {
		return err
	}
	accessObjectResponse, err := openapi3gen.NewSchemaRefForValue(kv.Access{}, doc.Components.Schemas)
	if err != nil {
		return err
	}
	valueResponse, err := openapi3gen.NewSchemaRefForValue([]kv.Value{}, doc.Components.Schemas)
	if err != nil {
		return err
	}
	// json.RawMessage is represented by the generator as an opaque object;
	// the wire contract accepts every JSON value, including null.
	valueResponse.Value.Items.Value.Properties["value"] = &openapi3.SchemaRef{Value: openapi3.NewSchema().WithNullable()}
	keyResponse, err := openapi3gen.NewSchemaRefForValue([]string{}, doc.Components.Schemas)
	if err != nil {
		return err
	}
	rawResponse := &openapi3.SchemaRef{Value: openapi3.NewSchema().WithNullable()}
	jsonResponse := func(status int, schema *openapi3.SchemaRef) *openapi3.ResponseRef {
		r := openapi3.NewResponse().WithDescription(http.StatusText(status))
		if schema != nil && (status == http.StatusOK || status == http.StatusCreated) {
			r.WithContent(openapi3.NewContentWithJSONSchema(schema.Value))
		}
		return &openapi3.ResponseRef{Value: r}
	}
	add := func(path, method, operationID string, body *openapi3.SchemaRef, statuses []int, security *openapi3.SecurityRequirements, query bool, params ...string) {
		op := openapi3.NewOperation()
		op.OperationID, op.Tags, op.Security = operationID, []string{"kv"}, security
		for _, name := range params {
			pattern := `^[A-Za-z0-9-_/,:*\s]{2,64}$`
			if name == "id" {
				pattern = `^[A-Za-z0-9]{16}$`
			}
			p := openapi3.NewPathParameter(name).WithSchema(openapi3.NewStringSchema().WithPattern(pattern))
			op.AddParameter(p)
		}
		if query {
			op.AddParameter(openapi3.NewQueryParameter("limit").WithSchema(openapi3.NewIntegerSchema().WithMin(0).WithMax(1000)))
			op.AddParameter(openapi3.NewQueryParameter("search").WithSchema(openapi3.NewStringSchema().WithMaxLength(64)))
		}
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body.Value)}
		}
		op.Responses = openapi3.NewResponses()
		for _, status := range statuses {
			var schema *openapi3.SchemaRef
			switch operationID {
			case "listKVNamespaces":
				schema = nsResponse
			case "listKVAccess":
				schema = accessResponse
			case "createKVAccess", "rotateKVAccessSecret":
				schema = accessObjectResponse
			case "listKVNamespaceValues", "listKVValues":
				schema = valueResponse
			case "listKVKeys":
				schema = keyResponse
			case "getPublicKVValue", "getKVValue":
				schema = rawResponse
			case "testKVAccess":
				schema = strict(map[string]*openapi3.SchemaRef{"id": {Value: openapi3.NewStringSchema().WithPattern(`^[A-Za-z0-9]{16}$`)}, "ns": str(), "name": {Value: str().Value.WithNullable()}}, "id", "ns", "name")
			default:
				schema = nil
			}
			op.Responses.Set(fmt.Sprint(status), jsonResponse(status, schema))
		}
		doc.AddOperation(path, method, op)
	}
	adminRead := &openapi3.SecurityRequirements{{"browserSession": {}}}
	adminWrite := &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}}
	bearer := &openapi3.SecurityRequirements{{"kvBearer": {}}}
	public := (*openapi3.SecurityRequirements)(nil)
	readAdmin := []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable}
	writeAdmin := []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable}
	readBearer := []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable}
	writeBearer := readBearer
	add("/auth/v1/kv/ns", "GET", "listKVNamespaces", nil, readAdmin, adminRead, false)
	add("/auth/v1/kv/ns", "POST", "createKVNamespace", nsBody, writeAdmin, adminWrite, false)
	add("/auth/v1/kv/ns/{ns}", "PUT", "updateKVNamespace", nsBody, writeAdmin, adminWrite, false, "ns")
	add("/auth/v1/kv/ns/{ns}", "DELETE", "deleteKVNamespace", nil, readAdmin, adminWrite, false, "ns")
	add("/auth/v1/kv/ns/{ns}/access", "GET", "listKVAccess", nil, readAdmin, adminRead, false, "ns")
	add("/auth/v1/kv/ns/{ns}/access", "POST", "createKVAccess", accessBody, []int{http.StatusCreated, http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable}, adminWrite, false, "ns")
	add("/auth/v1/kv/ns/{ns}/access/{id}", "PUT", "updateKVAccess", accessBody, readAdmin, adminWrite, false, "ns", "id")
	add("/auth/v1/kv/ns/{ns}/access/{id}", "DELETE", "deleteKVAccess", nil, readAdmin, adminWrite, false, "ns", "id")
	add("/auth/v1/kv/ns/{ns}/access/{id}/secret", "POST", "rotateKVAccessSecret", nil, readAdmin, adminWrite, false, "ns", "id")
	add("/auth/v1/kv/ns/{ns}/values", "GET", "listKVNamespaceValues", nil, readAdmin, adminRead, true, "ns")
	add("/auth/v1/kv/ns/{ns}/values", "POST", "createKVNamespaceValue", valueBody, writeAdmin, adminWrite, false, "ns")
	add("/auth/v1/kv/ns/{ns}/values", "PUT", "updateKVNamespaceValue", valueBody, writeAdmin, adminWrite, false, "ns")
	add("/auth/v1/kv/ns/{ns}/values/{key}", "DELETE", "deleteKVNamespaceValue", nil, readAdmin, adminWrite, false, "ns", "key")
	add("/auth/v1/kv/pub/{ns}/{key}", "GET", "getPublicKVValue", nil, []int{http.StatusOK, http.StatusBadRequest, http.StatusNotFound, http.StatusUnauthorized, http.StatusServiceUnavailable}, public, false, "ns", "key")
	add("/auth/v1/kv/keys", "GET", "listKVKeys", nil, readBearer, bearer, true)
	add("/auth/v1/kv/keys", "PUT", "setKVValue", valueBody, writeBearer, bearer, false)
	add("/auth/v1/kv/keys/{key}", "GET", "getKVValue", nil, readBearer, bearer, false, "key")
	add("/auth/v1/kv/keys/{key}", "DELETE", "deleteKVValue", nil, readBearer, bearer, false, "key")
	add("/auth/v1/kv/values", "GET", "listKVValues", nil, readBearer, bearer, true)
	add("/auth/v1/kv/test", "GET", "testKVAccess", nil, []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized, http.StatusServiceUnavailable}, bearer, false)
	return nil
}
