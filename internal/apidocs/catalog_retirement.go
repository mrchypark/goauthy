package apidocs

import (
	"fmt"

	"github.com/getkin/kin-openapi/openapi3"
)

func addRetirementOperations(doc *openapi3.T, _ Features) error {
	if doc == nil || doc.Paths == nil {
		return fmt.Errorf("openapi document has no paths")
	}
	str := func() *openapi3.SchemaRef { return &openapi3.SchemaRef{Value: openapi3.NewStringSchema()} }
	integer := func() *openapi3.SchemaRef { return &openapi3.SchemaRef{Value: openapi3.NewInt64Schema()} }
	strict := func(fields map[string]*openapi3.SchemaRef, required ...string) *openapi3.SchemaRef {
		s := openapi3.NewObjectSchema().WithoutAdditionalProperties()
		for n, v := range fields {
			s = s.WithPropertyRef(n, v)
		}
		s.Required = required
		return &openapi3.SchemaRef{Value: s}
	}
	prepare := strict(map[string]*openapi3.SchemaRef{"epoch": integer(), "old_key_id": str(), "replacement_key_id": str()}, "epoch", "old_key_id", "replacement_key_id")
	epoch := strict(map[string]*openapi3.SchemaRef{"epoch": integer()}, "epoch")
	prepare.Value.Properties["epoch"].Value.WithMin(1)
	epoch.Value.Properties["epoch"].Value.WithMin(1)
	prepare.Value.Properties["old_key_id"].Value.WithMinLength(1)
	prepare.Value.Properties["replacement_key_id"].Value.WithMinLength(1)
	status := strict(map[string]*openapi3.SchemaRef{"old_references": integer(), "non_active_references": integer(), "legacy_references": integer(), "tamper_references": integer(), "oidc_references": integer(), "dcr_references": integer(), "upstream_references": integer(), "passkey_enabled": {Value: openapi3.NewBoolSchema()}, "passkey_references": integer()}, "old_references", "non_active_references", "legacy_references", "tamper_references", "oidc_references", "dcr_references", "upstream_references", "passkey_enabled", "passkey_references")
	attestation := strict(map[string]*openapi3.SchemaRef{"node_id": str(), "boot_id": str(), "active_key_id": str(), "attestation_sequence": integer(), "attested_at_unix_ms": integer(), "status": status}, "node_id", "boot_id", "active_key_id", "attestation_sequence", "attested_at_unix_ms", "status")
	response := strict(map[string]*openapi3.SchemaRef{"epoch": integer(), "old_key_id": str(), "replacement_key_id": str(), "membership": {Value: openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema())}, "membership_digest": str(), "state": str(), "prepared_at_unix_ms": integer(), "fenced_at_unix_ms": integer(), "ready_at_unix_ms": integer(), "aborted_at_unix_ms": integer(), "attestations": {Value: openapi3.NewArraySchema().WithItems(attestation.Value)}}, "epoch", "old_key_id", "replacement_key_id", "membership", "membership_digest", "state", "prepared_at_unix_ms", "attestations")
	add := func(path, method string, body *openapi3.SchemaRef, statuses ...int) {
		op := openapi3.NewOperation()
		op.OperationID = method + path
		op.Tags = []string{"master-key-retirement"}
		op.Description = "Requires API-Key authorization for Secrets:read."
		if method == "POST" {
			op.Description = "The {action} path selects prepare (epoch, old_key_id, replacement_key_id; Secrets:create) or fence/ready/abort (epoch only; Secrets:update/delete respectively)."
		}
		op.Security = &openapi3.SecurityRequirements{{"apiKey": {}}}
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body.Value)}
		}
		op.Responses = openapi3.NewResponses()
		for _, code := range statuses {
			r := openapi3.NewResponse().WithDescription(fmt.Sprint(code))
			if code == 200 {
				r = r.WithJSONSchema(response.Value)
			}
			op.Responses.Set(fmt.Sprint(code), &openapi3.ResponseRef{Value: r})
		}
		doc.AddOperation(path, method, op)
	}
	add("/auth/v1/master_key_retirement", "GET", nil, 200, 400, 401, 403, 404, 503)
	actionBody := &openapi3.SchemaRef{Value: openapi3.NewOneOfSchema(prepare.Value, epoch.Value)}
	add("/auth/v1/master_key_retirement/{action}", "POST", actionBody, 200, 400, 401, 403, 404, 409, 503)
	p := doc.Paths.Value("/auth/v1/master_key_retirement/{action}")
	p.Parameters = append(p.Parameters, &openapi3.ParameterRef{Value: openapi3.NewPathParameter("action").WithRequired(true).WithSchema(openapi3.NewStringSchema().WithEnum("prepare", "fence", "ready", "abort"))})
	return nil
}
