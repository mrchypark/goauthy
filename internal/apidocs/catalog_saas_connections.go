package apidocs

import (
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
)

// addSaaSConnectionOperations documents the browser-only OAuth2 connection
// flow. Connection ownership and authorization state remain server-side.
func addSaaSConnectionOperations(doc *openapi3.T) error {
	str := openapi3.NewStringSchema()
	path := func(name string) *openapi3.Parameter {
		return openapi3.NewPathParameter(name).WithSchema(str)
	}
	postBody := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"provider_id": str,
	}).WithRequired([]string{"provider_id"})
	startResponse := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"authorization_url": str,
	}).WithRequired([]string{"authorization_url"})
	callbackResponse := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"connected": openapi3.NewBoolSchema(), "account_id": str, "scopes": openapi3.NewArraySchema().WithItems(str),
	}).WithRequired([]string{"connected", "account_id", "scopes"})
	connectionStatus := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"connected": openapi3.NewBoolSchema(), "state": openapi3.NewStringSchema().WithEnum("draft", "ready", "refreshing", "uncertain", "reconnecting", "revoked"),
		"version": openapi3.NewInt64Schema().WithMin(0), "provider_id": str, "account_id": str, "scopes": openapi3.NewArraySchema().WithItems(str),
	}).WithRequired([]string{"connected", "state", "version", "provider_id", "account_id", "scopes"})
	add := func(method, route, operationID string, security *openapi3.SecurityRequirements, body, response *openapi3.Schema, params ...*openapi3.Parameter) {
		op := &openapi3.Operation{OperationID: operationID, Summary: operationID, Tags: []string{"Account connections"}, Security: security, Responses: openapi3.NewResponses()}
		op.Description = "Browser-session OAuth2 connection flow; provider credentials, authorization state, and connection ownership are retained server-side. No bearer or API-key authentication is accepted."
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body)}
		}
		for _, p := range params {
			op.AddParameter(p)
		}
		for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable} {
			op.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
		}
		ok := openapi3.NewResponse().WithDescription(http.StatusText(http.StatusOK)).WithJSONSchema(response)
		op.AddResponse(http.StatusOK, ok)
		doc.AddOperation(route, method, op)
	}
	postSecurity := &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}}
	getSecurity := &openapi3.SecurityRequirements{{"browserSession": {}}}
	add(http.MethodPost, "/auth/v1/account/connections/{collection_id}/{connection_id}/oauth2", "startAccountConnectionOAuth2", postSecurity, postBody, startResponse, path("collection_id"), path("connection_id"))
	statusPath := "/auth/v1/account/connections/{collection_id}/{connection_id}/oauth2"
	statusParams := []*openapi3.Parameter{path("collection_id"), path("connection_id")}
	add(http.MethodGet, statusPath, "getAccountConnectionOAuth2Status", getSecurity, nil, connectionStatus, statusParams...)
	reconnectBody := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"version": openapi3.NewInt64Schema().WithMin(1),
	}).WithRequired([]string{"version"})
	add(http.MethodPost, statusPath+"/reconnect", "reconnectAccountConnectionOAuth2", postSecurity, reconnectBody, connectionStatus, statusParams...)
	doc.Paths.Value(statusPath + "/reconnect").Post.Description = "Prepares a local OAuth2 reconnect for an already-revoked connection at the supplied current version. This operation makes no provider call and does not revoke provider-side authorization. Start a new OAuth2 authorization flow separately; successful completion increments the token version. The existing connection ID and metadata are preserved. No bearer or API-key authentication is accepted."
	refreshBody := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"version": openapi3.NewInt64Schema().WithMin(1),
	}).WithRequired([]string{"version"})
	add(http.MethodPost, statusPath+"/refresh", "refreshAccountConnectionOAuth2", postSecurity, refreshBody, connectionStatus, statusParams...)
	doc.Paths.Value(statusPath + "/refresh").Post.Description = "Refreshes the registered HTTPS OAuth2 provider connection using the caller-supplied current version as a CAS fence. Requires an HTTPS issuer, owner browser session and CSRF; Bearer/API-key authentication, query parameters and If-Match are rejected. The provider and stored account identity must match, and refreshed scopes must remain a subset of the stored scopes. This is one durable exchange with no automatic retry or background refresh; an uncertain outcome requires reconnect. The endpoint returns metadata only, never tokens or credential material, and is not an SDK credential-receipt API. Unknown access-token expiry is preserved as unknown and is not eligible for credential delivery."
	revokeBody := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"version": openapi3.NewInt64Schema().WithMin(1),
	}).WithRequired([]string{"version"})
	revoke := &openapi3.Operation{OperationID: "revokeAccountConnectionOAuth2", Summary: "revokeAccountConnectionOAuth2", Tags: []string{"Account connections"}, Security: postSecurity, Responses: openapi3.NewResponses()}
	revoke.Description = "Locally revokes the connection only; provider-side authorization is not revoked. Credentials and ownership remain server-side, and no bearer or API-key authentication is accepted."
	revoke.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(revokeBody)}
	revoke.AddParameter(statusParams[0])
	revoke.AddParameter(statusParams[1])
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable} {
		revoke.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
	}
	revoke.AddResponse(http.StatusNoContent, openapi3.NewResponse().WithDescription(http.StatusText(http.StatusNoContent)))
	doc.AddOperation(statusPath, http.MethodDelete, revoke)
	state := openapi3.NewQueryParameter("state").WithRequired(true).WithSchema(str)
	code := openapi3.NewQueryParameter("code").WithRequired(true).WithSchema(str)
	add(http.MethodGet, "/auth/v1/saas/callback/{provider_id}", "completeAccountConnectionOAuth2", getSecurity, nil, callbackResponse, path("provider_id"), state, code)
	callback := doc.Paths.Value("/auth/v1/saas/callback/{provider_id}").Get
	callback.Description += " Successful top-level document navigation (exactly one Sec-Fetch-Mode: navigate and Sec-Fetch-Dest: document) returns a static HTML completion page with a fixed account link. Other requests retain the JSON metadata response. Neither representation grants consumer service access; separate explicit consent is required. Callback code/state and credentials are never reflected into the HTML page."
	callback.Responses.Status(http.StatusOK).Value.Content["text/html"] = &openapi3.MediaType{Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}
	return nil
}
