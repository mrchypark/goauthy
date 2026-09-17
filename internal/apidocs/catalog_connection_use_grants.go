package apidocs

import (
	"math"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
)

// addConnectionUseGrantOperations documents stored consent and narrow consumer
// boundaries; invocation and delivery are not a general SDK proxy.
func addConnectionUseGrantOperations(doc *openapi3.T) error {
	str := openapi3.NewStringSchema()
	path := func(name string) *openapi3.Parameter { return openapi3.NewPathParameter(name).WithSchema(str) }
	read := &openapi3.SecurityRequirements{{"browserSession": {}}}
	write := &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}}
	allowRefresh := openapi3.NewBoolSchema().WithDefault(false)
	input := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"consumer_client_id": str,
		"mode":               openapi3.NewStringSchema().WithEnum("proxy", "credential_delivery"),
		"purpose":            openapi3.NewStringSchema().WithMaxLength(256),
		"expires_at_unix_ms": openapi3.NewInt64Schema(),
		"connector_digest":   openapi3.NewStringSchema().WithPattern(`^[A-Za-z0-9_-]{42}[AQgw]$`),
		"credential_version": openapi3.NewInt64Schema().WithMin(1),
		"allow_refresh":      allowRefresh,
	}).WithRequired([]string{"consumer_client_id", "mode", "purpose", "expires_at_unix_ms"})
	grant := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"id": str, "owner_subject": str, "collection_id": str, "connection_id": str,
		"consumer_client_id": str, "mode": openapi3.NewStringSchema().WithEnum("proxy", "credential_delivery"),
		"purpose": openapi3.NewStringSchema().WithMaxLength(256), "resource": str, "generation": str,
		"consumer_generation": str, "provider_id": str, "connector_digest": str,
		"revision": openapi3.NewInt64Schema().WithMin(1), "provider_revision": openapi3.NewInt64Schema().WithMin(0),
		"expires_at_unix_ms": openapi3.NewInt64Schema(), "revoked": openapi3.NewBoolSchema(),
		"allow_refresh": allowRefresh,
	}).WithRequired([]string{"id", "owner_subject", "collection_id", "connection_id", "consumer_client_id", "mode", "purpose", "resource", "generation", "consumer_generation", "provider_id", "connector_digest", "revision", "provider_revision", "expires_at_unix_ms", "revoked"})
	route := "/auth/v1/account/connections/{collection_id}/{connection_id}/grants"
	add := func(route, method, operationID string, security *openapi3.SecurityRequirements, body, response *openapi3.Schema, params ...*openapi3.Parameter) *openapi3.Operation {
		op := &openapi3.Operation{OperationID: operationID, Summary: operationID, Tags: []string{"Account connections"}, Security: security, Responses: openapi3.NewResponses()}
		op.Description = "Stored consent metadata only; purpose is descriptive and does not restrict downstream use. Managed consumers must have the use scope and exact configured resource audience; credential delivery requires a confidential consumer. Exports cannot be recalled once delivered. No bearer or API-key authentication is accepted."
		for _, p := range params {
			op.AddParameter(p)
		}
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body)}
		}
		for _, status := range []int{400, 401, 404, 409, 503} {
			op.AddResponse(status, openapi3.NewResponse().WithDescription(http.StatusText(status)))
		}
		if method == http.MethodDelete {
			op.AddResponse(http.StatusPreconditionRequired, openapi3.NewResponse().WithDescription(http.StatusText(http.StatusPreconditionRequired)))
			op.AddResponse(http.StatusNoContent, openapi3.NewResponse().WithDescription(http.StatusText(http.StatusNoContent)))
		} else {
			status := http.StatusOK
			responseOut := openapi3.NewResponse().WithDescription(http.StatusText(status)).WithJSONSchema(response)
			if method == http.MethodPost {
				status = http.StatusCreated
				responseOut = openapi3.NewResponse().WithDescription(http.StatusText(status)).WithJSONSchema(response)
				responseOut.Headers = openapi3.Headers{"ETag": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: str}, Description: "Strong quoted grant revision"}}}
			}
			op.AddResponse(status, responseOut)
		}
		doc.AddOperation(route, method, op)
		return op
	}
	params := []*openapi3.Parameter{path("collection_id"), path("connection_id")}
	listOp := add(route, http.MethodGet, "listAccountConnectionUseGrants", read, nil, openapi3.NewArraySchema().WithMaxItems(256).WithItems(grant), params...)
	listOp.Description += " Results are newest-expiry first and capped at 256 records."
	createOp := add(route, http.MethodPost, "createAccountConnectionUseGrant", write, input, grant, params...)
	createOp.Description += " At most 32 active stored consents are allowed per connection; expiry must be in the future and no more than 30 days away."
	createOp.Description += " Optional credential_version is an OAuth-only reviewed snapshot precondition: it must match the current credential version or creation returns 409. The owner OAuth approval screen always supplies it; omission preserves existing direct API behavior. API-key consent uses connector_digest instead."
	grantID := path("grant_id")
	grantRoute := route + "/{grant_id}"
	deleteOp := add(grantRoute, http.MethodDelete, "revokeAccountConnectionUseGrant", write, nil, nil, path("collection_id"), path("connection_id"), grantID)
	deleteOp.AddParameter(openapi3.NewHeaderParameter("If-Match").WithRequired(true).WithSchema(openapi3.NewStringSchema().WithPattern(`^"[1-9][0-9]*"$`)))
	deleteOp.Description += " This revokes stored consent locally; it does not revoke provider authorization."
	oauth2Status := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"provider_id": str, "account_id": str, "scopes": openapi3.NewArraySchema().WithMaxItems(64).WithItems(str),
		"version": openapi3.NewInt64Schema().WithMin(1), "connected": openapi3.NewBoolSchema(), "state": str,
	}).WithRequired([]string{"provider_id", "account_id", "scopes", "version", "connected", "state"})
	statusEnvelope := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"grant": grant, "connection_generation": str,
	}).WithRequired([]string{"grant", "connection_generation"})
	status := &openapi3.Operation{OperationID: "getConnectionUseGrantStatus", Summary: "Get connection use grant status", Tags: []string{"Connections"}, Security: &openapi3.SecurityRequirements{{"bearerToken": {}}}, Responses: openapi3.NewResponses()}
	status.Description = "Bearer-only grant metadata status for the authenticated human owner. Requires goauthy.connections.read and the exact configured GOAUTHY_CONNECTIONS_RESOURCE audience; the token owner is authoritative, and the consumer client may be any target recorded on the grant. Cookies, query parameters, request bodies, machine tokens, token exchange, and DPoP are not accepted. Returns stored metadata including revoked or expired grants, with the expected consumer and connection generation and connector digest comparison. This is not an execution capability or OAuth/SDK readiness signal. Response is Cache-Control: no-store."
	for _, p := range []*openapi3.Parameter{path("collection_id"), path("connection_id"), grantID} {
		status.AddParameter(p)
	}
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable} {
		status.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
	}
	statusResponse := openapi3.NewResponse().WithDescription(http.StatusText(http.StatusOK)).WithJSONSchema(statusEnvelope)
	statusResponse.Headers = openapi3.Headers{"Cache-Control": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: str}, Description: "Always no-store", Example: "no-store"}}}
	status.AddResponse(http.StatusOK, statusResponse)
	doc.AddOperation("/auth/v1/connections/{collection_id}/{connection_id}/grants/{grant_id}", http.MethodGet, status)
	refreshVersion := openapi3.NewInt64Schema().WithMin(1).WithMax(float64(math.MaxInt64))
	refreshVersion.WithExclusiveMax(true)
	refreshBody := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"credential_version": refreshVersion}).WithRequired([]string{"credential_version"})
	refresh := &openapi3.Operation{OperationID: "refreshConnectionCredential", Summary: "Refresh connection credential", Tags: []string{"Connections"}, Security: &openapi3.SecurityRequirements{{"bearerToken": {}}}, Responses: openapi3.NewResponses()}
	refresh.Description = "Bearer-only explicit OAuth2 credential refresh for a confidential consumer's allow_refresh consent. Requires the human consumer's goauthy.connections.use token, exact GOAUTHY_CONNECTIONS_RESOURCE audience and HTTPS issuer. Cookies, Origin, Sec-Fetch-Site, query parameters, If-Match, CSRF headers, machine tokens, token exchange and DPoP are rejected. The strict body contains only credential_version; the response is public OAuth2 status metadata (provider, account, scopes, version, connected, state), never credentials. The provider is called at most once under the grant, client and authority guards; expired access tokens may refresh, but expired consumer authority or consent cannot. Stale versions do not call upstream. Unknown outcomes fail closed; recheck metadata and reconnect rather than blindly retrying. This is explicit only: delivery never refreshes automatically and no background scheduler exists."
	refresh.AddParameter(grantID)
	refresh.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(refreshBody)}
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusBadGateway, http.StatusServiceUnavailable} {
		refresh.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
	}
	refresh.AddResponse(http.StatusOK, openapi3.NewResponse().WithDescription(http.StatusText(http.StatusOK)).WithJSONSchema(oauth2Status))
	doc.AddOperation("/auth/v1/connection-grants/{grant_id}/refresh", http.MethodPost, refresh)
	credentialStatus := &openapi3.Operation{OperationID: "getConnectionCredentialStatus", Summary: "Get connection credential status", Tags: []string{"Connections"}, Security: &openapi3.SecurityRequirements{{"bearerToken": {}}}, Responses: openapi3.NewResponses()}
	credentialStatus.Description = "Bearer-only, metadata-only OAuth2 credential status for the authenticated confidential human consumer. Requires current credential_delivery consent, goauthy.connections.use and the exact GOAUTHY_CONNECTIONS_RESOURCE audience. Cookies, Origin, Sec-Fetch-Site, query parameters, request bodies, If-Match, CSRF headers, machine tokens, token exchange and DPoP are rejected. API-key and proxy grants are unavailable. The response exposes only provider_id, account_id, scopes, version, connected and state; it performs no upstream call or mutation. Expired access tokens remain inspectable, while expired/revoked grants or changed authority return 404. refreshing, uncertain and revoked states do not authorize retry; consult the owner."
	credentialStatus.AddParameter(grantID)
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable} {
		credentialStatus.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
	}
	credentialStatusResponse := openapi3.NewResponse().WithDescription(http.StatusText(http.StatusOK)).WithJSONSchema(oauth2Status)
	credentialStatusResponse.Headers = openapi3.Headers{"Cache-Control": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: str}, Description: "Always no-store", Example: "no-store"}}}
	credentialStatus.AddResponse(http.StatusOK, credentialStatusResponse)
	doc.AddOperation("/auth/v1/connection-grants/{grant_id}/credential-status", http.MethodGet, credentialStatus)
	handoffInput := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"collection_id": str, "connection_id": str, "consumer_client_id": str,
		"mode": openapi3.NewStringSchema().WithEnum("proxy", "credential_delivery"), "purpose": openapi3.NewStringSchema().WithMaxLength(256),
		"expires_at_unix_ms": openapi3.NewInt64Schema(), "return_uri": openapi3.NewStringSchema().WithMaxLength(2048),
		"state":         openapi3.NewStringSchema().WithMinLength(32).WithMaxLength(128).WithPattern(`^[A-Za-z0-9_-]+$`),
		"allow_refresh": allowRefresh,
	}).WithRequired([]string{"collection_id", "connection_id", "consumer_client_id", "mode", "purpose", "expires_at_unix_ms", "return_uri", "state"})
	oauth2Review := oauth2Status
	handoffReview := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"request_client_id": str, "return_uri": str, "expires_at_unix_ms": openapi3.NewInt64Schema(), "grant": grant,
		"connector": apiKeyConnectorInfoSchema(), "oauth2": oauth2Review, "review_digest": openapi3.NewStringSchema().WithMinLength(1),
	}).WithRequired([]string{"request_client_id", "return_uri", "expires_at_unix_ms", "grant", "connector", "review_digest"})
	handoffCreateResponse := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"id": str, "review_uri": str, "review": handoffReview,
	}).WithRequired([]string{"id", "review_uri", "review"})
	handoffCompleteResponse := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"return_uri": str}).WithRequired([]string{"return_uri"})
	handoffCreate := &openapi3.Operation{OperationID: "createConnectionHandoff", Summary: "Create connection handoff", Tags: []string{"Connections"}, Security: &openapi3.SecurityRequirements{{"bearerToken": {}}}, Responses: openapi3.NewResponses()}
	handoffCreate.Description = "Bearer-only human consumer proposal; requires goauthy.connections.write and the exact configured GOAUTHY_CONNECTIONS_RESOURCE audience. The token owner and requesting client are authoritative, and cookies, query parameters, API keys, machine tokens, token exchange, and DPoP are rejected. This creates no implicit consent: review_uri opens the HTML owner review page, while the /auth/v1/account/connection-handoffs/{handoff_id} route remains the JSON review endpoint. Registered API-key connections support proxy and credential_delivery; OAuth2 connections support credential_delivery only and require a confidential consumer. credential_delivery is a separate exact consent mode and never upgrades proxy consent. Approval warns that a raw API key's use cannot be constrained after delivery and consent expiry only stops future retrieval; it cannot recall a delivered key. Pending tickets are one-use, cryptorandom, owner-bound, limited to 16 per owner, and expire within 5 minutes (and no later than the requested grant expiry, capped at 30 days). The caller must retain its session state and verify returned grant metadata. No credential is delivered by this proposal endpoint."
	handoffCreate.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(handoffInput)}
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable} {
		handoffCreate.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
	}
	handoffCreate.AddResponse(http.StatusCreated, openapi3.NewResponse().WithDescription(http.StatusText(http.StatusCreated)).WithJSONSchema(handoffCreateResponse))
	doc.AddOperation("/auth/v1/connection-handoffs", http.MethodPost, handoffCreate)
	handoffPath := "/auth/v1/account/connection-handoffs/{handoff_id}"
	ownerHandoff := func(method string, body, response *openapi3.Schema, security *openapi3.SecurityRequirements, id string) *openapi3.Operation {
		op := &openapi3.Operation{OperationID: id, Summary: id, Tags: []string{"Connections"}, Security: security, Responses: openapi3.NewResponses()}
		op.Description = "Owner browser-session handoff review; this JSON endpoint never redirects or returns credentials."
		op.AddParameter(path("handoff_id"))
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body)}
		}
		for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable} {
			op.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
		}
		op.AddResponse(http.StatusOK, openapi3.NewResponse().WithDescription(http.StatusText(http.StatusOK)).WithJSONSchema(response))
		doc.AddOperation(handoffPath, method, op)
		return op
	}
	ownerGet := ownerHandoff(http.MethodGet, nil, handoffReview, &openapi3.SecurityRequirements{{"browserSession": {}}}, "getConnectionHandoffReview")
	ownerGet.Description += " Empty body and no query parameters are accepted."
	ownerPostBody := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"approve": openapi3.NewBoolSchema(), "review_digest": openapi3.NewStringSchema().WithMinLength(1), "connector_digest": openapi3.NewStringSchema().WithPattern(`^[A-Za-z0-9_-]{42}[AQgw]$`),
	}).WithRequired([]string{"approve"})
	ownerPostBody.OneOf = []*openapi3.SchemaRef{
		{Value: openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"approve": openapi3.NewBoolSchema().WithEnum(true), "review_digest": openapi3.NewStringSchema().WithMinLength(1)}).WithRequired([]string{"approve", "review_digest"})},
		{Value: openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"approve": openapi3.NewBoolSchema().WithEnum(true), "connector_digest": openapi3.NewStringSchema().WithPattern(`^[A-Za-z0-9_-]{42}[AQgw]$`)}).WithRequired([]string{"approve", "connector_digest"})},
		{Value: openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"approve": openapi3.NewBoolSchema().WithEnum(false)}).WithRequired([]string{"approve"})},
	}
	ownerPost := ownerHandoff(http.MethodPost, ownerPostBody, handoffCompleteResponse, &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}}, "completeConnectionHandoff")
	ownerPost.Description += " Approval accepts exactly one nonempty reviewed review_digest or legacy connector_digest; denial accepts neither. Approval binds the reviewed OAuth credential_version snapshot with connection generation and provider revision. The BFF must authenticate and consume cryptorandom expiring state bound to its own session, retain the proposed OAuth version for context, then recheck grant status against server-stored expected owner, connection, consumer, mode, resource, digest, generation, provider revision, revocation and expiry. OAuth refresh after approval is valid for the same consent and delivery reports the current version. Callback fields must not define those expectations. Responses are no-store."
	ownerPost.Description += " The grant digest comparison applies only to API-key connector_digest. OAuth grant connector_digest is empty and must never be compared to the one-ticket review_digest. Validate delivered OAuth account, scopes and current token expiry separately; do not pin post-approval delivery to the reviewed version."
	pageResponse := func(code int) *openapi3.Response {
		r := openapi3.NewResponse().WithDescription(http.StatusText(code))
		if code == http.StatusOK {
			r.Content = openapi3.Content{"text/html": {Schema: &openapi3.SchemaRef{Value: str}}}
			r.Headers = openapi3.Headers{
				"Cache-Control":           {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: str}, Description: "no-store", Example: "no-store"}},
				"Referrer-Policy":         {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: str}, Description: "no-referrer", Example: "no-referrer"}},
				"Content-Security-Policy": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: str}, Description: "Self-only form and frame policy"}},
			}
		}
		return r
	}
	page := &openapi3.Operation{OperationID: "getConnectionHandoffPage", Summary: "Review connection handoff page", Tags: []string{"Connections"}, Security: &openapi3.SecurityRequirements{}, Responses: openapi3.NewResponses()}
	page.Description = "HTML owner handoff page. Unauthenticated GET redirects 303 to connection-login; authenticated GET renders the review. No Bearer/API-key authentication is accepted. Responses are no-store, no-referrer, and protected by a self-only CSP; GET has no body or query parameters."
	page.AddParameter(path("handoff_id"))
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable} {
		page.AddResponse(code, pageResponse(code))
	}
	page.AddResponse(http.StatusSeeOther, pageResponse(http.StatusSeeOther))
	page.AddResponse(http.StatusOK, pageResponse(http.StatusOK))
	doc.AddOperation("/account/connection-handoffs/{handoff_id}", http.MethodGet, page)
	decisionForm := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"decision": openapi3.NewStringSchema().WithEnum("approve", "deny"), "csrf_token": str,
		"reviewed": openapi3.NewStringSchema().WithEnum("yes"), "review_digest": openapi3.NewStringSchema().WithMinLength(1), "connector_digest": openapi3.NewStringSchema().WithPattern(`^[A-Za-z0-9_-]{42}[AQgw]$`),
	}).WithRequired([]string{"decision", "csrf_token"})
	decisionForm.OneOf = []*openapi3.SchemaRef{
		{Value: openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"decision": openapi3.NewStringSchema().WithEnum("approve"), "csrf_token": str, "reviewed": openapi3.NewStringSchema().WithEnum("yes"), "review_digest": openapi3.NewStringSchema().WithMinLength(1)}).WithRequired([]string{"decision", "csrf_token", "reviewed", "review_digest"})},
		{Value: openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"decision": openapi3.NewStringSchema().WithEnum("approve"), "csrf_token": str, "reviewed": openapi3.NewStringSchema().WithEnum("yes"), "connector_digest": openapi3.NewStringSchema().WithPattern(`^[A-Za-z0-9_-]{42}[AQgw]$`)}).WithRequired([]string{"decision", "csrf_token", "reviewed", "connector_digest"})},
		{Value: openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"decision": openapi3.NewStringSchema().WithEnum("deny"), "csrf_token": str}).WithRequired([]string{"decision", "csrf_token"})},
	}
	pagePost := &openapi3.Operation{OperationID: "completeConnectionHandoffPage", Summary: "Complete connection handoff page", Tags: []string{"Connections"}, Security: &openapi3.SecurityRequirements{{"browserSession": {}}}, Responses: openapi3.NewResponses()}
	pagePost.Description = "HTML owner decision form, protected by hidden form csrf_token (not an X-CSRF-Token header). Approve requires reviewed=yes and exactly one nonempty review_digest or legacy connector_digest; deny requires decision=deny and neither digest. No automatic redirect is performed: the 200 HTML completion page contains the explicitly validated return link. No credentials are returned."
	pagePost.AddParameter(path("handoff_id"))
	pagePost.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithSchema(decisionForm, []string{"application/x-www-form-urlencoded"})}
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusConflict, http.StatusServiceUnavailable} {
		pagePost.AddResponse(code, pageResponse(code))
	}
	pagePost.AddResponse(http.StatusOK, pageResponse(http.StatusOK))
	doc.AddOperation("/account/connection-handoffs/{handoff_id}", http.MethodPost, pagePost)
	loginQuery := openapi3.NewQueryParameter("handoff_id").WithRequired(true).WithSchema(str)
	loginForm := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"interaction": str, "csrf_token": str, "username": str, "password": str}).WithRequired([]string{"interaction", "csrf_token", "username", "password"})
	login := func(method string, body *openapi3.Schema, code int, operationID string) {
		op := &openapi3.Operation{OperationID: operationID, Summary: operationID, Tags: []string{"Connections"}, Security: &openapi3.SecurityRequirements{}, Responses: openapi3.NewResponses()}
		op.Description = "Connection-handoff owner login; username and password are the only credentials accepted. Existing MFA sessions are accepted; forced MFA rejects downgrade and full cold-MFA is not yet supported. No Bearer/API-key authentication is accepted. Responses are no-store, no-referrer, and CSP-protected."
		if method == http.MethodGet {
			op.AddParameter(loginQuery)
			op.AddResponse(http.StatusSeeOther, pageResponse(http.StatusSeeOther))
		} else {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithSchema(body, []string{"application/x-www-form-urlencoded"})}
			op.AddResponse(http.StatusUnauthorized, pageResponse(http.StatusUnauthorized))
			op.AddResponse(http.StatusTooManyRequests, pageResponse(http.StatusTooManyRequests))
		}
		for _, c := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusServiceUnavailable} {
			op.AddResponse(c, pageResponse(c))
		}
		op.AddResponse(code, pageResponse(code))
		doc.AddOperation("/account/connection-login", method, op)
	}
	login(http.MethodGet, nil, http.StatusOK, "getConnectionHandoffLogin")
	login(http.MethodPost, loginForm, http.StatusSeeOther, "loginConnectionHandoff")
	operationID := openapi3.NewStringSchema().WithPattern(`^[a-z0-9][a-z0-9_-]{0,63}$`).WithMaxLength(64)
	invokeBody := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{"operation": operationID}).WithRequired([]string{"operation"})
	scalar := openapi3.NewAnyOfSchema(openapi3.NewStringSchema(), openapi3.NewInt64Schema(), openapi3.NewBoolSchema())
	projection := openapi3.NewObjectSchema().WithAnyAdditionalProperties()
	projection.AdditionalProperties = openapi3.AdditionalProperties{Schema: &openapi3.SchemaRef{Value: scalar}}
	invoke := &openapi3.Operation{OperationID: "invokeConnectionGrant", Summary: "Invoke connection grant", Tags: []string{"Connections"}, Security: &openapi3.SecurityRequirements{{"bearerToken": {}}}, Responses: openapi3.NewResponses()}
	invoke.Description = "Bearer-only consumer invocation. The token's owner subject and consumer client are authoritative; request JSON cannot provide either identity. Requires exact GOAUTHY_CONNECTIONS_RESOURCE audience and goauthy.connections.use scope; cookies, CSRF, machine tokens, token exchange, and DPoP are not accepted. The grant must be current owner/consumer, proxy mode, unrevoked, unexpired, and match its connection and consumer generations, provider revision, and connector digest. Only a registered API-key connector's fixed GET operation and scalar response-field projection are executed; credentials and upstream headers are never returned. No retries are performed. Revocation prevents later dispatch and result delivery but cannot undo an HTTP request already sent upstream."
	invoke.AddParameter(grantID)
	invoke.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(invokeBody)}
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusBadGateway, http.StatusServiceUnavailable} {
		invoke.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
	}
	invoke.AddResponse(http.StatusOK, openapi3.NewResponse().WithDescription(http.StatusText(http.StatusOK)).WithJSONSchema(projection))
	doc.AddOperation("/auth/v1/connection-grants/{grant_id}/invoke", http.MethodPost, invoke)
	deliveryKey := openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(2048)
	deliveryKey.Description = "Sensitive API key; never log or persist this response."
	delivery := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"kind": openapi3.NewStringSchema().WithEnum("api_key"), "api_key": deliveryKey, "grant_id": str, "provider_id": str,
		"connection_generation": str, "credential_version": openapi3.NewInt64Schema().WithMin(1),
		"connector_digest": str, "header": str, "prefix": str, "consent_expires_at_unix_ms": openapi3.NewInt64Schema(),
	}).WithRequired([]string{"kind", "api_key", "grant_id", "provider_id", "connection_generation", "credential_version", "connector_digest", "header", "prefix", "consent_expires_at_unix_ms"})
	oauthToken := openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(2048)
	oauthToken.Description = "Sensitive OAuth access token; never log or persist this response."
	oauthDelivery := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperties(map[string]*openapi3.Schema{
		"kind": openapi3.NewStringSchema().WithEnum("oauth2"), "access_token": oauthToken,
		"token_type": openapi3.NewStringSchema().WithEnum("Bearer"), "grant_id": str, "provider_id": str,
		"connection_generation": str, "credential_version": openapi3.NewInt64Schema().WithMin(1), "account_id": str,
		"scopes": openapi3.NewArraySchema().WithMaxItems(64).WithItems(str), "token_expires_at_unix_ms": openapi3.NewInt64Schema().WithMin(1),
		"consent_expires_at_unix_ms": openapi3.NewInt64Schema(),
	}).WithRequired([]string{"kind", "access_token", "token_type", "grant_id", "provider_id", "connection_generation", "credential_version", "account_id", "scopes", "token_expires_at_unix_ms", "consent_expires_at_unix_ms"})
	deliveryResponseSchema := openapi3.NewOneOfSchema(delivery, oauthDelivery)
	credential := &openapi3.Operation{OperationID: "deliverConnectionCredential", Summary: "Deliver connection credential", Tags: []string{"Connections"}, Security: &openapi3.SecurityRequirements{{"bearerToken": {}}}, Responses: openapi3.NewResponses()}
	credential.Description = "Bearer-only confidential-consumer credential delivery. Requires the authenticated human owner's consumer identity, exact GOAUTHY_CONNECTIONS_RESOURCE audience, goauthy.connections.use, and distinct credential_delivery consent; proxy consent never exports a key. Registered API-key and OAuth2 access-token delivery have distinct response kinds under that consent mode. Cookies, Origin, Sec-Fetch-Site, query parameters, request bodies including {}, CSRF headers, machine tokens, token exchange, and DPoP are rejected. The response contains only the sensitive credential plus registered metadata; refresh tokens, provider client secrets, and upstream headers are never delivered. OAuth delivery requires a known future token expiry, reported separately from consent expiry; unknown or expired tokens are rejected. No implicit network or refresh is performed. Consent expiry or revocation stops future retrieval but cannot recall a delivered key or token. Do not log or persist the response. Response is Cache-Control: no-store."
	credential.AddParameter(grantID)
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusBadGateway, http.StatusServiceUnavailable} {
		credential.AddResponse(code, openapi3.NewResponse().WithDescription(http.StatusText(code)))
	}
	deliveryResponse := openapi3.NewResponse().WithDescription(http.StatusText(http.StatusOK)).WithJSONSchema(deliveryResponseSchema)
	deliveryResponse.Headers = openapi3.Headers{"Cache-Control": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: str}, Description: "Always no-store", Example: "no-store"}}}
	credential.AddResponse(http.StatusOK, deliveryResponse)
	doc.AddOperation("/auth/v1/connection-grants/{grant_id}/credential", http.MethodPost, credential)
	return nil
}
