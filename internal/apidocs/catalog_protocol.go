package apidocs

import (
	"errors"
	"net/http"
	"sort"
	"strconv"

	"github.com/getkin/kin-openapi/openapi3"
)

func addProtocolOperations(doc *openapi3.T, features Features) error {
	if doc == nil {
		return errors.New("nil OpenAPI document")
	}
	if doc.Paths == nil {
		doc.Paths = openapi3.NewPaths()
	}
	if doc.Components == nil {
		doc.Components = &openapi3.Components{}
	}
	if doc.Components.Schemas == nil {
		doc.Components.Schemas = openapi3.Schemas{}
	}
	if doc.Components.SecuritySchemes == nil {
		doc.Components.SecuritySchemes = openapi3.SecuritySchemes{}
	}
	stringSchema := openapi3.NewStringSchema()
	form := func(properties map[string]*openapi3.Schema, required ...string) *openapi3.Schema {
		s := openapi3.NewObjectSchema()
		for n, p := range properties {
			s.WithProperty(n, p)
		}
		s.Required = required
		return s
	}
	ref := func(name string, s *openapi3.Schema) *openapi3.SchemaRef {
		doc.Components.Schemas[name] = &openapi3.SchemaRef{Value: s}
		return &openapi3.SchemaRef{Ref: "#/components/schemas/" + name}
	}
	jsonBody := func(s *openapi3.SchemaRef, required bool) *openapi3.RequestBodyRef {
		return &openapi3.RequestBodyRef{Value: (&openapi3.RequestBody{}).WithSchemaRef(s, []string{"application/json"}).WithRequired(required)}
	}
	formBody := func(s *openapi3.SchemaRef, required bool) *openapi3.RequestBodyRef {
		return &openapi3.RequestBodyRef{Value: (&openapi3.RequestBody{}).WithSchemaRef(s, []string{"application/x-www-form-urlencoded"}).WithRequired(required)}
	}
	resp := func(statuses ...int) *openapi3.Responses {
		r := openapi3.NewResponses()
		for _, status := range statuses {
			r.Set(strconv.Itoa(status), &openapi3.ResponseRef{Value: openapi3.NewResponse().WithDescription(http.StatusText(status))})
		}
		return r
	}
	operation := func(method, path, id, summary string, body *openapi3.RequestBodyRef, statuses ...int) {
		op := &openapi3.Operation{OperationID: id, Summary: summary, Responses: resp(statuses...)}
		op.Tags = []string{"OAuth/OIDC"}
		op.RequestBody = body
		doc.AddOperation(path, method, op)
	}
	operation("GET", "/.well-known/oauth-authorization-server", "oauthDiscovery", "OAuth authorization server metadata", nil, 200)
	operation("GET", "/.well-known/openid-configuration", "oidcDiscovery", "OpenID Connect provider metadata", nil, 200)
	operation("GET", "/", "health", "Return service identity", nil, 200)
	operation("GET", "/favicon.ico", "favicon", "Return service favicon", nil, 200, 404)
	token := ref("TokenResponse", form(map[string]*openapi3.Schema{"access_token": stringSchema, "token_type": stringSchema, "expires_in": openapi3.NewIntegerSchema(), "refresh_token": stringSchema, "id_token": stringSchema}, "access_token", "token_type", "expires_in"))
	// OAuth endpoints consume strict form-urlencoded requests; fields mirror the implemented fosite grants.
	tokenForm := ref("TokenRequest", form(map[string]*openapi3.Schema{"grant_type": stringSchema, "code": stringSchema, "redirect_uri": stringSchema, "client_id": stringSchema, "client_secret": stringSchema, "refresh_token": stringSchema, "scope": stringSchema, "device_code": stringSchema, "subject_token": stringSchema, "subject_token_type": stringSchema, "code_verifier": stringSchema}, "grant_type"))
	authForm := ref("AuthorizationRequest", form(map[string]*openapi3.Schema{"response_type": stringSchema, "client_id": stringSchema, "redirect_uri": stringSchema, "scope": stringSchema, "state": stringSchema, "nonce": stringSchema, "code_challenge": stringSchema, "code_challenge_method": stringSchema}, "response_type", "client_id", "redirect_uri"))
	operation("GET", "/oidc/authorize", "authorize", "Authorize an OAuth/OIDC client", nil, 200, 302, 400)
	for name, required := range map[string]bool{"response_type": true, "client_id": true, "redirect_uri": true, "scope": false, "state": false, "nonce": false, "code_challenge": false, "code_challenge_method": false} {
		doc.Paths.Value("/oidc/authorize").Get.Parameters = append(doc.Paths.Value("/oidc/authorize").Get.Parameters, &openapi3.ParameterRef{Value: &openapi3.Parameter{Name: name, In: "query", Required: required, Schema: &openapi3.SchemaRef{Value: stringSchema}}})
	}
	sort.Slice(doc.Paths.Value("/oidc/authorize").Get.Parameters, func(i, j int) bool {
		return doc.Paths.Value("/oidc/authorize").Get.Parameters[i].Value.Name < doc.Paths.Value("/oidc/authorize").Get.Parameters[j].Value.Name
	})
	_ = authForm
	operation("POST", "/oidc/token", "token", "Exchange an authorization, refresh, client-credentials, device, or subject token", formBody(tokenForm, true), 200, 400, 401)
	doc.Paths.Value("/oidc/token").Post.Responses.Set("200", &openapi3.ResponseRef{Value: openapi3.NewResponse().WithDescription("OK").WithJSONSchemaRef(token)})
	operation("POST", "/oidc/introspect", "introspect", "Inspect a token", formBody(ref("IntrospectionRequest", form(map[string]*openapi3.Schema{"token": stringSchema, "token_type_hint": stringSchema}, "token")), true), 200, 400, 401)
	operation("POST", "/oidc/revoke", "revoke", "Revoke a token", formBody(ref("RevocationRequest", form(map[string]*openapi3.Schema{"token": stringSchema, "token_type_hint": stringSchema}, "token")), true), 200, 400, 401)
	operation("GET", "/oidc/userinfo", "userInfoGet", "Return claims for the bearer token", nil, 200, 401)
	operation("POST", "/oidc/userinfo", "userInfoPost", "Return claims for the bearer token", nil, 200, 401)
	operation("GET", "/oidc/forward_auth", "forwardAuth", "Check bearer authorization for a reverse proxy", nil, 200, 401, 403)
	operation("GET", "/oidc/logout", "logoutGet", "Start OIDC logout", nil, 200, 302, 400)
	operation("POST", "/oidc/logout", "logoutPost", "Confirm OIDC logout", formBody(ref("LogoutRequest", form(map[string]*openapi3.Schema{"id_token_hint": stringSchema, "post_logout_redirect_uri": stringSchema, "state": stringSchema, "confirmation": stringSchema})), true), 200, 302, 400)
	operation("GET", "/oidc/jwks.json", "jwks", "Return signing keys", nil, 200)
	operation("POST", "/oidc/device", "deviceAuthorization", "Create an RFC 8628 device grant; confidential clients authenticate with their registered Basic or form-secret method, public clients send client_id", formBody(ref("DeviceAuthorizationRequest", form(map[string]*openapi3.Schema{"client_id": stringSchema, "client_secret": stringSchema, "scope": stringSchema, "resource": stringSchema}, "scope")), true), 200, 400, 401, 429, 503)
	doc.Paths.Value("/oidc/device").Post.Description = "Optional resource is one absolute HTTPS URL registered for the client and allowed by server policy. If omitted, a configured client default is used; otherwise the grant remains audience-less. The target is persisted through approval, token issuance and refresh. Do not send resource or audience when redeeming a device code or refresh token; target replacement/narrowing is not supported. Invalid or unauthorized targets return invalid_target."
	operation("GET", "/oidc/device/verify", "deviceVerifyPage", "Render device approval or redirect to sign-in", nil, 200, 303, 400)
	operation("GET", "/oidc/device/login", "deviceLoginPage", "Sign in before reviewing a device code", nil, 200, 303, 400, 403, 503)
	operation("POST", "/oidc/device/login", "deviceLogin", "Authenticate and return to explicit device verification", formBody(ref("DeviceLoginRequest", form(map[string]*openapi3.Schema{"interaction": stringSchema, "csrf_token": stringSchema, "username": stringSchema, "password": stringSchema}, "interaction", "csrf_token", "username", "password")), true), 303, 400, 401, 403, 429, 503)
	operation("POST", "/oidc/device/verify", "deviceVerify", "Approve or deny a device grant", formBody(ref("DeviceVerificationRequest", form(map[string]*openapi3.Schema{"user_code": stringSchema, "action": stringSchema, "csrf_token": stringSchema}, "user_code", "action", "csrf_token")), true), 200, 400, 403)
	if features.DCR {
		reg := ref("ClientRegistration", form(map[string]*openapi3.Schema{"client_id": stringSchema, "client_name": stringSchema, "redirect_uris": openapi3.NewArraySchema().WithItems(stringSchema), "grant_types": openapi3.NewArraySchema().WithItems(stringSchema), "response_types": openapi3.NewArraySchema().WithItems(stringSchema), "token_endpoint_auth_method": stringSchema, "scope": stringSchema, "client_uri": stringSchema, "logo_uri": stringSchema, "tos_uri": stringSchema, "policy_uri": stringSchema, "contacts": openapi3.NewArraySchema().WithItems(stringSchema), "software_statement": stringSchema}, "redirect_uris"))
		operation("POST", "/oidc/register", "registerClient", "Register an OAuth client (RFC 7591)", jsonBody(reg, true), 201, 400, 401, 429)
		doc.Paths.Value("/oidc/register").Post.Parameters = openapi3.Parameters{&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "Idempotency-Key", In: "header", Required: true, Schema: &openapi3.SchemaRef{Value: stringSchema}}}}
		operation("GET", "/oidc/register/{id}", "getClientRegistration", "Read registered client metadata", nil, 200, 401, 404)
		operation("PUT", "/oidc/register/{id}", "updateClientRegistration", "Replace registered client metadata", jsonBody(reg, true), 200, 400, 401, 404)
		operation("DELETE", "/oidc/register/{id}", "deleteClientRegistration", "Delete registered client metadata", nil, 204, 401, 404)
		id := &openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "id", In: "path", Required: true, Schema: &openapi3.SchemaRef{Value: stringSchema}}}
		for _, op := range []*openapi3.Operation{doc.Paths.Value("/oidc/register/{id}").Get, doc.Paths.Value("/oidc/register/{id}").Put, doc.Paths.Value("/oidc/register/{id}").Delete} {
			op.Parameters = openapi3.Parameters{id}
		}
	}
	operation("POST", "/auth/login", "login", "Authenticate a browser session", formBody(ref("LoginRequest", form(map[string]*openapi3.Schema{"interaction": stringSchema, "username": stringSchema, "password": stringSchema}, "interaction", "username", "password")), true), 200, 400, 401, 403, 406, 503)
	operation("GET", "/auth/profile", "profileGet", "Render profile continuation form", nil, 200, 403, 503)
	profileForm := ref("ProfileRequest", form(map[string]*openapi3.Schema{"interaction": stringSchema, "csrf_token": stringSchema, "given_name": stringSchema, "family_name": stringSchema, "preferred_username": stringSchema, "birthdate": stringSchema, "phone": stringSchema, "street": stringSchema, "zip": stringSchema, "city": stringSchema, "country": stringSchema, "tz": stringSchema}, "interaction", "csrf_token"))
	operation("POST", "/auth/profile", "profilePost", "Submit profile continuation update", formBody(profileForm, true), 200, 303, 400, 403, 409, 503)
	doc.Paths.Value("/auth/profile").Post.AddParameter(openapi3.NewQueryParameter("interaction").WithSchema(stringSchema).WithRequired(true))
	// OAuth client authentication is selected by the registered client. Form
	// credentials/private_key_jwt are described in the body, not a fake HTTP scheme.
	doc.Components.SecuritySchemes["clientBasic"] = &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{Type: "http", Scheme: "basic", Description: "Registered OAuth client ID and secret."}}
	doc.Components.SecuritySchemes["registrationBearer"] = &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{Type: "http", Scheme: "bearer", Description: "Per-client registration access token, not an OAuth access token."}}
	doc.Components.SecuritySchemes["registrationAdminBearer"] = &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{Type: "http", Scheme: "bearer", Description: "Configured DCR registration token."}}
	for _, name := range []string{"resource", "audience", "actor_token", "actor_token_type", "requested_token_type", "client_assertion", "client_assertion_type"} {
		doc.Components.Schemas["TokenRequest"].Value.WithProperty(name, stringSchema)
	}
	doc.Components.Schemas["TokenRequest"].Value.Description = "Grant-specific fields are required by the selected flow. Client authentication must match registration: Basic, form secret, private_key_jwt, or a permitted public client. Token exchange requires a confidential static client with the exchange grant enabled and accepts validated Bearer access-token inputs, including a nested actor chain. It accepts at most one resource or audience target, checked against the exchanger and server policies; managed default_aud entries apply independently. Repeated targets or both target fields are rejected. Requested scopes may only narrow the subject token; actor/exchanger scope lists do not constrain exchange. User roles, scoped groups, and custom access claims are resolved at issuance."
	for _, path := range []string{"/oidc/token", "/oidc/introspect", "/oidc/revoke"} {
		op := doc.Paths.Value(path).Post
		op.Security = &openapi3.SecurityRequirements{{"clientBasic": {}}, {}}
		op.Description = "Authenticate as the registered client via HTTP Basic or the configured request-body method. An empty security alternative represents form/JWT client authentication, not an unrestricted anonymous endpoint."
	}
	for _, name := range []string{"IntrospectionRequest", "RevocationRequest"} {
		for _, field := range []string{"client_id", "client_secret", "client_assertion", "client_assertion_type"} {
			doc.Components.Schemas[name].Value.WithProperty(field, stringSchema)
		}
	}
	for _, method := range []string{"GET", "POST"} {
		op := doc.Paths.Value("/oidc/userinfo").GetOperation(method)
		op.Security = &openapi3.SecurityRequirements{{"bearerToken": {}}}
		op.Responses.Status(200).Value.WithJSONSchema(form(map[string]*openapi3.Schema{"sub": stringSchema, "email": stringSchema, "email_verified": openapi3.NewBoolSchema(), "groups": openapi3.NewArraySchema().WithItems(stringSchema)}, "sub"))
		op.AddParameter(openapi3.NewHeaderParameter("DPoP").WithSchema(stringSchema))
	}
	doc.Paths.Value("/oidc/forward_auth").Get.Security = &openapi3.SecurityRequirements{{"bearerToken": {}}}
	doc.Paths.Value("/oidc/introspect").Post.Responses.Status(200).Value.WithJSONSchema(form(map[string]*openapi3.Schema{"active": openapi3.NewBoolSchema(), "sub": stringSchema, "client_id": stringSchema, "scope": stringSchema, "exp": openapi3.NewInt64Schema(), "iat": openapi3.NewInt64Schema(), "aud": openapi3.NewSchema()}, "active"))
	doc.Paths.Value("/oidc/jwks.json").Get.Responses.Status(200).Value.WithJSONSchema(form(map[string]*openapi3.Schema{"keys": openapi3.NewArraySchema().WithItems(form(map[string]*openapi3.Schema{"kty": stringSchema, "kid": stringSchema, "alg": stringSchema, "use": stringSchema, "crv": stringSchema, "x": stringSchema, "y": stringSchema, "n": stringSchema, "e": stringSchema}, "kty"))}, "keys"))
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		op := doc.Paths.Value(path).Get
		op.Responses.Status(200).Value.WithJSONSchema(form(map[string]*openapi3.Schema{"issuer": stringSchema, "authorization_endpoint": stringSchema, "token_endpoint": stringSchema, "jwks_uri": stringSchema, "grant_types_supported": openapi3.NewArraySchema().WithItems(stringSchema)}, "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"))
		op.AddResponse(304, openapi3.NewResponse().WithDescription("Unchanged ETag"))
	}
	for _, name := range []string{"prompt", "max_age", "resource", "response_mode"} {
		doc.Paths.Value("/oidc/authorize").Get.AddParameter(openapi3.NewQueryParameter(name).WithSchema(stringSchema))
	}
	for _, path := range []string{"/oidc/authorize", "/auth/login", "/auth/profile", "/oidc/device/verify", "/oidc/device/login", "/oidc/logout"} {
		for _, op := range doc.Paths.Value(path).Operations() {
			if op.Responses.Status(200) != nil {
				op.Responses.Status(200).Value.Content = openapi3.Content{"text/html": {Schema: &openapi3.SchemaRef{Value: stringSchema}}}
			}
		}
	}
	doc.Components.Schemas["LoginRequest"].Value.WithoutAdditionalProperties()
	doc.Paths.Value("/auth/login").Post.Description = "Requires the Init browser session and one-use interaction created by authorize. Exactly one occurrence of each of the three form fields; cross-site requests rejected. Success may continue an authorization redirect or render a passkey step-up page."
	doc.Paths.Value("/auth/login").Post.AddResponse(303, openapi3.NewResponse().WithDescription("Authorization redirect"))
	doc.Paths.Value("/auth/profile").Get.Security = &openapi3.SecurityRequirements{{"browserSession": {}}}
	doc.Paths.Value("/auth/profile").Get.Description = "Default off; enable with GOAUTHY_USER_VALUES_REVALIDATE_DURING_LOGIN. Requires an authenticated browser session and a valid one-use interaction from the authorize flow. The form retains auth_time and renders fields configured by the user-values policy."
	doc.Paths.Value("/auth/profile").Get.AddParameter(openapi3.NewQueryParameter("interaction").WithSchema(stringSchema).WithRequired(true))
	doc.Paths.Value("/auth/profile").Post.Security = &openapi3.SecurityRequirements{{"browserSession": {}}}
	doc.Paths.Value("/auth/profile").Post.Description = "Default off; enable with GOAUTHY_USER_VALUES_REVALIDATE_DURING_LOGIN. Requires an authenticated session, matching interaction in query and body, and a valid csrf_token. Accepts optional given_name, family_name, preferred_username, birthdate, phone, street, zip, city, country, tz fields; email and roles are not accepted. Success continues the authorization redirect. Responses: 400 validation error, 403 denied or invalid session, 409 CAS conflict, 503 feature disabled or storage unavailable."
	doc.Components.Schemas["ProfileRequest"].Value.WithoutAdditionalProperties()
	doc.Paths.Value("/auth/profile").Get.AddResponse(400, openapi3.NewResponse().WithDescription(http.StatusText(400)))
	doc.Paths.Value("/auth/profile").Post.AddResponse(400, openapi3.NewResponse().WithDescription(http.StatusText(400)))
	doc.Components.Schemas["DeviceAuthorizationRequest"].Value.WithRequired([]string{"scope"}).WithoutAdditionalProperties()
	doc.Components.Schemas["DeviceVerificationRequest"].Value.WithProperty("action", openapi3.NewStringSchema().WithEnum("approve", "deny")).WithoutAdditionalProperties()
	deviceResponse := form(map[string]*openapi3.Schema{"device_code": stringSchema, "user_code": stringSchema, "verification_uri": stringSchema, "verification_uri_complete": stringSchema, "expires_in": openapi3.NewInt64Schema(), "interval": openapi3.NewInt64Schema()}, "device_code", "user_code", "verification_uri", "expires_in", "interval")
	doc.Paths.Value("/oidc/device").Post.Responses.Status(200).Value.WithJSONSchema(deviceResponse)
	doc.Paths.Value("/oidc/device/verify").Get.AddParameter(openapi3.NewQueryParameter("user_code").WithSchema(stringSchema))
	doc.Paths.Value("/oidc/device/login").Get.AddParameter(openapi3.NewQueryParameter("user_code").WithSchema(stringSchema))
	doc.Paths.Value("/oidc/device/login").Post.Description = "Requires the init-session cookie, matching csrf_token and one-use device-login interaction from GET. The code is retained server-side. Successful login does not approve a device. Password-only login is rejected when forced MFA is configured."
	doc.Paths.Value("/oidc/device/verify").Post.Security = &openapi3.SecurityRequirements{{"browserSession": {}}}
	doc.Paths.Value("/oidc/device/verify").Post.Description = "The csrf_token form field must match the device verification cookie issued by GET; a current browser subject is also required."
	for _, op := range doc.Paths.Value("/oidc/logout").Operations() {
		op.Responses.Delete("302")
		op.AddResponse(303, openapi3.NewResponse().WithDescription("Registered logout redirect or issuer root"))
		op.AddResponse(503, openapi3.NewResponse().WithDescription("Storage unavailable"))
	}
	doc.Paths.Value("/oidc/logout").Post.AddResponse(204, openapi3.NewResponse().WithDescription("Backend logout completed"))
	doc.Components.Schemas["LogoutRequest"].Value.WithProperty("client_id", stringSchema).WithoutAdditionalProperties()
	for _, field := range []string{"id_token_hint", "client_id", "post_logout_redirect_uri", "state"} {
		doc.Paths.Value("/oidc/logout").Get.AddParameter(openapi3.NewQueryParameter(field).WithSchema(stringSchema))
	}
	doc.Paths.Value("/oidc/logout").Post.Description = "A confirmation POST contains only the confirmation token. A direct RP logout accepts the registered hint/client/redirect fields; duplicate fields and query strings are rejected."
	if features.DCR {
		create := doc.Components.Schemas["ClientRegistration"].Value
		create.Description = "Supports authorization_code, client_credentials, password, device_code and refresh_token grants. client_credentials requires client_secret_basic or client_secret_post. Authorization code requires redirect_uris and response_types=[code]; clients without it use empty redirect/response lists. refresh_token requires authorization_code or device_code, never refresh-only."
		create.WithProperty("grant_types", openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema().WithEnum("authorization_code", "client_credentials", "password", "urn:ietf:params:oauth:grant-type:device_code", "refresh_token")))
		delete(create.Properties, "client_id")
		delete(create.Properties, "scope")
		dpop := openapi3.NewBoolSchema().WithDefault(false)
		dpop.Description = "RFC 9449: require DPoP-bound access tokens. Must be a JSON boolean; null is rejected. Omitted on create or replacement PUT defaults to false."
		create.WithProperty("dpop_bound_access_tokens", dpop)
		backchannel := openapi3.NewStringSchema().WithNullable().WithPattern(`^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%@]+$`)
		backchannel.Description = "Registered backchannel logout URI. Null or omission on replacement PUT clears the URI and updates existing login associations. Outbound delivery applies separate network security checks."
		create.WithProperty("backchannel_logout_uri", backchannel)
		if !features.DCRAnonymous {
			audience := openapi3.NewArraySchema().WithItems(stringSchema)
			audience.Description = "GoAuthy extension: exact HTTPS resource identifiers selected from the server allowlist. Omitted or empty on PUT clears the client audience. Null is rejected; anonymous registration cannot set this field."
			create.WithProperty("audience", audience)
		}
		create.WithoutAdditionalProperties()
		update := form(map[string]*openapi3.Schema{}, "client_id", "redirect_uris").WithoutAdditionalProperties()
		update.Description = create.Description
		response := form(map[string]*openapi3.Schema{}, "client_id", "client_secret_expires_at", "redirect_uris", "grant_types", "response_types", "token_endpoint_auth_method", "dpop_bound_access_tokens")
		for field, schema := range create.Properties {
			update.WithPropertyRef(field, schema)
			response.WithPropertyRef(field, schema)
		}
		update.WithProperty("client_id", stringSchema)
		for _, field := range []string{"client_id", "client_secret", "registration_access_token", "registration_client_uri", "scope"} {
			response.WithProperty(field, stringSchema)
		}
		response.WithProperty("client_secret_expires_at", openapi3.NewInt64Schema())
		doc.Paths.Value("/oidc/register/{id}").Put.RequestBody = jsonBody(ref("ClientRegistrationUpdate", update), true)
		doc.Paths.Value("/oidc/register").Post.Responses.Status(201).Value.WithJSONSchema(response)
		doc.Paths.Value("/oidc/register").Post.AddResponse(422, openapi3.NewResponse().WithDescription("Idempotency key reused with different request"))
		if !features.DCRAnonymous {
			doc.Paths.Value("/oidc/register").Post.Security = &openapi3.SecurityRequirements{{"registrationAdminBearer": {}}}
		} else {
			doc.Paths.Value("/oidc/register").Post.Description = "Anonymous registration is configured; any Authorization header is rejected. Idempotency-Key remains required."
		}
		for method, op := range doc.Paths.Value("/oidc/register/{id}").Operations() {
			op.Security = &openapi3.SecurityRequirements{{"registrationBearer": {}}}
			if method != "DELETE" {
				op.Responses.Status(200).Value.WithJSONSchema(response)
			}
		}
	}
	return nil
}
