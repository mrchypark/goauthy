package apidocs

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3gen"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/mrchypark/goauthy/internal/account"
	"github.com/mrchypark/goauthy/internal/recovery"
)

// addAccountOperations adds the account-facing HTTP contract. Handlers remain
// the source of truth for behavior; this catalog deliberately documents only
// the request/response shapes that are stable at that boundary.
func addAccountOperations(doc *openapi3.T, features Features) error {
	if doc == nil {
		return fmt.Errorf("nil OpenAPI document")
	}
	add := func(path, method, id, summary string, status int, security ...map[string][]string) {
		op := openapi3.NewOperation()
		op.OperationID, op.Summary, op.Tags = id, summary, []string{"account"}
		for _, segment := range strings.Split(path, "/") {
			if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
				op.AddParameter(openapi3.NewPathParameter(strings.Trim(segment, "{}")).WithSchema(openapi3.NewStringSchema()))
			}
		}
		op.Responses = openapi3.NewResponses()
		response := openapi3.NewResponse().WithDescription(statusText(status))
		if path == "/account/password" {
			response.WithJSONSchema(openapi3.NewObjectSchema().WithProperty("csrf_token", openapi3.NewStringSchema()).WithProperty("password_policy", openapi3.NewObjectSchema().WithProperty("length_min", openapi3.NewIntegerSchema()).WithProperty("length_max", openapi3.NewIntegerSchema())))
		}
		op.AddResponse(status, response)
		var body *openapi3.Schema
		switch path {
		case "/auth/v1/users/request_reset":
			body = openapi3.NewObjectSchema().WithProperty("email", openapi3.NewStringSchema()).WithProperty("pow", openapi3.NewStringSchema())
		case "/auth/v1/users/{subject}/reset":
			body = openapi3.NewObjectSchema().WithProperty("magic_link_id", openapi3.NewStringSchema()).WithProperty("password", openapi3.NewStringSchema())
		case "/auth/v1/users/{subject}/mfa_token":
			body = openapi3.NewObjectSchema().WithProperty("password", openapi3.NewStringSchema()).WithProperty("mfa_code", openapi3.NewStringSchema())
		case "/auth/v1/users/{subject}/webauthn/register/start":
			body = openapi3.NewObjectSchema().WithProperty("passkey_name", openapi3.NewStringSchema()).WithProperty("mfa_mod_token_id", openapi3.NewStringSchema())
		case "/auth/v1/users/{subject}/webauthn/register/finish":
			body = openapi3.NewObjectSchema().WithProperty("passkey_name", openapi3.NewStringSchema()).WithProperty("data", openapi3.NewObjectSchema())
		case "/auth/v1/users/{subject}/webauthn/auth/start":
			body = openapi3.NewObjectSchema().WithProperty("purpose", openapi3.NewStringSchema().WithEnum("MfaModToken", "PasswordNew"))
		case "/auth/v1/users/{subject}/webauthn/auth/finish":
			body = openapi3.NewObjectSchema().WithProperty("code", openapi3.NewStringSchema()).WithProperty("data", openapi3.NewObjectSchema())
		}
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body)}
		}
		if len(security) > 0 {
			reqs := make(openapi3.SecurityRequirements, len(security))
			for i, req := range security {
				reqs[i] = req
			}
			op.Security = &reqs
		}
		doc.AddOperation(path, strings.ToUpper(method), op)
	}
	pathParam := func(op *openapi3.Operation, name string) {
		p := openapi3.NewPathParameter(name).WithSchema(openapi3.NewStringSchema())
		op.AddParameter(p)
	}
	secure := map[string][]string{"browserSession": {}}
	csrf := map[string][]string{"csrfToken": {}}
	api := map[string][]string{"apiKey": {}}
	add("/account/password", "get", "getPassword", "Get password policy and CSRF token", 200, secure)
	for _, page := range []struct{ path, id, media string }{
		{"/account", "accountDashboard", "text/html"},
		{"/account/app.js", "accountDashboardScript", "text/javascript"},
		{"/account/connections.js", "accountConnectionsScript", "text/javascript"},
		{"/account/connection-grants.js", "accountConnectionGrantsScript", "text/javascript"},
		{"/account/devices.js", "accountDevicesScript", "text/javascript"},
		{"/account/account.css", "accountDashboardStyle", "text/css"},
	} {
		add(page.path, "get", page.id, "Authenticated account dashboard", 200, secure)
		doc.Paths.Value(page.path).Get.Responses.Status(200).Value.Content = openapi3.Content{page.media: &openapi3.MediaType{Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}}
	}
	add("/account/data", "get", "accountDashboardData", "Get current account profile and issuer-bound CSRF token; Authorization headers are rejected", 200, secure)
	dashboard := openapi3.NewObjectSchema()
	for _, name := range []string{"subject", "email", "preferred_username", "given_name", "family_name", "csrf_token", "base_path"} {
		dashboard.WithProperty(name, openapi3.NewStringSchema())
	}
	dashboard.WithProperty("email_verified", openapi3.NewBoolSchema())
	dashboard.WithProperty("features", openapi3.NewObjectSchema().WithProperty("password", openapi3.NewBoolSchema()).WithProperty("passkeys", openapi3.NewBoolSchema()).WithProperty("passkey_conversion", openapi3.NewBoolSchema()))
	dashboard.WithProperty("password_policy", doc.Paths.Value("/account/password").Get.Responses.Status(200).Value.Content["application/json"].Schema.Value.Properties["password_policy"].Value)
	doc.Paths.Value("/account/data").Get.Responses.Status(200).Value.WithJSONSchema(dashboard)
	op := openapi3.NewOperation()
	op.OperationID, op.Summary, op.Tags = "putSelfPassword", "Change the authenticated user's password", []string{"account"}
	op.Responses = openapi3.NewResponses()
	op.AddResponse(200, openapi3.NewResponse().WithDescription("Password changed"))
	op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(openapi3.NewObjectSchema().WithProperty("password_current", openapi3.NewStringSchema()).WithProperty("password_new", openapi3.NewStringSchema()).WithProperty("mfa_code", openapi3.NewStringSchema()))}
	op.Security = &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}}
	path := "/auth/v1/users/{subject}/self"
	pathParam(op, "subject")
	doc.AddOperation(path, "PUT", op)

	op = openapi3.NewOperation()
	op.OperationID, op.Summary, op.Tags = "deleteUser", "Delete a user", []string{"account"}
	op.Responses = openapi3.NewResponses()
	op.AddResponse(204, openapi3.NewResponse().WithDescription("User deleted"))
	pathParam(op, "subject")
	op.Security = &openapi3.SecurityRequirements{secure, api}
	doc.AddOperation("/auth/v1/users/{subject}", "DELETE", op)
	for _, method := range []string{"get", "delete"} {
		id := "selfDelete"
		status := 204
		if method == "get" {
			id, status = "selfDeleteCheck", 202
		}
		op = openapi3.NewOperation()
		op.OperationID, op.Summary, op.Tags = id, "Self-delete account", []string{"account"}
		op.Responses = openapi3.NewResponses()
		op.AddResponse(status, openapi3.NewResponse().WithDescription(statusText(status)))
		pathParam(op, "subject")
		if method == "delete" {
			op.Security = &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}}
		} else {
			op.Security = &openapi3.SecurityRequirements{secure}
		}
		doc.AddOperation("/auth/v1/users/{subject}/self/delete", strings.ToUpper(method), op)
	}

	if features.Passkeys {
		addPasskeyOperations(doc, add, pathParam, secure, csrf)
	}
	add("/auth/v1/users/{subject}/revoke/{code}", "get", "revokeUnknownLogin", "Revoke a login using an emailed code", 200)
	revoke := doc.Paths.Value("/auth/v1/users/{subject}/revoke/{code}").Get
	revoke.Description = "Public bearer action link. Valid IP queries return HTML with status 200 for both successful revocation and generic code errors. Codes are shared per user until consumed and have no automatic expiry. Query IP is event metadata, not proof of the original login address."
	revoke.AddParameter(openapi3.NewQueryParameter("ip").WithRequired(true).WithSchema(openapi3.NewStringSchema()))
	revoke.Responses.Status(200).Value.Content = openapi3.Content{"text/html": {Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}}
	if features.Recovery {
		addRecoveryOperations(doc, add, pathParam)
	}
	if features.Recovery && features.OpenRegistration {
		add("/auth/v1/users/register", "post", "registerUser", "Register a user", 204)
		add("/auth/v1/users/register", "options", "registerUserOptions", "Describe registration CORS policy", 204)
	}
	if features.Upstream {
		add("/upstream/{providerID}/backchannel-logout", "post", "upstreamBackchannelLogout", "Receive a signed upstream OIDC logout", 200)
		mutation := map[string][]string{"browserSession": {}, "csrfToken": {}}
		add("/auth/v1/providers/{providerID}/link", "post", "linkProvider", "Link an upstream provider", 302, mutation)
		add("/auth/v1/providers/{providerID}/link", "delete", "unlinkProvider", "Unlink an upstream provider", 204, mutation)
		for _, suffix := range []string{"start", "callback"} {
			add("/upstream/{providerID}/"+suffix, "get", "upstream"+suffix, "Upstream provider "+suffix, 302)
		}
	}
	if features.WebID {
		add("/auth/{subject}/profile", "get", "webIDProfile", "Get a WebID profile", 200)
		profile := doc.Paths.Value("/auth/{subject}/profile").Get.Responses.Status(200).Value
		profile.Content = openapi3.Content{"text/turtle": {Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}}
	}
	// The account handler has branch-specific proofs. Describe those exact
	// fields rather than presenting a password or bearer as a generic bypass.
	strictBody := func(path, method string, props map[string]*openapi3.Schema, required ...string) *openapi3.Schema {
		s := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithRequired(required)
		for name, v := range props {
			s.WithProperty(name, v)
		}
		doc.Paths.Value(path).GetOperation(method).RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(s)}
		return s
	}
	str := openapi3.NewStringSchema()
	password := openapi3.NewStringSchema().WithMaxLength(256)
	passwordPolicy := doc.Paths.Value("/account/password").Get.Responses.Status(200).Value.Content["application/json"].Schema.Value.Properties["password_policy"].Value
	for _, name := range []string{"lower_case", "upper_case", "digits", "special", "history", "valid_days"} {
		passwordPolicy.WithProperty(name, openapi3.NewIntegerSchema())
	}
	change := strictBody("/auth/v1/users/{subject}/self", "PUT", map[string]*openapi3.Schema{"password_current": password, "password_new": password, "mfa_code": str}, "password_new")
	change.OneOf = openapi3.SchemaRefs{{Value: openapi3.NewSchema().WithRequired([]string{"password_current"})}, {Value: openapi3.NewSchema().WithRequired([]string{"mfa_code"})}}
	doc.Paths.Value("/auth/v1/users/{subject}").Delete.Security = &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}, {"apiKey": {}}}
	if features.Passkeys {
		// Reuse the actual library DTOs. URLEncodedBase64 marshals as an
		// unpadded base64url string, not an object or standard-base64 bytes.
		wireSchema := func(value any) (*openapi3.SchemaRef, error) {
			return openapi3gen.NewSchemaRefForValue(value, nil, openapi3gen.UseAllExportedFields(), openapi3gen.SchemaCustomizer(func(_ string, typ reflect.Type, _ reflect.StructTag, schema *openapi3.Schema) error {
				if typ == reflect.TypeFor[protocol.URLEncodedBase64]() {
					*schema = *openapi3.NewStringSchema().WithPattern("^[A-Za-z0-9_-]*$")
				}
				return nil
			}))
		}
		assertion, err := wireSchema(protocol.CredentialAssertion{})
		if err != nil {
			return err
		}
		creation, err := wireSchema(protocol.CredentialCreation{})
		if err != nil {
			return err
		}
		credentials, err := wireSchema([]account.PasskeyResponse{})
		if err != nil {
			return err
		}
		assertion.Value.WithRequired([]string{"publicKey"})
		assertion.Value.Properties["publicKey"].Value.WithRequired([]string{"challenge"})
		creation.Value.WithRequired([]string{"publicKey"})
		creation.Value.Properties["publicKey"].Value.WithRequired([]string{"rp", "user", "challenge"})
		for path, item := range doc.Paths.Map() {
			if strings.HasPrefix(path, "/auth/v1/users/{subject}/") && (strings.Contains(path, "webauthn") || strings.HasSuffix(path, "mfa_token")) {
				for method, op := range item.Operations() {
					if method != "GET" {
						op.Security = &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}}
					}
				}
			}
		}
		doc.Paths.Value("/auth/v1/users/{subject}/webauthn").Get.Security = &openapi3.SecurityRequirements{{"browserSession": {}}, {"apiKey": {}}}
		mod := strictBody("/auth/v1/users/{subject}/mfa_token", "POST", map[string]*openapi3.Schema{"password": password, "mfa_code": str})
		mod.OneOf = openapi3.SchemaRefs{{Value: openapi3.NewSchema().WithRequired([]string{"password"})}, {Value: openapi3.NewSchema().WithRequired([]string{"mfa_code"})}}
		strictBody("/auth/v1/users/{subject}/webauthn/register/start", "POST", map[string]*openapi3.Schema{"passkey_name": str, "mfa_mod_token_id": str}, "passkey_name", "mfa_mod_token_id")
		strictBody("/auth/v1/users/{subject}/webauthn/register/finish", "POST", map[string]*openapi3.Schema{"passkey_name": str, "data": openapi3.NewObjectSchema()}, "passkey_name", "data")
		strictBody("/auth/v1/users/{subject}/webauthn/auth/start", "POST", map[string]*openapi3.Schema{"purpose": openapi3.NewStringSchema().WithEnum("MfaModToken", "PasswordNew")}, "purpose")
		strictBody("/auth/v1/users/{subject}/webauthn/auth/finish", "POST", map[string]*openapi3.Schema{"code": str, "data": openapi3.NewObjectSchema()}, "code", "data")
		strictBody("/auth/v1/users/{subject}/webauthn/delete/{name}", "DELETE", map[string]*openapi3.Schema{"mfa_mod_token_id": str}, "mfa_mod_token_id")
		del := doc.Paths.Value("/auth/v1/users/{subject}/webauthn/delete/{name}").Delete
		del.RequestBody.Value.Required = false
		del.Description = "Self deletion requires the JSON modification token. Administrator reset of another subject requires an empty body. API keys are read-only and cannot delete."
		username := openapi3.NewStringSchema()
		username.Description = "Optional username for a fresh passkey-only login when the remembered cookie is absent. A present invalid cookie is rejected."
		strictBody("/auth/v1/users/webauthn_start", "POST", map[string]*openapi3.Schema{"purpose": openapi3.NewObjectSchema().WithProperty("Login", str).WithRequired([]string{"Login"}), "username": username}, "purpose")
		strictBody("/auth/v1/users/webauthn_finish", "POST", map[string]*openapi3.Schema{"code": str, "data": str}, "code", "data")
		finishLogin := doc.Paths.Value("/auth/v1/users/webauthn_finish").Post
		finishLogin.RequestBody.Value.Content["application/x-www-form-urlencoded"] = finishLogin.RequestBody.Value.Content["application/json"]
		doc.Paths.Value("/auth/v1/users/webauthn_start").Post.Responses.Status(200).Value.WithJSONSchema(openapi3.NewObjectSchema().WithProperty("code", str).WithPropertyRef("rcr", assertion).WithProperty("exp", openapi3.NewDateTimeSchema()).WithRequired([]string{"code", "rcr", "exp"}))
		finishLogin.Responses.Status(200).Value.Content = openapi3.Content{"text/html": {Schema: &openapi3.SchemaRef{Value: str}}}
		finishLogin.AddResponse(303, openapi3.NewResponse().WithDescription("Authorization redirect via Location, same as password login"))
		doc.Paths.Value("/auth/v1/users/{subject}/webauthn/auth/start").Post.Responses.Status(200).Value.WithJSONSchema(openapi3.NewObjectSchema().WithProperty("code", str).WithPropertyRef("rcr", assertion).WithProperty("exp", openapi3.NewInt64Schema()).WithRequired([]string{"code", "rcr", "exp"}))
		doc.Paths.Value("/auth/v1/users/{subject}/webauthn/auth/finish").Post.Responses.Status(202).Value.WithJSONSchema(openapi3.NewObjectSchema().WithProperty("code", str).WithProperty("user_id", str).WithRequired([]string{"code", "user_id"}))
		doc.Paths.Value("/auth/v1/users/{subject}/webauthn/register/start").Post.Responses.Status(200).Value.WithJSONSchema(creation.Value)
		doc.Paths.Value("/auth/v1/users/{subject}/webauthn").Get.Responses.Status(200).Value.WithJSONSchema(credentials.Value)
		doc.Paths.Value("/auth/v1/users/{subject}/mfa_token").Post.Responses.Status(200).Value.WithJSONSchema(openapi3.NewObjectSchema().WithProperty("id", str).WithProperty("user_id", str).WithProperty("exp", openapi3.NewInt64Schema()).WithRequired([]string{"id", "user_id", "exp"}))
		doc.Paths.Value("/auth/v1/users/{subject}/self/convert_passkey").Post.Description = "Empty body. Requires a peer-bound self session with authentication method mfa, a user-verified passkey, and session CSRF; a password session is not sufficient."
		doc.Paths.Value("/auth/v1/users/webauthn_finish").Post.Description = "data is a JSON-encoded assertion string. The one-use code and browser interaction/session bind this ceremony."
	}
	if features.Recovery {
		strictBody("/auth/v1/users/request_reset", "POST", map[string]*openapi3.Schema{"email": str, "pow": str}, "email", "pow")
		strictBody("/auth/v1/users/{subject}/reset", "PUT", map[string]*openapi3.Schema{"magic_link_id": str, "password": password}, "magic_link_id", "password")
		reset := doc.Paths.Value("/auth/v1/users/{subject}/reset").Put
		reset.AddParameter(openapi3.NewHeaderParameter("X-Pwd-CSRF-Token").WithRequired(true).WithSchema(str))
		reset.Description = "Requires the reset cookie and X-Pwd-CSRF-Token issued by GET for this magic link; an ordinary session or OAuth bearer does not replace this proof."
		doc.Paths.Value("/auth/v1/users/{subject}/reset/{token}").Get.Responses.Status(200).Value.WithJSONSchema(doc.Paths.Value("/account/password").Get.Responses.Status(200).Value.Content["application/json"].Schema.Value)
		doc.Paths.Value("/auth/v1/pow").Post.Responses.Status(200).Value.Content = openapi3.Content{"text/plain": {Schema: &openapi3.SchemaRef{Value: str}}}
	}
	if features.Recovery {
		add("/auth/v1/users/otp/start", "post", "otpStart", "Send an OTP code to the user", 200)
		doc.Paths.Value("/auth/v1/users/otp/start").Post.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(openapi3.NewObjectSchema().WithProperty("subject", str))}
		doc.Paths.Value("/auth/v1/users/otp/start").Post.Responses.Status(200).Value.WithJSONSchema(openapi3.NewObjectSchema().WithProperty("expires_at", openapi3.NewDateTimeSchema()))
		doc.Paths.Value("/auth/v1/users/otp/start").Post.Description = "Public endpoint. No browser session or API key is required; only cross-site request protection applies."
		doc.Paths.Value("/auth/v1/users/otp/start").Post.Security = &openapi3.SecurityRequirements{}
		add("/auth/v1/users/otp/verify", "post", "otpVerify", "Verify an OTP code during login", 200)
		otpVerify := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithProperty("code", str).WithRequired([]string{"code"})
		doc.Paths.Value("/auth/v1/users/otp/verify").Post.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(otpVerify)}
		doc.Paths.Value("/auth/v1/users/otp/verify").Post.Responses.Status(200).Value.Content = openapi3.Content{"text/html": {Schema: &openapi3.SchemaRef{Value: str}}}
		doc.Paths.Value("/auth/v1/users/otp/verify").Post.AddResponse(303, openapi3.NewResponse().WithDescription("Authorization redirect via Location, same as password login"))
		doc.Paths.Value("/auth/v1/users/otp/verify").Post.Description = "Public login-flow endpoint. Requires an init (unauthenticated) browser session cookie from the login page; the session stores the interaction. Successful verification completes the OAuth authorization flow. No browserSession or apiKey security applies."
		doc.Paths.Value("/auth/v1/users/otp/verify").Post.Security = &openapi3.SecurityRequirements{}
		doc.Paths.Value("/auth/v1/users/otp/verify").Post.Responses.Set("400", &openapi3.ResponseRef{Value: openapi3.NewResponse().WithDescription("Bad request")})
		doc.Paths.Value("/auth/v1/users/otp/verify").Post.Responses.Set("401", &openapi3.ResponseRef{Value: openapi3.NewResponse().WithDescription("Invalid or expired OTP")})
	}
	if features.Recovery && features.OpenRegistration {
		schema, err := openapi3gen.NewSchemaRefForValue(recovery.RegistrationRequest{}, nil)
		if err != nil {
			return err
		}
		schema.Value.WithRequired([]string{"email", "pow"}).WithoutAdditionalProperties()
		doc.Paths.Value("/auth/v1/users/register").Post.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(schema.Value)}
		doc.Paths.Value("/auth/v1/users/register").Post.Description = "Ordinary profile fields follow deployment policy: given_name is required by default; family_name and nested user values are optional by default. A missing or empty required value returns 400 before consuming PoW or sending mail. Hidden fields are still accepted when syntactically valid. Matching Rauthy v0.36.2, nested requirements are checked only when user_values is present and non-null. The static schema describes the configurable request shape, not an exemption from runtime required-field policy."
	}
	if features.Recovery && features.OpenRegistration && features.Passkeys {
		add("/auth/v1/register/passkey/start", "post", "registerPasskeyStartPublic", "Start passkey registration (public CORS)", 200)
		passkeyStartSchema, err := openapi3gen.NewSchemaRefForValue(recovery.RegistrationRequest{}, nil)
		if err != nil {
			return err
		}
		passkeyStartSchema.Value.WithProperty("passkey_name", str).WithRequired([]string{"email", "passkey_name", "pow"}).WithoutAdditionalProperties()
		doc.Paths.Value("/auth/v1/register/passkey/start").Post.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(passkeyStartSchema.Value)}
		doc.Paths.Value("/auth/v1/register/passkey/start").Post.Responses.Status(200).Value.WithJSONSchema(openapi3.NewObjectSchema().WithProperty("credential_creation", openapi3.NewObjectSchema()).WithProperty("code", str).WithProperty("expires_at", openapi3.NewStringSchema()))
		doc.Paths.Value("/auth/v1/register/passkey/start").Post.Description = "Public CORS endpoint. No browser session or API key is required. Profile fields follow deployment policy: email, passkey_name, and pow are required; preferred_username, family_name, given_name, user_values, redirect_uri, and captcha_response are optional by default."
		doc.Paths.Value("/auth/v1/register/passkey/start").Post.Security = &openapi3.SecurityRequirements{}
		add("/auth/v1/register/passkey/start", "options", "registerPasskeyStartOptions", "Describe passkey registration CORS policy", 204)
		add("/auth/v1/register/passkey/finish", "post", "registerPasskeyFinishPublic", "Finish passkey registration (public CORS)", 200)
		doc.Paths.Value("/auth/v1/register/passkey/finish").Post.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(openapi3.NewObjectSchema().WithProperty("code", str).WithProperty("passkey_name", str).WithProperty("credential_id", str))}
		doc.Paths.Value("/auth/v1/register/passkey/finish").Post.Responses.Status(200).Value.WithJSONSchema(openapi3.NewObjectSchema().WithProperty("passkey_name", str).WithProperty("subject", str))
		doc.Paths.Value("/auth/v1/register/passkey/finish").Post.Description = "Public CORS endpoint. Completes passkey registration started by the /start endpoint. Request body is {code, passkey_name, credential_id}."
		doc.Paths.Value("/auth/v1/register/passkey/finish").Post.Security = &openapi3.SecurityRequirements{}
		add("/auth/v1/register/passkey/finish", "options", "registerPasskeyFinishOptions", "Describe passkey registration CORS policy", 204)
	}
	if features.Upstream {
		logout := doc.Paths.Value("/upstream/{providerID}/backchannel-logout").Post
		logout.Security = &openapi3.SecurityRequirements{}
		logout.Description = "Signed logout_token form POST from a configured OIDC provider. Maximum encoded body 24 KiB and token 16 KiB; issuer, audience, signature, events, nonce absence and token times are verified. A 200 response requires durable local revocation and replay receipt. No browser cookie or CSRF token is required. Invalid or failed requests return 400 without sensitive details."
		logout.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithSchema(openapi3.NewObjectSchema().WithProperty("logout_token", openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(16<<10)).WithRequired([]string{"logout_token"}), []string{"application/x-www-form-urlencoded"})}
		doc.Paths.Value("/upstream/{providerID}/start").Get.AddParameter(openapi3.NewQueryParameter("redirect_uri").WithRequired(true).WithSchema(str))
		for _, field := range []string{"state", "code", "error"} {
			doc.Paths.Value("/upstream/{providerID}/callback").Get.AddParameter(openapi3.NewQueryParameter(field).WithSchema(str))
		}
	}
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			if len(op.Tags) == 1 && op.Tags[0] == "account" {
				for _, status := range []int{400, 401, 403, 406, 429, 503} {
					op.AddResponse(status, openapi3.NewResponse().WithDescription(http.StatusText(status)))
				}
			}
		}
	}
	return nil
}

func statusText(status int) string {
	return map[int]string{200: "Success", 202: "Accepted", 204: "No content", 302: "Redirect"}[status]
}

func addPasskeyOperations(doc *openapi3.T, add func(string, string, string, string, int, ...map[string][]string), param func(*openapi3.Operation, string), secure, csrf map[string][]string) {
	add("/auth/v1/users/webauthn_start", "post", "webauthnStart", "Start passkey authentication", 200)
	add("/auth/v1/users/webauthn_finish", "post", "webauthnFinish", "Finish passkey authentication", 200)
	add("/auth/v1/users/{subject}/webauthn", "get", "listPasskeys", "List passkeys", 200, secure)
	mutation := map[string][]string{"browserSession": {}, "csrfToken": {}}
	add("/auth/v1/users/{subject}/webauthn/register/start", "post", "registerPasskeyStart", "Start passkey registration", 200, mutation)
	add("/auth/v1/users/{subject}/webauthn/register/finish", "post", "registerPasskeyFinish", "Finish passkey registration", 201, mutation)
	add("/auth/v1/users/{subject}/webauthn/delete/{name}", "delete", "deletePasskey", "Delete a passkey", 200, mutation)
	add("/auth/v1/users/{subject}/mfa_token", "post", "issueMFAModificationToken", "Issue an MFA modification token", 200, mutation)
	add("/auth/v1/users/{subject}/webauthn/auth/start", "post", "mfaWebauthnStart", "Start MFA WebAuthn proof", 200, mutation)
	add("/auth/v1/users/{subject}/webauthn/auth/finish", "post", "mfaWebauthnFinish", "Finish MFA WebAuthn proof", 202, mutation)
	add("/auth/v1/users/{subject}/self/convert_passkey", "post", "convertSelfPasskey", "Convert the account to passkey-only authentication", 200, mutation)
}

func addRecoveryOperations(doc *openapi3.T, add func(string, string, string, string, int, ...map[string][]string), param func(*openapi3.Operation, string)) {
	add("/auth/v1/users/request_reset", "post", "requestPasswordReset", "Request a password reset", 200)
	add("/auth/v1/users/{subject}/reset/{token}", "get", "getPasswordReset", "Begin a password reset", 200)
	add("/auth/v1/users/{subject}/reset", "put", "putPasswordReset", "Complete a password reset", 202)
	add("/auth/v1/pow", "post", "issueProofOfWork", "Issue a proof-of-work challenge", 200)
}
