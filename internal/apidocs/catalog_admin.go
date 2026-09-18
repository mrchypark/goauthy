package apidocs

import (
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3gen"
	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/rbac"
)

// Wire contracts are from rbac/http.go, claims/http.go, apikey/http.go,
// ipblacklist/admin.go and masterkeyretirement/http.go, not database rows.
func addAdminOperations(doc *openapi3.T, features Features) error {
	if doc == nil || doc.Paths == nil || doc.Components == nil {
		return fmt.Errorf("uninitialized API document")
	}
	s := openapi3.NewStringSchema()
	anyJSON := openapi3.NewSchema().WithNullable()
	strs := openapi3.NewArraySchema().WithItems(s)
	obj := func(props map[string]*openapi3.Schema, required ...string) *openapi3.Schema {
		v := openapi3.NewObjectSchema().WithoutAdditionalProperties().WithRequired(required)
		for name, p := range props {
			v.WithProperty(name, p)
		}
		return v
	}
	read := &openapi3.SecurityRequirements{{"browserSession": {}}, {"apiKey": {}}}
	write := &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}, {"apiKey": {}}}
	browserRead := &openapi3.SecurityRequirements{{"browserSession": {}}}
	browserWrite := &openapi3.SecurityRequirements{{"browserSession": {}, "csrfToken": {}}}
	keyOnly := &openapi3.SecurityRequirements{{"apiKey": {}}}
	add := func(method, path, summary string, body, result *openapi3.Schema, auth *openapi3.SecurityRequirements) *openapi3.Operation {
		op := &openapi3.Operation{OperationID: method + path, Summary: summary, Tags: []string{"Administration"}, Security: auth, Responses: openapi3.NewResponses()}
		for _, part := range strings.Split(path, "/") {
			if strings.HasPrefix(part, "{") {
				op.AddParameter(openapi3.NewPathParameter(strings.Trim(part, "{}")).WithSchema(s))
			}
		}
		if body != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithJSONSchema(body)}
		}
		for _, status := range []int{200, 400, 401, 403, 404, 409, 503} {
			op.AddResponse(status, openapi3.NewResponse().WithDescription(http.StatusText(status)))
		}
		if result != nil {
			op.Responses.Status(200).Value.WithJSONSchema(result)
		}
		doc.AddOperation(path, method, op)
		return op
	}
	page := add("GET", "/auth/v1/admin", "Read-only administrator navigation", nil, nil, browserRead)
	page.Responses.Status(200).Value.Content = openapi3.Content{"text/html": {Schema: &openapi3.SchemaRef{Value: s}}}
	userRef, err := openapi3gen.NewSchemaRefForValue(rbac.UserResponseSimple{}, doc.Components.Schemas)
	if err != nil {
		return err
	}
	userRef.Value.Required = []string{"id", "email", "given_name", "family_name", "created_at", "last_login", "picture_id"}
	userRef.Value.WithoutAdditionalProperties()
	userRef.Value.Properties["created_at"].Value.WithMin(0)
	userRef.Value.Properties["last_login"].Value.WithMin(0)
	users := add("GET", "/auth/v1/users", "List users", nil, openapi3.NewArraySchema().WithItems(userRef.Value), read)
	mode := openapi3.NewStringSchema().WithEnum("required", "optional", "hidden")
	preferredConfig := obj(map[string]*openapi3.Schema{
		"preferred_username": mode, "immutable": openapi3.NewBoolSchema(),
		"blacklist":      openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema().WithMaxLength(128)),
		"pattern_html":   openapi3.NewStringSchema().WithMaxLength(4096),
		"pattern_hint":   openapi3.NewStringSchema().WithNullable().WithMaxLength(512),
		"email_fallback": openapi3.NewBoolSchema(),
	}, "preferred_username", "immutable", "blacklist", "pattern_html", "pattern_hint", "email_fallback")
	valuesConfig := obj(map[string]*openapi3.Schema{
		"given_name": mode, "family_name": mode, "birthdate": mode, "street": mode,
		"zip": mode, "city": mode, "country": mode, "phone": mode, "tz": mode,
		"revalidate_during_login": openapi3.NewBoolSchema().WithEnum(false), "preferred_username": preferredConfig,
	}, "given_name", "family_name", "birthdate", "street", "zip", "city", "country", "phone", "tz", "revalidate_during_login", "preferred_username")
	valuesConfigAuth := read
	if features.OpenRegistration {
		valuesConfigAuth = &openapi3.SecurityRequirements{}
	}
	valuesConfigOp := add("GET", "/auth/v1/users/values_config", "Read user profile configuration", nil, valuesConfig, valuesConfigAuth)
	valuesConfigOp.Description = "Public when registration is open, including requests with invalid credentials. Otherwise requires a current full/delegated administrator session or Users:read API key; no fallback from a supplied invalid key to the browser session. Body and query parameters are not accepted. Returns configured presentation metadata separately from the internal server regex. Preferred username email fallback defaults to true and controls ID-token and UserInfo profile claims. Login revalidation remains unimplemented and exposes its fixed default false."
	for _, q := range []*openapi3.Parameter{
		openapi3.NewQueryParameter("page_size").WithSchema(openapi3.NewInt32Schema().WithMin(1).WithMax(65535)),
		openapi3.NewQueryParameter("offset").WithSchema(openapi3.NewInt32Schema().WithMin(0).WithMax(65535)),
		openapi3.NewQueryParameter("backwards").WithSchema(openapi3.NewBoolSchema()),
		openapi3.NewQueryParameter("continuation_token").WithSchema(openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(700)),
		openapi3.NewQueryParameter("session_state").WithSchema(openapi3.NewStringSchema().WithEnum("Init", "Auth", "LoggedOut", "Unknown")),
	} {
		users.AddParameter(q)
	}
	for _, code := range []string{"200", "206"} {
		if code == "206" {
			users.AddResponse(206, openapi3.NewResponse().WithDescription("Partial content").WithJSONSchema(openapi3.NewArraySchema().WithItems(userRef.Value)))
		}
		r := users.Responses.Value(code).Value
		r.Headers = openapi3.Headers{"x-user-count": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: openapi3.NewInt64Schema()}}}}
		if code == "206" {
			r.Headers["x-page-count"] = &openapi3.HeaderRef{Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: openapi3.NewInt64Schema()}}}
			r.Headers["x-page-size"] = r.Headers["x-page-count"]
		}
		if code == "206" {
			r.Headers["x-continuation-token"] = &openapi3.HeaderRef{Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithMaxLength(700)}}}
		}
	}
	sessionRef, err := openapi3gen.NewSchemaRefForValue(rbac.Session{}, doc.Components.Schemas)
	if err != nil {
		return err
	}
	sessionRef.Value.WithoutAdditionalProperties()
	sessionRef.Value.Required = []string{"id", "is_mfa", "state", "exp", "last_seen", "remote_ip"}
	// The generator shares string schemas: replace state rather than mutating
	// the shared schema used by id/user_id/remote_ip.
	sessionRef.Value.WithProperty("state", openapi3.NewStringSchema().WithEnum("Init", "Auth", "LoggedOut", "Unknown"))
	sessionRef.Value.Properties["exp"].Value.WithMin(0)
	sessionRef.Value.Properties["last_seen"].Value.WithMin(0)
	sessions := add("GET", "/auth/v1/sessions", "List browser sessions", nil, openapi3.NewArraySchema().WithItems(sessionRef.Value), read)
	sessions.Description = "Requires an API key with Sessions:read or a direct/delegated browser administrator; delegated administrators have read-only visibility of all sessions. session_state defaults to Auth; stored Auth is not a promise that a session is unexpired. Results are sorted by expiry then digest ID descending. User count determines whether pagination applies, with a page size of max(requested or 20, configured threshold); below threshold pagination is ignored. Retained revoked rows project as LoggedOut. IDs are stored digests, never raw browser cookies. is_mfa currently represents GoAuthy's explicit mfa authentication method; broader WebAuthn/provider projection parity remains incomplete. Browser authorization failure uses the shared 401 response; insufficient API-key rights use 403. Request bodies are not accepted."
	for _, q := range []*openapi3.Parameter{openapi3.NewQueryParameter("page_size").WithSchema(openapi3.NewInt32Schema().WithMin(1).WithMax(65535)), openapi3.NewQueryParameter("offset").WithSchema(openapi3.NewInt32Schema().WithMin(0).WithMax(65535)), openapi3.NewQueryParameter("backwards").WithSchema(openapi3.NewBoolSchema()), openapi3.NewQueryParameter("continuation_token").WithSchema(openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(700)), openapi3.NewQueryParameter("session_state").WithSchema(openapi3.NewStringSchema().WithEnum("Init", "Auth", "LoggedOut", "Unknown").WithDefault("Auth"))} {
		sessions.AddParameter(q)
	}
	sessions.AddResponse(206, openapi3.NewResponse().WithDescription("Partial content").WithJSONSchema(openapi3.NewArraySchema().WithItems(sessionRef.Value)))
	response := sessions.Responses.Status(206).Value
	response.Headers = openapi3.Headers{"x-page-size": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: openapi3.NewInt64Schema()}}}, "x-page-count": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: openapi3.NewInt64Schema()}}}, "x-continuation-token": {Value: &openapi3.Header{Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithMaxLength(700)}}}}
	detailRef, err := openapi3gen.NewSchemaRefForValue(rbac.UserResponse{}, doc.Components.Schemas)
	if err != nil {
		return err
	}
	detail := detailRef.Value
	detail.WithoutAdditionalProperties()
	detail.Required = []string{"id", "email", "language", "roles", "enabled", "email_verified", "created_at", "account_type", "user_values"}
	for _, ref := range detail.Properties {
		ref.Value.Nullable = false
	}
	detail.WithProperty("account_type", openapi3.NewStringSchema().WithEnum("password", "passkey", "new", "federated", "federated_password", "federated_passkey"))
	detail.WithProperty("language", openapi3.NewStringSchema().WithEnum("de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans"))
	detail.Properties["language"].Value.Description = "Stored user language; unknown legacy preference projects as en."
	valuesSchema := detail.Properties["user_values"].Value
	valuesSchema.WithoutAdditionalProperties()
	for _, ref := range valuesSchema.Properties {
		ref.Value.Nullable = false
	}
	for _, name := range []string{"created_at", "last_login", "password_expires", "last_failed_login", "failed_login_attempts", "user_expires"} {
		detail.Properties[name].Value.WithMin(0)
	}
	userDetail := add("GET", "/auth/v1/users/{subject}", "Read user detail", nil, detail, read)
	userDetail.Responses.Set("428", &openapi3.ResponseRef{Value: openapi3.NewResponse().WithDescription("Target is outside delegated administrator scope")})
	updateValues := obj(map[string]*openapi3.Schema{
		"birthdate": openapi3.NewStringSchema().WithNullable().WithPattern(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`),
		"phone":     openapi3.NewStringSchema().WithNullable().WithPattern(`^\+[0-9]{0,32}$`),
		"street":    openapi3.NewStringSchema().WithNullable().WithMaxLength(48),
		"zip":       openapi3.NewStringSchema().WithNullable().WithPattern(`^[a-zA-Z0-9]{1,24}$`),
		"city":      openapi3.NewStringSchema().WithNullable().WithMaxLength(48),
		"country":   openapi3.NewStringSchema().WithNullable().WithMaxLength(48),
		"tz":        openapi3.NewStringSchema().WithNullable().WithMinLength(1).WithMaxLength(48),
	}).WithNullable()
	update := obj(map[string]*openapi3.Schema{
		"email":       openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(254),
		"roles":       openapi3.NewArraySchema().WithMaxItems(64).WithUniqueItems(true).WithItems(openapi3.NewStringSchema().WithPattern(`^[A-Za-z0-9_/,*:.-]{2,64}$`)),
		"groups":      openapi3.NewArraySchema().WithNullable().WithMaxItems(64).WithUniqueItems(true).WithItems(openapi3.NewStringSchema().WithPattern(`^[A-Za-z0-9_/,*:-]{2,64}$`)),
		"given_name":  openapi3.NewStringSchema().WithNullable().WithMinLength(1).WithMaxLength(32),
		"family_name": openapi3.NewStringSchema().WithNullable().WithMinLength(1).WithMaxLength(32),
		"language":    openapi3.NewStringSchema().WithNullable().WithEnum("de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans", nil),
		"password":    openapi3.NewStringSchema().WithNullable().WithMaxLength(256),
		"enabled":     openapi3.NewBoolSchema(), "email_verified": openapi3.NewBoolSchema(),
		"user_expires": openapi3.NewInt64Schema().WithNullable().WithMin(1719784800).WithMax(float64(math.MaxInt64 / 1000)),
		"user_values":  updateValues,
	}, "email", "roles", "enabled", "email_verified")
	updateOp := add("PUT", "/auth/v1/users/{subject}", "Update user", update, detail, write)
	preferred := openapi3.NewStringSchema().WithNullable().WithMaxLength(128)
	preferred.Description = "Runtime-configured username syntax; default ^[a-z][a-z0-9_-]{1,61}$. Missing/null requests clearing; supplied empty strings still undergo regex validation."
	preferredOp := add("PUT", "/auth/v1/users/{subject}/self/preferred_username", "Update preferred username", obj(map[string]*openapi3.Schema{"preferred_username": preferred, "force_overwrite": openapi3.NewBoolSchema().WithNullable()}), nil, write)
	preferredOp.AddResponse(406, openapi3.NewResponse().WithDescription("Username is reserved or already assigned"))
	preferredOp.AddResponse(428, openapi3.NewResponse().WithDescription("Target is outside delegated administrator scope"))
	preferredOp.Description = "Authenticated self-service, Users:update keys, or direct/delegated administrators. Delegated administrators may initialize only an unnamed, non-administrator target within their current group scope. Only full administrators and Users:update keys may force_overwrite. Existing names are immutable by default (400 without force); required and blacklist rules also apply to forced updates. Success is an empty 200 response. Missing legacy email metadata returns 409 rather than fabricating a profile email."
	updateOp.AddResponse(428, openapi3.NewResponse().WithDescription("Target is outside delegated administrator scope"))
	updateOp.Description = "Requires Users:update or a direct/delegated browser administrator. An update-only API key receives this mutation's result without Users:read. Delegated changes preserve roles and change only managed groups; removing the last managed group still returns the committed result. Omitted/null names, groups, expiry and profile values clear them; omitted/null language and password preserve them. Preferred username is not accepted. Current password policy, canonical email, display-name syntax and IANA timezones receive additional server validation. Conflict (409) covers email collision, final administrator protection and concurrent authority/state changes. Success includes the transaction's profile even if it revokes the caller's session. With SMTP enabled, email changes notify both addresses after commit; delivery is best effort."
	updateOp.Description += " Clearing names is subject to deployment required-field policy: given_name is required by default, other ordinary fields optional. Missing/null/empty required names return 400; nested requirements apply only when user_values is present and non-null, matching Rauthy v0.36.2. Hidden fields remain writable with valid syntax. Administrative POST creation is exempt from required-field policy. The static schema permits configurable optional fields; runtime policy can require them."
	entity := obj(map[string]*openapi3.Schema{"id": s, "name": s, "meta": anyJSON}, "id", "name")
	for _, resource := range []string{"roles", "groups"} {
		field := strings.TrimSuffix(resource, "s")
		body := obj(map[string]*openapi3.Schema{field: s, "meta": anyJSON}, field)
		base := "/auth/v1/" + resource
		add("GET", base, "List "+resource, nil, openapi3.NewArraySchema().WithItems(entity), read)
		add("POST", base, "Create "+field, body, entity, write)
		add("PUT", base+"/{id}", "Update "+field, body, entity, write)
		add("DELETE", base+"/{id}", "Delete "+field, nil, nil, write)
	}
	scope := obj(map[string]*openapi3.Schema{"scope": s, "attr_include_access": strs, "attr_include_id": strs, "claims_at_root": openapi3.NewBoolSchema()}, "scope")
	add("GET", "/auth/v1/scopes", "List claim scopes", nil, openapi3.NewArraySchema().WithItems(scope), read)
	add("POST", "/auth/v1/scopes", "Create claim scope", scope, scope, write)
	add("PUT", "/auth/v1/scopes/{id}", "Update claim scope", scope, scope, write)
	add("DELETE", "/auth/v1/scopes/{id}", "Delete claim scope", nil, nil, write)
	attr := obj(map[string]*openapi3.Schema{"name": s, "desc": s, "default_value": anyJSON, "typ": s, "user_editable": openapi3.NewBoolSchema()}, "name")
	attrs := obj(map[string]*openapi3.Schema{"values": openapi3.NewArraySchema().WithItems(attr)}, "values")
	add("GET", "/auth/v1/users/attr", "List attribute definitions", nil, attrs, read)
	add("POST", "/auth/v1/users/attr", "Create attribute definition", attr, attr, write)
	add("PUT", "/auth/v1/users/attr/{name}", "Update attribute definition", attr, attr, write)
	add("DELETE", "/auth/v1/users/attr/{name}", "Delete attribute definition", nil, nil, write)
	value := obj(map[string]*openapi3.Schema{"key": s, "value": anyJSON}, "key", "value")
	values := obj(map[string]*openapi3.Schema{"values": openapi3.NewArraySchema().WithItems(value)}, "values")
	add("GET", "/auth/v1/users/{subject}/attr", "Read user attribute values", nil, values, read)
	add("PUT", "/auth/v1/users/{subject}/attr", "Set user attribute values (self limited to editable attributes)", values, values, write)
	editable := obj(map[string]*openapi3.Schema{"name": s, "desc": s, "default_value": anyJSON, "typ": s, "value": anyJSON}, "name")
	add("GET", "/auth/v1/users/{subject}/attr/editable", "Read own editable attributes; no administrator override", nil, obj(map[string]*openapi3.Schema{"values": openapi3.NewArraySchema().WithItems(editable)}, "values"), browserRead)
	clientScopes := obj(map[string]*openapi3.Schema{"allowed_scopes": strs, "default_scopes": strs}, "allowed_scopes", "default_scopes")
	clientClaims := obj(map[string]*openapi3.Schema{"claims": openapi3.NewObjectSchema().WithNullable(), "claims_at_root": openapi3.NewBoolSchema(), "revision": openapi3.NewInt64Schema().WithMin(0)}, "claims", "claims_at_root", "revision")
	restriction := obj(map[string]*openapi3.Schema{"restrict_group_prefix": openapi3.NewStringSchema().WithNullable(), "revision": openapi3.NewInt64Schema()}, "revision", "restrict_group_prefix")
	for _, p := range []struct {
		name string
		body *openapi3.Schema
	}{{"scopes", clientScopes}, {"claims", clientClaims}, {"login-restriction", restriction}} {
		path := "/auth/v1/clients/{id}/" + p.name
		result := p.body
		if p.name != "claims" {
			// client_id is emitted by the handler but must not be accepted
			// in the strict update body; the path selects the client.
			result = obj(map[string]*openapi3.Schema{"client_id": s}, append([]string{"client_id"}, p.body.Required...)...)
			for name, schema := range p.body.Properties {
				result.WithPropertyRef(name, schema)
			}
		}
		add("GET", path, "Read bootstrap client "+p.name, nil, result, read)
		add("PUT", path, "Update bootstrap client "+p.name, p.body, result, write)
	}
	membership := obj(map[string]*openapi3.Schema{"put": openapi3.NewArraySchema().WithItems(obj(map[string]*openapi3.Schema{"key": openapi3.NewStringSchema().WithEnum("roles", "groups"), "value": strs}, "key", "value")), "del": openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema().WithEnum("roles", "groups"))})
	add("PATCH", "/auth/v1/users/{subject}", "Patch role/group membership only", membership, obj(map[string]*openapi3.Schema{"id": s, "roles": strs, "groups": strs}, "id", "roles", "groups"), write)
	// Reuse the public Go wire types; private response wrappers below remain explicit.
	keyRequest, err := openapi3gen.NewSchemaRefForValue(apikey.Request{}, doc.Components.Schemas)
	if err != nil {
		return err
	}
	keyResponse, err := openapi3gen.NewSchemaRefForValue(apikey.Key{}, doc.Components.Schemas)
	if err != nil {
		return err
	}
	keyRequest.Value.WithoutAdditionalProperties().WithRequired([]string{"name", "access"})
	add("GET", "/auth/v1/api_keys", "List API keys (browser administrator only)", nil, obj(map[string]*openapi3.Schema{"keys": openapi3.NewArraySchema().WithItems(keyResponse.Value)}, "keys"), browserRead)
	create := add("POST", "/auth/v1/api_keys", "Create API key; returns the one-time name$secret", keyRequest.Value, nil, browserWrite)
	create.Responses.Status(200).Value.Content = openapi3.Content{"text/plain": {Schema: &openapi3.SchemaRef{Value: s}}}
	add("PUT", "/auth/v1/api_keys/{name}", "Update API key", keyRequest.Value, keyResponse.Value, browserWrite)
	add("DELETE", "/auth/v1/api_keys/{name}", "Delete API key", nil, nil, browserWrite)
	rotate := add("PUT", "/auth/v1/api_keys/{name}/secret", "Rotate API key secret", nil, nil, browserWrite)
	rotate.Responses.Status(200).Value.Content = create.Responses.Status(200).Value.Content
	add("GET", "/auth/v1/api_keys/{name}/test", "Check the API key named in the path", nil, keyResponse.Value, keyOnly)
	event := obj(map[string]*openapi3.Schema{"id": s, "occurred_at_unix_ms": openapi3.NewInt64Schema(), "type": s, "action": s, "outcome": s, "actor_kind": s, "actor_hash": s, "target_hash": s}, "id", "occurred_at_unix_ms", "type", "action", "outcome", "actor_kind", "target_hash")
	events := add("GET", "/auth/v1/events", "Read durable audit events (Events:read API key only)", nil, obj(map[string]*openapi3.Schema{"events": openapi3.NewArraySchema().WithItems(event), "next_cursor": obj(map[string]*openapi3.Schema{"sequence": openapi3.NewInt64Schema()}, "sequence")}, "events"), keyOnly)
	events.AddParameter(openapi3.NewQueryParameter("limit").WithSchema(openapi3.NewIntegerSchema().WithMin(1).WithMax(1000)))
	events.AddParameter(openapi3.NewQueryParameter("cursor").WithSchema(openapi3.NewInt64Schema().WithMin(0)))
	// POST /auth/v1/events is the lifecycle-event query API. Its wire types and
	// bounds are defined by eventlog.Query/Event (internal/eventlog/events.go).
	// Keep this separate from the legacy audit GET above: the two response
	// formats are intentionally unrelated.
	seconds := openapi3.NewInt64Schema().WithMin(1719784800).WithMax(float64(math.MaxInt64 / 1000))
	types := []interface{}{
		"InvalidLogins", "IpBlacklisted", "IpBlacklistRemoved", "JwksRotated",
		"NewUserRegistered", "NewRauthyAdmin", "NewRauthyVersion", "PossibleBruteForce",
		"RauthyStarted", "RauthyHealthy", "RauthyUnhealthy", "SecretsMigrated",
		"UserEmailChange", "UserPasswordReset", "Test", "BackchannelLogoutFailed",
		"ScimTaskFailed", "ForcedLogout", "UserLoginRevoke", "SuspiciousApiScan",
		"LoginNewLocation", "TokenIssued", "CredentialStuffing", "EmailSendError",
	}
	query := obj(map[string]*openapi3.Schema{
		"from":  seconds,
		"until": openapi3.NewInt64Schema().WithMin(1719784800).WithMax(float64(math.MaxInt64 / 1000)).WithNullable(),
		"level": openapi3.NewStringSchema().WithEnum("info", "notice", "warning", "critical"),
		"typ":   openapi3.NewStringSchema().WithMaxLength(24).WithEnum(types...).WithNullable(),
	}, "from", "level")
	eventResult := obj(map[string]*openapi3.Schema{
		"id":        s,
		"timestamp": openapi3.NewInt64Schema(),
		"level":     openapi3.NewStringSchema().WithEnum("info", "notice", "warning", "critical"),
		"typ":       openapi3.NewStringSchema().WithMaxLength(24).WithEnum(types...),
		"ip":        openapi3.NewStringSchema().WithNullable(),
		"data":      openapi3.NewInt64Schema().WithNullable(),
		"text":      openapi3.NewStringSchema().WithNullable(),
	}, "id", "timestamp", "level", "typ", "ip", "data", "text")
	eventQueryOp := add("POST", "/auth/v1/events", "Query lifecycle events (Events:read)", query,
		openapi3.NewArraySchema().WithItems(eventResult), read)
	eventQueryOp.Description = "Requires an API key with Events:read or an authenticated browser administrator. Browser authorization accepts direct administrators and delegated group administrators; the handler also validates the active peer-bound session."
	eventStream := add("GET", "/auth/v1/events/stream", "Stream lifecycle events as server-sent events (Events:read)", nil, openapi3.NewStringSchema(), read)
	eventStream.Description = "Requires an API key with Events:read or an authenticated browser administrator, including delegated group administrators. Streams a bounded committed window after filtering, in chronological order; latest is limited to 1000 and defaults to 0. Frames begin with retry: 10000, contain JSON event records in data fields, and close when authorization fails. Last-Event-ID replay is not supported."
	eventStream.AddParameter(openapi3.NewQueryParameter("latest").WithSchema(openapi3.NewIntegerSchema().WithMin(0).WithMax(1000).WithDefault(0)))
	eventStream.AddParameter(openapi3.NewQueryParameter("level").WithSchema(openapi3.NewStringSchema().WithEnum("info", "notice", "warning", "critical").WithDefault("info")))
	eventStream.Responses.Status(200).Value.Content = openapi3.Content{"text/event-stream": {Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}}
	eventTest := add("POST", "/auth/v1/events/test", "Create a durable test lifecycle event", nil, nil, write)
	eventTest.Description = "Requires an API key with Events:create or a direct browser administrator with a CSRF token. Delegated group administrators and Events:read-only keys are insufficient. On a successful durable commit the server assigns level info, type Test, the request IP, and text \"This is a Test-Event\". Each POST creates an independent event; no HTTP idempotency protocol is implied."
	forcedLogout := add("DELETE", "/auth/v1/sessions/{subject}", "Force logout all sessions for one user", nil, nil, write)
	forcedLogout.Description = "Requires an API key with Sessions:delete or a browser administrator with a CSRF token. Delegated administrators may only manage ordinary users in a matching managed group; they cannot manage administrator targets, including themselves. Atomically revokes the target user's local browser/OAuth artifacts, queues one subject-only back-channel delivery per known user/client login and records one Notice ForcedLogout event. Other users of the same client are not revoked. Success has an empty body and does not wait for external delivery. Credentials remain usable for a fresh login; previously issued stateless tokens at external relying parties require their own validation/logout handling. Query parameters and a request body are not accepted."
	sessionDelete := add("DELETE", "/auth/v1/sessions/id/{session_id}", "Delete one browser session", nil, nil, write)
	sessionDelete.Description = "Requires an API key with Sessions:delete or a direct browser administrator with a CSRF token. Delegated administrators are not allowed. session_id is a canonical stored 32-byte base64url digest, not the raw browser cookie. Atomically removes this browser session and interactions, invalidates its session-bound OAuth artifacts, and queues registered back-channel deliveries. Other sessions, including the same user's other sessions and sessionless grants, remain unchanged. No ForcedLogout event is emitted. Success is an empty 200 response; a missing session returns 404. External relying parties must process logout or otherwise validate token revocation; the response does not wait for external delivery. No query parameters or body are accepted."
	logoutAll := add("DELETE", "/auth/v1/sessions", "Log out all existing sessions", nil, nil, write)
	logoutAll.Description = "Requires an API key with Sessions:delete or a direct browser administrator with a CSRF token. Delegated administrators are not allowed. Atomically revokes all browser sessions, outstanding authorization codes and issued access/refresh tokens, including sessionless client-credentials tokens, and queues one subject-only back-channel delivery per known user/client login. Browser rows are retained as LoggedOut. Identity/client/API-key credentials and pending device authorizations remain usable; this is not an issuance shutdown. No ForcedLogout event is emitted. Success is an empty 200 response, including when no sessions exist, and does not wait for external delivery. External relying parties must process logout or otherwise validate token revocation. No query parameters or body are accepted."
	logo := add("GET", "/auth/v1/clients/{id}/logo", "Read public client logo", nil, nil, nil)
	logo.Description = "Returns the client small raster or SVG logo, falling back to the global rauthy logo. An updated query value enables public cache headers."
	logo.AddParameter(openapi3.NewQueryParameter("updated").WithSchema(openapi3.NewInt64Schema()))
	logo.Responses.Status(200).Value.Content = openapi3.Content{"image/webp": {Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithFormat("binary")}}, "image/svg+xml": {Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithFormat("binary")}}}
	logoPut := add("PUT", "/auth/v1/clients/{id}/logo", "Replace client logo (Clients:update)", nil, nil, write)
	logoPut.Description = "Processes the first multipart field as PNG, JPEG or SVG; the request is limited to 10 MiB. Atomically replaces logo resolutions while preserving favicon."
	logoPut.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithSchema(obj(map[string]*openapi3.Schema{"file": openapi3.NewStringSchema().WithFormat("binary")}, "file"), []string{"multipart/form-data"})}
	add("DELETE", "/auth/v1/clients/{id}/logo", "Delete client logo (Clients:update)", nil, nil, write).Description = "Deletes nonfavicon logo resolutions and preserves the separately managed favicon."
	icon := add("GET", "/auth/v1/clients/{id}/favicon", "Read client favicon", nil, nil, nil)
	icon.Description = "Exact client favicon lookup with no global fallback. An updated query value enables public cache headers; legacy PNG/ICO assets remain readable after migration."
	icon.AddParameter(openapi3.NewQueryParameter("updated").WithSchema(openapi3.NewInt64Schema()))
	icon.Responses.Status(200).Value.Content = openapi3.Content{"image/*": {Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithFormat("binary")}}}
	iconPut := add("PUT", "/auth/v1/clients/{id}/favicon", "Replace client favicon (Clients:update)", nil, nil, write)
	iconPut.Description = "First multipart field accepts PNG/JPEG normalized to 32px WebP or sanitized SVG. Maximum request size 10 MiB. No ETag precondition is required."
	iconPut.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithRequired(true).WithSchema(obj(map[string]*openapi3.Schema{"file": openapi3.NewStringSchema().WithFormat("binary")}, "file"), []string{"multipart/form-data"})}
	add("DELETE", "/auth/v1/clients/{id}/favicon", "Delete client favicon (Clients:update)", nil, nil, write)
	hsl := openapi3.NewArraySchema().WithMinItems(3).WithMaxItems(3).WithItems(openapi3.NewIntegerSchema().WithMin(0).WithMax(360))
	hsl.Description = "HSL tuple: hue 0–360, saturation and lightness 0–100."
	cssValue := openapi3.NewStringSchema().WithMinLength(1)
	cssValue.Description = "Lowercase CSS value containing letters a–z, digits, whitespace and -, . # ( ) % /."
	themeCSS := obj(map[string]*openapi3.Schema{
		"text": hsl, "text_high": hsl, "bg": hsl, "bg_high": hsl,
		"action": openapi3.NewArraySchema().WithMinItems(3).WithMaxItems(3).WithItems(openapi3.NewIntegerSchema().WithMin(0).WithMax(65535)), "accent": hsl, "error": hsl,
		"btn_text": cssValue, "theme_sun": cssValue, "theme_moon": cssValue,
	}, "text", "text_high", "bg", "bg_high", "action", "accent", "error", "btn_text", "theme_sun", "theme_moon")
	theme := obj(map[string]*openapi3.Schema{
		"client_id": openapi3.NewStringSchema().WithMinLength(2).WithMaxLength(256),
		"light":     themeCSS, "dark": themeCSS, "border_radius": cssValue,
	}, "client_id", "light", "dark", "border_radius")
	globalCSS := add("GET", "/auth/v1/theme/global.css", "Read shared theme styles", nil, nil, nil)
	globalCSS.Responses.Status(200).Value.Content = openapi3.Content{"text/css": {Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}}
	themePublic := add("GET", "/auth/v1/theme/{client_id}/{timestamp}", "Read public theme CSS", nil, nil, nil)
	themePublic.Description = "Returns the requested client theme, then the stored global rauthy theme, then built-in defaults. Timestamp is a signed 64-bit cache-busting value."
	themePublic.Responses.Status(200).Value.Content = openapi3.Content{"text/css": {Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}}
	for _, parameter := range themePublic.Parameters {
		if parameter.Value.Name == "timestamp" {
			parameter.Value.Schema = &openapi3.SchemaRef{Value: openapi3.NewInt64Schema()}
		}
	}
	add("POST", "/auth/v1/theme/{client_id}", "Read theme configuration (Clients:read)", nil, theme, read).Description = "A missing client-specific theme returns built-in defaults, without using the stored global override."
	add("PUT", "/auth/v1/theme/{client_id}", "Replace theme (Clients:update)", theme, nil, write).Description = "Requires an existing client and matching client_id in path and payload. Returns an empty 200 response with Clear-Site-Data cache directive."
	add("DELETE", "/auth/v1/theme/{client_id}", "Delete theme (Clients:delete)", nil, nil, write).Description = "Deletes the stored override; missing overrides also return an empty 200 response with Clear-Site-Data cache directive."
	if features.Blacklist {
		ip := obj(map[string]*openapi3.Schema{"ip": s, "exp": openapi3.NewInt64Schema()}, "ip", "exp")
		ip.Description = "Canonical IP/CIDR and absolute Unix expiry seconds, which must be in the future."
		add("GET", "/auth/v1/blacklist", "List IP blacklist", nil, obj(map[string]*openapi3.Schema{"ips": openapi3.NewArraySchema().WithItems(ip)}, "ips"), read)
		add("POST", "/auth/v1/blacklist", "Add IP blacklist entry", ip, ip, write)
		add("GET", "/auth/v1/blacklist/{ip}", "Read IP blacklist entry", nil, ip, read)
		add("PUT", "/auth/v1/blacklist/{ip}", "Update IP blacklist entry", ip, ip, write)
		add("DELETE", "/auth/v1/blacklist/{ip}", "Delete IP blacklist entry", nil, nil, write)
	}
	if features.Recovery {
		// Independent schemas: a generator may share refs for the same Go type.
		// Tightening timezone must not accidentally tighten email or array items.
		membership := func(pattern string) *openapi3.Schema {
			return openapi3.NewArraySchema().WithMaxItems(64).WithUniqueItems(true).WithItems(openapi3.NewStringSchema().WithPattern(pattern))
		}
		preferredUsername := openapi3.NewStringSchema().WithNullable().WithMaxLength(128)
		preferredUsername.Description = "Runtime preferred-username regex applies to supplied values, including empty strings. Default: ^[a-z][a-z0-9_-]{1,61}$. Administrator creation exempts required and blacklist policy, not syntax or uniqueness."
		create := obj(map[string]*openapi3.Schema{
			"email":    openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(254),
			"language": openapi3.NewStringSchema().WithEnum("de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans"),
			"roles":    membership(`^[A-Za-z0-9_/,*:.-]{2,64}$`), "groups": membership(`^[A-Za-z0-9_/,*:-]{2,64}$`).WithNullable(),
			"preferred_username": preferredUsername,
			"given_name":         openapi3.NewStringSchema().WithNullable().WithMinLength(1).WithMaxLength(32),
			"family_name":        openapi3.NewStringSchema().WithNullable().WithMinLength(1).WithMaxLength(32),
			"user_expires":       openapi3.NewInt64Schema().WithNullable().WithMin(1719784800).WithMax(float64(math.MaxInt64 / 1000)),
			"tz":                 openapi3.NewStringSchema().WithNullable().WithMinLength(1).WithMaxLength(48),
		}, "email", "language", "roles")
		createOp := add("POST", "/auth/v1/users", "Create user", create, detail, write)
		createOp.Description = "Requires Users/create or a browser administrator. Delegated creators must assign no roles and only managed groups, including at least one existing group. Unknown entity names are filtered. Email is canonicalized; preferred usernames must match the deployment regex and be unique. Administrator creation exempts required/blacklist policy. Names and IANA timezones receive additional server validation."
		createOp.AddResponse(406, openapi3.NewResponse().WithDescription(http.StatusText(406)))
	}
	adminRegisterOp := add("POST", "/auth/v1/users/{subject}/webauthn/admin_register", "Admin passkey registration", nil, nil, browserWrite)
	adminRegisterOp.Description = "Initiates passkey registration for an admin-provisioned user. Requires an admin browser session and returns WebAuthn credential creation options."
	convertPasswordOp := add("POST", "/auth/v1/users/{subject}/convert_password", "Admin password conversion", obj(map[string]*openapi3.Schema{"password_new": openapi3.NewStringSchema().WithMinLength(1).WithMaxLength(256)}, "password_new"), nil, browserWrite)
	convertPasswordOp.Description = "Converts a passkey-only user to password authentication. Requires an admin browser session. Returns 409 if the user already has a password."
	convertPasswordOp.Responses.Delete("200")
	convertPasswordOp.AddResponse(204, openapi3.NewResponse().WithDescription(http.StatusText(204)))
	addManagedClientOperations(doc)
	if err := addAccountDeviceOperations(doc); err != nil {
		return err
	}
	if err := addConnectionResourceOperations(doc); err != nil {
		return err
	}
	if err := addConnectionAPIKeyOperations(doc); err != nil {
		return err
	}
	if err := addConnectionUseGrantOperations(doc); err != nil {
		return err
	}
	if err := addSaaSProviderOperations(doc); err != nil {
		return err
	}
	return nil
}
