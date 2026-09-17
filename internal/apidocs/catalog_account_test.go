package apidocs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/mrchypark/goauthy/internal/account"
)

func TestAddAccountOperationsFeatureContract(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{Passkeys: true, Recovery: true, OpenRegistration: true, Upstream: true, WebID: true}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []struct {
		path, method string
		status       int
	}{
		{"/account/password", "get", 200}, {"/auth/v1/users/{subject}/self", "put", 200}, {"/auth/v1/users/{subject}", "delete", 204},
		{"/auth/v1/users/{subject}/self/delete", "get", 202}, {"/auth/v1/users/{subject}/self/delete", "delete", 204},
		{"/auth/v1/users/{subject}/webauthn", "get", 200}, {"/auth/v1/users/{subject}/webauthn/register/finish", "post", 201},
		{"/auth/v1/users/request_reset", "post", 200}, {"/auth/v1/users/{subject}/reset", "put", 202}, {"/auth/v1/users/register", "post", 204},
		{"/auth/v1/providers/{providerID}/link", "delete", 204}, {"/auth/{subject}/profile", "get", 200},
	} {
		item := doc.Paths.Find(route.path)
		if item == nil {
			t.Fatalf("missing path %s", route.path)
		}
		op := item.GetOperation(strings.ToUpper(route.method))
		if op == nil {
			t.Fatalf("missing %s %s", route.method, route.path)
		}
		if op.Responses.Status(route.status) == nil {
			t.Fatalf("%s %s missing status %d", route.method, route.path, route.status)
		}
	}
	if p := doc.Paths.Find("/auth/v1/users/{subject}"); p == nil || p.Delete.Security == nil || len(*p.Delete.Security) != 2 {
		t.Fatal("delete user must expose browser/API-key alternatives")
	}
	if p := doc.Paths.Find("/auth/v1/users/{subject}/self"); p == nil || len(p.Put.Parameters) != 1 || p.Put.Parameters[0].Value.Name != "subject" || !p.Put.Parameters[0].Value.Required {
		t.Fatal("subject path parameter contract missing")
	}
	if body := doc.Paths.Find("/auth/v1/users/request_reset").Post.RequestBody.Value; body == nil || body.Content.Get("application/json").Schema.Value.Properties["email"] == nil || body.Content.Get("application/json").Schema.Value.Properties["pow"] == nil {
		t.Fatal("reset request schema missing email/pow")
	}
	if body := doc.Paths.Find("/auth/v1/users/{subject}/reset").Put.RequestBody.Value; body == nil || body.Content.Get("application/json").Schema.Value.Properties["password"] == nil {
		t.Fatal("reset request schema missing password")
	}
	registration := doc.Paths.Find("/auth/v1/users/register").Post
	if !strings.Contains(registration.Description, "given_name is required by default") || !strings.Contains(registration.Description, "before consuming PoW") {
		t.Fatal("registration runtime profile policy contract missing")
	}
}

func TestAddAccountOperationsFeatureGates(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/auth/v1/users/webauthn_start", "/auth/v1/users/request_reset", "/auth/v1/users/register", "/auth/v1/providers/{providerID}/link", "/auth/{subject}/profile", "/.well-known/web-identity", "/auth/v1/fed_cm/config"} {
		if doc.Paths.Find(path) != nil {
			t.Fatalf("feature-disabled path present: %s", path)
		}
	}
	doc = &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{OpenRegistration: true}); err != nil {
		t.Fatal(err)
	}
	if doc.Paths.Value("/auth/v1/users/register") != nil {
		t.Fatal("registration requires recovery runtime too")
	}
}

func TestAccountDashboardContract(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	for path, media := range map[string]string{"/account": "text/html", "/account/app.js": "text/javascript", "/account/connection-grants.js": "text/javascript", "/account/account.css": "text/css", "/account/data": "application/json"} {
		op := doc.Paths.Value(path).Get
		if op.Security == nil || len(*op.Security) != 1 {
			t.Fatalf("%s must require browser session", path)
		}
		if _, ok := (*op.Security)[0]["browserSession"]; !ok {
			t.Fatalf("%s must not accept bearer or API-key authority", path)
		}
		if op.Responses.Status(200).Value.Content[media] == nil {
			t.Fatalf("%s missing media %s", path, media)
		}
	}
	schema := doc.Paths.Value("/account/data").Get.Responses.Status(200).Value.Content["application/json"].Schema.Value
	for _, name := range []string{"subject", "email", "email_verified", "preferred_username", "given_name", "family_name", "csrf_token", "base_path", "features"} {
		if schema.Properties[name] == nil {
			t.Fatalf("missing dashboard property %s", name)
		}
	}
	policy := schema.Properties["password_policy"].Value
	for _, name := range []string{"password", "passkeys", "passkey_conversion"} {
		if property := schema.Properties["features"].Value.Properties[name]; property == nil || !property.Value.Type.Is("boolean") {
			t.Fatalf("missing boolean dashboard capability %s", name)
		}
	}
	if policy.Properties["length_min"] == nil || policy.Properties["valid_days"] == nil || policy.Properties["csrf_token"] != nil {
		t.Fatal("dashboard must expose the password policy, not a nested password response")
	}
}

func TestAccountWebAuthnWireSchemas(t *testing.T) {
	data, err := Document("https://id.example.test", Features{Passkeys: true})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	challenge := protocol.URLEncodedBase64{255, 255, 255, 0}
	assertion := protocol.CredentialAssertion{Response: protocol.PublicKeyCredentialRequestOptions{Challenge: challenge, RelyingPartyID: "id.example.test"}}
	creation := protocol.CredentialCreation{Response: protocol.PublicKeyCredentialCreationOptions{Challenge: challenge,
		RelyingParty: protocol.RelyingPartyEntity{ID: "id.example.test", CredentialEntity: protocol.CredentialEntity{Name: "GoAuthy"}},
		User:         protocol.UserEntity{ID: "user-handle", DisplayName: "Alice", CredentialEntity: protocol.CredentialEntity{Name: "alice"}},
	}}
	now := time.Unix(1700000000, 0).UTC()
	for _, fixture := range []struct {
		path, method string
		status       int
		body         any
	}{
		{"/auth/v1/users/webauthn_start", "POST", 200, map[string]any{"code": "one-use", "rcr": assertion, "exp": now}},
		{"/auth/v1/users/{subject}/webauthn/auth/start", "POST", 200, map[string]any{"code": "one-use", "rcr": assertion, "exp": now.Unix()}},
		{"/auth/v1/users/{subject}/webauthn/auth/finish", "POST", 202, map[string]any{"code": "proof", "user_id": "alice"}},
		{"/auth/v1/users/{subject}/webauthn/register/start", "POST", 200, creation},
		{"/auth/v1/users/{subject}/webauthn", "GET", 200, []account.PasskeyResponse{{Name: "passkey", Registered: now.Unix(), LastUsed: now.Unix(), UserVerified: true}}},
	} {
		t.Run(fixture.path, func(t *testing.T) {
			encoded, err := json.Marshal(fixture.body)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal(encoded, &value); err != nil {
				t.Fatal(err)
			}
			schema := doc.Paths.Value(fixture.path).GetOperation(fixture.method).Responses.Status(fixture.status).Value.Content["application/json"].Schema.Value
			if err := schema.VisitJSON(value); err != nil {
				t.Fatal(err)
			}
		})
	}
	login := doc.Paths.Value("/auth/v1/users/webauthn_finish").Post
	if login.Responses.Status(303) == nil || login.Responses.Status(200).Value.Content["application/json"] != nil || login.Responses.Status(200).Value.Content["text/html"] == nil {
		t.Fatal("login finishes through authorization, not redirect_uri JSON")
	}
}

func TestUpstreamLogoutHasSignedFormContract(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{Upstream: true}); err != nil {
		t.Fatal(err)
	}
	op := doc.Paths.Value("/upstream/{providerID}/backchannel-logout").Post
	if op.Security == nil || len(*op.Security) != 0 || op.Responses.Status(200) == nil || op.Responses.Status(400) == nil {
		t.Fatal("logout must use token proof with explicit success/failure responses")
	}
	form := op.RequestBody.Value.Content["application/x-www-form-urlencoded"]
	if form == nil || form.Schema.Value.Properties["logout_token"] == nil || len(form.Schema.Value.Required) != 1 || form.Schema.Value.Required[0] != "logout_token" {
		t.Fatal("missing signed form token contract")
	}
	disabled := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(disabled, Features{}); err != nil {
		t.Fatal(err)
	}
	if disabled.Paths.Value("/upstream/{providerID}/backchannel-logout") != nil {
		t.Fatal("disabled upstream advertised logout")
	}
}


func TestOTPRoutesPublicNoBrowserAuth(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{Recovery: true}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/auth/v1/users/otp/start", "/auth/v1/users/otp/verify"} {
		op := doc.Paths.Value(path).Post
		if op == nil {
			t.Fatalf("missing %s", path)
		}
		if op.Security != nil && len(*op.Security) > 0 {
			t.Fatalf("%s must be public (no security requirement)", path)
		}
		if op.Responses.Status(200) == nil {
			t.Fatalf("%s missing 200 response", path)
		}
	}
}

func TestOTPSchemasComplete(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{Recovery: true}); err != nil {
		t.Fatal(err)
	}
	startBody := doc.Paths.Value("/auth/v1/users/otp/start").Post.RequestBody.Value.Content["application/json"].Schema.Value
	if startBody.Properties["subject"] == nil {
		t.Fatal("otp/start missing subject in request body")
	}
	startResp := doc.Paths.Value("/auth/v1/users/otp/start").Post.Responses.Status(200).Value.Content["application/json"].Schema.Value
	if startResp.Properties["expires_at"] == nil {
		t.Fatal("otp/start response missing expires_at")
	}
	verifyBody := doc.Paths.Value("/auth/v1/users/otp/verify").Post.RequestBody.Value.Content["application/json"].Schema.Value
	if verifyBody.Properties["code"] == nil {
		t.Fatal("otp/verify missing code in request body")
	}
	if verifyBody.Properties["subject"] != nil {
		t.Fatal("otp/verify must not accept subject (strict decoder rejects it)")
	}
	if verifyBody.AdditionalProperties.Schema != nil {
		t.Fatal("otp/verify must not allow additional properties")
	}
	if verifyResp := doc.Paths.Value("/auth/v1/users/otp/verify").Post.Responses.Status(200); verifyResp == nil || verifyResp.Value.Content["application/json"] != nil {
		t.Fatal("otp/verify 200 must not return JSON (completes OAuth flow)")
	}
	if doc.Paths.Value("/auth/v1/users/otp/verify").Post.Responses.Status(303) == nil {
		t.Fatal("otp/verify missing 303 authorization redirect")
	}
}

func TestOTPRoutesGatedByRecovery(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{}); err != nil {
		t.Fatal(err)
	}
	if doc.Paths.Value("/auth/v1/users/otp/start") != nil {
		t.Fatal("otp/start must be absent when recovery disabled")
	}
	if doc.Paths.Value("/auth/v1/users/otp/verify") != nil {
		t.Fatal("otp/verify must be absent when recovery disabled")
	}
}

func TestOTPVerifyErrorResponses(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{Recovery: true}); err != nil {
		t.Fatal(err)
	}
	op := doc.Paths.Value("/auth/v1/users/otp/verify").Post
	if op.Responses.Status(400) == nil {
		t.Fatal("otp/verify missing 400 Bad request response")
	}
	if op.Responses.Status(401) == nil {
		t.Fatal("otp/verify missing 401 Invalid or expired OTP response")
	}
	if op.Responses.Status(410) != nil {
		t.Fatal("otp/verify must not have 410 (expired maps to 401)")
	}
	if op.Security != nil && len(*op.Security) > 0 {
		t.Fatal("otp/verify must be public (no security requirement)")
	}
	if !strings.Contains(op.Description, "init (unauthenticated) browser session cookie") {
		t.Fatal("otp/verify description must document init browser session cookie requirement")
	}
}

func TestPublicPasskeyRoutesRequireRecovery(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{OpenRegistration: true, Passkeys: true}); err != nil {
		t.Fatal(err)
	}
	if doc.Paths.Value("/auth/v1/register/passkey/start") != nil {
		t.Fatal("passkey registration must require recovery feature too")
	}
	doc2 := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc2, Features{Recovery: true, OpenRegistration: true, Passkeys: true}); err != nil {
		t.Fatal(err)
	}
	if doc2.Paths.Value("/auth/v1/register/passkey/start") == nil {
		t.Fatal("passkey registration should be present with all features")
	}
	if doc2.Paths.Value("/auth/v1/register/passkey/finish") == nil {
		t.Fatal("passkey finish should be present with all features")
	}
}

func TestPublicPasskeyRoutesNoSecurity(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{Recovery: true, OpenRegistration: true, Passkeys: true}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/auth/v1/register/passkey/start", "/auth/v1/register/passkey/finish"} {
		op := doc.Paths.Value(path).Post
		if op == nil {
			t.Fatalf("missing %s", path)
		}
		if op.Security != nil && len(*op.Security) > 0 {
			t.Fatalf("%s must be public (no security requirement)", path)
		}
	}
}

func TestPublicPasskeySchemasComplete(t *testing.T) {
	doc := &openapi3.T{Paths: openapi3.NewPaths()}
	if err := addAccountOperations(doc, Features{Recovery: true, OpenRegistration: true, Passkeys: true}); err != nil {
		t.Fatal(err)
	}
	startBody := doc.Paths.Value("/auth/v1/register/passkey/start").Post.RequestBody.Value.Content["application/json"].Schema.Value
	for _, field := range []string{"email", "passkey_name", "pow"} {
		if startBody.Properties[field] == nil {
			t.Fatalf("passkey start missing %s", field)
		}
	}
	for _, field := range []string{"preferred_username", "family_name", "given_name", "redirect_uri", "captcha_response"} {
		if startBody.Properties[field] == nil {
			t.Fatalf("passkey start missing optional field %s", field)
		}
	}
	if startBody.AdditionalProperties.Schema != nil {
		t.Fatal("passkey start must not allow additional properties")
	}
	finishBody := doc.Paths.Value("/auth/v1/register/passkey/finish").Post.RequestBody.Value.Content["application/json"].Schema.Value
	for _, field := range []string{"code", "passkey_name", "credential_id"} {
		if finishBody.Properties[field] == nil {
			t.Fatalf("passkey finish missing %s", field)
		}
	}
}
