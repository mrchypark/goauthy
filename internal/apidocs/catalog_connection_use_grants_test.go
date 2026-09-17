package apidocs

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mrchypark/goauthy/internal/saas"
)

func TestConnectionUseGrantCatalog(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Info: &openapi3.Info{Title: "test", Version: "test"}, Paths: openapi3.NewPaths(), Components: &components}
	if err := addConnectionUseGrantOperations(doc); err != nil {
		t.Fatal(err)
	}
	route := "/auth/v1/account/connections/{collection_id}/{connection_id}/grants"
	get, post := doc.Paths.Value(route).Get, doc.Paths.Value(route).Post
	for _, op := range []*openapi3.Operation{get, post} {
		if op == nil || len(*op.Security) != 1 || (*op.Security)[0]["browserSession"] == nil || (*op.Security)[0]["bearerToken"] != nil || (*op.Security)[0]["apiKey"] != nil {
			t.Fatalf("unexpected grant security: %#v", op)
		}
	}
	list := get.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	if list.MaxItems == nil || *list.MaxItems != 256 {
		t.Fatal("grant list must cap at 256")
	}
	if post.RequestBody == nil {
		t.Fatal("grant create body missing")
	}
	body := post.RequestBody.Value.Content["application/json"].Schema.Value
	for _, field := range []string{"consumer_client_id", "mode", "purpose", "expires_at_unix_ms"} {
		if body.Properties[field] == nil {
			t.Fatalf("missing input field %s", field)
		}
	}
	if body.Properties["connector_digest"] == nil || len(body.Required) != 4 {
		t.Fatal("reviewed connector digest must be optional")
	}
	if body.Properties["allow_refresh"] == nil || body.Properties["allow_refresh"].Value.Default != false {
		t.Fatal("allow_refresh must be optional and default false")
	}
	for _, invalid := range []any{nil, "true", float64(1)} {
		if body.Properties["allow_refresh"].Value.VisitJSON(invalid) == nil {
			t.Fatalf("invalid allow_refresh accepted: %#v", invalid)
		}
	}
	version := body.Properties["credential_version"]
	if version == nil || version.Value.VisitJSON(float64(1)) != nil {
		t.Fatal("reviewed OAuth version is missing")
	}
	for _, invalid := range []any{nil, float64(0), float64(-1), float64(1.5), "1"} {
		if version.Value.VisitJSON(invalid) == nil {
			t.Fatal("invalid reviewed OAuth version accepted")
		}
	}
	if err := body.VisitJSON(map[string]any{"consumer_client_id": "c", "mode": "proxy", "purpose": "p", "expires_at_unix_ms": float64(1), "connector_digest": strings.Repeat("A", 43)}); err != nil {
		t.Fatal("valid reviewed connector digest rejected: ", err)
	}
	if err := body.VisitJSON(map[string]any{"consumer_client_id": "c", "mode": "proxy", "purpose": "p", "expires_at_unix_ms": float64(1), "connector_digest": nil}); err == nil {
		t.Fatal("reviewed connector digest must reject null")
	}
	if body.Properties["mode"].Value.VisitJSON("proxy") != nil || body.Properties["mode"].Value.VisitJSON("credential_delivery") != nil || body.Properties["mode"].Value.VisitJSON("secret") == nil {
		t.Fatal("mode enum incorrect")
	}
	if body.Properties["purpose"].Value.MaxLength == nil || *body.Properties["purpose"].Value.MaxLength != 256 {
		t.Fatal("purpose limit missing")
	}
	grant := post.Responses.Status(http.StatusCreated).Value.Content["application/json"].Schema.Value
	if grant.Properties["allow_refresh"] == nil || grant.Properties["allow_refresh"].Value.Default != false {
		t.Fatal("grant response missing allow_refresh default")
	}
	for _, secret := range []string{"credential", "access_token", "refresh_token", "client_secret"} {
		if grant.Properties[secret] != nil {
			t.Fatalf("secret field exposed: %s", secret)
		}
	}
	deletePath := route + "/{grant_id}"
	del := doc.Paths.Value(deletePath).Delete
	if del == nil || len(*del.Security) != 1 || (*del.Security)[0]["csrfToken"] == nil || del.Parameters.GetByInAndName("header", "If-Match") == nil || del.Responses.Status(http.StatusPreconditionRequired) == nil || del.Responses.Status(http.StatusNoContent) == nil {
		t.Fatal("grant revoke contract incomplete")
	}
	if del.RequestBody != nil || del.Responses.Status(http.StatusNoContent).Value.Content != nil {
		t.Fatal("revoke must have empty 204 response and no body")
	}
	for _, status := range []int{400, 401, 404, 409, 503} {
		if get.Responses.Status(status) == nil || post.Responses.Status(status) == nil || del.Responses.Status(status) == nil {
			t.Fatalf("missing status %d", status)
		}
	}
	invoke := doc.Paths.Value("/auth/v1/connection-grants/{grant_id}/invoke").Post
	if invoke == nil || len(*invoke.Security) != 1 || (*invoke.Security)[0]["bearerToken"] == nil || (*invoke.Security)[0]["browserSession"] != nil || (*invoke.Security)[0]["csrfToken"] != nil || (*invoke.Security)[0]["apiKey"] != nil {
		t.Fatal("invoke must be bearer-only")
	}
	if invoke.RequestBody == nil || !invoke.RequestBody.Value.Required || len(invoke.RequestBody.Value.Content) != 1 || invoke.RequestBody.Value.Content["application/json"] == nil {
		t.Fatal("invoke must require JSON body")
	}
	invokeBody := invoke.RequestBody.Value.Content["application/json"].Schema.Value
	if invokeBody.AdditionalProperties.Has == nil || *invokeBody.AdditionalProperties.Has || len(invokeBody.Required) != 1 || invokeBody.Required[0] != "operation" {
		t.Fatal("invoke body must be closed and require operation")
	}
	if err := invokeBody.VisitJSON(map[string]any{"operation": "account"}); err != nil {
		t.Fatal("valid operation rejected: ", err)
	}
	for _, value := range []any{"Account", "account!", strings.Repeat("a", 65), ""} {
		if err := invokeBody.VisitJSON(map[string]any{"operation": value}); err == nil {
			t.Fatalf("non-canonical operation accepted: %#v", value)
		}
	}
	if err := invokeBody.VisitJSON(map[string]any{"operation": "account", "owner_subject": "attacker"}); err == nil {
		t.Fatal("identity fields must be rejected")
	}
	result := invoke.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	if result.AdditionalProperties.Schema == nil || len(result.AdditionalProperties.Schema.Value.AnyOf) != 3 {
		t.Fatal("invoke result must be scalar projection")
	}
	if err := result.VisitJSON(map[string]any{"id": "acct", "count": float64(2), "active": true}); err != nil {
		t.Fatal("scalar projection rejected: ", err)
	}
	if err := result.VisitJSON(map[string]any{"nested": map[string]any{"secret": "x"}}); err == nil {
		t.Fatal("non-scalar projection accepted")
	}
	for _, secret := range []string{"credential", "access_token", "refresh_token", "client_secret", "upstream_headers"} {
		if result.Properties[secret] != nil {
			t.Fatalf("secret/upstream field exposed: %s", secret)
		}
	}
	for _, status := range []int{400, 401, 404, 409, 502, 503} {
		if invoke.Responses.Status(status) == nil {
			t.Fatalf("invoke missing status %d", status)
		}
	}
	if !strings.Contains(invoke.Description, "GOAUTHY_CONNECTIONS_RESOURCE") || !strings.Contains(invoke.Description, "goauthy.connections.use") || !strings.Contains(invoke.Description, "No retries") {
		t.Fatal("invoke security/runtime description incomplete")
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	credential := doc.Paths.Value("/auth/v1/connection-grants/{grant_id}/credential").Post
	if credential == nil || len(*credential.Security) != 1 || (*credential.Security)[0]["bearerToken"] == nil || (*credential.Security)[0]["browserSession"] != nil || (*credential.Security)[0]["apiKey"] != nil || credential.RequestBody != nil || len(credential.Parameters) != 1 {
		t.Fatal("credential delivery must be bearer-only, bodyless, and grant-scoped")
	}
	credentialResult := credential.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	if len(credentialResult.OneOf) != 2 {
		t.Fatal("credential delivery must be an API-key/OAuth2 oneOf")
	}
	apiKeyResult, oauthResult := credentialResult.OneOf[0].Value, credentialResult.OneOf[1].Value
	if apiKeyResult.AdditionalProperties.Has == nil || *apiKeyResult.AdditionalProperties.Has || apiKeyResult.Properties["api_key"] == nil || apiKeyResult.Properties["api_key"].Value.WriteOnly || oauthResult.AdditionalProperties.Has == nil || *oauthResult.AdditionalProperties.Has {
		t.Fatal("credential delivery variants must be closed and response-readable")
	}
	apiKeyValue := map[string]any{"kind": "api_key", "api_key": "secret", "grant_id": "g", "provider_id": "p", "connection_generation": "gen", "credential_version": float64(1), "connector_digest": "digest", "header": "Authorization", "prefix": "Bearer ", "consent_expires_at_unix_ms": float64(2)}
	oauthValue := map[string]any{"kind": "oauth2", "access_token": "token", "token_type": "Bearer", "grant_id": "g", "provider_id": "p", "connection_generation": "gen", "credential_version": float64(1), "account_id": "acct", "scopes": []any{"read"}, "token_expires_at_unix_ms": float64(3), "consent_expires_at_unix_ms": float64(2)}
	for _, value := range []map[string]any{apiKeyValue, oauthValue} {
		if err := credentialResult.VisitJSON(value); err != nil {
			t.Fatalf("valid credential delivery rejected: %v", err)
		}
	}
	for _, secret := range []string{"refresh_token", "client_secret", "upstream_headers"} {
		if apiKeyResult.Properties[secret] != nil || oauthResult.Properties[secret] != nil {
			t.Fatalf("forbidden credential field exposed: %s", secret)
		}
	}
	if err := credentialResult.VisitJSON(map[string]any{"kind": "oauth2", "access_token": "token", "token_type": "Bearer", "grant_id": "g", "provider_id": "p", "connection_generation": "gen", "credential_version": float64(1), "account_id": "acct", "scopes": []any{"read"}, "token_expires_at_unix_ms": float64(3), "consent_expires_at_unix_ms": float64(2), "refresh_token": "bad"}); err == nil {
		t.Fatal("mixed OAuth secret accepted")
	}
	if credential.Responses.Status(http.StatusOK).Value.Headers["Cache-Control"].Value.Example != "no-store" || !strings.Contains(credential.Description, "credential_delivery") || !strings.Contains(credential.Description, "proxy consent never exports") {
		t.Fatal("credential delivery safety contract incomplete")
	}
	for _, status := range []int{400, 401, 404, 409, 502, 503} {
		if credential.Responses.Status(status) == nil {
			t.Fatalf("credential delivery missing status %d", status)
		}
	}
	handoffCreate := doc.Paths.Value("/auth/v1/connection-handoffs").Post
	if handoffCreate == nil || handoffCreate.OperationID != "createConnectionHandoff" || len(*handoffCreate.Security) != 1 || (*handoffCreate.Security)[0]["bearerToken"] == nil || (*handoffCreate.Security)[0]["browserSession"] != nil {
		t.Fatal("handoff create must be bearer-only")
	}
	handoffBody := handoffCreate.RequestBody.Value.Content["application/json"].Schema.Value
	if handoffBody.AdditionalProperties.Has == nil || *handoffBody.AdditionalProperties.Has || len(handoffBody.Required) != 8 || handoffBody.Properties["allow_refresh"] == nil || handoffBody.Properties["allow_refresh"].Value.Default != false {
		t.Fatal("handoff create body must be strict and complete")
	}
	if err := handoffBody.VisitJSON(map[string]any{"collection_id": "c", "connection_id": "x", "consumer_client_id": "consumer", "mode": "proxy", "purpose": "p", "expires_at_unix_ms": float64(1), "return_uri": "https://example.test/cb", "state": strings.Repeat("s", 32)}); err != nil {
		t.Fatal("valid handoff body rejected: ", err)
	}
	if err := handoffBody.VisitJSON(map[string]any{"collection_id": "c", "connection_id": "x", "consumer_client_id": "consumer", "mode": "credential_delivery", "purpose": "p", "expires_at_unix_ms": float64(1), "return_uri": "https://example.test/cb", "state": strings.Repeat("s", 32)}); err != nil {
		t.Fatal("credential delivery handoff rejected: ", err)
	}
	if handoffCreate.Responses.Status(http.StatusCreated) == nil || handoffCreate.Responses.Status(http.StatusBadGateway) != nil {
		t.Fatal("handoff create statuses incorrect")
	}
	refresh := doc.Paths.Value("/auth/v1/connection-grants/{grant_id}/refresh").Post
	if refresh == nil || len(*refresh.Security) != 1 || (*refresh.Security)[0]["bearerToken"] == nil || refresh.RequestBody == nil {
		t.Fatal("grant refresh must be bearer-only with a body")
	}
	refreshBody := refresh.RequestBody.Value.Content["application/json"].Schema.Value
	if refreshBody.AdditionalProperties.Has == nil || *refreshBody.AdditionalProperties.Has || len(refreshBody.Required) != 1 || refreshBody.Properties["credential_version"] == nil {
		t.Fatal("refresh body must be strict and require credential_version")
	}
	if err := refreshBody.VisitJSON(map[string]any{"credential_version": float64(1)}); err != nil {
		t.Fatal("valid refresh body rejected: ", err)
	}
	for _, value := range []any{nil, float64(0), float64(-1), float64(1.5), "1", float64(1 << 63)} {
		if err := refreshBody.VisitJSON(map[string]any{"credential_version": value}); err == nil {
			t.Fatalf("invalid refresh version accepted: %#v", value)
		}
	}
	refreshResult := refresh.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	if len(refreshResult.Required) != 6 || refreshResult.Properties["access_token"] != nil || refreshResult.Properties["refresh_token"] != nil {
		t.Fatal("refresh response must be public OAuth2 status only")
	}
	credentialStatus := doc.Paths.Value("/auth/v1/connection-grants/{grant_id}/credential-status").Get
	if credentialStatus == nil || len(*credentialStatus.Security) != 1 || (*credentialStatus.Security)[0]["bearerToken"] == nil || credentialStatus.RequestBody != nil || len(credentialStatus.Parameters) != 1 {
		t.Fatal("credential status must be bearer-only, bodyless and grant-scoped")
	}
	statusResult := credentialStatus.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	if len(statusResult.Required) != 6 || statusResult.Properties["access_token"] != nil || statusResult.Properties["refresh_token"] != nil || credentialStatus.Responses.Status(http.StatusOK).Value.Headers["Cache-Control"].Value.Example != "no-store" {
		t.Fatal("credential status must expose only no-store OAuth2 metadata")
	}
	for _, code := range []int{400, 401, 404, 503} {
		if credentialStatus.Responses.Status(code) == nil {
			t.Fatalf("credential status missing status %d", code)
		}
	}
	handoffPath := "/auth/v1/account/connection-handoffs/{handoff_id}"
	handoffGet, handoffPost := doc.Paths.Value(handoffPath).Get, doc.Paths.Value(handoffPath).Post
	if handoffGet == nil || handoffPost == nil || len(*handoffGet.Security) != 1 || (*handoffGet.Security)[0]["browserSession"] == nil || len(*handoffPost.Security) != 1 || (*handoffPost.Security)[0]["csrfToken"] == nil || (*handoffPost.Security)[0]["browserSession"] == nil {
		t.Fatal("owner handoff security incomplete")
	}
	if handoffGet.RequestBody != nil || handoffGet.Parameters.GetByInAndName("query", "anything") != nil || handoffPost.RequestBody == nil {
		t.Fatal("handoff review/completion body contract incorrect")
	}
	reviewSchema := handoffGet.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	if len(reviewSchema.Required) != 6 || reviewSchema.Properties["review_digest"] == nil || reviewSchema.Properties["oauth2"] == nil || reviewSchema.Properties["connector"] == nil {
		t.Fatal("handoff response schemas incomplete")
	}
	if err := reviewSchema.VisitJSON(map[string]any{"request_client_id": "client", "return_uri": "https://example.test/cb", "expires_at_unix_ms": float64(1), "grant": map[string]any{}, "connector": map[string]any{}, "review_digest": "digest", "oauth2": map[string]any{"provider_id": "p", "account_id": "a", "scopes": []any{"read"}, "version": float64(1), "connected": true, "state": "ready"}}); err == nil {
		t.Fatal("incomplete grant unexpectedly accepted in review")
	}
	if len(handoffPost.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value.Required) != 1 {
		t.Fatal("handoff completion response schema incomplete")
	}
	for _, op := range []*openapi3.Operation{handoffGet, handoffPost} {
		for _, code := range []int{400, 401, 404, 409, 503} {
			if op.Responses.Status(code) == nil {
				t.Fatalf("handoff missing status %d", code)
			}
		}
	}
	if !strings.Contains(handoffCreate.Description, "no implicit consent") || !strings.Contains(handoffCreate.Description, "5 minutes") || !strings.Contains(handoffCreate.Description, "16 per owner") || !strings.Contains(handoffCreate.Description, "never upgrades proxy consent") || !strings.Contains(handoffCreate.Description, "cannot be constrained") {
		t.Fatal("handoff proposal constraints missing")
	}
	statusPath := "/auth/v1/connections/{collection_id}/{connection_id}/grants/{grant_id}"
	status := doc.Paths.Value(statusPath).Get
	if status == nil || status.OperationID != "getConnectionUseGrantStatus" || len(*status.Security) != 1 || (*status.Security)[0]["bearerToken"] == nil || (*status.Security)[0]["browserSession"] != nil || (*status.Security)[0]["apiKey"] != nil {
		t.Fatal("grant status must be bearer-only")
	}
	if status.RequestBody != nil || status.Parameters.GetByInAndName("query", "") != nil || len(status.Parameters) != 3 {
		t.Fatal("grant status must have only path parameters and no body")
	}
	statusSchema := status.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	if len(statusSchema.Required) != 2 || statusSchema.Properties["grant"] == nil || statusSchema.Properties["connection_generation"] == nil || statusSchema.AdditionalProperties.Has == nil || *statusSchema.AdditionalProperties.Has {
		t.Fatal("grant status envelope must be exact")
	}
	if err := statusSchema.VisitJSON(map[string]any{"grant": map[string]any{}, "connection_generation": "g"}); err == nil {
		t.Fatal("incomplete grant metadata accepted")
	}
	if status.Responses.Status(http.StatusOK).Value.Headers["Cache-Control"].Value.Example != "no-store" {
		t.Fatal("grant status must be no-store")
	}
	for _, code := range []int{400, 401, 404, 503} {
		if status.Responses.Status(code) == nil {
			t.Fatalf("grant status missing status %d", code)
		}
	}
	if !strings.Contains(status.Description, "goauthy.connections.read") || !strings.Contains(status.Description, "GOAUTHY_CONNECTIONS_RESOURCE") || !strings.Contains(status.Description, "not an execution capability") {
		t.Fatal("grant status description incomplete")
	}
	page := doc.Paths.Value("/account/connection-handoffs/{handoff_id}")
	if page == nil || page.Get == nil || page.Post == nil || page.Get.RequestBody != nil || len(*page.Get.Security) != 0 || len(*page.Post.Security) != 1 || (*page.Post.Security)[0]["browserSession"] == nil {
		t.Fatal("HTML handoff page contract incomplete")
	}
	pageForm := page.Post.RequestBody.Value.Content["application/x-www-form-urlencoded"].Schema.Value
	if pageForm.AdditionalProperties.Has == nil || *pageForm.AdditionalProperties.Has || pageForm.Properties["csrf_token"] == nil || pageForm.Properties["reviewed"] == nil || pageForm.Properties["review_digest"] == nil || pageForm.Properties["connector_digest"] == nil {
		t.Fatal("HTML decision form must be strict and CSRF-protected")
	}
	if page.Get.Responses.Status(http.StatusSeeOther) == nil || page.Get.Responses.Status(http.StatusOK) == nil || page.Post.Responses.Status(http.StatusOK) == nil || page.Post.Responses.Status(http.StatusConflict) == nil {
		t.Fatal("HTML handoff page statuses incomplete")
	}
	for _, name := range []string{"Cache-Control", "Referrer-Policy", "Content-Security-Policy"} {
		if page.Get.Responses.Status(http.StatusOK).Value.Headers[name] == nil {
			t.Fatalf("HTML page missing %s header", name)
		}
	}
	loginPath := doc.Paths.Value("/account/connection-login")
	if loginPath == nil || loginPath.Get == nil || loginPath.Post == nil || len(*loginPath.Get.Security) != 0 || loginPath.Get.Parameters.GetByInAndName("query", "handoff_id") == nil {
		t.Fatal("handoff login contract incomplete")
	}
	loginBody := loginPath.Post.RequestBody.Value.Content["application/x-www-form-urlencoded"].Schema.Value
	if loginBody.AdditionalProperties.Has == nil || *loginBody.AdditionalProperties.Has || len(loginBody.Required) != 4 {
		t.Fatal("login form must be strict with four fields")
	}
	for _, field := range []string{"interaction", "csrf_token", "username", "password"} {
		if loginBody.Properties[field] == nil {
			t.Fatalf("login form missing %s", field)
		}
	}
	if loginPath.Get.Responses.Status(http.StatusOK) == nil || loginPath.Get.Responses.Status(http.StatusBadRequest) == nil || loginPath.Get.Responses.Status(http.StatusForbidden) == nil || loginPath.Get.Responses.Status(http.StatusServiceUnavailable) == nil || loginPath.Post.Responses.Status(http.StatusSeeOther) == nil {
		t.Fatal("handoff login statuses incomplete")
	}
	if !strings.Contains(loginPath.Post.Description, "forced MFA") || !strings.Contains(loginPath.Post.Description, "full cold-MFA") {
		t.Fatal("MFA login boundaries missing")
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionHandoffReviewMatchesSaaSPublicJSON(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Info: &openapi3.Info{Title: "test", Version: "test"}, Paths: openapi3.NewPaths(), Components: &components}
	if err := addConnectionUseGrantOperations(doc); err != nil {
		t.Fatal(err)
	}
	reviewSchema := doc.Paths.Value("/auth/v1/account/connection-handoffs/{handoff_id}").Get.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	grant := saas.UseGrant{ID: "", Owner: "owner", CollectionID: "collection", ConnectionID: "connection", ConsumerClientID: "consumer", Mode: "credential_delivery", Purpose: "purpose", Resource: "https://resource.example", Generation: "generation", ConsumerGeneration: "consumer-generation", ProviderID: "provider", Revision: 1, ProviderRevision: 2, ExpiresAt: 300}
	for _, review := range []saas.UseHandoffReview{
		{RequestClientID: "requester", ReturnURI: "https://return.example/cb", ExpiresAt: 200, Grant: grant, Connector: saas.APIKeyConnectorInfo{Operations: []saas.APIKeyOperationInfo{}}, OAuth2: &saas.OAuth2Status{ProviderID: "provider", AccountID: "account", Scopes: []string{"read"}, Version: 3, Connected: true, State: "ready"}, ReviewDigest: "oauth-review"},
		{RequestClientID: "requester", ReturnURI: "https://return.example/cb", ExpiresAt: 200, Grant: grant, Connector: saas.APIKeyConnectorInfo{Operations: []saas.APIKeyOperationInfo{}}, ReviewDigest: "api-key-review"},
	} {
		raw, err := json.Marshal(review)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		if err := reviewSchema.VisitJSON(value); err != nil {
			t.Fatalf("public review JSON rejected: %v (%s)", err, raw)
		}
	}
}
