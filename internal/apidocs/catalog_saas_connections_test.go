package apidocs

import (
	"net/http"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestSaaSConnectionCatalog(t *testing.T) {
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	doc := &openapi3.T{OpenAPI: "3.0.3", Paths: openapi3.NewPaths(), Components: &components}
	if err := addSaaSConnectionOperations(doc); err != nil {
		t.Fatal(err)
	}
	start := doc.Paths.Value("/auth/v1/account/connections/{collection_id}/{connection_id}/oauth2").Post
	if start == nil || len(*start.Security) != 1 || (*start.Security)[0]["browserSession"] == nil || (*start.Security)[0]["csrfToken"] == nil {
		t.Fatalf("start security=%v", start.Security)
	}
	if start.RequestBody == nil || start.RequestBody.Value.Content["application/json"].Schema.Value.Properties["provider_id"] == nil {
		t.Fatal("start must accept provider_id JSON")
	}
	if start.RequestBody.Value.Content["application/json"].Schema.Value.Properties["provider_id"].Value.WriteOnly {
		t.Fatal("provider_id must not be secret")
	}
	if start.Parameters.GetByInAndName("path", "collection_id") == nil || start.Parameters.GetByInAndName("path", "connection_id") == nil {
		t.Fatal("start path parameters missing")
	}
	startSchema := start.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	if startSchema.Properties["authorization_url"] == nil || startSchema.Properties["credential"] != nil {
		t.Fatal("start response must expose only authorization URL")
	}
	status := doc.Paths.Value("/auth/v1/account/connections/{collection_id}/{connection_id}/oauth2").Get
	if status == nil || len(*status.Security) != 1 || (*status.Security)[0]["browserSession"] == nil || (*status.Security)[0]["bearerToken"] != nil || (*status.Security)[0]["apiKey"] != nil {
		t.Fatalf("status security=%v", status.Security)
	}
	statusSchema := status.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	for _, field := range []string{"connected", "state", "version", "provider_id", "account_id", "scopes"} {
		if statusSchema.Properties[field] == nil {
			t.Fatalf("status missing %s", field)
		}
	}
	for _, state := range []string{"draft", "ready", "refreshing", "uncertain", "reconnecting", "revoked"} {
		if err := statusSchema.Properties["state"].Value.VisitJSON(state); err != nil {
			t.Fatalf("status state %q rejected: %v", state, err)
		}
	}
	if statusSchema.Properties["version"].Value.Min == nil || *statusSchema.Properties["version"].Value.Min != 0 {
		t.Fatal("status version must allow zero")
	}
	revoke := doc.Paths.Value("/auth/v1/account/connections/{collection_id}/{connection_id}/oauth2").Delete
	if revoke == nil || len(*revoke.Security) != 1 || (*revoke.Security)[0]["browserSession"] == nil || (*revoke.Security)[0]["csrfToken"] == nil || (*revoke.Security)[0]["bearerToken"] != nil || (*revoke.Security)[0]["apiKey"] != nil {
		t.Fatalf("revoke security=%v", revoke.Security)
	}
	if revoke.RequestBody == nil || revoke.RequestBody.Value.Content["application/json"].Schema.Value.Properties["version"] == nil || revoke.Responses.Status(http.StatusNoContent).Value.Content != nil {
		t.Fatal("revoke must require version and return empty 204")
	}
	if min := revoke.RequestBody.Value.Content["application/json"].Schema.Value.Properties["version"].Value.Min; min == nil || *min != 1 {
		t.Fatal("revoke version must be >= 1")
	}
	if revoke.Description == "" || !strings.Contains(revoke.Description, "not revoked") {
		t.Fatal("revoke must distinguish local revoke from provider revocation")
	}
	reconnectPath := "/auth/v1/account/connections/{collection_id}/{connection_id}/oauth2/reconnect"
	reconnect := doc.Paths.Value(reconnectPath).Post
	if reconnect == nil || len(*reconnect.Security) != 1 || (*reconnect.Security)[0]["browserSession"] == nil || (*reconnect.Security)[0]["csrfToken"] == nil || (*reconnect.Security)[0]["bearerToken"] != nil {
		t.Fatalf("reconnect security=%v", reconnect.Security)
	}
	if reconnect.RequestBody == nil || reconnect.RequestBody.Value.Content["application/json"].Schema.Value.Properties["version"] == nil {
		t.Fatal("reconnect must require version")
	}
	if min := reconnect.RequestBody.Value.Content["application/json"].Schema.Value.Properties["version"].Value.Min; min == nil || *min != 1 {
		t.Fatal("reconnect version must be >= 1")
	}
	if reconnect.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value != statusSchema || !strings.Contains(strings.ToLower(reconnect.Description), "no provider call") || !strings.Contains(reconnect.Description, "does not revoke provider-side authorization") {
		t.Fatal("reconnect must return status and avoid provider calls during preparation")
	}
	refreshPath := "/auth/v1/account/connections/{collection_id}/{connection_id}/oauth2/refresh"
	refresh := doc.Paths.Value(refreshPath).Post
	if refresh == nil || refresh.OperationID != "refreshAccountConnectionOAuth2" || len(*refresh.Security) != 1 || (*refresh.Security)[0]["browserSession"] == nil || (*refresh.Security)[0]["csrfToken"] == nil || (*refresh.Security)[0]["bearerToken"] != nil || (*refresh.Security)[0]["apiKey"] != nil {
		t.Fatalf("refresh security=%v", refresh.Security)
	}
	if refresh.RequestBody == nil || refresh.RequestBody.Value.Content["application/json"].Schema.Value.AdditionalProperties.Has == nil || *refresh.RequestBody.Value.Content["application/json"].Schema.Value.AdditionalProperties.Has {
		t.Fatal("refresh body must be strict JSON")
	}
	refreshBody := refresh.RequestBody.Value.Content["application/json"].Schema.Value
	if len(refreshBody.Required) != 1 || refreshBody.Properties["version"] == nil || refreshBody.Properties["version"].Value.Min == nil || *refreshBody.Properties["version"].Value.Min != 1 {
		t.Fatal("refresh must require current version >= 1")
	}
	if refresh.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value != statusSchema {
		t.Fatal("refresh must return metadata-only OAuth status")
	}
	for _, secret := range []string{"access_token", "refresh_token", "client_secret", "credential"} {
		if statusSchema.Properties[secret] != nil {
			t.Fatalf("refresh status exposes secret field %s", secret)
		}
	}
	for _, statusCode := range []int{400, 401, 404, 409, 503} {
		if refresh.Responses.Status(statusCode) == nil {
			t.Fatalf("refresh missing documented error %d", statusCode)
		}
	}
	if !strings.Contains(refresh.Description, "HTTPS") || !strings.Contains(refresh.Description, "no automatic retry") || !strings.Contains(refresh.Description, "uncertain outcome") || !strings.Contains(refresh.Description, "subset") {
		t.Fatal("refresh description missing safety/fence contract")
	}
	callback := doc.Paths.Value("/auth/v1/saas/callback/{provider_id}").Get
	if callback == nil || len(*callback.Security) != 1 || (*callback.Security)[0]["browserSession"] == nil || (*callback.Security)[0]["bearerToken"] != nil || (*callback.Security)[0]["apiKey"] != nil {
		t.Fatalf("callback security=%v", callback.Security)
	}
	if callback.Parameters.GetByInAndName("path", "provider_id") == nil || callback.Parameters.GetByInAndName("query", "state") == nil || callback.Parameters.GetByInAndName("query", "code") == nil {
		t.Fatal("callback parameters missing")
	}
	callbackSchema := callback.Responses.Status(http.StatusOK).Value.Content["application/json"].Schema.Value
	if callback.Responses.Status(http.StatusOK).Value.Content["text/html"] == nil || !strings.Contains(callback.Description, "Sec-Fetch-Mode") || !strings.Contains(callback.Description, "separate explicit consent") {
		t.Fatal("callback HTML navigation contract missing")
	}
	for _, field := range []string{"connected", "account_id", "scopes"} {
		if callbackSchema.Properties[field] == nil {
			t.Fatalf("callback missing %s", field)
		}
	}
	for _, status := range []int{400, 401, 404, 409, 503} {
		if start.Responses.Status(status) == nil || callback.Responses.Status(status) == nil || reconnect.Responses.Status(status) == nil {
			t.Fatalf("missing documented error %d", status)
		}
	}
}
