package apidocs

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mrchypark/goauthy/internal/rbac"
)

func TestSessionListContract(t *testing.T) {
	data, err := Document("https://issuer.example", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	op := doc.Paths.Value("/auth/v1/sessions").Get
	if op == nil || op.Responses.Status(200) == nil || op.Responses.Status(206) == nil {
		t.Fatal("missing sessions operation/responses")
	}
	item := op.Responses.Status(200).Value.Content.Get("application/json").Schema.Value.Items.Value
	for _, name := range []string{"id", "is_mfa", "state", "exp", "last_seen", "remote_ip"} {
		if item.Properties[name] == nil || !slices.Contains(item.Required, name) {
			t.Fatalf("missing %s", name)
		}
	}
	if item.Properties["remote_ip"].Value.Nullable == false {
		t.Fatal("remote_ip must be nullable")
	}
	if item.Properties["user_id"] == nil {
		t.Fatal("missing optional user_id")
	}
	if slices.Contains(item.Required, "user_id") {
		t.Fatal("user_id must remain optional")
	}
	if op.Parameters.GetByInAndName("query", "session_state").Schema.Value.Default != "Auth" {
		t.Fatal("session state default must be Auth")
	}
	userID, peerIP := "ordinary-user", "127.0.0.1"
	for _, dto := range []rbac.Session{{ID: "init", State: "Init"}, {ID: "authenticated", UserID: &userID, RemoteIP: &peerIP, State: "Auth", Exp: 1700000000, LastSeen: 1699999999}} {
		wire, err := json.Marshal(dto)
		if err != nil {
			t.Fatal(err)
		}
		var sample any
		if err := json.Unmarshal(wire, &sample); err != nil {
			t.Fatal(err)
		}
		if err := item.VisitJSON(sample); err != nil {
			t.Fatalf("DTO does not match OpenAPI: %v", err)
		}
	}
	if op.Responses.Status(206).Value.Headers["x-page-size"] == nil || op.Responses.Status(206).Value.Headers["x-page-count"] == nil || op.Responses.Status(206).Value.Headers["x-continuation-token"] == nil {
		t.Fatal("missing pagination headers")
	}
	if op.Responses.Status(206).Value.Headers["x-user-count"] != nil {
		t.Fatal("sessions must not emit x-user-count")
	}
}
